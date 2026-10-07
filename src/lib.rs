//! Persistent opaque Share queue. Encryption and profile application belong to clients.
use std::{
    io,
    net::SocketAddr,
    os::unix::fs::{
        DirBuilderExt,
        OpenOptionsExt,
        PermissionsExt,
    },
    path::{
        Path,
        PathBuf,
    },
    sync::Arc,
    time::{
        Duration,
        SystemTime,
        UNIX_EPOCH,
    },
};

use axum::{
    Json,
    Router,
    body::Body,
    extract::{
        ConnectInfo,
        Query,
        Request,
        State,
    },
    http::{
        Method,
        StatusCode,
    },
    response::{
        IntoResponse,
        Response,
    },
};
use fs2::FileExt;
use futures_util::StreamExt;
use rand::RngCore;
use serde::{
    Deserialize,
    Serialize,
};
use subtle::ConstantTimeEq;
use tokio::{
    fs,
    io::AsyncWriteExt,
    sync::{
        Mutex,
        Semaphore,
    },
    time::timeout,
};
use tokio_util::io::ReaderStream;

pub const USER_RETENTION_HOURS: i64 = 72;
const MAX_ITEMS: usize = 512;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(3600);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub id: String,
    pub title: String,
    pub kind: Kind,
    pub size: i64,
    pub created: i64,
    pub expires: i64,
    pub manager: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub retention_adjusted: bool,
}


#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Files,
    Configuration,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub manager: bool,
    pub user_retention_hours: i64,
}

#[derive(Deserialize)]
struct Upload {
    title: String,
    kind: Kind,
    hours: i64,
}

pub struct Queue {
    root: PathBuf,
    token: String,
    max_bytes: i64,
    hosts: Vec<String>,
    upload: Semaphore,
    catalog: Mutex<()>,
    // Keep the OS lock for the queue lifetime, including startup cleanup.
    _lock: std::fs::File,
}

type ApiResult = Result<Response, (StatusCode, &'static str)>;
const STORAGE_ERROR: (StatusCode, &str) = (
    StatusCode::SERVICE_UNAVAILABLE,
    "Share storage unavailable\n",
);

fn private_directory(path: &Path) -> io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::other(
            "Share storage must be a private directory",
        ));
    }
    Ok(())
}

fn random_hex(bytes: usize) -> io::Result<String> {
    use std::fmt::Write;
    let mut data = vec![0; bytes];
    rand::rngs::OsRng
        .try_fill_bytes(&mut data)
        .map_err(io::Error::other)?;
    let mut value = String::with_capacity(bytes * 2);
    for byte in data {
        write!(&mut value, "{byte:02x}").map_err(io::Error::other)?;
    }
    Ok(value)
}
fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn now() -> io::Result<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_secs(),
    )
    .map_err(io::Error::other)
}

impl Queue {
    pub async fn open(root: PathBuf, max_bytes: i64, hosts: Vec<String>) -> io::Result<Arc<Self>> {
        if max_bytes <= 0
            || max_bytes == i64::MAX
            || hosts.is_empty()
            || hosts.iter().any(|host| {
                host.is_empty()
                    || host.contains('/')
                    || host.chars().any(char::is_whitespace)
                    || (host.parse::<std::net::IpAddr>().is_err()
                        && !host
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.'))
            })
        {
            return Err(io::Error::other("invalid Share configuration"));
        }
        private_directory(&root)?;
        let lock_path = root.join("queue.lock");
        if lock_path.is_symlink() {
            return Err(io::Error::other("unsafe queue lock"));
        }
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(lock_path)?;
        lock.try_lock_exclusive()?;
        let token_path = root.join("manager.token");
        let token = match fs::symlink_metadata(&token_path).await {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.len() != 64
                    || metadata.permissions().mode() & 0o077 != 0
                {
                    return Err(io::Error::other("invalid manager authority"));
                }
                fs::read_to_string(&token_path).await?
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let value = random_hex(32)?;
                let mut file = tempfile::NamedTempFile::new_in(&root)?;
                std::io::Write::write_all(&mut file, value.as_bytes())?;
                file.as_file().sync_all()?;
                file.persist_noclobber(&token_path)
                    .map_err(io::Error::other)?;
                std::fs::File::open(&root)?.sync_all()?;
                value
            }
            Err(error) => return Err(error),
        };
        if token.len() != 64 || !token.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(io::Error::other("invalid manager authority"));
        }
        let root = root.join("queue");
        private_directory(&root)?;
        let mut entries = fs::read_dir(&root).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_name().to_string_lossy().starts_with(".upload-") {
                if !entry.file_type().await?.is_dir() {
                    return Err(io::Error::other("unsafe upload staging"));
                }
                fs::remove_dir_all(entry.path()).await?;
            }
        }
        let queue = Arc::new(Self {
            root,
            token,
            max_bytes,
            hosts,
            upload: Semaphore::new(1),
            catalog: Mutex::new(()),
            _lock: lock,
        });
        queue.inventory().await?;
        Ok(queue)
    }

    async fn inventory(&self) -> io::Result<(Vec<Item>, i64)> {
        let _guard = self.catalog.lock().await;
        let clock = now()?;
        let mut entries = fs::read_dir(&self.root).await?;
        let mut items = Vec::new();
        let mut used = 0_i64;
        while let Some(entry) = entries.next_entry().await? {
            let id = entry.file_name().to_string_lossy().into_owned();
            if !valid_id(&id) {
                continue;
            }
            if !entry.file_type().await?.is_dir() {
                return Err(io::Error::other("invalid queue storage"));
            }
            let path = entry.path().join("metadata.json");
            let metadata = fs::symlink_metadata(&path).await?;
            if !metadata.is_file() || metadata.len() > 8192 {
                return Err(io::Error::other("invalid queued metadata"));
            }
            let item: Item =
                serde_json::from_slice(&fs::read(path).await?).map_err(io::Error::other)?;
            if item.id != id || item.size <= 0 {
                return Err(io::Error::other("invalid queued item"));
            }
            if item.expires != 0 && item.expires <= clock {
                fs::remove_dir_all(entry.path()).await?;
                continue;
            }
            let data = fs::symlink_metadata(entry.path().join("bundle")).await?;
            if !data.is_file() || i64::try_from(data.len()).ok() != Some(item.size) {
                return Err(io::Error::other("invalid queued bundle"));
            }
            used = used
                .checked_add(item.size)
                .ok_or_else(|| io::Error::other("invalid queue size"))?;
            items.push(item);
            if items.len() > MAX_ITEMS {
                return Err(io::Error::other("queue catalog limit exceeded"));
            }
        }
        items.sort_by(|a, b| b.created.cmp(&a.created).then(a.id.cmp(&b.id)));
        Ok((items, used))
    }

    async fn admitted(&self, peer: SocketAddr) -> bool {
        timeout(Duration::from_secs(3), async {
            for host in &self.hosts {
                if let Ok(addresses) = tokio::net::lookup_host((host.as_str(), 0)).await
                    && addresses
                        .into_iter()
                        .any(|addr| addr.ip().to_canonical() == peer.ip().to_canonical())
                {
                    return true;
                }
            }
            false
        })
        .await
        .unwrap_or(false)
    }

    pub async fn sweep(&self) -> io::Result<()> {
        self.inventory().await.map(|_| ())
    }

    async fn upload(&self, request: Request, manager: bool) -> ApiResult {
        // Query parsing precedes duration arithmetic; ordinary limits clamp even i64::MAX.
        let Query(mut upload) = Query::<Upload>::try_from_uri(request.uri())
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid share details\n"))?;
        if upload.hours < 0 || (manager && upload.hours > i64::MAX / 3_600_000_000_000) {
            return Err((StatusCode::BAD_REQUEST, "invalid retention hours\n"));
        }
        upload.title = upload.title.trim().to_owned();
        if upload.title.is_empty()
            || upload.title.len() > 512
            || upload.title.chars().any(char::is_control)
        {
            return Err((StatusCode::BAD_REQUEST, "invalid share details\n"));
        }
        if matches!(upload.kind, Kind::Configuration) && !manager {
            return Err((StatusCode::FORBIDDEN, "manager authority required\n"));
        }
        let adjusted = !manager && (upload.hours == 0 || upload.hours > USER_RETENTION_HOURS);
        if adjusted {
            upload.hours = USER_RETENTION_HOURS;
        }
        let _permit = self
            .upload
            .try_acquire()
            .map_err(|_| (StatusCode::CONFLICT, "another upload is in progress\n"))?;
        let (items, used) = self.inventory().await.map_err(|_| STORAGE_ERROR)?;
        let remaining = self.max_bytes - used;
        if remaining <= 0 || items.len() >= MAX_ITEMS {
            return Err((StatusCode::INSUFFICIENT_STORAGE, "Share storage is full\n"));
        }
        let staging = tempfile::Builder::new()
            .prefix(".upload-")
            .tempdir_in(&self.root)
            .map_err(|_| STORAGE_ERROR)?;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(staging.path().join("bundle"))
            .await
            .map_err(|_| STORAGE_ERROR)?;
        let mut stream = request.into_body().into_data_stream();
        let size = timeout(TRANSFER_TIMEOUT, async {
            let mut size = 0_i64;
            while let Some(chunk) = stream.next().await {
                let chunk =
                    chunk.map_err(|_| (StatusCode::BAD_REQUEST, "upload did not complete\n"))?;
                let length = i64::try_from(chunk.len()).map_err(|_| STORAGE_ERROR)?;
                if length > remaining - size {
                    return Err((StatusCode::INSUFFICIENT_STORAGE, "Share storage is full\n"));
                }
                file.write_all(&chunk).await.map_err(|_| STORAGE_ERROR)?;
                size += length;
            }
            file.sync_all().await.map_err(|_| STORAGE_ERROR)?;
            Ok(size)
        })
        .await
        .map_err(|_| (StatusCode::REQUEST_TIMEOUT, "upload did not complete\n"))??;
        drop(file);
        if size == 0 {
            return Err((StatusCode::BAD_REQUEST, "upload did not complete\n"));
        }
        let created = now().map_err(|_| STORAGE_ERROR)?;
        let mut item = Item {
            id: random_hex(16).map_err(|_| STORAGE_ERROR)?,
            title: upload.title,
            kind: upload.kind,
            size,
            created,
            expires: if upload.hours == 0 {
                0
            } else {
                created + upload.hours * 3600
            },
            manager,
            retention_adjusted: false,
        };
        let metadata = serde_json::to_vec(&item).map_err(|_| STORAGE_ERROR)?;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(staging.path().join("metadata.json"))
            .await
            .map_err(|_| STORAGE_ERROR)?;
        file.write_all(&metadata).await.map_err(|_| STORAGE_ERROR)?;
        file.sync_all().await.map_err(|_| STORAGE_ERROR)?;
        fs::File::open(staging.path())
            .await
            .map_err(|_| STORAGE_ERROR)?
            .sync_all()
            .await
            .map_err(|_| STORAGE_ERROR)?;
        let _guard = self.catalog.lock().await;
        fs::rename(staging.path(), self.root.join(&item.id))
            .await
            .map_err(|_| STORAGE_ERROR)?;
        fs::File::open(&self.root)
            .await
            .map_err(|_| STORAGE_ERROR)?
            .sync_all()
            .await
            .map_err(|_| STORAGE_ERROR)?;
        item.retention_adjusted = adjusted;
        Ok((StatusCode::CREATED, Json(item)).into_response())
    }

    async fn request(&self, peer: SocketAddr, request: Request) -> ApiResult {
        let expected = format!("Bearer {}", self.token);
        let manager = request
            .headers()
            .get("authorization")
            .is_some_and(|value| bool::from(value.as_bytes().ct_eq(expected.as_bytes())));
        if !manager && !self.admitted(peer).await {
            return Err((StatusCode::FORBIDDEN, "VPN access required\n"));
        }
        let path = request.uri().path();
        if path == "/policy" && request.method() == Method::GET {
            return Ok(Json(Policy {
                manager,
                user_retention_hours: USER_RETENTION_HOURS,
            })
            .into_response());
        }
        if path == "/items" && request.method() == Method::POST {
            return self.upload(request, manager).await;
        }
        let (items, _) = self.inventory().await.map_err(|_| STORAGE_ERROR)?;
        if path == "/items" && request.method() == Method::GET {
            return Ok(Json(items).into_response());
        }
        let id = path.strip_prefix("/items/").unwrap_or("");
        if request.method() != Method::GET || !valid_id(id) {
            return Err((StatusCode::NOT_FOUND, "404 page not found\n"));
        }
        let item = items
            .iter()
            .find(|item| item.id == id)
            .ok_or((StatusCode::NOT_FOUND, "404 page not found\n"))?;
        let file = {
            let _guard = self.catalog.lock().await;
            fs::File::open(self.root.join(id).join("bundle"))
                .await
                .map_err(|_| (StatusCode::NOT_FOUND, "404 page not found\n"))?
        };
        let mut response = Body::from_stream(ReaderStream::new(file)).into_response();
        response.headers_mut().insert(
            "content-type",
            "application/octet-stream"
                .parse()
                .map_err(|_| STORAGE_ERROR)?,
        );
        response.headers_mut().insert(
            "content-length",
            item.size.to_string().parse().map_err(|_| STORAGE_ERROR)?,
        );
        Ok(response)
    }
}

async fn handle(
    State(queue): State<Arc<Queue>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let mut response = queue.request(peer, request).await.into_response();
    response.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        "x-content-type-options",
        axum::http::HeaderValue::from_static("nosniff"),
    );
    response
}

pub fn router(queue: Arc<Queue>) -> Router {
    Router::new().fallback(handle).with_state(queue)
}

/// Probe both admitted endpoints without authority or a proxy fallback.
pub async fn probe(address: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = reqwest::Url::parse(&format!("http://{address}"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("invalid probe address".into());
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;
    for (path, limit) in [("policy", 8192), ("items", 4 << 20)] {
        let response = client
            .get(url.join(path)?)
            .send()
            .await?
            .error_for_status()?;
        if !response.status().is_success() {
            return Err("Share probe requires a successful HTTP response".into());
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if bytes.len() + chunk.len() > limit {
                return Err("Share probe response too large".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        if path == "policy" {
            let policy: Policy = serde_json::from_slice(&bytes)?;
            if policy.manager || policy.user_retention_hours != USER_RETENTION_HOURS {
                return Err("invalid Share policy".into());
            }
        } else {
            let _: Vec<Item> = serde_json::from_slice(&bytes)?;
        }
    }
    Ok(())
}
