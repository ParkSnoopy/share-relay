#![expect(
    clippy::panic_in_result_fn,
    reason = "Integration tests assert contracts and propagate setup/transport errors"
)]

use std::{
    io,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    http::StatusCode,
    response::IntoResponse,
};
use reqwest::Client;
use serde_json::{
    Value,
    json,
};
use share_relay::{
    Item,
    Queue,
};
use tokio::{
    io::AsyncWriteExt,
    net::{
        TcpListener,
        TcpStream,
    },
    task::JoinHandle,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn private_temp() -> Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(directory)
}

struct Server {
    address: SocketAddr,
    task: JoinHandle<io::Result<()>>,
    queue: Arc<Queue>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn start(root: &Path, quota: i64, host: &str) -> Result<Self> {
        let queue = Queue::open(root.to_path_buf(), quota, vec![host.to_owned()]).await?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let app = share_relay::router(queue.clone());
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
        });
        Ok(Self {
            address,
            task,
            queue,
        })
    }
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }
    async fn stop(self) {
        self.task.abort();
        // Await cancellation so the queue's process lock is released before reopening.
        while !self.task.is_finished() {
            tokio::task::yield_now().await;
        }
    }
}
fn client() -> Result<Client> {
    Ok(Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()?)
}
async fn token(root: &Path) -> Result<String> {
    Ok(tokio::fs::read_to_string(root.join("manager.token")).await?)
}

#[tokio::test]
async fn api_authority_retention_persistence_and_expiry() -> Result {
    let directory = private_temp()?;
    let server = Server::start(directory.path(), 1 << 20, "localhost").await?;
    let client = client()?;
    let authority = token(directory.path()).await?;
    share_relay::probe(&server.address.to_string()).await?;
    let policy: Value = client
        .get(server.url("/policy"))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(policy, json!({"manager":false, "userRetentionHours":72}));
    for hours in [0, 73, 96, i64::MAX] {
        let response = client
            .post(server.url("/items"))
            .query(&[
                ("title", "  DUMMY 한글  "),
                ("kind", "files"),
                ("hours", &hours.to_string()),
            ])
            .bearer_auth("DUMMY-forged-authority")
            .body("DUMMY ciphertext")
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let item: Item = response.json().await?;
        assert!(!item.manager && item.retention_adjusted);
        assert_eq!(item.expires - item.created, 72 * 3600);
        assert_eq!(item.title, "DUMMY 한글");
        let downloaded = client
            .get(server.url(&format!("/items/{}", item.id)))
            .send()
            .await?;
        assert_eq!(
            downloaded.headers()["content-type"],
            "application/octet-stream"
        );
        assert_eq!(downloaded.bytes().await?, "DUMMY ciphertext");
        tokio::fs::remove_dir_all(directory.path().join("queue").join(item.id)).await?;
    }
    let forbidden = client
        .post(server.url("/items?title=DUMMY&kind=configuration&hours=0"))
        .body("DUMMY")
        .send()
        .await?;
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    let ordinary: Item = client
        .post(server.url("/items?title=DUMMY&kind=files&hours=1"))
        .body("DUMMY ordinary")
        .send()
        .await?
        .json()
        .await?;
    let permanent: Item = client
        .post(server.url("/items?title=DUMMY&kind=configuration&hours=0"))
        .bearer_auth(&authority)
        .body("DUMMY configuration")
        .send()
        .await?
        .json()
        .await?;
    assert!(permanent.manager && !permanent.retention_adjusted);
    assert_eq!(permanent.expires, 0);
    let policy: Value = client
        .get(server.url("/policy"))
        .bearer_auth(&authority)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(policy["manager"], true);
    server.stop().await;
    let abandoned = directory.path().join("queue/.upload-DUMMY");
    tokio::fs::create_dir(&abandoned).await?;
    tokio::fs::write(abandoned.join("bundle"), "DUMMY incomplete").await?;
    let server = Server::start(directory.path(), 1 << 20, "localhost").await?;
    assert!(!abandoned.exists());
    assert_eq!(token(directory.path()).await?, authority);
    let items: Vec<Item> = client
        .get(server.url("/items"))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|item| !item.retention_adjusted));
    let mut expired = ordinary.clone();
    expired.expires = 1;
    tokio::fs::write(
        directory
            .path()
            .join("queue")
            .join(&ordinary.id)
            .join("metadata.json"),
        serde_json::to_vec(&expired)?,
    )
    .await?;
    server.queue.sweep().await?;
    assert!(!directory.path().join("queue").join(&ordinary.id).exists());
    assert_eq!(
        client
            .get(server.url(&format!("/items/{}", ordinary.id)))
            .send()
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    let items: Vec<Item> = client
        .get(server.url("/items"))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, permanent.id);
    Ok(())
}

#[tokio::test]
async fn source_admission_and_manager_bypass() -> Result {
    let directory = private_temp()?;
    let server = Server::start(directory.path(), 1024, "192.0.2.1").await?;
    let client = client()?;
    for path in ["/policy", "/items", "/items/../../manager.token"] {
        let response = client
            .get(server.url(path))
            .header("X-Forwarded-For", "192.0.2.1")
            .bearer_auth("DUMMY-forged")
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    assert!(
        share_relay::probe(&server.address.to_string())
            .await
            .is_err()
    );
    let response = client
        .get(server.url("/policy"))
        .bearer_auth(token(directory.path()).await?)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.json::<Value>().await?["manager"], true);
    Ok(())
}

#[tokio::test]
async fn validation_quota_and_partial_upload_cleanup() -> Result {
    let directory = private_temp()?;
    let server = Server::start(directory.path(), 32, "127.0.0.1").await?;
    let client = client()?;
    for query in [
        "title=DUMMY&kind=files&hours=-1",
        "title=DUMMY&kind=files&hours=oops",
        "title=&kind=files&hours=1",
        "title=%0aDUMMY%00&kind=files&hours=1",
        "title=DUMMY&kind=other&hours=1",
    ] {
        let response = client
            .post(server.url(&format!("/items?{query}")))
            .body("DUMMY")
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
    }
    let response = client
        .post(server.url("/items?title=DUMMY&kind=files&hours=9223372036854775807"))
        .bearer_auth(token(directory.path()).await?)
        .body("DUMMY")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        client
            .post(server.url("/items?title=DUMMY&kind=files&hours=1"))
            .body("")
            .send()
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        client
            .post(server.url("/items?title=DUMMY&kind=files&hours=1"))
            .body(vec![0; 33])
            .send()
            .await?
            .status(),
        StatusCode::INSUFFICIENT_STORAGE
    );
    let mut socket = TcpStream::connect(server.address).await?;
    socket.write_all(b"POST /items?title=DUMMY&kind=files&hours=1 HTTP/1.1\r\nHost: share\r\nContent-Length: 20\r\n\r\npartial").await?;
    drop(socket);
    // Observe cleanup before asserting catalog state; bounded, no blind long delay.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let response = client
            .post(server.url("/items?title=DUMMY&kind=files&hours=1"))
            .body(vec![1; 32])
            .send()
            .await?;
        if response.status() == StatusCode::CONFLICT && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        }
        assert_eq!(response.status(), StatusCode::CREATED);
        break;
    }
    assert_eq!(
        client
            .post(server.url("/items?title=DUMMY&kind=files&hours=1"))
            .body("x")
            .send()
            .await?
            .status(),
        StatusCode::INSUFFICIENT_STORAGE
    );
    let mut entries = tokio::fs::read_dir(directory.path().join("queue")).await?;
    while let Some(entry) = entries.next_entry().await? {
        assert!(!entry.file_name().to_string_lossy().starts_with(".upload-"));
    }
    assert_eq!(
        client
            .get(server.url("/items/%2e%2e%2fmanager.token"))
            .send()
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_uploads_are_serialized_but_reads_are_not() -> Result {
    let directory = private_temp()?;
    let server = Server::start(directory.path(), 1 << 20, "127.0.0.1").await?;
    let client = client()?;
    let mut socket = TcpStream::connect(server.address).await?;
    socket.write_all(b"POST /items?title=DUMMY&kind=files&hours=1 HTTP/1.1\r\nHost: share\r\nContent-Length: 100\r\n\r\nx").await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let mut entries = tokio::fs::read_dir(directory.path().join("queue")).await?;
        if entries.next_entry().await?.is_some() {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            return Err("upload did not start".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        client
            .post(server.url("/items?title=DUMMY&kind=files&hours=1"))
            .body("x")
            .send()
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        client
            .get(server.url("/items"))
            .send()
            .await?
            .json::<Value>()
            .await?,
        json!([])
    );
    assert!(
        Queue::open(
            directory.path().to_path_buf(),
            1024,
            vec!["localhost".into()]
        )
        .await
        .is_err()
    );
    drop(socket);
    Ok(())
}

#[tokio::test]
async fn probe_rejects_missing_invalid_denied_and_redirected_endpoints() -> Result {
    for (policy_status, policy, list_status, list) in [
        (
            200,
            r#"{"manager":false,"userRetentionHours":72}"#,
            200,
            "[]",
        ),
        (404, "missing", 200, "[]"),
        (
            200,
            r#"{"manager":false,"userRetentionHours":72}"#,
            403,
            "denied",
        ),
        (
            200,
            r#"{"manager":false,"userRetentionHours":72}"#,
            200,
            "welcome",
        ),
        (302, "redirect", 200, "[]"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let app = Router::new().fallback(move |request: axum::extract::Request| {
            async move {
                assert!(request.headers().get("authorization").is_none());
                let (status, body) = if request.uri().path() == "/policy" {
                    (policy_status, policy)
                } else {
                    (list_status, list)
                };
                (
                    StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    Body::from(body),
                )
                    .into_response()
            }
        });
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        let result = share_relay::probe(&address.to_string()).await;
        task.abort();
        assert_eq!(
            result.is_ok(),
            policy_status == 200 && list_status == 200 && list == "[]"
        );
    }
    Ok(())
}

#[tokio::test]
async fn private_storage_and_configuration_fail_closed() -> Result {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    for hosts in [
        vec![],
        vec![String::new()],
        vec!["0.0.0.0/0".into()],
        vec!["localhost,".into()],
    ] {
        assert!(
            Queue::open(directory.path().to_path_buf(), 1024, hosts)
                .await
                .is_err()
        );
    }
    for quota in [0, -1, i64::MAX] {
        assert!(
            Queue::open(
                directory.path().to_path_buf(),
                quota,
                vec!["localhost".into()]
            )
            .await
            .is_err()
        );
    }
    tokio::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).await?;
    assert!(
        Queue::open(
            directory.path().to_path_buf(),
            1024,
            vec!["localhost".into()]
        )
        .await
        .is_err()
    );
    tokio::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).await?;
    tokio::fs::write(directory.path().join("manager.token"), "DUMMY malformed").await?;
    assert!(
        Queue::open(
            directory.path().to_path_buf(),
            1024,
            vec!["localhost".into()]
        )
        .await
        .is_err()
    );
    Ok(())
}
