//! Standalone Share service and admitted HTTP readiness probe.
use std::{
    io::{
        self,
        Write,
    },
    net::SocketAddr,
    path::PathBuf,
    time::Duration,
};

use clap::{
    Parser,
    Subcommand,
};
use share_relay::Queue;
use tokio::{
    net::TcpListener,
    signal::unix::{
        SignalKind,
        signal,
    },
};

#[derive(Parser)]
#[command(version, about = "Persistent encrypted-bundle queue")]
struct Arguments {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(long, env = "SHARE_RELAY_ADDR", default_value = "0.0.0.0:6697")]
    address: SocketAddr,
    #[arg(
        long,
        env = "SHARE_DATA_DIR",
        default_value = "/var/lib/snoo-box-share"
    )]
    data_dir: PathBuf,
    #[arg(long, env = "SHARE_STORAGE_BYTES", default_value = "10737418240")]
    storage_bytes: i64,
    #[arg(long, env = "SHARE_RELAY_ALLOWED_HOST", value_delimiter = ',')]
    allowed_host: Vec<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Validate both HTTP endpoints from the caller's network namespace.
    Probe { address: String },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let arguments = Arguments::parse();
    if let Some(Command::Probe { address }) = arguments.command {
        return share_relay::probe(&address).await;
    }
    let queue = Queue::open(
        arguments.data_dir,
        arguments.storage_bytes,
        arguments.allowed_host,
    )
    .await?;
    let listener = TcpListener::bind(arguments.address).await?;
    // Only the public listener address is logged; never requests, tokens, or payloads.
    writeln!(
        io::stderr(),
        "Share listening on {}",
        listener.local_addr()?
    )?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let sweeping = queue.clone();
    let sweeper = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if sweeping.sweep().await.is_err() {
                let _ = writeln!(io::stderr(), "Share expiry cleanup failed");
            }
        }
    });
    let (shutdown, requested) = tokio::sync::oneshot::channel();
    let service = axum::serve(
        listener,
        share_relay::router(queue).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = requested.await;
    });
    let service = std::future::IntoFuture::into_future(service);
    tokio::pin!(service);
    tokio::select! {
        result = &mut service => { sweeper.abort(); result?; return Ok(()); }
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
    let _ = shutdown.send(());
    // Do not leave slow peers holding shutdown forever; startup cleans abandoned uploads.
    if let Ok(result) = tokio::time::timeout(Duration::from_secs(10), service).await {
        result?;
    }
    sweeper.abort();
    Ok(())
}
