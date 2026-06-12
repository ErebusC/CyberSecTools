use std::path::PathBuf;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use rust_embed::RustEmbed;

use crate::assets::{StaticAssets, WasmAssets};

pub struct AppState {
    pub target_url: String,
    pub collab_url: String,
    /// URL given to the template: either a remote https:// URL or "/logo-img".
    pub logo_url: String,
    /// Local file path served at /logo-img, if a local logo was configured.
    pub logo_path: Option<PathBuf>,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate<'a> {
    target_url: &'a str,
    collab_url: &'a str,
    logo_url: &'a str,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let has_logo_path = state.logo_path.is_some();

    // All routes must be registered before with_state() freezes the state type.
    let mut router = Router::new()
        .route("/", get(index_handler))
        .route("/static/{*path}", get(static_handler))
        .route("/wasm/{*path}", get(wasm_handler));

    if has_logo_path {
        router = router.route("/logo-img", get(logo_handler));
    }

    router.with_state(state)
}

async fn index_handler(State(state): State<Arc<AppState>>) -> Response {
    let template = IndexTemplate {
        target_url: &state.target_url,
        collab_url: &state.collab_url,
        logo_url: &state.logo_url,
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            tracing::error!("failed to render index template: {}", err);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn static_handler(Path(path): Path<String>) -> Response {
    serve_embedded::<StaticAssets>(&path)
}

async fn wasm_handler(Path(path): Path<String>) -> Response {
    serve_embedded::<WasmAssets>(&path)
}

async fn logo_handler(State(state): State<Arc<AppState>>) -> Response {
    let path = match &state.logo_path {
        Some(p) => p.clone(),
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    match tokio::fs::read(&path).await {
        Ok(bytes) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            ([(header::CONTENT_TYPE, mime.as_ref().to_owned())], bytes).into_response()
        }
        Err(err) => {
            tracing::warn!("failed to read logo file {}: {}", path.display(), err);
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

fn serve_embedded<E: RustEmbed>(path: &str) -> Response {
    match E::get(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                [(header::CONTENT_TYPE, mime.as_ref().to_owned())],
                file.data.into_owned(),
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
