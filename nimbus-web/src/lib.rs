// =============================================================================
// NimbusDNS Web Panel - Static File Serving
// =============================================================================
// Exposes the Assets struct and helper functions for the API server
// to embed the web panel on the same port.

use axum::{
    response::Response,
    http::StatusCode,
};
use rust_embed::Embed;

/// Embedded static files for the web panel
#[derive(Embed)]
#[folder = "static/"]
pub struct Assets;

/// Serve a file from the embedded assets
pub fn serve_file(filename: &str) -> Response {
    let filename = if filename.is_empty() || filename == "/" {
        "index.html"
    } else {
        filename.trim_start_matches('/')
    };

    match Assets::get(filename) {
        Some(content) => {
            let mime = mime_type(filename);
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", mime)
                .body(axum::body::Body::from(content.data))
                .unwrap()
        }
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(axum::body::Body::from("Not found"))
            .unwrap(),
    }
}

fn mime_type(filename: &str) -> &'static str {
    if filename.ends_with(".html") { "text/html; charset=utf-8" }
    else if filename.ends_with(".css") { "text/css; charset=utf-8" }
    else if filename.ends_with(".js") { "application/javascript; charset=utf-8" }
    else if filename.ends_with(".png") { "image/png" }
    else if filename.ends_with(".svg") { "image/svg+xml" }
    else if filename.ends_with(".ico") { "image/x-icon" }
    else { "application/octet-stream" }
}
