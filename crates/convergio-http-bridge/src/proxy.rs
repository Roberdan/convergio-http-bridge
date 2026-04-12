//! Route proxy — forwards requests under /api/ext/ to HTTP extensions.
//!
//! When an extension declares routes_prefix="/api/ext/openclaw", any request to
//! /api/ext/openclaw/* is proxied to the extension's base_url.

use axum::body::Body;
use axum::extract::Path;
use axum::http::{Method, Request, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use convergio_db::pool::ConnPool;
use std::time::Duration;
use tracing::warn;

/// Shared reqwest client for proxy requests (avoids per-request allocation).
static PROXY_CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build proxy HTTP client")
});

/// Headers that must not be forwarded to the upstream extension.
const HOP_BY_HOP: &[&str] = &[
    "host",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
];

/// Proxy handler: captures /api/ext/*rest, splits into ext_id + remaining path.
pub async fn proxy_handler(
    axum::Extension(pool): axum::Extension<ConnPool>,
    method: Method,
    Path(rest): Path<String>,
    req: Request<Body>,
) -> impl IntoResponse {
    // rest = "openclaw/some/path" — first segment is ext_id
    let (ext_id, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx + 1..]),
        None => (rest.as_str(), ""),
    };

    let (base_url, state) = {
        let conn = match pool.get() {
            Ok(c) => c,
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
        };
        match crate::store::get_by_id(&conn, ext_id) {
            Ok(Some(ext)) => (ext.base_url, ext.state),
            Ok(None) => return err_response(StatusCode::NOT_FOUND, "extension not found"),
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &e),
        }
    };

    if state != crate::types::BridgeState::Active {
        return err_response(StatusCode::SERVICE_UNAVAILABLE, "extension not active");
    }

    // Preserve query string from the original request
    let query = req.uri().query();
    let target_url = match (path.is_empty(), query) {
        (true, None) => base_url.clone(),
        (true, Some(q)) => format!("{base_url}?{q}"),
        (false, None) => format!("{base_url}/{path}"),
        (false, Some(q)) => format!("{base_url}/{path}?{q}"),
    };
    forward_request(&target_url, method, req, ext_id).await
}

async fn forward_request(
    url: &str,
    method: Method,
    req: Request<Body>,
    ext_id: &str,
) -> axum::response::Response {
    let client = &*PROXY_CLIENT;
    let builder = match method {
        Method::GET => client.get(url),
        Method::POST => client.post(url),
        Method::PUT => client.put(url),
        Method::DELETE => client.delete(url),
        Method::PATCH => client.patch(url),
        _ => return err_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    };

    // Forward headers, skipping hop-by-hop headers
    let (parts, body) = req.into_parts();
    let mut builder = builder;
    for (name, value) in &parts.headers {
        if HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            builder = builder.header(name.as_str(), v);
        }
    }

    // Forward request body for methods that carry one
    if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
        let bytes = match axum::body::to_bytes(Body::new(body), 10 * 1024 * 1024).await {
            Ok(b) => b,
            Err(e) => {
                warn!(ext_id = %ext_id, error = %e, "failed to read request body");
                return err_response(StatusCode::BAD_REQUEST, "failed to read request body");
            }
        };
        builder = builder.body(bytes);
    }

    match builder.send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let body = resp.text().await.unwrap_or_default();
            (status, body).into_response()
        }
        Err(e) => {
            warn!(ext_id = %ext_id, error = %e, "proxy request failed");
            err_response(StatusCode::BAD_GATEWAY, &format!("proxy: {e}"))
        }
    }
}

fn err_response(status: StatusCode, msg: &str) -> axum::response::Response {
    (status, Json(serde_json::json!({"error": msg}))).into_response()
}

/// Build the proxy route: /api/ext/{*rest} catches all extension traffic.
pub fn proxy_routes() -> axum::Router {
    axum::Router::new().route("/api/ext/*rest", axum::routing::any(proxy_handler))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_routes_builds() {
        let _router = proxy_routes();
    }

    #[test]
    fn parse_ext_id_from_path() {
        let rest = "openclaw/contracts/list";
        let (ext_id, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx + 1..]),
            None => (rest, ""),
        };
        assert_eq!(ext_id, "openclaw");
        assert_eq!(path, "contracts/list");
    }

    #[test]
    fn parse_ext_id_no_subpath() {
        let rest = "openclaw";
        let (ext_id, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx + 1..]),
            None => (rest, ""),
        };
        assert_eq!(ext_id, "openclaw");
        assert_eq!(path, "");
    }

    #[test]
    fn hop_by_hop_headers_blocked() {
        for h in HOP_BY_HOP {
            assert!(
                [
                    "host",
                    "connection",
                    "keep-alive",
                    "transfer-encoding",
                    "te",
                    "trailer",
                    "upgrade"
                ]
                .contains(h),
                "unexpected hop-by-hop header: {h}"
            );
        }
    }
}
