//! Axum handlers for the HTTP extension bridge API.
//!
//! - POST /api/extensions/register — register an external extension
//! - GET  /api/extensions — list all active extensions
//! - GET  /api/extensions/:id — get a single extension
//! - DELETE /api/extensions/:id — remove an extension

use crate::store;
use crate::types::RegisterRequest;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use convergio_db::pool::ConnPool;

/// POST /api/extensions/register
pub async fn register_extension(
    axum::Extension(pool): axum::Extension<ConnPool>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    if let Err(msg) = validate_request(&req) {
        return (StatusCode::BAD_REQUEST, Json(error_body(&msg))).into_response();
    }
    let conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body(&format!("db: {e}"))),
            )
                .into_response()
        }
    };
    // Check for duplicate
    match store::get_by_id(&conn, &req.id) {
        Ok(Some(existing)) if existing.state != crate::types::BridgeState::Removed => {
            return (
                StatusCode::CONFLICT,
                Json(error_body(&format!(
                    "extension '{}' already registered",
                    req.id
                ))),
            )
                .into_response()
        }
        Ok(Some(_removed)) => {
            // Extension was removed — delete old record so it can be re-registered
            if let Err(e) = store::delete_extension(&conn, &req.id) {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_body(&e))).into_response();
            }
        }
        _ => {}
    }
    match store::insert_extension(&conn, &req) {
        Ok(()) => {
            tracing::info!(ext_id = %req.id, "HTTP extension registered");
            (
                StatusCode::CREATED,
                Json(serde_json::json!({"id": req.id, "status": "registered"})),
            )
                .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(error_body(&e))).into_response(),
    }
}

/// GET /api/extensions
pub async fn list_extensions(
    axum::Extension(pool): axum::Extension<ConnPool>,
) -> impl IntoResponse {
    let conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body(&format!("db: {e}"))),
            )
                .into_response()
        }
    };
    match store::list_active(&conn) {
        Ok(list) => Json(serde_json::json!({"extensions": list})).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(error_body(&e))).into_response(),
    }
}

/// GET /api/extensions/:id
pub async fn get_extension(
    axum::Extension(pool): axum::Extension<ConnPool>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body(&format!("db: {e}"))),
            )
                .into_response()
        }
    };
    match store::get_by_id(&conn, &id) {
        Ok(Some(ext)) => Json(serde_json::json!(ext)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(error_body(&format!("extension '{id}' not found"))),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(error_body(&e))).into_response(),
    }
}

/// DELETE /api/extensions/:id
pub async fn remove_extension(
    axum::Extension(pool): axum::Extension<ConnPool>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body(&format!("db: {e}"))),
            )
                .into_response()
        }
    };
    match store::remove_extension(&conn, &id) {
        Ok(true) => {
            tracing::info!(ext_id = %id, "HTTP extension removed");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(error_body(&format!("extension '{id}' not found"))),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(error_body(&e))).into_response(),
    }
}

fn validate_request(req: &RegisterRequest) -> Result<(), String> {
    if req.id.is_empty() {
        return Err("id is required".into());
    }
    if req.base_url.is_empty() {
        return Err("base_url is required".into());
    }
    // Block non-HTTP schemes and private/metadata IPs (SSRF mitigation)
    if !req.base_url.starts_with("http://") && !req.base_url.starts_with("https://") {
        return Err("base_url must use http:// or https://".into());
    }
    if let Some(host) = extract_host(&req.base_url) {
        if is_private_host(&host) {
            return Err("base_url must not target private/metadata addresses".into());
        }
    }
    if !req.routes_prefix.starts_with("/api/ext/") {
        return Err("routes_prefix must start with /api/ext/".into());
    }
    Ok(())
}

/// Extract the host portion from a URL (without port).
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1)?;
    let host_port = after_scheme.split('/').next()?;
    Some(host_port.split(':').next()?.to_lowercase())
}

/// Returns true if the host resolves to a private, loopback, or cloud-metadata address.
fn is_private_host(host: &str) -> bool {
    const BLOCKED: &[&str] = &[
        "169.254.169.254", // cloud metadata
        "metadata.google.internal",
        "100.100.100.200", // alibaba metadata
    ];
    if BLOCKED.contains(&host) {
        return true;
    }
    // Parse as IPv4 and check private ranges
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return ip.is_loopback()
            || ip.is_link_local()
            || ip.is_broadcast()
            || ip.is_unspecified()
            || is_rfc1918(ip);
    }
    // IPv6 loopback
    if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        return ip.is_loopback() || ip.is_unspecified();
    }
    false
}

fn is_rfc1918(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    matches!(octets, [10, ..] | [172, 16..=31, ..] | [192, 168, ..])
}

fn error_body(msg: &str) -> serde_json::Value {
    serde_json::json!({
        "error": {
            "message": msg,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_empty_id() {
        let req = RegisterRequest {
            id: String::new(),
            manifest: convergio_types::manifest::Manifest {
                id: String::new(),
                description: String::new(),
                version: "1.0.0".to_string(),
                kind: convergio_types::manifest::ModuleKind::Integration,
                provides: vec![],
                requires: vec![],
                agent_tools: vec![],
                required_roles: vec![],
            },
            base_url: "http://localhost:3100".into(),
            health_endpoint: "/health".into(),
            events_webhook: "/webhook/events".into(),
            routes_prefix: "/api/ext/test".into(),
        };
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn validate_rejects_bad_prefix() {
        let req = RegisterRequest {
            id: "test".into(),
            manifest: convergio_types::manifest::Manifest {
                id: "test".to_string(),
                description: String::new(),
                version: "1.0.0".to_string(),
                kind: convergio_types::manifest::ModuleKind::Integration,
                provides: vec![],
                requires: vec![],
                agent_tools: vec![],
                required_roles: vec![],
            },
            base_url: "http://localhost:3100".into(),
            health_endpoint: "/health".into(),
            events_webhook: "/webhook/events".into(),
            routes_prefix: "/wrong/prefix".into(),
        };
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn validate_accepts_valid_request() {
        let req = RegisterRequest {
            id: "openclaw-bridge".into(),
            manifest: convergio_types::manifest::Manifest {
                id: "openclaw-bridge".to_string(),
                description: "Legal AI".to_string(),
                version: "1.0.0".to_string(),
                kind: convergio_types::manifest::ModuleKind::Integration,
                provides: vec![],
                requires: vec![],
                agent_tools: vec![],
                required_roles: vec![],
            },
            base_url: "http://ext-service.example.com:3100".into(),
            health_endpoint: "/health".into(),
            events_webhook: "/webhook/events".into(),
            routes_prefix: "/api/ext/openclaw".into(),
        };
        assert!(validate_request(&req).is_ok());
    }

    #[test]
    fn validate_rejects_private_base_url() {
        let cases = [
            "http://10.0.0.1:3100",
            "http://192.168.1.1:3100",
            "http://172.16.0.1:3100",
            "http://169.254.169.254/latest/meta-data",
            "http://127.0.0.1:3100",
        ];
        for url in cases {
            let req = RegisterRequest {
                id: "test".into(),
                manifest: convergio_types::manifest::Manifest {
                    id: "test".to_string(),
                    description: String::new(),
                    version: "1.0.0".to_string(),
                    kind: convergio_types::manifest::ModuleKind::Integration,
                    provides: vec![],
                    requires: vec![],
                    agent_tools: vec![],
                    required_roles: vec![],
                },
                base_url: url.into(),
                health_endpoint: "/health".into(),
                events_webhook: "/webhook/events".into(),
                routes_prefix: "/api/ext/test".into(),
            };
            assert!(
                validate_request(&req).is_err(),
                "should reject private URL: {url}"
            );
        }
    }

    #[test]
    fn validate_rejects_non_http_scheme() {
        let req = RegisterRequest {
            id: "test".into(),
            manifest: convergio_types::manifest::Manifest {
                id: "test".to_string(),
                description: String::new(),
                version: "1.0.0".to_string(),
                kind: convergio_types::manifest::ModuleKind::Integration,
                provides: vec![],
                requires: vec![],
                agent_tools: vec![],
                required_roles: vec![],
            },
            base_url: "file:///etc/passwd".into(),
            health_endpoint: "/health".into(),
            events_webhook: "/webhook/events".into(),
            routes_prefix: "/api/ext/test".into(),
        };
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn error_body_no_hardcoded_code() {
        let body = error_body("test message");
        let error = body.get("error").unwrap();
        assert!(
            error.get("code").is_none(),
            "error_body must not hardcode a status code"
        );
        assert_eq!(error.get("message").unwrap(), "test message");
    }
}
