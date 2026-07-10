// =============================================================================
// NimbusDNS REST API
// =============================================================================
// Axum-based REST API for NimbusDNS administration.
// Endpoints mirror the original API

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use std::net::TcpStream;
use std::time::Duration;

use axum::{
    Router,
    routing::{get, post, delete, patch},
    response::{Json, IntoResponse, Response},
    http::StatusCode,
    extract::{State, Path, Request, Query},
};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tower::Service;
use tracing::info;

use nimbus_core::AppState;
use nimbus_core::DnsHandle;

mod auth;

/// Shared application state accessible from API handlers
pub struct ApiState {
    /// Number of queries processed (for stats)
    pub query_count: std::sync::atomic::AtomicU64,
    /// Server start time
    pub start_time: std::time::Instant,
}

impl Default for ApiState {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiState {
    pub fn new() -> Self {
        Self {
            query_count: std::sync::atomic::AtomicU64::new(0),
            start_time: std::time::Instant::now(),
        }
    }
}

/// Start the API server
pub async fn serve(
    state: Arc<AppState>,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<DnsHandle> {
    let api_state = Arc::new(ApiState::new());

    let internal_state = Arc::new(InternalState {
        app_state: state.clone(),
        api_state: api_state.clone(),
        auth_rate_limiter: Arc::new(auth::AuthRateLimiter::new(
            state.config.read().webserver.api_rate_limit as usize,
            60, // 1-minute window
        )),
    });

    // -- Build router -----------------------------------------------------
    let app = Router::new()
        // Web panel (public, embedded SPA)
        .route("/", get(web_root))
        .route("/{*path}", get(web_static))

        // Authentication (public)
        .route("/api/auth", post(authenticate))
        .route("/api/auth/setup", post(setup_password))
        .route("/api/auth/session", delete(delete_session))


        // Statistics
        .route("/api/stats", get(get_stats))
        .route("/api/stats/summary", get(get_stats_summary))
        .route("/api/stats/top_clients", get(get_top_clients))
        .route("/api/stats/top_domains", get(get_top_domains))
        .route("/api/stats/top_upstreams", get(get_top_upstreams))
        .route("/api/stats/query_types", get(get_query_types))
        .route("/api/stats/recent_blocked", get(get_recent_blocked))

        // DNS blocking
        .route("/api/dns/benchmark", post(post_dns_benchmark))
        .route("/api/blocking", get(get_blocking_status))
        .route("/api/blocking", post(set_blocking_status))

        // Lists
        .route("/api/allowlist", get(get_allowlist))
        .route("/api/denylist", get(get_denylist))
        .route("/api/allowlist", post(add_to_allowlist))
        .route("/api/denylist", post(add_to_denylist))
        .route("/api/allowlist/{id}", delete(remove_from_allowlist))
        .route("/api/denylist/{id}", delete(remove_from_denylist))

        // Domains
        .route("/api/domains", get(get_domains))

        // Groups
        .route("/api/groups", get(get_groups))
        .route("/api/groups", post(create_group))

        // Clients
        .route("/api/clients", get(get_clients))

        // Adlists
        .route("/api/adlists", get(get_adlists))
        .route("/api/blocklist", get(get_blocklist_status))
        .route("/api/blocklist", post(post_blocklist_add))
        .route("/api/blocklist/entries", get(get_blocklist_entries))
        .route("/api/blocklist/refresh", post(post_blocklist_refresh))
        .route("/api/blocklist/{domain}", delete(delete_blocklist_entry))

        // Database
        .route("/api/database", get(get_database_info))

        // Query log
        .route("/api/queries", get(get_queries))
        .route("/api/queries/suggestions", get(get_queries_suggestions))
        .route("/api/history", get(get_history))

        // Network
        .route("/api/network", get(get_network))

        // Info / Health
        .route("/api/version", get(get_version))
        .route("/api/info", get(get_info))
        .route("/api/info/system", get(get_system_info))
        .route("/api/health", get(get_health))

        // Config
        .route("/api/config", get(get_config))
        .route("/api/config", patch(update_config))
        .route("/api/config/{element}", get(get_config_element))
        .route("/api/config/_properties", get(get_config_properties))

        // DHCP
        .route("/api/dhcp", get(get_dhcp_status))
        .route("/api/dhcp/leases", get(get_dhcp_leases))

        // Logs
        .route("/api/logs", get(get_logs))

        // Endpoints list
        .route("/api/endpoints", get(get_endpoints))

        .layer(AuthLayer::new(internal_state.clone()))
        .layer(tower_http::cors::CorsLayer::permissive())
        .with_state(internal_state);

    // Bind and serve - use configured port, listen on all interfaces
    let bind_port = state.config.read().webserver.http_port();
    let addr = SocketAddr::from(([0, 0, 0, 0], bind_port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("API server listening on {}", addr);

    // Clone shutdown receiver for the cleanup task
    let cleanup_shutdown = shutdown_rx.clone();
    // Clone state for the cleanup task (Arc clone)
    let cleanup_state = state.clone();

    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let mut rx = shutdown_rx;
                rx.changed().await.ok();
                info!("API server shutting down...");
            })
            .await
            .ok();
    });

    // -- Background session cleanup + query retention --------------------
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // hourly
        let mut rx = cleanup_shutdown;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Clean expired sessions
                    if let Err(e) = cleanup_state.database.nimbus_db.cleanup_expired_sessions() {
                        tracing::warn!("Session cleanup error: {}", e);
                    }
                    // Delete old queries based on retention config (only if logging is enabled)
                    let cfg = cleanup_state.config.read();
                    if cfg.dns.query_log {
                        let retention = cfg.dns.query_retention;
                        if retention > 0
                            && let Err(e) = cleanup_state.database.nimbus_db.delete_old_queries(retention as i64) {
                                tracing::warn!("Query retention cleanup error: {}", e);
                            }
                    }
                    // Clean stale overTime client histories
                    cleanup_state.over_time.cleanup_stale_clients();
                }
                _ = rx.changed() => {
                    tracing::info!("Cleanup task shutting down...");
                    break;
                }
            }
        }
    });

    Ok(DnsHandle::new())
}

// =============================================================================
// Internal state combining app state + API state
// =============================================================================

#[derive(Clone)]
struct InternalState {
    app_state: Arc<AppState>,
    api_state: Arc<ApiState>,
    auth_rate_limiter: Arc<auth::AuthRateLimiter>,
}

// =============================================================================
// API Response helpers
// =============================================================================

fn api_ok<T: Serialize>(data: T) -> (StatusCode, Json<serde_json::Value>) {
    let response = serde_json::json!({
        "data": data,
        "timestamp": chrono::Utc::now().timestamp(),
    });
    (StatusCode::OK, Json(response))
}

fn api_err(status: StatusCode, msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    let error = serde_json::json!({
        "error": msg,
        "code": status.as_u16(),
    });
    (status, Json(error))
}

#[derive(Serialize)]
struct StatsSummary {
    total_queries: i64,
    blocked_queries: i64,
    percent_blocked: f64,
    cached_queries: i64,
    forwarded_queries: i64,
    query_per_second: f64,
    uptime_seconds: u64,
}

#[derive(Serialize)]
struct VersionInfo {
    version: String,
    branch: String,
    hash: String,
    rust_version: String,
}

#[derive(Serialize)]
struct HealthInfo {
    status: String,
    database: bool,
    upstreams: u64,
    cache_entries: usize,
}

// =============================================================================
// Web Panel Handlers (embedded SPA)
// =============================================================================

async fn web_root() -> axum::response::Response {
    nimbus_web::serve_file("index.html")
}

async fn web_static(path: axum::extract::Path<String>) -> axum::response::Response {
    nimbus_web::serve_file(&path.0)
}

// =============================================================================
// Auth Middleware
// =============================================================================

/// Auth middleware as a tower Layer.
/// All routes except `/api/auth*` require a valid session.
#[derive(Clone)]
struct AuthLayer {
    state: Arc<InternalState>,
}

impl AuthLayer {
    fn new(state: Arc<InternalState>) -> Self {
        Self { state }
    }
}

impl<S> tower::Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, service: S) -> Self::Service {
        AuthService {
            inner: service,
            state: self.state.clone(),
        }
    }
}

/// Auth middleware service that wraps inner routes.
#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    state: Arc<InternalState>,
}

impl<S, ReqBody> Service<axum::http::Request<ReqBody>> for AuthService<S>
where
    S: Service<axum::http::Request<ReqBody>, Response = Response, Error = std::convert::Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: axum::http::Request<ReqBody>) -> Self::Future {
        let state = self.state.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let path = req.uri().path().to_string();

            // Only protect /api/* endpoints (web panel is public)
            // Skip auth for /api/auth/* and public info endpoints
            if path.starts_with("/api/") && !path.starts_with("/api/auth/") && path != "/api/auth"
                && path != "/api/info" && path != "/api/version" && path != "/api/health" {
                let password_hash = &state.app_state.config.read().webserver.password_hash;
                if auth::is_auth_enabled(password_hash) {
                    let sid = match auth::extract_sid_from_headers(req.headers()) {
                        Some(s) => s,
                        None => {
                            return Ok(auth::AuthError::Unauthorized.into_response());
                        }
                    };
                    if let Err(e) = auth::validate_session(&state.app_state.database.nimbus_db, &sid) {
                        return Ok(e.into_response());
                    }
                }
            }

            inner.call(req).await
        })
    }
}

// =============================================================================
// Route Handlers
// =============================================================================

async fn get_stats(State(state): State<Arc<InternalState>>) -> (StatusCode, Json<serde_json::Value>) {
    let stats = match state.app_state.database.nimbus_db.get_stats() {
        Ok(s) => s,
        Err(e) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let uptime = state.api_state.start_time.elapsed().as_secs();
    let qps = if uptime > 0 {
        stats.total as f64 / uptime as f64
    } else {
        0.0
    };

    let percent = if stats.total > 0 {
        (stats.blocked as f64 / stats.total as f64) * 100.0
    } else {
        0.0
    };

    api_ok(StatsSummary {
        total_queries: stats.total,
        blocked_queries: stats.blocked,
        percent_blocked: percent,
        cached_queries: stats.cached,
        forwarded_queries: stats.forwarded,
        query_per_second: qps,
        uptime_seconds: uptime,
    })
}

async fn get_stats_summary(State(state): State<Arc<InternalState>>) -> (StatusCode, Json<serde_json::Value>) {
    let snap = state.app_state.over_time.get_snapshot();
    api_ok(serde_json::json!({
        "total_queries": snap.total_queries,
        "blocked_queries": snap.blocked_queries,
        "cached_queries": snap.cached_queries,
        "forwarded_queries": snap.forwarded_queries,
        "percent_blocked": if snap.total_queries > 0 { snap.blocked_queries as f64 / snap.total_queries as f64 * 100.0 } else { 0.0 },
        "query_per_second": snap.queries_per_second,
        "uptime_seconds": snap.uptime_seconds,
    }))
}

async fn get_top_clients(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    match state.app_state.database.nimbus_db.get_top_clients(10) {
        Ok(items) => Ok(api_ok(items)),
        Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

async fn get_top_domains(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    match state.app_state.database.nimbus_db.get_top_domains(10) {
        Ok(items) => Ok(api_ok(items)),
        Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

async fn get_top_upstreams(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    match state.app_state.database.nimbus_db.get_top_upstreams(10) {
        Ok(items) => Ok(api_ok(items)),
        Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

async fn get_query_types(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    match state.app_state.database.nimbus_db.get_query_type_distribution() {
        Ok(items) => Ok(api_ok(items)),
        Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

async fn get_recent_blocked(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    match state.app_state.database.nimbus_db.get_recent_blocked(20) {
        Ok(items) => Ok(api_ok(items)),
        Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

/// POST /api/dns/benchmark - measure TCP latency to a DNS server
async fn post_dns_benchmark(
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let ip = body.get("ip").and_then(|v| v.as_str()).unwrap_or("");
    let port = body.get("port").and_then(|v| v.as_u64()).unwrap_or(853) as u16;
    if ip.is_empty() {
        return api_ok(serde_json::json!({"error": "ip required"}));
    }
    let start = std::time::Instant::now();
    match TcpStream::connect_timeout(
        &format!("{}:{}", ip, port).parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
        Duration::from_secs(3),
    ) {
        Ok(_) => {
            let ms = start.elapsed().as_millis() as u64;
            api_ok(serde_json::json!({"latency_ms": ms}))
        }
        Err(_) => api_ok(serde_json::json!({"latency_ms": null, "error": "timeout"})),
    }
}

async fn get_blocking_status(State(state): State<Arc<InternalState>>) -> (StatusCode, Json<serde_json::Value>) {
    api_ok(serde_json::json!({
        "blocking": state.app_state.config.read().dns.blocking_mode,
        "enabled": true
    }))
}

/// Request body for adding a domain to a list
#[derive(Debug, Deserialize)]
pub struct AddDomainRequest {
    pub domain: String,
    pub comment: Option<String>,
}

/// Request body for creating a group
#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
}

async fn get_allowlist(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    match state.app_state.database.gravity.get_domainlist(0) {
        Ok(items) => Ok(api_ok(items)),
        Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

async fn get_denylist(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    match state.app_state.database.gravity.get_domainlist(1) {
        Ok(items) => Ok(api_ok(items)),
        Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

/// Reload the blocking engine after list mutations (spawn_blocking for SQLite)
fn reload_blocking(state: &InternalState) {
    if let Some(ref engine) = state.app_state.blocking {
        let engine = engine.clone();
        let gravity = state.app_state.database.gravity.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = engine.reload(&gravity) {
                tracing::warn!("Blocking engine reload failed: {}", e);
            }
        });
    }
}

async fn add_to_allowlist(
    State(state): State<Arc<InternalState>>,
    Json(body): Json<AddDomainRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    match state.app_state.database.gravity.add_domainlist(0, &body.domain, body.comment.as_deref()) {
        Ok(id) => {
            reload_blocking(&state);
            Ok(api_ok(serde_json::json!({"status": "added", "id": id})))
        }
        Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

async fn add_to_denylist(
    State(state): State<Arc<InternalState>>,
    Json(body): Json<AddDomainRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    match state.app_state.database.gravity.add_domainlist(1, &body.domain, body.comment.as_deref()) {
        Ok(id) => {
            reload_blocking(&state);
            Ok(api_ok(serde_json::json!({"status": "added", "id": id})))
        }
        Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

async fn remove_from_allowlist(
    State(state): State<Arc<InternalState>>,
    Path(id): Path<i32>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    match state.app_state.database.gravity.remove_domainlist(id) {
        Ok(_) => {
            reload_blocking(&state);
            Ok(api_ok(serde_json::json!({"status": "removed"})))
        }
        Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

async fn remove_from_denylist(
    State(state): State<Arc<InternalState>>,
    Path(id): Path<i32>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    match state.app_state.database.gravity.remove_domainlist(id) {
        Ok(_) => {
            reload_blocking(&state);
            Ok(api_ok(serde_json::json!({"status": "removed"})))
        }
        Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

async fn get_domains(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    // Combine all domainlist types
    let mut all = Vec::new();
    for dtype in 0..=3 {
        match state.app_state.database.gravity.get_domainlist(dtype) {
            Ok(items) => all.extend(items),
            Err(e) => return Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
        }
    }
    Ok(api_ok(all))
}

async fn get_groups(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    match state.app_state.database.gravity.get_groups() {
        Ok(items) => Ok(api_ok(items)),
        Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

async fn create_group(
    State(state): State<Arc<InternalState>>,
    Json(body): Json<CreateGroupRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    match state.app_state.database.gravity.create_group(&body.name, body.description.as_deref()) {
        Ok(id) => Ok(api_ok(serde_json::json!({"status": "created", "id": id}))),
        Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

async fn get_clients(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    match state.app_state.database.gravity.get_clients() {
        Ok(items) => Ok(api_ok(items)),
        Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

async fn get_adlists(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    match state.app_state.database.gravity.get_adlists() {
        Ok(items) => Ok(api_ok(items)),
        Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

async fn get_database_info() -> (StatusCode, Json<serde_json::Value>) {
    api_ok(serde_json::json!({
        "gravity": "/etc/nimbusdns/gravity.db",
        "nimbus": "/etc/nimbusdns/nimbusdns.db"
    }))
}

/// Query parameters for /api/queries
#[derive(Debug, Default, serde::Deserialize)]
pub struct QueriesParams {
    pub domain: Option<String>,
    pub client: Option<String>,
    pub status: Option<i32>,
    pub from: Option<i64>,
    pub until: Option<i64>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

async fn get_queries(
    State(state): State<Arc<InternalState>>,
    Query(params): Query<QueriesParams>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let filter = nimbus_core::database::queries::QueryFilter {
        domain: params.domain,
        client: params.client,
        status: params.status,
        from: params.from,
        until: params.until,
        limit: params.limit.unwrap_or(100).min(1000),
        offset: params.offset.unwrap_or(0).max(0),
    };

    match state.app_state.database.nimbus_db.get_queries(&filter) {
        Ok((entries, total)) => Ok(api_ok(serde_json::json!({
            "entries": entries,
            "total": total,
            "limit": filter.limit,
            "offset": filter.offset,
        }))),
        Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

/// Query parameters for /api/queries/suggestions
#[derive(Debug, serde::Deserialize)]
pub struct SuggestionsParams {
    pub q: Option<String>,
    pub field: Option<String>,
}

async fn get_queries_suggestions(
    State(state): State<Arc<InternalState>>,
    Query(params): Query<SuggestionsParams>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let query = params.q.unwrap_or_default();
    let field = params.field.as_deref().unwrap_or("domain");
    let limit = 10;

    match field {
        "domain" => match state.app_state.database.nimbus_db.get_domain_suggestions(&query, limit) {
            Ok(items) => Ok(api_ok(items)),
            Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
        },
        "client" => match state.app_state.database.nimbus_db.get_client_suggestions(&query, limit) {
            Ok(items) => Ok(api_ok(items)),
            Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
        },
        _ => Err(api_err(StatusCode::BAD_REQUEST, "field must be 'domain' or 'client'")),
    }
}

async fn get_history(
    State(state): State<Arc<InternalState>>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    // Use overTime in-memory data for real-time stats
    let slots = state.app_state.over_time.get_history();
    if !slots.is_empty() {
        return Ok(api_ok(slots));
    }
    // Fallback to DB query if overTime is empty (e.g., fresh start)
    match state.app_state.database.nimbus_db.get_query_history() {
        Ok(slots) => Ok(api_ok(slots)),
        Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

async fn get_network() -> (StatusCode, Json<serde_json::Value>) {
    api_ok(Vec::<String>::new())
}

async fn get_version() -> (StatusCode, Json<serde_json::Value>) {
    api_ok(VersionInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        branch: "main".to_string(),
        hash: "rust-port".to_string(),
        rust_version: "1.96".to_string(),
    })
}

async fn get_info(State(state): State<Arc<InternalState>>) -> (StatusCode, Json<serde_json::Value>) {
    api_ok(serde_json::json!({
        "hostname": nimbus_core::hostname(),
        "uptime_seconds": state.api_state.start_time.elapsed().as_secs(),
        "rust_version": "1.96",
        "features": {
            "dot": true,
            "blocking": true,
        },
        "password_set": state.app_state.config.read().webserver.password_hash.as_ref().is_some_and(|h| !h.is_empty())
    }))
}

/// GET /api/info/system - container resource usage (CPU/RAM via cgroup)
async fn get_system_info() -> (StatusCode, Json<serde_json::Value>) {
    // Read memory and CPU in a blocking task to avoid blocking the async runtime
    let (mem_bytes, mem_limit, cpu_pct) = tokio::task::spawn_blocking(|| {
        let mem_bytes = std::fs::read_to_string("/sys/fs/cgroup/memory.current").ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .or_else(|| {
                std::fs::read_to_string("/sys/fs/cgroup/memory/memory.usage_in_bytes").ok()
                    .and_then(|s| s.trim().parse::<u64>().ok())
            });
        let mem_limit = std::fs::read_to_string("/sys/fs/cgroup/memory.max").ok()
            .and_then(|s| s.trim().to_string().parse::<u64>().ok())
            .or_else(|| {
                std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes").ok()
                    .and_then(|s| s.trim().parse::<u64>().ok())
            });

        let read_cpu = || -> std::io::Result<u64> {
            let s = std::fs::read_to_string("/sys/fs/cgroup/cpu.stat")?;
            s.lines()
                .find(|l| l.starts_with("usage_usec"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "cpu.stat"))
        };
        let cpu_pct = (|| -> Option<f64> {
            let u1 = read_cpu().ok()?;
            std::thread::sleep(std::time::Duration::from_millis(200));
            let u2 = read_cpu().ok()?;
            let dt = 200_000.0;
            let du = (u2 - u1) as f64;
            Some((du / dt * 100.0).clamp(0.0, 100.0))
        })();

        (mem_bytes, mem_limit, cpu_pct)
    }).await.unwrap_or((None, None, None));

    api_ok(serde_json::json!({
        "memory_bytes": mem_bytes,
        "memory_limit_bytes": mem_limit,
        "cpu_percent": cpu_pct,
    }))
}

async fn get_health(State(state): State<Arc<InternalState>>) -> (StatusCode, Json<serde_json::Value>) {
    api_ok(HealthInfo {
        status: "healthy".to_string(),
        database: true,
        upstreams: state.app_state.config.read().dns.upstreams.len() as u64,
        cache_entries: 0,
    })
}

/// POST /api/auth/setup - set initial password (first-time setup)
async fn setup_password(
    State(state): State<Arc<InternalState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<auth::AuthRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), String> {
    // If password is already set, require a valid session to change it
    if auth::is_auth_enabled(&state.app_state.config.read().webserver.password_hash) {
        let sid = auth::extract_sid_from_headers(&headers)
            .ok_or_else(|| "Authentication required".to_string())?;
        auth::validate_session(&state.app_state.database.nimbus_db, &sid)
            .map_err(|_| "Authentication required".to_string())?;
    }
    let password = body.password.as_deref().unwrap_or("");
    if password.is_empty() {
        return Err("Password cannot be empty".to_string());
    }
    let hashed = auth::hash_password(password).map_err(|e| format!("Hash error: {}", e))?;
    let mut config = state.app_state.config.write();
    config.webserver.password_hash = Some(hashed);
    // Write to config file
    let path = state.app_state.config_path.clone();
    let cfg_clone = config.clone();
    drop(config);
    write_config_file(&cfg_clone, &path)
        .map_err(|e| format!("Config write error: {}", e))?;
    Ok(api_ok(serde_json::json!({"status": "password_set"})))
}

async fn authenticate(
    State(state): State<Arc<InternalState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<auth::AuthRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), auth::AuthError> {
    // Get client IP for rate limiting
    let client_ip = headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers.get("X-Real-IP")
                .and_then(|v| v.to_str().ok())
        })
        .unwrap_or("unknown")
        .to_string();

    // Rate limiting check
    if !state.auth_rate_limiter.check(&client_ip) {
        return Err(auth::AuthError::RateLimited);
    }

    // Verify password (if auth is enabled)
    let password_hash = &state.app_state.config.read().webserver.password_hash;
    let password = body.password.as_deref().unwrap_or("");
    if auth::is_auth_enabled(password_hash)
        && !auth::verify_password(password, password_hash) {
            return Err(auth::AuthError::InvalidCredentials);
        }

    // Create session (minimum 60 seconds)
    let timeout = state.app_state.config.read().webserver.session_timeout.max(60);
    let sid = auth::create_session(&state.app_state.database.nimbus_db, Some(&client_ip), None, timeout)?;

    // Clear rate limit on success
    state.auth_rate_limiter.record_success(&client_ip);

    Ok(api_ok(serde_json::json!({
        "session": {
            "sid": sid,
            "valid": true,
        }
    })))
}

async fn delete_session(
    State(state): State<Arc<InternalState>>,
    req: Request,
) -> Result<(StatusCode, Json<serde_json::Value>), auth::AuthError> {
    // Extract SID from request headers
    let sid = auth::extract_sid_from_headers(req.headers())
        .ok_or(auth::AuthError::Unauthorized)?;

    // Validate the session (also touches last_used_at)
    auth::validate_session(&state.app_state.database.nimbus_db, &sid)?;

    // Delete the session
    state.app_state.database.nimbus_db.delete_session(&sid)?;

    Ok(api_ok(serde_json::json!({"status": "logged_out"})))
}

// =============================================================================
// Config Endpoint Helpers
// =============================================================================

/// Recursively deep-merge two JSON values (like JSON Merge Patch, RFC 7396).
fn json_merge(a: &mut serde_json::Value, b: &serde_json::Value) {
    match (a, b) {
        (serde_json::Value::Object(a), serde_json::Value::Object(b)) => {
            for (k, v) in b {
                json_merge(a.entry(k.clone()).or_insert(serde_json::Value::Null), v);
            }
        }
        (a, b) => *a = b.clone(),
    }
}

/// Serialize the full Config to TOML and write to the config file.
fn write_config_file(config: &nimbus_core::config::Config, path: &std::path::Path) -> Result<(), String> {
    let toml_str = toml::to_string_pretty(config).map_err(|e| format!("TOML serialize: {}", e))?;
    std::fs::write(path, toml_str).map_err(|e| format!("Write {}: {}", path.display(), e))?;
    Ok(())
}

// =============================================================================
// Config Handlers
// =============================================================================

async fn get_config(State(state): State<Arc<InternalState>>) -> (StatusCode, Json<serde_json::Value>) {
    let cfg = &*state.app_state.config.read();
    let mut json = serde_json::to_value(cfg).unwrap_or_default();
    // Redact secrets
    if let Some(obj) = json.as_object_mut()
        && let Some(ws) = obj.get_mut("webserver").and_then(|v| v.as_object_mut()) {
            ws.remove("password-hash");
        }
    api_ok(json)
}

/// PATCH /api/config - partial update via JSON deep-merge
async fn update_config(
    State(state): State<Arc<InternalState>>,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    // Auth is handled by AuthLayer middleware

    // Deep-merge the body into the current config
    let mut current = serde_json::to_value(&*state.app_state.config.read())
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    json_merge(&mut current, &body);

    // Deserialize merged value back to Config
    let new_config: nimbus_core::config::Config = serde_json::from_value(current)
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, &format!("Invalid config: {}", e)))?;

    // Write to config file
    write_config_file(&new_config, &state.app_state.config_path)
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;

    // Update in-memory config
    let mut config = state.app_state.config.write();

    // Sync DHCP config with running server if available
    if body.get("dhcp").is_some()
        && let Some(ref dhcp_cfg) = state.app_state.dhcp_config {
            *dhcp_cfg.write() = new_config.dhcp.clone();
        }

    // If query-logging is being disabled, purge ALL existing query logs
    if !new_config.dns.query_log {
        let db = state.app_state.database.nimbus_db.clone();
        tokio::task::spawn_blocking(move || {
            // max_age_secs=0 → cutoff = now - 0 = now → delete everything older than now (all)
            if let Err(e) = db.delete_old_queries(0) {
                tracing::warn!("Failed to purge query logs: {}", e);
            } else {
                tracing::info!("Query logs purged (logging disabled)");
            }
        });
    }

    *config = new_config;
    drop(config);

    Ok(api_ok(serde_json::json!({"status": "updated"})))
}

/// GET /api/config/{element} - return a single config section
async fn get_config_element(
    State(state): State<Arc<InternalState>>,
    Path(element): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let config = state.app_state.config.read();
    // Convert config to a JSON object and index by element name
    let value = serde_json::to_value(&*config)
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    match value.get(&element) {
        Some(section) => Ok(api_ok(section.clone())),
        None => Err(api_err(StatusCode::NOT_FOUND, &format!("Unknown config section: {}", element))),
    }
}

/// GET /api/config/_properties - return metadata about config sections
async fn get_config_properties() -> (StatusCode, Json<serde_json::Value>) {
    // Return the list of available config sections (with descriptions)
    let properties = serde_json::json!([
        {"name": "dns", "type": "object", "description": "DNS resolver settings"},
        {"name": "webserver", "type": "object", "description": "Web server / API settings"},
        {"name": "database", "type": "object", "description": "Database settings"},
        {"name": "debug", "type": "object", "description": "Debug settings"},
        {"name": "misc", "type": "object", "description": "Miscellaneous settings"},
        {"name": "files", "type": "object", "description": "File path settings"},
    ]);
    api_ok(properties)
}

// =============================================================================
// Remaining Endpoints
// =============================================================================

/// POST /api/blocking - enable/disable/toggle blocking
async fn set_blocking_status(
    State(state): State<Arc<InternalState>>,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let mut config = state.app_state.config.write();

    use nimbus_core::config::BlockingMode;
    let new_mode = match action {
        "enable" | "on" => BlockingMode::Null,
        "disable" | "off" => BlockingMode::Disabled,
        "toggle" => match config.dns.blocking_mode {
            BlockingMode::Disabled => BlockingMode::Null,
            _ => BlockingMode::Disabled,
        },
        _ => return Err(api_err(StatusCode::BAD_REQUEST, "action must be 'enable', 'disable', or 'toggle'")),
    };

    config.dns.blocking_mode = new_mode;
    let mode_str = format!("{:?}", new_mode);
    Ok(api_ok(serde_json::json!({"status": "updated", "blocking": mode_str})))
}

/// GET /api/dhcp - DHCP status
async fn get_dhcp_status(State(state): State<Arc<InternalState>>) -> (StatusCode, Json<serde_json::Value>) {
    let cfg = state.app_state.config.read();
    let enabled = cfg.dhcp.enabled;
    let start = cfg.dhcp.pool_start.map(|s| s.to_string()).unwrap_or_default();
    let end = cfg.dhcp.pool_end.map(|e| e.to_string()).unwrap_or_default();
    api_ok(serde_json::json!({"enabled": enabled, "range": format!("{} - {}", start, end)}))
}

/// GET /api/dhcp/leases - DHCP lease list
async fn get_dhcp_leases(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    match &state.app_state.dhcp_server {
        Some(server) => {
            let leases = nimbus_core::dhcp::get_leases(server);
            Ok(api_ok(leases))
        }
        None => Ok(api_ok(Vec::<String>::new())),
    }
}

/// GET /api/logs - list available log types
async fn get_logs() -> (StatusCode, Json<serde_json::Value>) {
    api_ok(serde_json::json!(["nimbusdns", "access"]))
}

/// GET /api/blocklist - blocklist status info
async fn get_blocklist_status(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let count = state.app_state.database.gravity.total_blocked()
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(api_ok(serde_json::json!({
        "source": "StevenBlack/hosts",
        "domains": count,
    })))
}

/// POST /api/blocklist/refresh - trigger blocklist refresh
async fn post_blocklist_refresh(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let gravity = state.app_state.database.gravity.clone();
    let url = state.app_state.config.read().blocking.source_url.clone();
    tokio::spawn(async move {
        if let Err(e) = nimbus_core::blocking::fetcher::fetch_and_import(&gravity, &url).await {
            tracing::warn!("Blocklist refresh failed: {}", e);
        }
    });
    Ok(api_ok(serde_json::json!({"status": "refresh_started"})))
}

/// POST /api/blocklist - add a custom domain to the blocklist
async fn post_blocklist_add(
    State(state): State<Arc<InternalState>>,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let domain = body.get("domain").and_then(|v| v.as_str()).unwrap_or("");
    if domain.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "domain is required"));
    }
    state.app_state.database.gravity.add_gravity_domain(domain)
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    reload_blocking(&state);
    Ok(api_ok(serde_json::json!({"status": "added", "domain": domain})))
}

/// DELETE /api/blocklist/{domain} - remove a domain from the blocklist
async fn delete_blocklist_entry(
    State(state): State<Arc<InternalState>>,
    Path(domain): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    state.app_state.database.gravity.remove_gravity_domain(&domain)
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    reload_blocking(&state);
    Ok(api_ok(serde_json::json!({"status": "removed", "domain": domain})))
}

/// GET /api/blocklist/entries - get all blocklist entries (paginated)
async fn get_blocklist_entries(
    State(state): State<Arc<InternalState>>,
    Query(params): Query<QueriesParams>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let page = params.offset.unwrap_or(1).max(1) as usize;
    let limit = params.limit.unwrap_or(100).min(1000) as usize;
    match state.app_state.database.gravity.get_gravity_entries(page, limit) {
        Ok((domains, total)) => Ok(api_ok(serde_json::json!({
            "entries": domains,
            "total": total,
            "page": page,
            "limit": limit,
        }))),
        Err(e) => Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

/// GET /api/endpoints - list all available API endpoints
async fn get_endpoints() -> (StatusCode, Json<serde_json::Value>) {
    let endpoints = vec![
        "/api/auth", "/api/auth/session",
        "/api/stats", "/api/stats/summary", "/api/stats/top_clients",
        "/api/stats/top_domains", "/api/stats/top_upstreams",
        "/api/stats/query_types", "/api/stats/recent_blocked",
        "/api/blocking", "/api/allowlist", "/api/denylist",
        "/api/domains", "/api/groups", "/api/clients", "/api/adlists",
        "/api/database", "/api/queries", "/api/queries/suggestions",
        "/api/history", "/api/blocklist", "/api/blocklist/entries",
        "/api/blocklist/refresh", "/api/version", "/api/info",
        "/api/info/system", "/api/health", "/api/config", "/api/config/{element}",
        "/api/config/_properties", "/api/dhcp", "/api/dhcp/leases",
        "/api/logs", "/api/endpoints",
    ];
    api_ok(endpoints)
}
