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
        session_cache: auth::SessionCache::new(),
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
        .with_state(internal_state.clone());

    // Bind and serve - use configured port, listen on all interfaces
    let bind_port = state.config.read().webserver.http_port();
    let addr = SocketAddr::from(([0, 0, 0, 0], bind_port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("API server listening on {}", addr);

    // Clone shutdown receiver for the cleanup task
    let cleanup_shutdown = shutdown_rx.clone();
    // Clone internal state for the cleanup task (Arc clone — has session_cache)
    let cleanup_state = internal_state.clone();

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
                    // Clean expired sessions (DB)
                    let db = cleanup_state.app_state.database.nimbus_db.clone();
                    if let Err(e) = tokio::task::spawn_blocking(move || db.cleanup_expired_sessions())
                        .await
                        .map_err(|e| e.to_string())
                        .and_then(|r| r.map_err(|e| e.to_string()))
                    {
                        tracing::warn!("Session cleanup error: {}", e);
                    }
                    // Clean expired sessions from the in-memory cache too
                    cleanup_state.session_cache.remove_expired(chrono::Utc::now().timestamp());
                    // Delete old queries based on retention config (only if logging is enabled).
                    // Extract values out of the !Send read guard before the `.await` below.
                    let (query_log, retention) = {
                        let cfg = cleanup_state.app_state.config.read();
                        (cfg.dns.query_log, cfg.dns.query_retention)
                    };
                    if query_log && retention > 0 {
                        let db = cleanup_state.app_state.database.nimbus_db.clone();
                        if let Err(e) = tokio::task::spawn_blocking(move || db.delete_old_queries(retention as i64))
                            .await
                            .map_err(|e| e.to_string())
                            .and_then(|r| r.map_err(|e| e.to_string()))
                        {
                            tracing::warn!("Query retention cleanup error: {}", e);
                        }
                    }
                    // Clean stale overTime client histories
                    cleanup_state.app_state.over_time.cleanup_stale_clients();
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
    /// In-memory session cache (avoids SQLite on every authenticated request)
    session_cache: auth::SessionCache,
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

/// Run a blocking database call on the blocking thread pool so async worker
/// threads (which also serve DNS on the same tokio runtime) are never stalled
/// by synchronous SQLite I/O — rusqlite's `Connection` is a blocking API.
async fn db_blocking<F, T, E>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
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
                    if let Err(e) = state.session_cache.validate(&state.app_state.database.nimbus_db, &sid) {
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
    // Use the O(1) in-memory atomic counters (overTime) instead of 4 full
    // table COUNT(*) scans on every dashboard load.
    let snap = state.app_state.over_time.get_snapshot();
    let total = snap.total_queries.max(0) as u64;
    let blocked = snap.blocked_queries.max(0) as u64;
    let cached = snap.cached_queries.max(0) as u64;
    let forwarded = snap.forwarded_queries.max(0) as u64;

    let percent = if total > 0 {
        (blocked as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    api_ok(StatsSummary {
        total_queries: total as i64,
        blocked_queries: blocked as i64,
        percent_blocked: percent,
        cached_queries: cached as i64,
        forwarded_queries: forwarded as i64,
        query_per_second: snap.queries_per_second,
        uptime_seconds: snap.uptime_seconds,
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
    let db = state.app_state.database.nimbus_db.clone();
    let items = db_blocking(move || db.get_top_clients(10))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(api_ok(items))
}

async fn get_top_domains(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let db = state.app_state.database.nimbus_db.clone();
    let items = db_blocking(move || db.get_top_domains(10))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(api_ok(items))
}

async fn get_top_upstreams(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let db = state.app_state.database.nimbus_db.clone();
    let items = db_blocking(move || db.get_top_upstreams(10))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(api_ok(items))
}

async fn get_query_types(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let db = state.app_state.database.nimbus_db.clone();
    let items = db_blocking(move || db.get_query_type_distribution())
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(api_ok(items))
}

async fn get_recent_blocked(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let db = state.app_state.database.nimbus_db.clone();
    let items = db_blocking(move || db.get_recent_blocked(20))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(api_ok(items))
}

/// POST /api/dns/benchmark - measure TCP latency to a DNS server.
/// Runs on the blocking pool so a slow/unreachable target (up to 3s per
/// attempt) never stalls a tokio worker thread that is also serving DNS.
async fn post_dns_benchmark(
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let ip = body.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let port = body.get("port").and_then(|v| v.as_u64()).unwrap_or(853);
    if ip.is_empty() {
        return api_ok(serde_json::json!({"error": "ip required"}));
    }
    let result = tokio::task::spawn_blocking(move || {
        let start = std::time::Instant::now();
        match TcpStream::connect_timeout(
            &format!("{}:{}", ip, port).parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
            Duration::from_secs(3),
        ) {
            Ok(_) => Some(start.elapsed().as_millis() as u64),
            Err(_) => None,
        }
    })
    .await
    .unwrap_or(None);

    match result {
        Some(ms) => api_ok(serde_json::json!({"latency_ms": ms})),
        None => api_ok(serde_json::json!({"latency_ms": null, "error": "timeout"})),
    }
}

async fn get_blocking_status(State(state): State<Arc<InternalState>>) -> (StatusCode, Json<serde_json::Value>) {
    let mode = state.app_state.config.read().dns.blocking_mode;
    use nimbus_core::config::BlockingMode;
    api_ok(serde_json::json!({
        "blocking": mode,
        "enabled": mode != BlockingMode::Disabled
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
    let db = state.app_state.database.gravity.clone();
    let items = db_blocking(move || db.get_domainlist(0))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(api_ok(items))
}

async fn get_denylist(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let db = state.app_state.database.gravity.clone();
    let items = db_blocking(move || db.get_domainlist(1))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(api_ok(items))
}

/// Reload the blocking engine after list mutations (spawn_blocking for SQLite)
/// Apply a single-domain mutation to the in-memory blocking lists instead of
/// reloading the entire gravity table (100k+ rows) per API change (C2).
fn apply_blocking_delta(
    state: &InternalState,
    action: BlockingDelta,
    domain: &str,
) {
    if let Some(ref engine) = state.app_state.blocking {
        let engine = engine.clone();
        let domain = domain.to_string();
        tokio::task::spawn_blocking(move || {
            let lists_arc = engine.lists();
            let mut lists = lists_arc.write();
            match action {
                BlockingDelta::AddAllow => lists.add_allow_domain(&domain),
                BlockingDelta::RemoveAllow => lists.remove_allow_domain(&domain),
                BlockingDelta::AddDeny => lists.add_deny_domain(&domain),
                BlockingDelta::RemoveDeny => lists.remove_deny_domain(&domain),
                BlockingDelta::AddGravity => lists.add_gravity_domain(&domain),
                BlockingDelta::RemoveGravity => lists.remove_gravity_domain(&domain),
            }
            tracing::debug!("Blocking delta applied: {:?} {}", action, domain);
        });
    }
}

#[derive(Debug, Clone, Copy)]
enum BlockingDelta {
    AddAllow,
    RemoveAllow,
    AddDeny,
    RemoveDeny,
    AddGravity,
    RemoveGravity,
}

async fn add_to_allowlist(
    State(state): State<Arc<InternalState>>,
    Json(body): Json<AddDomainRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let db = state.app_state.database.gravity.clone();
    let domain = body.domain.clone();
    let comment = body.comment.clone();
    let id = db_blocking(move || db.add_domainlist(0, &domain, comment.as_deref()))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    apply_blocking_delta(&state, BlockingDelta::AddAllow, &body.domain);
    Ok(api_ok(serde_json::json!({"status": "added", "id": id})))
}

async fn add_to_denylist(
    State(state): State<Arc<InternalState>>,
    Json(body): Json<AddDomainRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let db = state.app_state.database.gravity.clone();
    let domain = body.domain.clone();
    let comment = body.comment.clone();
    let id = db_blocking(move || db.add_domainlist(1, &domain, comment.as_deref()))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    apply_blocking_delta(&state, BlockingDelta::AddDeny, &body.domain);
    Ok(api_ok(serde_json::json!({"status": "added", "id": id})))
}

async fn remove_from_allowlist(
    State(state): State<Arc<InternalState>>,
    Path(id): Path<i32>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    // Resolve the domain from the DB so we can remove it from memory too
    let gravity = state.app_state.database.gravity.clone();
    let domain = db_blocking(move || gravity.get_domainlist(0))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?
        .into_iter().find(|e| e.id == id).map(|e| e.domain);
    let gravity = state.app_state.database.gravity.clone();
    db_blocking(move || gravity.remove_domainlist(id))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    if let Some(d) = domain {
        apply_blocking_delta(&state, BlockingDelta::RemoveAllow, &d);
    }
    Ok(api_ok(serde_json::json!({"status": "removed"})))
}

async fn remove_from_denylist(
    State(state): State<Arc<InternalState>>,
    Path(id): Path<i32>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let gravity = state.app_state.database.gravity.clone();
    let domain = db_blocking(move || gravity.get_domainlist(1))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?
        .into_iter().find(|e| e.id == id).map(|e| e.domain);
    let gravity = state.app_state.database.gravity.clone();
    db_blocking(move || gravity.remove_domainlist(id))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    if let Some(d) = domain {
        apply_blocking_delta(&state, BlockingDelta::RemoveDeny, &d);
    }
    Ok(api_ok(serde_json::json!({"status": "removed"})))
}

async fn get_domains(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    // Combine all domainlist types
    let db = state.app_state.database.gravity.clone();
    let all = db_blocking::<_, _, nimbus_core::database::DatabaseError>(move || {
        let mut all = Vec::new();
        for dtype in 0..=3 {
            all.extend(db.get_domainlist(dtype)?);
        }
        Ok(all)
    })
    .await
    .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(api_ok(all))
}

async fn get_groups(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let db = state.app_state.database.gravity.clone();
    let items = db_blocking(move || db.get_groups())
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(api_ok(items))
}

async fn create_group(
    State(state): State<Arc<InternalState>>,
    Json(body): Json<CreateGroupRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let db = state.app_state.database.gravity.clone();
    let name = body.name.clone();
    let description = body.description.clone();
    let id = db_blocking(move || db.create_group(&name, description.as_deref()))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(api_ok(serde_json::json!({"status": "created", "id": id})))
}

async fn get_clients(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let db = state.app_state.database.gravity.clone();
    let items = db_blocking(move || db.get_clients())
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(api_ok(items))
}

async fn get_adlists(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let db = state.app_state.database.gravity.clone();
    let items = db_blocking(move || db.get_adlists())
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(api_ok(items))
}

async fn get_database_info(State(state): State<Arc<InternalState>>) -> (StatusCode, Json<serde_json::Value>) {
    let cfg = state.app_state.config.read();
    api_ok(serde_json::json!({
        "gravity": cfg.database.gravity_db.display().to_string(),
        "nimbus": cfg.database.nimbus_db.display().to_string(),
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
        // Negative limit would become SQLite `LIMIT -5` = unlimited (B11).
        limit: params.limit.unwrap_or(100).clamp(1, 1000),
        offset: params.offset.unwrap_or(0).max(0),
    };

    let db = state.app_state.database.nimbus_db.clone();
    let limit = filter.limit;
    let offset = filter.offset;
    let (entries, total) = db_blocking(move || db.get_queries(&filter))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(api_ok(serde_json::json!({
        "entries": entries,
        "total": total,
        "limit": limit,
        "offset": offset,
    })))
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
        "domain" => {
            let db = state.app_state.database.nimbus_db.clone();
            let items = db_blocking(move || db.get_domain_suggestions(&query, limit))
                .await
                .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
            Ok(api_ok(items))
        }
        "client" => {
            let db = state.app_state.database.nimbus_db.clone();
            let items = db_blocking(move || db.get_client_suggestions(&query, limit))
                .await
                .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
            Ok(api_ok(items))
        }
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
    let db = state.app_state.database.nimbus_db.clone();
    let slots = db_blocking(move || db.get_query_history())
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(api_ok(slots))
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
    // Actually probe the DB instead of always reporting healthy (B9).
    let db = state.app_state.database.nimbus_db.clone();
    let db_ok = db_blocking(move || db.todays_queries()).await.is_ok();
    let status = if db_ok { "healthy" } else { "degraded" };
    api_ok(HealthInfo {
        status: status.to_string(),
        database: db_ok,
        upstreams: state.app_state.config.read().dns.upstreams.len() as u64,
        cache_entries: 0,
    })
}

/// POST /api/auth/setup - set initial password (first-time setup)
async fn setup_password(
    State(state): State<Arc<InternalState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<auth::AuthRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    // If password is already set, require a valid session to change it
    // (clone the hash first so the config read guard is dropped before any
    // `.await` — parking_lot guards are !Send, so holding one across an await
    // would make the handler future non-Send and fail to compile).
    let password_hash = state.app_state.config.read().webserver.password_hash.clone();
    if auth::is_auth_enabled(&password_hash) {
        let sid = auth::extract_sid_from_headers(&headers)
            .ok_or_else(|| api_err(StatusCode::UNAUTHORIZED, "Authentication required"))?;
        let db = state.app_state.database.nimbus_db.clone();
        let sid_clone = sid.clone();
        tokio::task::spawn_blocking(move || auth::validate_session(&db, &sid_clone))
            .await
            .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .map_err(|_| api_err(StatusCode::UNAUTHORIZED, "Authentication required"))?;
    }
    let password = body.password.as_deref().unwrap_or("").to_string();
    if password.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "Password cannot be empty"));
    }
    // Argon2 hashing is memory-hard and takes ~50-100ms — never run it on an
    // async worker thread.
    let hashed = tokio::task::spawn_blocking(move || auth::hash_password(&password))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    // Scoped block: the config write guard is !Send, so it must be dropped
    // before the next `.await` (the spawn_blocking write below).
    let cfg_clone = {
        let mut config = state.app_state.config.write();
        config.webserver.password_hash = Some(hashed);
        config.clone()
    };
    // Write to config file (blocking fs I/O)
    let path = state.app_state.config_path.clone();
    let write_result = tokio::task::spawn_blocking(move || write_config_file(&cfg_clone, &path))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    write_result.map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
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

    // Verify password (if auth is enabled). Argon2 verification is
    // memory-hard — run it on the blocking pool, not an async worker.
    let password_hash = state.app_state.config.read().webserver.password_hash.clone();
    let password = body.password.as_deref().unwrap_or("").to_string();
    if auth::is_auth_enabled(&password_hash)
        && !tokio::task::spawn_blocking(move || auth::verify_password(&password, &password_hash))
            .await
            .unwrap_or(false)
    {
        return Err(auth::AuthError::InvalidCredentials);
    }

    // Create session (minimum 60 seconds)
    let timeout = state.app_state.config.read().webserver.session_timeout.max(60);
    let db = state.app_state.database.nimbus_db.clone();
    let client_ip_db = client_ip.clone();
    let sid = tokio::task::spawn_blocking(move || {
        auth::create_session(&db, Some(&client_ip_db), None, timeout)
    })
    .await
    .map_err(|e| auth::AuthError::Internal(e.to_string()))??;

    // Cache the new session in memory
    let db = state.app_state.database.nimbus_db.clone();
    let sid_db = sid.clone();
    let session = tokio::task::spawn_blocking(move || db.get_session(&sid_db))
        .await
        .map_err(|e| auth::AuthError::Internal(e.to_string()))?
        .map_err(auth::AuthError::from)?
        .ok_or(auth::AuthError::Unauthorized)?;
    state.session_cache.insert(&session);

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

    // Validate the session via the cache (also removes from cache on logout)
    let cache = state.session_cache.clone();
    let db = state.app_state.database.nimbus_db.clone();
    let sid_validate = sid.clone();
    tokio::task::spawn_blocking(move || cache.validate(&db, &sid_validate))
        .await
        .map_err(|e| auth::AuthError::Internal(e.to_string()))??;

    // Delete the session
    let db = state.app_state.database.nimbus_db.clone();
    let sid_delete = sid.clone();
    tokio::task::spawn_blocking(move || db.delete_session(&sid_delete))
        .await
        .map_err(|e| auth::AuthError::Internal(e.to_string()))?
        .map_err(auth::AuthError::from)?;
    state.session_cache.remove(&sid);

    Ok(api_ok(serde_json::json!({"status": "logged_out"})))
}

// =============================================================================
// Config Endpoint Helpers
// =============================================================================

/// Recursively deep-merge two JSON values (RFC 7396 JSON Merge Patch).
/// A `null` value in the patch REMOVES the corresponding key from the target.
fn json_merge(a: &mut serde_json::Value, b: &serde_json::Value) {
    match (a, b) {
        (serde_json::Value::Object(a), serde_json::Value::Object(b)) => {
            for (k, v) in b {
                if v.is_null() {
                    a.remove(k);
                } else {
                    json_merge(a.entry(k.clone()).or_insert(serde_json::Value::Null), v);
                }
            }
        }
        (a, b) => *a = b.clone(),
    }
}

/// Remove secret fields from a config JSON value so they can neither be
/// leaked through the API nor overwritten via PATCH. Only `setup_password`
/// is allowed to change the password hash.
fn strip_secrets_from_config(json: &mut serde_json::Value) {
    if let Some(obj) = json.as_object_mut()
        && let Some(ws) = obj.get_mut("webserver").and_then(|v| v.as_object_mut()) {
            ws.remove("password-hash");
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

    // Never allow the password hash to be set via PATCH — it can only be
    // changed through /api/auth/setup. Without this, a client could
    // overwrite the admin password (or lock everyone out) via config.
    let mut body = body;
    strip_secrets_from_config(&mut body);

    // Deep-merge the body into the current config
    let mut current = serde_json::to_value(&*state.app_state.config.read())
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    json_merge(&mut current, &body);

    // Deserialize merged value back to Config
    let new_config: nimbus_core::config::Config = serde_json::from_value(current)
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, &format!("Invalid config: {}", e)))?;

    // Validate before persisting — reject configs that would break the
    // server (e.g. empty upstreams, rate_limit = 0) or prevent restart.
    new_config.validate()
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, &format!("Invalid config: {}", e)))?;

    // Write to config file (blocking fs I/O — off the async worker)
    let path = state.app_state.config_path.clone();
    let cfg_to_write = new_config.clone();
    let write_result = tokio::task::spawn_blocking(move || write_config_file(&cfg_to_write, &path))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    write_result.map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;

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
    let mut value = serde_json::to_value(&*config)
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    // Redact secrets so e.g. GET /api/config/webserver does not leak the hash
    strip_secrets_from_config(&mut value);

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
    let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // Scoped block: the config write guard is !Send, so it must be dropped
    // before the `.await` that persists the file below.
    let (cfg_to_write, mode_str) = {
        let mut config = state.app_state.config.write();
        use nimbus_core::config::BlockingMode;
        let new_mode = match action.as_str() {
            "enable" | "on" => BlockingMode::Null,
            "disable" | "off" => BlockingMode::Disabled,
            "toggle" => match config.dns.blocking_mode {
                BlockingMode::Disabled => BlockingMode::Null,
                _ => BlockingMode::Disabled,
            },
            _ => return Err(api_err(StatusCode::BAD_REQUEST, "action must be 'enable', 'disable', or 'toggle'")),
        };
        config.dns.blocking_mode = new_mode;
        (config.clone(), format!("{:?}", new_mode))
    };

    // Persist to config file so the change survives restart (blocking fs I/O)
    let path = state.app_state.config_path.clone();
    let write_result = tokio::task::spawn_blocking(move || write_config_file(&cfg_to_write, &path))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    write_result.map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
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

/// GET /api/dhcp/leases - DHCP lease list (enriched with vendor info)
async fn get_dhcp_leases(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    match &state.app_state.dhcp_server {
        Some(server) => {
            let mut leases = nimbus_core::dhcp::get_leases(server);
            // Enrich each lease with vendor/manufacturer info from OUI database
            for lease in &mut leases {
                lease.vendor = state.app_state.oui.lookup(&lease.mac).map(String::from);
            }
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
    let gravity = state.app_state.database.gravity.clone();
    let count = db_blocking(move || gravity.total_blocked())
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    let source = state.app_state.config.read().blocking.source_url.clone();
    Ok(api_ok(serde_json::json!({
        "source": source,
        "domains": count,
    })))
}

/// POST /api/blocklist/refresh - trigger blocklist refresh
async fn post_blocklist_refresh(State(state): State<Arc<InternalState>>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let gravity = state.app_state.database.gravity.clone();
    let url = state.app_state.config.read().blocking.source_url.clone();
    tokio::spawn(async move {
        if let Err(e) = nimbus_core::blocking::fetcher::fetch_and_import(gravity, &url).await {
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
    let gravity = state.app_state.database.gravity.clone();
    let domain_db = domain.to_string();
    db_blocking(move || gravity.add_gravity_domain(&domain_db))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    apply_blocking_delta(&state, BlockingDelta::AddGravity, domain);
    Ok(api_ok(serde_json::json!({"status": "added", "domain": domain})))
}

/// DELETE /api/blocklist/{domain} - remove a domain from the blocklist
async fn delete_blocklist_entry(
    State(state): State<Arc<InternalState>>,
    Path(domain): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let gravity = state.app_state.database.gravity.clone();
    let domain_db = domain.clone();
    db_blocking(move || gravity.remove_gravity_domain(&domain_db))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    apply_blocking_delta(&state, BlockingDelta::RemoveGravity, &domain);
    Ok(api_ok(serde_json::json!({"status": "removed", "domain": domain})))
}

/// GET /api/blocklist/entries - get all blocklist entries (paginated)
async fn get_blocklist_entries(
    State(state): State<Arc<InternalState>>,
    Query(params): Query<QueriesParams>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    // `offset` is a row offset (consistent with /api/queries), not a page
    // number — pass it straight through to the DB layer.
    let limit = params.limit.unwrap_or(100).clamp(1, 1000) as usize;
    let offset = params.offset.unwrap_or(0).max(0) as usize;
    let gravity = state.app_state.database.gravity.clone();
    let (domains, total) = db_blocking(move || gravity.get_gravity_entries(offset, limit))
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(api_ok(serde_json::json!({
        "entries": domains,
        "total": total,
        "offset": offset,
        "limit": limit,
    })))
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

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn test_strip_secrets_removes_password_hash() {
        let mut json = serde_json::json!({
            "webserver": {
                "password-hash": "$argon2id$secret",
                "ports": ["80o"]
            },
            "dns": { "upstreams": [] }
        });
        strip_secrets_from_config(&mut json);
        assert!(json["webserver"].get("password-hash").is_none());
        assert!(json["webserver"]["ports"].is_array());
        assert!(json["dns"].is_object());
    }

    #[test]
    fn test_strip_secrets_no_webserver_is_noop() {
        let mut json = serde_json::json!({ "dns": { "upstreams": [] } });
        strip_secrets_from_config(&mut json);
        assert_eq!(json["dns"]["upstreams"], serde_json::json!([]));
    }

    // -- json_merge RFC 7396 null-delete (B7) -----------------------------

    #[test]
    fn test_json_merge_null_removes_key() {
        let mut base = serde_json::json!({
            "dns": { "upstreams": [{"address": "8.8.8.8", "port": 53}], "rate_limit": 100 }
        });
        let patch = serde_json::json!({
            "dns": { "upstreams": null }
        });
        json_merge(&mut base, &patch);
        assert!(
            base["dns"].get("upstreams").is_none(),
            "null patch must REMOVE the key, got {:?}",
            base
        );
        // Unrelated sibling keys survive
        assert_eq!(base["dns"]["rate_limit"], serde_json::json!(100));
    }

    #[test]
    fn test_json_merge_nested_object_merge() {
        let mut base = serde_json::json!({ "a": { "x": 1, "y": 2 }, "b": 3 });
        let patch = serde_json::json!({ "a": { "y": 20 } });
        json_merge(&mut base, &patch);
        assert_eq!(base["a"]["x"], serde_json::json!(1));
        assert_eq!(base["a"]["y"], serde_json::json!(20));
        assert_eq!(base["b"], serde_json::json!(3));
    }
}
