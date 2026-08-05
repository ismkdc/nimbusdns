// =============================================================================
// Authentication System
// =============================================================================
// Password verification, session management, and rate limiting.
// Used by the API server middleware and auth endpoints.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use dashmap::DashMap;
use serde::Deserialize;
use argon2::Argon2;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand_core::OsRng;

use tracing::warn;
use uuid::Uuid;

use nimbus_core::database::{
    queries::{QueryDb, Session},
    DatabaseError,
};

// =============================================================================
// Auth Error Type
// =============================================================================

/// Authentication and authorization errors
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Invalid username/password
    InvalidCredentials,
    /// Session expired, not found, or invalid
    Unauthorized,
    /// Rate limited
    RateLimited,
    /// Internal error
    Internal(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidCredentials => write!(f, "Invalid credentials"),
            AuthError::Unauthorized => write!(f, "Unauthorized"),
            AuthError::RateLimited => write!(f, "Rate limited"),
            AuthError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl From<DatabaseError> for AuthError {
    fn from(e: DatabaseError) -> Self {
        AuthError::Internal(e.to_string())
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid credentials"),
            AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "Session expired or not found"),
            AuthError::RateLimited => {
                (StatusCode::TOO_MANY_REQUESTS, "Rate limited, try again later")
            }
            AuthError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.as_str()),
        };
        (
            status,
            Json(serde_json::json!({
                "error": msg,
                "code": status.as_u16(),
            })),
        )
            .into_response()
    }
}

// =============================================================================
// Password Verification (Argon2id)
// =============================================================================

/// Hash a password using Argon2id (memory-hard, salt auto-generated).
/// Returns the PHC string format for storage.
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Hashing failed: {}", e))?;
    Ok(hash.to_string())
}

/// Verify a password against a stored Argon2id PHC hash, with legacy SHA-256 fallback.
pub fn verify_password(password: &str, stored_hash: &Option<String>) -> bool {
    let hash = match stored_hash {
        Some(h) => h,
        None => return false,
    };
    // Empty hash still requires a password - an explicitly empty stored hash
    // means "no password" but the caller must provide something.
    // is_auth_enabled() gates whether this code path is even reached.
    if hash.is_empty() {
        return password.is_empty(); // Only allow empty password if stored hash is empty
    }
    // Try Argon2 verification
    if let Ok(parsed) = PasswordHash::new(hash)
        && Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok() {
            return true;
        }
    // Legacy SHA-256 fallback (64-char hex)
    if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        use sha2::{Digest, Sha256};
        let computed = Sha256::digest(password.as_bytes())
            .iter().map(|b| format!("{:02x}", b)).collect::<String>();
        return computed == *hash;
    }
    false
}

/// Check whether the server has any authentication enabled.
/// If password_hash is None or empty, auth is disabled.
pub fn is_auth_enabled(password_hash: &Option<String>) -> bool {
    match password_hash {
        Some(h) => !h.is_empty(),
        None => false,
    }
}

// =============================================================================
// Session Management
// =============================================================================

/// Create a new session in the database and return the SID.
pub fn create_session(
    db: &QueryDb,
    client_ip: Option<&str>,
    user_agent: Option<&str>,
    timeout_secs: u64,
) -> Result<String, AuthError> {
    let sid = Uuid::new_v4().to_string();
    let expires_at = chrono::Utc::now().timestamp() + timeout_secs as i64;
    db.create_session(&sid, expires_at, client_ip, user_agent)?;
    Ok(sid)
}

/// Validate a session SID and return the session if valid.
/// Touches `last_used_at` on successful validation.
pub fn validate_session(db: &QueryDb, sid: &str) -> Result<Session, AuthError> {
    let session = db.get_session(sid)?.ok_or(AuthError::Unauthorized)?;

    let now = chrono::Utc::now().timestamp();
    if session.expires_at < now {
        // Clean up expired session
        let _ = db.delete_session(sid);
        return Err(AuthError::Unauthorized);
    }

    // Touch last_used_at
    if let Err(e) = db.touch_session(sid) {
        warn!("Failed to touch session {}: {}", sid, e);
    }

    Ok(session)
}

// =============================================================================
// Session Cache (in-memory)
// =============================================================================

/// In-memory session cache. Validates sessions without touching SQLite on
/// every request. Expired sessions are evicted lazily on access.
#[derive(Clone)]
pub struct SessionCache {
    sessions: DashMap<String, Session>,
}

impl SessionCache {
    pub fn new() -> Self {
        Self { sessions: DashMap::new() }
    }

    /// Validate a SID. Cache hit: check expiry in memory (no DB). Cache miss:
    /// load from DB, evict if expired, cache the valid session.
    pub fn validate(&self, db: &QueryDb, sid: &str) -> Result<Session, AuthError> {
        let now = chrono::Utc::now().timestamp();

        // Fast path: in-memory
        if let Some(s) = self.sessions.get(sid) {
            if s.expires_at >= now {
                return Ok(s.clone());
            }
            drop(s);
            self.sessions.remove(sid);
        }

        // Slow path: DB
        let session = db.get_session(sid)?.ok_or(AuthError::Unauthorized)?;
        if session.expires_at < now {
            let _ = db.delete_session(sid);
            self.sessions.remove(sid);
            return Err(AuthError::Unauthorized);
        }

        self.sessions.insert(sid.to_string(), session.clone());
        Ok(session)
    }

    /// Cache a session after login.
    pub fn insert(&self, session: &Session) {
        self.sessions.insert(session.sid.clone(), session.clone());
    }

    /// Remove a session from the cache (logout / expiry).
    pub fn remove(&self, sid: &str) {
        self.sessions.remove(sid);
    }

    /// Update a session's expiry in the cache (sliding expiration).
    #[allow(dead_code)] // reserved for sliding-expiry feature; part of planned SessionCache interface
    pub fn update_expiry(&self, sid: &str, expires_at: i64) {
        if let Some(mut s) = self.sessions.get_mut(sid) {
            s.expires_at = expires_at;
        }
    }

    /// Remove all expired sessions from the cache. Called by the hourly
    /// cleanup task alongside `cleanup_expired_sessions` so the cache cannot
    /// accumulate stale entries for sessions already deleted from the DB.
    pub fn remove_expired(&self, now: i64) {
        self.sessions.retain(|_, s| s.expires_at >= now);
    }
}

/// Extract a SID from request headers.
/// Checks (in order): `X-API-Key` header, `sid` cookie.
pub fn extract_sid_from_headers(
    headers: &axum::http::HeaderMap,
) -> Option<String> {
    // 1. Check X-API-Key header
    if let Some(value) = headers
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        && !value.is_empty() {
            return Some(value.to_string());
        }

    // 2. Check Cookie header for sid=...
    if let Some(cookies) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        for cookie in cookies.split(';') {
            let cookie = cookie.trim();
            if let Some(value) = cookie.strip_prefix("sid=")
                && !value.is_empty() {
                    return Some(value.to_string());
                }
        }
    }

    None
}

// =============================================================================
// Rate Limiting (auth endpoints)
// =============================================================================

/// Simple in-memory rate limiter for auth endpoints.
/// Tracks failed attempts per IP address within a sliding window.
pub struct AuthRateLimiter {
    attempts: DashMap<String, Vec<i64>>,
    max_attempts: usize,
    window_secs: i64,
}

impl AuthRateLimiter {
    /// Create a new rate limiter.
    /// `max_attempts` is the number of allowed attempts within `window_secs`.
    pub fn new(max_attempts: usize, window_secs: i64) -> Self {
        Self {
            attempts: DashMap::new(),
            max_attempts,
            window_secs,
        }
    }

    /// Check if a request from `key` (e.g. IP address) is allowed.
    /// Returns `true` if the request is within the rate limit.
    pub fn check(&self, key: &str) -> bool {
        let now = chrono::Utc::now().timestamp();
        let mut timestamps = self.attempts.entry(key.to_string()).or_default();

        // Remove entries outside the window (also prunes the Vec so stale
        // timestamps for a given key never accumulate unbounded — B9).
        timestamps.retain(|t| *t > now - self.window_secs);

        if timestamps.len() >= self.max_attempts {
            return false;
        }

        timestamps.push(now);
        true
    }

    /// Record a successful attempt (remove from rate limiter).
    pub fn record_success(&self, key: &str) {
        self.attempts.remove(key);
    }

}

// =============================================================================
// Request/Response Types
// =============================================================================

/// POST /api/auth request body
#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub password: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use nimbus_core::database::queries::{QueryDb, Session};

    fn test_db() -> QueryDb {
        QueryDb::open(std::path::Path::new(":memory:"), 1000).unwrap()
    }

    fn seed_session(db: &QueryDb, sid: &str) -> Session {
        db.create_session(sid, chrono::Utc::now().timestamp() + 3600, Some("127.0.0.1"), Some("test")).unwrap();
        db.get_session(sid).unwrap().unwrap()
    }

    #[test]
    fn test_session_cache_hit_and_miss() {
        let db = test_db();
        let cache = SessionCache::new();
        // Miss -> DB
        assert!(cache.validate(&db, "nonexistent").is_err());
        // Hit path: seed DB, first validate loads into cache
        let s = seed_session(&db, "abc");
        let got = cache.validate(&db, "abc").unwrap();
        assert_eq!(got.sid, "abc");
        assert_eq!(s.sid, got.sid);
    }

    #[test]
    fn test_session_cache_expired_removed() {
        let db = test_db();
        let cache = SessionCache::new();
        // Session already expired
        db.create_session("old", chrono::Utc::now().timestamp() - 10, None, None).unwrap();
        assert!(cache.validate(&db, "old").is_err());
        // Cache must not hold the expired entry
        assert!(cache.validate(&db, "old").is_err());
    }

    #[test]
    fn test_session_cache_remove_expired() {
        let db = test_db();
        let cache = SessionCache::new();
        // Two valid + one expired session in the cache
        let s1 = seed_session(&db, "a");
        let s2 = seed_session(&db, "b");
        cache.insert(&s1);
        cache.insert(&s2);
        db.create_session("gone", chrono::Utc::now().timestamp() - 10, None, None).unwrap();
        let expired = db.get_session("gone").unwrap().unwrap();
        cache.insert(&expired);

        let now = chrono::Utc::now().timestamp();
        cache.remove_expired(now);

        // Valid sessions still served from cache
        assert!(cache.validate(&db, "a").is_ok());
        assert!(cache.validate(&db, "b").is_ok());
        // Expired session no longer in cache
        assert!(cache.validate(&db, "gone").is_err());
    }

    #[test]
    fn test_session_cache_warm_hit_served_from_memory() {
        let db = test_db();
        let cache = SessionCache::new();
        // Load session into cache
        let s = seed_session(&db, "warm");
        cache.insert(&s);
        // Remove it from the DB — a warm cache must still serve it from memory
        db.delete_session("warm").unwrap();
        assert!(cache.validate(&db, "warm").is_ok());
    }

    // -- AuthRateLimiter key cleanup (B9) ---------------------------------

    #[test]
    fn test_rate_limiter_expired_key_pruned() {
        let limiter = AuthRateLimiter::new(5, 60);
        assert!(limiter.check("1.2.3.4"));
        assert_eq!(limiter.attempts.len(), 1);
        // Force window expiry by moving timestamps back
        let past = chrono::Utc::now().timestamp() - 120;
        limiter.attempts.insert("1.2.3.4".into(), vec![past]);
        // Next check prunes the expired timestamp and records a fresh one
        assert!(limiter.check("1.2.3.4"));
        let entry = limiter.attempts.get("1.2.3.4").unwrap();
        assert_eq!(entry.len(), 1, "expired timestamps must be pruned, not accumulated");
    }

    #[test]
    fn test_rate_limiter_blocks_after_max() {
        let limiter = AuthRateLimiter::new(3, 60);
        assert!(limiter.check("9.9.9.9"));
        assert!(limiter.check("9.9.9.9"));
        assert!(limiter.check("9.9.9.9"));
        assert!(!limiter.check("9.9.9.9"), "fourth attempt must be blocked");
        // Key retained while within window
        assert_eq!(limiter.attempts.len(), 1);
    }

    // ======================================================================
    // Password hashing & verification
    // ======================================================================

    fn sha256_hex(s: &str) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(s.as_bytes()).iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_hash_and_verify_password() {
        let hash = hash_password("s3cret!").unwrap();
        assert!(hash.starts_with("$argon2"), "expected argon2 PHC string, got: {}", hash);
        assert!(verify_password("s3cret!", &Some(hash.clone())));
        assert!(!verify_password("wrong", &Some(hash)));
    }

    #[test]
    fn test_verify_password_legacy_sha256_fallback() {
        // A 64-char hex hash is treated as the legacy SHA-256 scheme
        let stored = sha256_hex("legacypass");
        assert!(verify_password("legacypass", &Some(stored.clone())));
        assert!(!verify_password("wrongpass", &Some(stored)));
    }

    #[test]
    fn test_verify_password_empty_hash_requires_empty_password() {
        // An explicitly empty stored hash means "no password": only an empty
        // password matches (auth_enabled gates whether this path is reached).
        assert!(verify_password("", &Some(String::new())));
        assert!(!verify_password("anything", &Some(String::new())));
    }

    #[test]
    fn test_verify_password_none_or_invalid_is_false() {
        assert!(!verify_password("anything", &None));
        assert!(!verify_password("x", &Some("not-a-valid-hash".into())));
        // A 63-char hex string is NOT a valid legacy SHA-256 (needs exactly 64)
        assert!(!verify_password("x", &Some("a".repeat(63))));
    }

    #[test]
    fn test_is_auth_enabled() {
        assert!(!is_auth_enabled(&None));
        assert!(!is_auth_enabled(&Some(String::new())));
        assert!(is_auth_enabled(&Some("$argon2id$v=19$...".into())));
    }

    // ======================================================================
    // SID extraction from headers
    // ======================================================================

    #[test]
    fn test_extract_sid_x_api_key_takes_precedence() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-API-Key", "apikey-123".parse().unwrap());
        headers.insert(axum::http::header::COOKIE, "sid=cookie-456".parse().unwrap());
        assert_eq!(extract_sid_from_headers(&headers).as_deref(), Some("apikey-123"));
    }

    #[test]
    fn test_extract_sid_from_cookie() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(axum::http::header::COOKIE, "theme=dark; sid=cookie-456".parse().unwrap());
        assert_eq!(extract_sid_from_headers(&headers).as_deref(), Some("cookie-456"));
    }

    #[test]
    fn test_extract_sid_empty_api_key_falls_back_to_cookie() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-API-Key", "".parse().unwrap());
        headers.insert(axum::http::header::COOKIE, "sid=cookie-456".parse().unwrap());
        assert_eq!(extract_sid_from_headers(&headers).as_deref(), Some("cookie-456"));
    }

    #[test]
    fn test_extract_sid_missing_is_none() {
        let headers = axum::http::HeaderMap::new();
        assert_eq!(extract_sid_from_headers(&headers), None);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(axum::http::header::COOKIE, "theme=dark".parse().unwrap());
        assert_eq!(extract_sid_from_headers(&headers), None, "cookie without sid must be ignored");
    }
}


