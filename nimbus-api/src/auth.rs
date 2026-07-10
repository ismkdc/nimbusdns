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

        // Remove entries outside the window
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


