// =============================================================================
// Database Layer
// =============================================================================
// SQLite3-based storage for:
//   - Gravity database (adlist, domainlist, groups, clients)
//   - Query database (queries, network, settings, sessions)

pub mod gravity;
pub mod queries;
pub mod schema;
pub mod writer;

use std::path::Path;
use std::sync::Arc;

use rusqlite::{Connection, OpenFlags};
use parking_lot::Mutex;
use thiserror::Error;
use tracing::{info, debug};

pub use gravity::{GravityDb, BlockingDecision};
pub use queries::{QueryDb, StoredQuery, QueryStatus, QueryStats, Session};

/// Database error type
#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Migration error: {0}")]
    Migration(String),
    #[error("Not found: {0}")]
    NotFound(String),
}

/// Main database manager
pub struct Database {
    /// Gravity database connection (adlists, blocking rules)
    pub gravity: Arc<GravityDb>,
    /// NIMBUS query database (query log, network table, sessions)
    pub nimbus_db: Arc<QueryDb>,
}

impl Database {
    /// Open (or create) all database files
    pub fn open(config: &crate::config::DatabaseConfig) -> Result<Self, DatabaseError> {
        let gravity = GravityDb::open(&config.gravity_db, config.busy_timeout)?;
        let nimbus_db = QueryDb::open(&config.nimbus_db, config.busy_timeout)?;

        info!("Database connections established");

        Ok(Self {
            gravity: Arc::new(gravity),
            nimbus_db: Arc::new(nimbus_db),
        })
    }

    /// Close all database connections cleanly
    pub fn close(&self) -> Result<(), DatabaseError> {
        info!("Database connections closed");
        Ok(())
    }

    /// Compact/analyze the database (called periodically)
    pub fn analyze(&self) -> Result<(), DatabaseError> {
        self.nimbus_db.analyze()?;
        self.gravity.analyze()?;
        Ok(())
    }

    /// Delete old queries based on retention policy
    pub fn delete_old_queries(&self, max_age_secs: i64) -> Result<i64, DatabaseError> {
        self.nimbus_db.delete_old_queries(max_age_secs)
    }
}

/// Wrapper around rusqlite Connection with WAL mode and thread safety
pub struct SafeConnection {
    conn: Mutex<Connection>,
    path: std::path::PathBuf,
}

impl SafeConnection {
    /// Open a SQLite database with optimal settings
    pub fn open(path: &Path, busy_timeout: u64) -> Result<Self, DatabaseError> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;

        // Use WAL mode for better concurrent performance
        conn.execute_batch(&format!(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA busy_timeout={busy_timeout};
             PRAGMA foreign_keys=ON;
             PRAGMA cache_size=-16384;        -- 16 MB cache
             PRAGMA temp_store=MEMORY;
             PRAGMA mmap_size=268435456;      -- 256 MB mmap
             PRAGMA page_size=4096;
             PRAGMA default_cache_size=4096;
             PRAGMA secure_delete=OFF;"
        ))?;

        debug!("Database opened: {} (page_size=4096, WAL mode)", path.display());

        Ok(Self {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
        })
    }

    /// Execute a closure with a mutable reference to the connection
    pub fn with_conn<F, T>(&self, f: F) -> Result<T, DatabaseError>
    where
        F: FnOnce(&mut Connection) -> Result<T, DatabaseError>,
    {
        let mut conn = self.conn.lock();
        f(&mut conn)
    }

    /// Get the database file path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Run ANALYZE on the database
    pub fn analyze(&self) -> Result<(), DatabaseError> {
        self.with_conn(|conn| {
            conn.execute_batch("ANALYZE;")?;
            Ok(())
        })?;
        info!("Database analyzed: {}", self.path.display());
        Ok(())
    }
}

/// Run all pending database migrations
pub fn run_migrations(conn: &Connection) -> Result<(), DatabaseError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );"
    )?;

    let current_version: i32 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    // Migration 1: Initial schema
    if current_version < 1 {
        conn.execute_batch(schema::INITIAL_NIMBUS_SCHEMA)?;
        conn.execute("INSERT INTO schema_version (version) VALUES (1)", [])?;
        info!("Applied migration v1 (initial schema)");
    }

    // Migration 2: Add sessions table
    if current_version < 2 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions (
                sid TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                last_used_at INTEGER,
                client_ip TEXT,
                user_agent TEXT,
                data BLOB
            );"
        )?;
        conn.execute("INSERT INTO schema_version (version) VALUES (2)", [])?;
        info!("Applied migration v2 (sessions table)");
    }

    // Migration 3: Add message table
    if current_version < 3 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS message (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                type TEXT NOT NULL,
                message TEXT NOT NULL,
                data BLOB
            );"
        )?;
        conn.execute("INSERT INTO schema_version (version) VALUES (3)", [])?;
        info!("Applied migration v3 (message table)");
    }

    // Migration 4: Drop UNIQUE(timestamp, dbl_domain, dbl_client) from
    // `queries`. The old constraint + INSERT OR IGNORE silently dropped
    // repeated queries from the same client/domain within the same second,
    // causing missing query-log entries and understated statistics.
    if current_version < 4 {
        conn.execute_batch(
            "CREATE TABLE queries_v4 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                dbl_domain TEXT NOT NULL,
                dbl_client TEXT,
                dbl_forward TEXT,
                dbl_type INTEGER,
                dbl_status INTEGER,
                dbl_reply_time INTEGER,
                dbl_reply_type INTEGER,
                dbl_flags INTEGER,
                dbl_interface TEXT,
                dbl_elapsed_ms INTEGER,
                dbl_adlist_id INTEGER,
                dbl_cache_id INTEGER,
                dbl_regex_id INTEGER,
                dbl_upstream_id INTEGER
            );
            INSERT INTO queries_v4 SELECT
                id, timestamp, dbl_domain, dbl_client, dbl_forward, dbl_type,
                dbl_status, dbl_reply_time, dbl_reply_type, dbl_flags,
                dbl_interface, dbl_elapsed_ms, dbl_adlist_id, dbl_cache_id,
                dbl_regex_id, dbl_upstream_id
            FROM queries;
            DROP TABLE queries;
            ALTER TABLE queries_v4 RENAME TO queries;
            CREATE INDEX IF NOT EXISTS idx_queries_timestamp ON queries(timestamp);
            CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries(dbl_domain);
            CREATE INDEX IF NOT EXISTS idx_queries_client ON queries(dbl_client);"
        )?;
        conn.execute("INSERT INTO schema_version (version) VALUES (4)", [])?;
        info!("Applied migration v4 (drop queries UNIQUE constraint)");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_busy_timeout_param_applied() {
        // The caller-provided busy_timeout must be honored by the PRAGMA,
        // not silently ignored and replaced with a hardcoded value.
        let conn = SafeConnection::open(Path::new(":memory:"), 4321).unwrap();
        let got: i64 = conn
            .with_conn(|c| Ok(c.query_row("PRAGMA busy_timeout", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(got, 4321);
    }

    #[test]
    fn test_run_migrations_to_current_version() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        let version: i32 = conn
            .query_row("SELECT COALESCE(MAX(version), 0) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 4, "migrations must reach the current schema version");

        for table in ["queries", "sessions", "message"] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "table {table} must exist after migrations");
        }

        // Idempotent: a second run must not error or bump the version
        run_migrations(&conn).unwrap();
        let version: i32 = conn
            .query_row("SELECT COALESCE(MAX(version), 0) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 4);
    }
}
