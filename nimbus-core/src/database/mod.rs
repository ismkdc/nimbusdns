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
    /// FTL query database (query log, network table, sessions)
    pub ftl: Arc<QueryDb>,
    /// Configuration reference
    #[allow(dead_code)]
    config: Arc<crate::config::DatabaseConfig>,
}

impl Database {
    /// Open (or create) all database files
    pub fn open(config: &crate::config::DatabaseConfig) -> Result<Self, DatabaseError> {
        let gravity = GravityDb::open(&config.gravity_db, config.busy_timeout)?;
        let ftl = QueryDb::open(&config.ftl_db, config.busy_timeout)?;

        info!("Database connections established");

        Ok(Self {
            gravity: Arc::new(gravity),
            ftl: Arc::new(ftl),
            config: Arc::new(config.clone()),
        })
    }

    /// Close all database connections cleanly
    pub fn close(&self) -> Result<(), DatabaseError> {
        info!("Database connections closed");
        Ok(())
    }

    /// Compact/analyze the database (called periodically)
    pub fn analyze(&self) -> Result<(), DatabaseError> {
        self.ftl.analyze()?;
        self.gravity.analyze()?;
        Ok(())
    }

    /// Delete old queries based on retention policy
    pub fn delete_old_queries(&self, max_age_secs: i64) -> Result<i64, DatabaseError> {
        self.ftl.delete_old_queries(max_age_secs)
    }
}

/// Wrapper around rusqlite Connection with WAL mode and thread safety
pub struct SafeConnection {
    conn: Mutex<Connection>,
    path: std::path::PathBuf,
}

impl SafeConnection {
    /// Open a SQLite database with optimal settings
    pub fn open(path: &Path, _busy_timeout: u64) -> Result<Self, DatabaseError> {
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
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA busy_timeout=1000;
             PRAGMA foreign_keys=ON;
             PRAGMA cache_size=-16384;        -- 16 MB cache
             PRAGMA temp_store=MEMORY;
             PRAGMA mmap_size=268435456;      -- 256 MB mmap
             PRAGMA page_size=4096;
             PRAGMA default_cache_size=4096;
             PRAGMA secure_delete=OFF;"
        )?;

        debug!("Database opened: {} (page_size=4096, WAL mode)", path.display());

        Ok(Self {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
        })
    }

    /// Execute a closure with a reference to the connection
    pub fn with_conn<F, T>(&self, f: F) -> Result<T, DatabaseError>
    where
        F: FnOnce(&Connection) -> Result<T, DatabaseError>,
    {
        let conn = self.conn.lock();
        f(&conn)
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
        conn.execute_batch(schema::INITIAL_FTL_SCHEMA)?;
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

    Ok(())
}
