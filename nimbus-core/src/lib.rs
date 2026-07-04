// =============================================================================
// NimbusDNS Core Library
// =============================================================================
// Shared types and modules used by all crates.

// Unsafe is needed only for fork() in daemon module - contained there.
// Clippy pedantic checks are opt-in during CI.
#![warn(clippy::all)]

pub mod config;
pub mod daemon;
pub mod database;
pub mod logging;
pub mod signals;
pub mod dns;
pub mod blocking;
pub mod capabilities;
pub mod dhcp;
pub mod over_time;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::watch;

/// Central application state shared across all modules
pub struct AppState {
    /// Configuration (protected by RwLock for runtime updates via API)
    pub config: parking_lot::RwLock<config::Config>,
    /// Path to the config file (for write-back from API)
    pub config_path: std::path::PathBuf,
    /// Database handle
    pub database: database::Database,
    /// In-memory time-based query statistics
    pub over_time: over_time::OverTime,
    /// Background database writer for low-latency query logging
    pub db_writer: Option<database::writer::DbWriter>,
    /// DHCP server state (None if disabled)
    pub dhcp_server: Option<Arc<dhcp::DhcpServer>>,
    /// DHCP config (shared with running server for live toggle)
    pub dhcp_config: Option<Arc<parking_lot::RwLock<config::DhcpConfig>>>,
    /// Blocking engine (None until initialized in main)
    pub blocking: Option<Arc<blocking::BlockingEngine>>,
    /// Is the daemon running?
    pub running: AtomicBool,
}

impl AppState {
    pub fn new(config: config::Config, database: database::Database) -> Self {
        Self {
            config_path: std::path::PathBuf::from("/etc/nimbusdns/nimbus.toml"),
            config: parking_lot::RwLock::new(config),
            database,
            over_time: over_time::OverTime::new(),
            db_writer: None,
            dhcp_server: None,
            dhcp_config: None,
            blocking: None,
            running: AtomicBool::new(true),
        }
    }

    /// Create AppState with an explicit config file path
    pub fn with_config_path(config: config::Config, database: database::Database, path: std::path::PathBuf) -> Self {
        Self {
            config_path: path,
            config: parking_lot::RwLock::new(config),
            database,
            over_time: over_time::OverTime::new(),
            db_writer: None,
            dhcp_server: None,
            dhcp_config: None,
            blocking: None,
            running: AtomicBool::new(true),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn shutdown(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Handle returned by start() functions for graceful shutdown
pub struct DnsHandle {
    pub shutdown: Option<watch::Sender<bool>>,
}

impl DnsHandle {
    pub fn new() -> Self {
        Self { shutdown: None }
    }

    pub fn shutdown(&self) {
        if let Some(tx) = &self.shutdown {
            let _ = tx.send(true);
        }
    }
}

impl Default for DnsHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the system hostname
pub fn hostname() -> String {
    // Use fully qualified path to avoid name conflict with this function
    fn inner() -> Result<String, Box<dyn std::error::Error>> {
        let h = ::hostname::get()?;
        Ok(h.to_string_lossy().to_string())
    }
    inner().unwrap_or_else(|_| "unknown".to_string())
}
