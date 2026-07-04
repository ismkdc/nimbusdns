// =============================================================================
// Logging System (tracing-based)
// =============================================================================

use std::sync::OnceLock;

use tracing::Level;
use tracing_subscriber::{
    fmt,
    prelude::*,
    EnvFilter,
};

static LOG_INITIALIZED: OnceLock<bool> = OnceLock::new();

/// Initialize logging subsystem.
/// Reads RUST_LOG environment variable for filtering.
/// Default: "info,nimbus=debug"
pub fn init() -> anyhow::Result<()> {
    if LOG_INITIALIZED.get().is_some() {
        return Ok(());
    }

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            EnvFilter::builder()
                .with_default_directive(Level::INFO.into())
                .parse("nimbus=debug,want=info")
                .unwrap()
        });

    // Register the log layer (console)
    let fmt_layer = fmt::Layer::default()
        .with_target(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_ansi(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();

    LOG_INITIALIZED.set(true).ok();

    log_startup_banner();

    Ok(())
}

/// Print the startup banner
fn log_startup_banner() {
    tracing::info!("--------------------------------------------------");
    tracing::info!("NimbusDNS Rust Port");
    tracing::info!("  NimbusDNS DNS engine with native DNS-over-TLS");
    tracing::info!("  Version: {}", env!("CARGO_PKG_VERSION"));
    tracing::info!("--------------------------------------------------");
}

/// Log levels that map to original log level semantics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtlLogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Critical,
}

impl FtlLogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERR",
            Self::Critical => "CRIT",
        }
    }
}

/// Log macro convenience functions
pub mod ftl {
    use super::*;

    pub fn debug(target: &str, msg: impl std::fmt::Display) {
        if !should_debug(target) {
            return;
        }
        tracing::debug!(target = %target, "{msg}");
    }

    pub fn info(msg: impl std::fmt::Display) {
        tracing::info!("{msg}");
    }

    pub fn warn(msg: impl std::fmt::Display) {
        tracing::warn!("{msg}");
    }

    pub fn error(msg: impl std::fmt::Display) {
        tracing::error!("{msg}");
    }

    pub fn critical(msg: impl std::fmt::Display) {
        tracing::error!(target: "nimbus::critical", "{msg}");
    }

    /// Check if a given debug target is enabled
    fn should_debug(_target: &str) -> bool {
        let _filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("off"));
        // This is a simplification; the real filter is checked by tracing
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        // Should not panic on double init
        init().ok();
        init().ok();
    }
}
