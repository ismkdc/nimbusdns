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
    init_with_file(None)
}

/// Initialize logging with an optional log file. When a file is given (e.g.
/// from `files.log_file` in the config), logs are written to it instead of
/// stdout — otherwise a daemonized process (whose stdout is /dev/null) would
/// silently lose all logs (B16).
pub fn init_with_file(log_file: Option<&std::path::Path>) -> anyhow::Result<()> {
    if LOG_INITIALIZED.get().is_some() {
        return Ok(());
    }

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            EnvFilter::builder()
                .with_default_directive(Level::INFO.into())
                .parse("nimbus=info")
                .expect("Invalid RUST_LOG filter")
        });

    // Register the log layer (console, or file when configured)
    let fmt_layer = fmt::Layer::default()
        .with_target(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_ansi(log_file.is_none());

    match log_file {
        Some(path) => {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| anyhow::anyhow!("Failed to open log file {}: {}", path.display(), e))?;
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer.with_writer(file))
                .init();
        }
        None => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .init();
        }
    }

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

/// Log a detailed configuration summary at startup so operators can see the
/// effective runtime settings in one place (version, DNS, DHCP, web, DB,
/// fetcher) without digging into the config file.
pub fn log_config_summary(cfg: &crate::config::Config) {
    use crate::config::DnsUpstream;

    tracing::info!("=== NimbusDNS {} configuration summary ===", env!("CARGO_PKG_VERSION"));

    // DNS
    tracing::info!("DNS bind: {} (rate limit: {} qps, query_log: {})",
        cfg.dns.bind, cfg.dns.rate_limit, cfg.dns.query_log);
    for (i, up) in cfg.dns.upstreams.iter().enumerate() {
        let desc = match up {
            DnsUpstream::Plain { address, port } => format!("udp://{}:{}", address, port),
            DnsUpstream::Tls { address, port, hostname } => format!("tls://{}:{}#{}", address, port, hostname),
        };
        tracing::info!("  upstream[{}]: {}", i, desc);
    }
    tracing::info!("Blocking mode: {:?} (blocking_ip: {})",
        cfg.dns.blocking_mode, cfg.dns.blocking_ip);

    // DHCP
    if cfg.dhcp.enabled {
        let start = cfg.dhcp.pool_start.map(|s| s.to_string()).unwrap_or_else(|| "auto".into());
        let end = cfg.dhcp.pool_end.map(|e| e.to_string()).unwrap_or_else(|| "auto".into());
        tracing::info!("DHCP: enabled (interface: {:?}, pool: {}-{}, lease: {}s, domain: {:?})",
            cfg.dhcp.interface, start, end, cfg.dhcp.lease_time, cfg.dhcp.domain);
    } else {
        tracing::info!("DHCP: disabled");
    }

    // Web / API
    tracing::info!("Web server ports: {:?}", cfg.webserver.ports);

    // Database
    tracing::info!("Gravity DB: {}", cfg.database.gravity_db.display());
    tracing::info!("Nimbus DB: {}", cfg.database.nimbus_db.display());

    // Fetcher / blocking
    tracing::info!("Blocklist source: {}", cfg.blocking.source_url);
    tracing::info!("Blocklist refresh interval: {}s", cfg.blocking.refresh_interval);

    tracing::info!("=== end configuration summary ===");
}

/// Log levels that map to original log level semantics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NimbusLogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Critical,
}

impl NimbusLogLevel {
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
pub mod nimbus {
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
