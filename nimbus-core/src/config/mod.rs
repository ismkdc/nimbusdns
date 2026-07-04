// =============================================================================
// Configuration System
// =============================================================================
// Supports:
//   - /etc/nimbusdns/nimbus.toml (primary config file)
//   - Environment variables (FTLCONF_*) override
//   - CLI arguments
//   - Legacy /etc/nimbusdns/nimbus.conf (import on first run)

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Configuration error
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file {path}: {source}")]
    FileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("Failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("Environment variable error: {0}")]
    Env(#[from] std::env::VarError),
    #[error("Validation error: {0}")]
    Validation(String),
}

/// Top-level configuration (mirrors nimbus.toml structure)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub struct Config {
    /// DNS resolver settings
    #[serde(default)]
    pub dns: DnsConfig,

    /// DHCP server settings
    #[serde(default)]
    pub dhcp: DhcpConfig,

    /// Web server / API settings
    #[serde(default)]
    pub webserver: WebServerConfig,

    /// Database settings
    #[serde(default)]
    pub database: DatabaseConfig,

    /// Debug settings
    #[serde(default)]
    pub debug: DebugConfig,

    /// Miscellaneous settings
    #[serde(default)]
    pub misc: MiscConfig,

    /// Blocklist / blocking settings
    #[serde(default)]
    pub blocking: BlockingConfig,

    /// File paths
    #[serde(default)]
    pub files: FileConfig,
}

/// DNS resolver configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DnsConfig {
    /// Upstream DNS servers (plain or tls://)
    #[serde(default = "default_upstreams")]
    pub upstreams: Vec<DnsUpstream>,

    /// Bind address for DNS listener
    #[serde(default = "default_dns_bind")]
    pub bind: SocketAddr,

    /// Blocking mode: NULL, NXDOMAIN, IP, REFUSED
    #[serde(default)]
    pub blocking_mode: BlockingMode,

    /// Rate limit (queries per second per client)
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,

    /// Cache size (number of entries)
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,

    /// Enable query logging (default: true)
    #[serde(default = "default_true")]
    pub query_log: bool,

    /// Query retention in seconds (default: 30 days)
    #[serde(default = "default_query_retention")]
    pub query_retention: u64,

    /// IP address to return when blocking_mode = IP
    #[serde(default = "default_blocking_ip")]
    pub blocking_ip: std::net::IpAddr,

    /// Interface to listen on (empty = all)
    #[serde(default)]
    pub interface: Option<String>,

    /// Port for DNS listener
    #[serde(default = "default_dns_port")]
    pub port: u16,

    /// Maximum concurrent DNS queries
    #[serde(default = "default_max_queries")]
    pub max_concurrent_queries: usize,

    /// DoT connection pool size per upstream
    #[serde(default = "default_dot_conn_max")]
    pub dot_conn_max: usize,

    /// DoT pipeline depth per connection
    #[serde(default = "default_dot_job_max")]
    pub dot_job_max: usize,

    /// DoT overflow queue size
    #[serde(default = "default_dot_pending_max")]
    pub dot_pending_max: usize,
}

/// Configuration for a DNS upstream server
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DnsUpstream {
    /// Plain DNS over UDP/TCP
    Plain {
        /// IP address
        address: std::net::IpAddr,
        /// Port (default 53)
        port: u16,
    },
    /// DNS over TLS
    Tls {
        /// IP address
        address: std::net::IpAddr,
        /// Port (default 853)
        port: u16,
        /// TLS hostname for SNI and certificate verification
        hostname: String,
    },
}

/// How to respond to blocked domains
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[derive(Default)]
pub enum BlockingMode {
    /// Return 0.0.0.0 (and :: for AAAA)
    #[default]
    Null,
    /// Return NXDOMAIN
    Nxdomain,
    /// Return a configurable IP
    Ip,
    /// Return REFUSED
    Refused,
    /// Return NODATA (empty answer)
    Nodata,
    /// Disable blocking
    Disabled,
}


/// DHCP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DhcpConfig {
    /// Enable DHCP server
    #[serde(default)]
    pub enabled: bool,
    /// Interface to listen on
    #[serde(default)]
    pub interface: Option<String>,
    /// Gateway/router IP
    #[serde(default)]
    pub router: Option<std::net::Ipv4Addr>,
    /// Subnet mask
    #[serde(default = "default_dhcp_mask")]
    pub netmask: std::net::Ipv4Addr,
    /// DNS server to offer
    #[serde(default)]
    pub dns_server: Option<std::net::Ipv4Addr>,
    /// IP pool start
    #[serde(default)]
    pub pool_start: Option<std::net::Ipv4Addr>,
    /// IP pool end
    #[serde(default)]
    pub pool_end: Option<std::net::Ipv4Addr>,
    /// Lease time in seconds (default: 24h)
    #[serde(default = "default_dhcp_lease_time")]
    pub lease_time: u32,
    /// Domain name
    #[serde(default)]
    pub domain: Option<String>,
}

fn default_dhcp_mask() -> std::net::Ipv4Addr {
    "255.255.255.0".parse().unwrap()
}

fn default_dhcp_lease_time() -> u32 {
    86400
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: None,
            router: None,
            netmask: default_dhcp_mask(),
            dns_server: None,
            pool_start: None,
            pool_end: None,
            lease_time: default_dhcp_lease_time(),
            domain: None,
        }
    }
}

/// Web server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WebServerConfig {
    /// Listen addresses (e.g., "80o" = plain, "443os" = TLS)
    #[serde(default = "default_web_ports")]
    pub ports: Vec<String>,

    /// TLS certificate paths (None = generate self-signed or disable TLS)
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,

    /// TLS key path
    #[serde(default)]
    pub tls_key: Option<PathBuf>,

    /// API password (hashed)
    #[serde(default)]
    pub password_hash: Option<String>,

    /// Session timeout in seconds (minimum 60)
    #[serde(default = "default_session_timeout")]
    pub session_timeout: u64,

    /// Rate limit for API requests
    #[serde(default = "default_api_rate_limit")]
    pub api_rate_limit: u32,

    /// Enable 2FA (TOTP)
    #[serde(default)]
    pub totp_enabled: bool,

    /// TOTP secret (base32 encoded) for 2FA
    #[serde(default, skip_serializing)]
    pub totp_secret: Option<String>,
}

/// A parsed web server port entry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebPort {
    /// Plain HTTP on the given port
    Http(u16),
    /// HTTPS with TLS on the given port
    Https(u16),
}

impl WebPort {
    /// Parse a port string like "80o" (HTTP) or "443os" (HTTPS).
    /// Returns None for invalid formats.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        if let Some(port_str) = s.strip_suffix("os") {
            // HTTPS with TLS
            let port: u16 = port_str.parse().ok()?;
            Some(WebPort::Https(port))
        } else if let Some(port_str) = s.strip_suffix('o') {
            // Plain HTTP
            let port: u16 = port_str.parse().ok()?;
            Some(WebPort::Http(port))
        } else {
            // Try plain number (default to HTTP)
            let port: u16 = s.parse().ok()?;
            Some(WebPort::Http(port))
        }
    }

    /// Get the port number
    pub fn port(&self) -> u16 {
        match self {
            WebPort::Http(p) | WebPort::Https(p) => *p,
        }
    }

    /// Returns true if this port uses TLS
    pub fn is_tls(&self) -> bool {
        matches!(self, WebPort::Https(_))
    }
}

impl WebServerConfig {
    /// Get all parsed web ports
    pub fn parsed_ports(&self) -> Vec<WebPort> {
        self.ports.iter().filter_map(|s| WebPort::parse(s)).collect()
    }

    /// Get the first plain HTTP port, defaulting to 8080 if none found
    pub fn http_port(&self) -> u16 {
        self.parsed_ports().iter()
            .find(|p| !p.is_tls())
            .map(|p| p.port())
            .unwrap_or(8080)
    }

    /// Get bind address for a specific interface (binds to all interfaces)
    pub fn bind_addr(&self, iface: &str) -> std::net::SocketAddr {
        let port = match iface {
            "api" | "http" => self.http_port(),
            _ => self.http_port(),
        };
        std::net::SocketAddr::from(([0, 0, 0, 0], port))
    }
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DatabaseConfig {
    /// Path to gravity database
    #[serde(default = "default_gravity_db")]
    pub gravity_db: PathBuf,

    /// Path to Query database
    #[serde(default = "default_ftl_db")]
    pub ftl_db: PathBuf,

    /// Maximum number of queries stored
    #[serde(default = "default_max_queries_stored")]
    pub max_queries_stored: u64,

    /// How often to analyze the database (seconds)
    #[serde(default = "default_db_analyze_interval")]
    pub analyze_interval: u64,

    /// How often to delete old queries (seconds)
    #[serde(default = "default_db_delete_interval")]
    pub delete_interval: u64,

    /// Maximum age of stored queries (seconds)
    #[serde(default = "default_query_retention")]
    pub query_retention: u64,

    /// Busy timeout in milliseconds
    #[serde(default = "default_db_busy_timeout")]
    pub busy_timeout: u64,
}

/// Debug configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub struct DebugConfig {
    /// Enable all debug flags
    #[serde(default)]
    pub all: bool,

    /// Enable resolver debugging
    #[serde(default)]
    pub resolver: bool,

    /// Enable API debugging
    #[serde(default)]
    pub api: bool,

    /// Enable database debugging
    #[serde(default)]
    pub database: bool,

    /// Enable DNS debugging
    #[serde(default)]
    pub dns: bool,

    /// Enable locking debugging
    #[serde(default)]
    pub locking: bool,

    /// Enable EDNS0 debugging
    #[serde(default)]
    pub edns0: bool,

    /// Enable regex debugging
    #[serde(default)]
    pub regex: bool,

    /// Enable config debugging
    #[serde(default)]
    pub config: bool,

    /// Enable DoT debugging
    #[serde(default)]
    pub dot: bool,
}

impl DebugConfig {
    /// Check if any debugging is enabled
    pub fn any(&self) -> bool {
        self.all || self.resolver || self.api || self.database
            || self.dns || self.locking || self.edns0
            || self.regex || self.config || self.dot
    }
}

/// Miscellaneous configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MiscConfig {
    /// Delay startup by N seconds (for network readiness)
    #[serde(default)]
    pub delay_startup: u64,

    /// Process nice value (-20 to 19, -999 = no change)
    #[serde(default = "default_nice")]
    pub nice: i32,

    /// Check if another instance is running
    #[serde(default = "default_true")]
    pub check_other_instance: bool,

    /// Enable IPv6 resolution
    #[serde(default = "default_true")]
    pub enable_ipv6: bool,

    /// Normalize CPU usage by core count
    #[serde(default = "default_true")]
    pub normalize_cpu: bool,
}

/// Blocklist / blocking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockingConfig {
    /// URL for the blocklist source (StevenBlack hosts file)
    #[serde(default = "default_blocklist_url")]
    pub source_url: String,
    /// Refresh interval in seconds (default: 86400 = 24h)
    #[serde(default = "default_blocklist_refresh")]
    pub refresh_interval: u64,
}

fn default_blocklist_url() -> String {
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".into()
}

fn default_blocklist_refresh() -> u64 {
    86400
}

impl Default for BlockingConfig {
    fn default() -> Self {
        Self {
            source_url: default_blocklist_url(),
            refresh_interval: default_blocklist_refresh(),
        }
    }
}

/// File paths configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FileConfig {
    /// PID file path
    #[serde(default = "default_pid_file")]
    pub pid_file: PathBuf,

    /// Log file path
    #[serde(default = "default_log_file")]
    pub log_file: Option<PathBuf>,

    /// Socket path
    #[serde(default = "default_socket")]
    pub socket: Option<PathBuf>,

    /// Setup vars (legacy import)
    #[serde(default = "default_setup_vars")]
    pub setup_vars: Option<PathBuf>,
}

// =============================================================================
// Defaults
// =============================================================================

fn default_upstreams() -> Vec<DnsUpstream> {
    vec![
        DnsUpstream::Tls {
            address: "8.8.8.8".parse().unwrap(),
            port: 853,
            hostname: "dns.google".into(),
        },
        DnsUpstream::Tls {
            address: "1.1.1.1".parse().unwrap(),
            port: 853,
            hostname: "cloudflare-dns.com".into(),
        },
    ]
}

fn default_dns_bind() -> SocketAddr {
    "0.0.0.0:53".parse().unwrap()
}

fn default_dns_port() -> u16 {
    53
}

fn default_rate_limit() -> u32 {
    1000
}

fn default_cache_size() -> usize {
    10_000
}

fn default_blocking_ip() -> std::net::IpAddr {
    "0.0.0.0".parse().unwrap()
}

fn default_max_queries() -> usize {
    150
}

fn default_dot_conn_max() -> usize {
    4
}

fn default_dot_job_max() -> usize {
    32
}

fn default_dot_pending_max() -> usize {
    16
}

fn default_web_ports() -> Vec<String> {
    vec!["80o".into(), "443os".into()]
}

fn default_session_timeout() -> u64 {
    86400 // 24 hours
}

fn default_api_rate_limit() -> u32 {
    100
}

fn default_gravity_db() -> PathBuf {
    std::env::var("FTLCONF_database_gravity_db")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/nimbusdns/gravity.db"))
}

fn default_ftl_db() -> PathBuf {
    std::env::var("FTLCONF_database_ftl_db")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/nimbusdns/nimbusdns.db"))
}

fn default_max_queries_stored() -> u64 {
    500_000
}

fn default_db_analyze_interval() -> u64 {
    604_800 // 1 week
}

fn default_db_delete_interval() -> u64 {
    86_400 // 1 day
}

fn default_query_retention() -> u64 {
    365 * 86_400 // 1 year
}

fn default_db_busy_timeout() -> u64 {
    1000
}

fn default_nice() -> i32 {
    -999
}

fn default_true() -> bool {
    true
}

fn default_pid_file() -> PathBuf {
    std::env::var("FTLCONF_files_pid_file")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // Try /run, fallback to tmp
            let run = PathBuf::from("/run/nimbusdns.pid");
            if run.parent().is_some_and(|p| p.exists()) {
                run
            } else {
                std::env::temp_dir().join("nimbusdns.pid")
            }
        })
}

fn default_log_file() -> Option<PathBuf> {
    Some(
        std::env::var("FTLCONF_files_log_file")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let log = PathBuf::from("/var/log/nimbusdns/nimbus.log");
                if log.parent().is_some_and(|p| p.exists()) {
                    log
                } else {
                    std::env::temp_dir().join("nimbusdns.log")
                }
            })
    )
}

fn default_socket() -> Option<PathBuf> {
    Some(
        std::env::var("FTLCONF_files_socket")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let sock = PathBuf::from("/run/nimbusdns/nimbus.sock");
                if sock.parent().is_some_and(|p| p.exists()) {
                    sock
                } else {
                    std::env::temp_dir().join("nimbus.sock")
                }
            })
    )
}

fn default_setup_vars() -> Option<PathBuf> {
    Some(PathBuf::from("/etc/nimbusdns/nimbus.conf"))
}

// =============================================================================
// Environment variable override logic
// =============================================================================
const ENV_PREFIX: &str = "FTLCONF_";

/// Load config from file and apply environment variable overrides
impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let mut config: Config = if path.exists() {
            let contents = std::fs::read_to_string(path)
                .map_err(|e| ConfigError::FileRead {
                    path: path.to_path_buf(),
                    source: e,
                })?;
            toml::from_str(&contents)?
        } else {
            Config::default()
        };

        config.apply_env_overrides()?;
        config.validate()?;
        Ok(config)
    }

    /// Override config values from FTLCONF_* environment variables
    fn apply_env_overrides(&mut self) -> Result<(), ConfigError> {
        for (key, value) in std::env::vars() {
            if let Some(inner) = key.strip_prefix(ENV_PREFIX) {
                self.set_from_env(inner, &value)?;
            }
        }
        Ok(())
    }

    fn set_from_env(&mut self, key: &str, value: &str) -> Result<(), ConfigError> {
        // Supports: FTLCONF_dns_upstreams, FTLCONF_dns_blocking_mode, etc.
        // Maps to config.dns.upstreams, config.dns.blocking_mode, etc.
        let parts: Vec<&str> = key.split('_').collect();
        match parts.as_slice() {
            ["dns", "upstreams"] => {
                self.dns.upstreams = parse_upstreams(value)?;
            }
            ["dns", "blocking", "mode"] | ["dns", "blockingMode"] => {
                self.dns.blocking_mode = parse_blocking_mode(value)?;
            }
            ["dns", "rate", "limit"] | ["dns", "rateLimit"] => {
                self.dns.rate_limit = value.parse().map_err(|_| {
                    ConfigError::Validation(format!("Invalid rate_limit: {}", value))
                })?;
            }
            ["dns", "port"] => {
                self.dns.port = value.parse().map_err(|_| {
                    ConfigError::Validation(format!("Invalid port: {}", value))
                })?;
                // Update bind address port
                self.dns.bind.set_port(self.dns.port);
            }
            ["dns", "bind"] => {
                self.dns.bind = value.parse().map_err(|_| {
                    ConfigError::Validation(format!("Invalid bind address: {}", value))
                })?;
            }
            ["dns", "blocking", "ip"] | ["dns", "blockingIp"] => {
                self.dns.blocking_ip = value.parse().map_err(|_| {
                    ConfigError::Validation(format!("Invalid blocking IP: {}", value))
                })?;
            }
            ["webserver", "port"] => {
                self.webserver.ports = value.split(',').map(|s| s.trim().to_string()).collect();
            }
            ["dhcp", "enabled"] => {
                self.dhcp.enabled = value == "true" || value == "1";
            }
            ["dhcp", "pool", "start"] | ["dhcp", "poolStart"] => {
                if let Ok(ip) = value.parse() { self.dhcp.pool_start = Some(ip); }
            }
            ["dhcp", "pool", "end"] | ["dhcp", "poolEnd"] => {
                if let Ok(ip) = value.parse() { self.dhcp.pool_end = Some(ip); }
            }
            ["dhcp", "router"] => {
                if let Ok(ip) = value.parse() { self.dhcp.router = Some(ip); }
            }
            ["dhcp", "dns", "server"] | ["dhcp", "dnsServer"] => {
                if let Ok(ip) = value.parse() { self.dhcp.dns_server = Some(ip); }
            }
            ["dhcp", "lease", "time"] | ["dhcp", "leaseTime"] => {
                if let Ok(v) = value.parse() { self.dhcp.lease_time = v; }
            }
            ["dhcp", "domain"] => {
                self.dhcp.domain = Some(value.to_string());
            }
            ["debug", flag] => {
                match *flag {
                    "all" | "All" => self.debug.all = true,
                    "resolver" => self.debug.resolver = true,
                    "api" => self.debug.api = true,
                    "database" | "Database" => self.debug.database = true,
                    "dns" | "DNS" => self.debug.dns = true,
                    "locking" => self.debug.locking = true,
                    "edns0" | "EDNS0" => self.debug.edns0 = true,
                    "regex" => self.debug.regex = true,
                    "config" => self.debug.config = true,
                    "dot" | "DoT" => self.debug.dot = true,
                    _ => {}
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        // Validate upstreams
        if self.dns.upstreams.is_empty() {
            return Err(ConfigError::Validation(
                "At least one DNS upstream must be configured".into(),
            ));
        }

        // Validate blocking mode
        if self.dns.blocking_mode == BlockingMode::Ip {
            // IP blocking mode needs an IP configured
        }

        // Validate rate limit
        if self.dns.rate_limit == 0 {
            return Err(ConfigError::Validation(
                "Rate limit must be > 0".into(),
            ));
        }

        Ok(())
    }
}


impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            upstreams: default_upstreams(),
            bind: default_dns_bind(),
            blocking_mode: BlockingMode::default(),
            rate_limit: default_rate_limit(),
            cache_size: default_cache_size(),
            blocking_ip: default_blocking_ip(),
            query_log: true,
            query_retention: default_query_retention(),
            interface: None,
            port: 53,
            max_concurrent_queries: default_max_queries(),
            dot_conn_max: default_dot_conn_max(),
            dot_job_max: default_dot_job_max(),
            dot_pending_max: default_dot_pending_max(),
        }
    }
}

impl Default for WebServerConfig {
    fn default() -> Self {
        Self {
            ports: default_web_ports(),
            tls_cert: None,
            tls_key: None,
            password_hash: None,
            session_timeout: default_session_timeout(),
            api_rate_limit: default_api_rate_limit(),
            totp_enabled: false,
            totp_secret: None,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            gravity_db: default_gravity_db(),
            ftl_db: default_ftl_db(),
            max_queries_stored: default_max_queries_stored(),
            analyze_interval: default_db_analyze_interval(),
            delete_interval: default_db_delete_interval(),
            query_retention: default_query_retention(),
            busy_timeout: default_db_busy_timeout(),
        }
    }
}


impl Default for MiscConfig {
    fn default() -> Self {
        Self {
            delay_startup: 0,
            nice: default_nice(),
            check_other_instance: true,
            enable_ipv6: true,
            normalize_cpu: true,
        }
    }
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            pid_file: default_pid_file(),
            log_file: default_log_file(),
            socket: default_socket(),
            setup_vars: default_setup_vars(),
        }
    }
}

// =============================================================================
// Parsing helpers
// =============================================================================

/// Parse upstream string format:
///   tls://8.8.8.8#853#dns.google
///   8.8.8.8
///   8.8.8.8#53
fn parse_upstreams(input: &str) -> Result<Vec<DnsUpstream>, ConfigError> {
    let mut upstreams = Vec::new();
    for part in input.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(tls_part) = part.strip_prefix("tls://") {
            let parts: Vec<&str> = tls_part.split('#').collect();
            let address: std::net::IpAddr = parts[0].parse().map_err(|_| {
                ConfigError::Validation(format!("Invalid IP in upstream: {}", parts[0]))
            })?;
            let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(853);
            let hostname = parts.get(2).unwrap_or(&parts[0]).to_string();
            upstreams.push(DnsUpstream::Tls {
                address,
                port,
                hostname,
            });
        } else {
            let parts: Vec<&str> = part.split('#').collect();
            let address: std::net::IpAddr = parts[0].parse().map_err(|_| {
                ConfigError::Validation(format!("Invalid IP in upstream: {}", parts[0]))
            })?;
            let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(53);
            upstreams.push(DnsUpstream::Plain { address, port });
        }
    }
    if upstreams.is_empty() {
        return Err(ConfigError::Validation(
            "No valid upstreams found in environment variable".into(),
        ));
    }
    Ok(upstreams)
}

fn parse_blocking_mode(s: &str) -> Result<BlockingMode, ConfigError> {
    match s.to_uppercase().as_str() {
        "NULL" => Ok(BlockingMode::Null),
        "NXDOMAIN" => Ok(BlockingMode::Nxdomain),
        "IP" => Ok(BlockingMode::Ip),
        "REFUSED" => Ok(BlockingMode::Refused),
        "NODATA" => Ok(BlockingMode::Nodata),
        "DISABLED" => Ok(BlockingMode::Disabled),
        _ => Err(ConfigError::Validation(format!(
            "Unknown blocking mode: {}. Valid: NULL, NXDOMAIN, IP, REFUSED, NODATA, DISABLED",
            s
        ))),
    }
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_upstreams_plain() {
        let upstreams = parse_upstreams("8.8.8.8;1.1.1.1#53").unwrap();
        assert_eq!(upstreams.len(), 2);
        assert_eq!(
            upstreams[0],
            DnsUpstream::Plain {
                address: "8.8.8.8".parse().unwrap(),
                port: 53,
            }
        );
    }

    #[test]
    fn test_parse_upstreams_tls() {
        let upstreams = parse_upstreams("tls://8.8.8.8#853#dns.google").unwrap();
        assert_eq!(upstreams.len(), 1);
        assert_eq!(
            upstreams[0],
            DnsUpstream::Tls {
                address: "8.8.8.8".parse().unwrap(),
                port: 853,
                hostname: "dns.google".into(),
            }
        );
    }

    #[test]
    fn test_parse_blocking_mode() {
        assert_eq!(parse_blocking_mode("NULL").unwrap(), BlockingMode::Null);
        assert_eq!(parse_blocking_mode("NXDOMAIN").unwrap(), BlockingMode::Nxdomain);
        assert!(parse_blocking_mode("INVALID").is_err());
    }
}
