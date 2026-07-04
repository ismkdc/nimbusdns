// =============================================================================
// NimbusDNS Blocking Engine - In-Memory
// =============================================================================
// All blocking data is loaded into RAM at startup (and refreshed on SIGHUP/API).
// This eliminates per-query SQLite queries and regex recompilation.
// Uses: DashMap for exact matches, Vec<Regex> for patterns.

use std::sync::Arc;

use dashmap::DashSet;
use parking_lot::RwLock;
use regex::Regex;
use tracing::{info, warn};

pub mod fetcher;

use crate::config::{BlockingMode, Config};
use crate::database::gravity::GravityDb;

/// In-memory blocking list loaded from the gravity database
pub struct BlockingLists {
    /// Exact allowlisted domains (type = 0)
    allowlist_exact: DashSet<String>,
    /// Exact denylisted domains (type = 1)
    denylist_exact: DashSet<String>,
    /// Pre-compiled allowlist regex patterns (type = 2)
    allowlist_regex: Vec<Regex>,
    /// Pre-compiled denylist regex patterns (type = 3)
    denylist_regex: Vec<Regex>,
    /// Exact gravity/blocked domains (from adlists)
    gravity_exact: DashSet<String>,
    /// Statistics
    total_blocked: usize,
    adlist_count: usize,
}

impl BlockingLists {
    /// Load all blocking data from the gravity database
    pub fn load(gravity: &GravityDb) -> Result<Self, crate::database::DatabaseError> {
        info!("Loading blocking lists into memory...");

        let allowlist_exact = DashSet::new();
        let denylist_exact = DashSet::new();
        let mut allowlist_regex = Vec::new();
        let mut denylist_regex = Vec::new();
        let gravity_exact = DashSet::new();

        // Load exact allowlist (type = 0)
        if let Ok(domains) = gravity.get_domainlist_by_type(0) {
            for domain in domains {
                allowlist_exact.insert(domain.to_lowercase());
            }
            info!("Loaded {} allowlist entries", allowlist_exact.len());
        }

        // Load exact denylist (type = 1)
        if let Ok(domains) = gravity.get_domainlist_by_type(1) {
            for domain in domains {
                denylist_exact.insert(domain.to_lowercase());
            }
            info!("Loaded {} denylist entries", denylist_exact.len());
        }

        // Load regex allowlist patterns (type = 2)
        if let Ok(patterns) = gravity.get_domainlist_by_type(2) {
            for p in patterns {
                match Self::compile_regex(&p) {
                    Some(re) => allowlist_regex.push(re),
                    None => warn!("Invalid allowlist regex pattern: {}", p),
                }
            }
            info!("Loaded {} allowlist regex patterns", allowlist_regex.len());
        }

        // Load regex denylist patterns (type = 3)
        if let Ok(patterns) = gravity.get_domainlist_by_type(3) {
            for p in patterns {
                match Self::compile_regex(&p) {
                    Some(re) => denylist_regex.push(re),
                    None => warn!("Invalid denylist regex pattern: {}", p),
                }
            }
            info!("Loaded {} denylist regex patterns", denylist_regex.len());
        }

        // Load gravity (all blocked domains from adlists)
        // Handle wildcard gravity entries (e.g. `*.example.com`)
        if let Ok(domains) = gravity.get_all_gravity_domains() {
            let mut wildcard_count = 0;
            for domain in domains {
                let trimmed = domain.trim();
                if trimmed.starts_with("*.") || trimmed.starts_with('*') {
                    // Wildcard - compile as regex
                    if let Some(re) = Self::compile_regex(trimmed) {
                        denylist_regex.push(re);
                        wildcard_count += 1;
                    }
                } else {
                    gravity_exact.insert(trimmed.to_lowercase());
                }
            }
            info!("Loaded {} gravity domains ({} exact, {} wildcard regex)",
                gravity_exact.len() + wildcard_count, gravity_exact.len(), wildcard_count);
        }

        let total_blocked = gravity_exact.len() + denylist_exact.len();
        let adlist_count = gravity.adlist_count().unwrap_or(0) as usize;

        info!("Blocking lists loaded ({} total blocked, {} adlists)", total_blocked, adlist_count);

        Ok(Self {
            allowlist_exact,
            denylist_exact,
            allowlist_regex,
            denylist_regex,
            gravity_exact,
            total_blocked,
            adlist_count,
        })
    }

    /// Compile a regex pattern safely, returns None on invalid patterns.
    /// Patterns in `/pattern/` format are treated as raw regex.
    /// Patterns starting with `*.` or `*` are wildcard domain patterns.
    /// Everything else is a literal domain (exact, case-insensitive).
    pub(crate) fn compile_regex(pattern: &str) -> Option<Regex> {
        let body = pattern.trim();

        // Empty patterns are invalid
        if body.is_empty() || body.len() < 2 {
            return None;
        }

        // Detect /pattern/ raw regex format
        // NOTE: body.len() > 1 (not > 2) so that `//` (empty pattern) is caught as raw regex → None
        let is_raw_regex = body.starts_with('/') && body.len() > 1 && body.ends_with('/');

        let pattern_str = if is_raw_regex {
            // Raw regex - strip / delimiters, add (?i) for case-insensitive
            let inner = body.strip_prefix('/').and_then(|s| s.strip_suffix('/')).unwrap_or(body);
            if inner.is_empty() {
                return None;
            }
            format!("(?i){}", inner)
        } else if let Some(suffix) = body.strip_prefix("*.") {
            // *.example.com -> matches x.example.com but NOT notexample.com
            let suffix = regex::escape(suffix);
            format!("(?i)(^|\\.){}$", suffix)
        } else if let Some(suffix) = body.strip_prefix('*') {
            // *example.com -> matches anything ending with .example.com
            let suffix = regex::escape(suffix);
            format!("(?i)(^|\\.){}$", suffix)
        } else {
            // Plain literal domain - exact match, case-insensitive
            format!("(?i)^{}$", regex::escape(body))
        };

        // Validate: regex must compile and not be a trivial match-all
        let re = Regex::new(&pattern_str).ok()?;
        // Reject patterns that match empty string or everything
        if re.as_str() == "(?i)" {
            return None;
        }
        Some(re)
    }

    /// Check if a domain is blocked
    pub fn check_blocked(&self, domain: &str) -> BlockingDecision {
        // Strip trailing dot (FQDN) and lowercase for consistent matching
        let domain_lower = domain.trim_end_matches('.').to_lowercase();

        // 1. Check exact allowlist (fastest)
        if self.allowlist_exact.contains(&domain_lower) {
            return BlockingDecision::Allowlisted;
        }

        // 2. Check regex allowlist (all patterns compiled with (?i) for case-insensitivity)
        for re in &self.allowlist_regex {
            if re.is_match(&domain_lower) {
                return BlockingDecision::Allowlisted;
            }
        }

        // 3. Check exact denylist
        if self.denylist_exact.contains(&domain_lower) {
            return BlockingDecision::Blocked("exact".into());
        }

        // 4. Check regex denylist (all patterns compiled with (?i) for case-insensitivity)
        for re in &self.denylist_regex {
            if re.is_match(&domain_lower) {
                return BlockingDecision::BlockedByRegex;
            }
        }

        // 5. Check gravity
        if self.gravity_exact.contains(&domain_lower) {
            return BlockingDecision::Blocked("gravity".into());
        }

        BlockingDecision::NotBlocked
    }

    pub fn total_blocked(&self) -> u64 {
        self.total_blocked as u64
    }

    pub fn adlist_count(&self) -> u64 {
        self.adlist_count as u64
    }
}

/// Result of a domain blocking check (matches original GravityDb::BlockingDecision)
#[derive(Debug, Clone, PartialEq)]
pub enum BlockingDecision {
    NotBlocked,
    Allowlisted,
    Blocked(String),
    BlockedByRegex,
}

impl BlockingDecision {
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked(_) | Self::BlockedByRegex)
    }
}

/// Blocking engine - manages all blocking/filtering state
pub struct BlockingEngine {
    lists: Arc<RwLock<BlockingLists>>,
    mode: BlockingMode,
}

impl BlockingEngine {
    /// Create a new blocking engine and load lists from database
    pub fn load(gravity: &GravityDb, config: &Config) -> Result<Self, crate::database::DatabaseError> {
        let lists = BlockingLists::load(gravity)?;
        Ok(Self {
            lists: Arc::new(RwLock::new(lists)),
            mode: config.dns.blocking_mode,
        })
    }

    /// Reload blocking lists from database (on SIGHUP / API change)
    pub fn reload(&self, gravity: &GravityDb) -> Result<(), crate::database::DatabaseError> {
        let new_lists = BlockingLists::load(gravity)?;
        *self.lists.write() = new_lists;
        info!("Blocking lists reloaded");
        Ok(())
    }

    pub fn mode(&self) -> BlockingMode {
        self.mode
    }

    pub fn set_mode(&mut self, mode: BlockingMode) {
        self.mode = mode;
    }

    /// Check if a domain should be blocked - O(1) for exact, O(n) for regex
    pub fn is_blocked(&self, domain: &str) -> bool {
        self.lists.read().check_blocked(domain).is_blocked()
    }

    pub fn stats(&self) -> BlockingStats {
        let lists = self.lists.read();
        BlockingStats {
            total_blocked: lists.total_blocked(),
            adlist_count: lists.adlist_count(),
            blocking_mode: self.mode,
        }
    }

    /// Get the inner lists for direct use in QueryRouter
    pub fn lists(&self) -> Arc<RwLock<BlockingLists>> {
        self.lists.clone()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockingStats {
    pub total_blocked: u64,
    pub adlist_count: u64,
    pub blocking_mode: BlockingMode,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocking_decision() {
        assert!(BlockingDecision::Blocked("test".into()).is_blocked());
        assert!(BlockingDecision::BlockedByRegex.is_blocked());
        assert!(!BlockingDecision::NotBlocked.is_blocked());
        assert!(!BlockingDecision::Allowlisted.is_blocked());
    }

    #[test]
    fn test_compile_regex_wildcard_domain_boundary() {
        // *.example.com should NOT match notexample.com
        let re = BlockingLists::compile_regex("*.example.com").unwrap();
        assert!(re.is_match("sub.example.com"), "sub.example.com should match *.example.com");
        assert!(re.is_match("example.com"), "example.com should match *.example.com");
        assert!(!re.is_match("notexample.com"), "notexample.com should NOT match *.example.com");
        assert!(!re.is_match("test.notexample.com"), "test.notexample.com should NOT match *.example.com");
    }

    #[test]
    fn test_compile_regex_exact() {
        let re = BlockingLists::compile_regex("example.com").unwrap();
        assert!(re.is_match("example.com"), "exact match");
        assert!(re.is_match("Example.COM"), "case insensitive");
        assert!(!re.is_match("notexample.com"), "domain boundary");
        assert!(!re.is_match("sub.example.com"), "subdomain not exact");
    }

    #[test]
    fn test_compile_regex_raw_regex() {
        let re = BlockingLists::compile_regex("/^tracker\\..*\\.example\\.com$/").unwrap();
        assert!(re.is_match("tracker.sub.example.com"));
        assert!(!re.is_match("safe.example.com"));
        assert!(!re.is_match("tracker.example.com.evil.com"));
    }

    #[test]
    fn test_compile_regex_invalid() {
        // Empty and whitespace-only patterns are invalid
        assert!(BlockingLists::compile_regex("").is_none());
        assert!(BlockingLists::compile_regex("  ").is_none());
        // Malformed raw regex with empty body
        assert!(BlockingLists::compile_regex("//").is_none());
    }

    #[test]
    fn test_compile_regex_wildcard_boundary() {
        let re = BlockingLists::compile_regex("*.example.com").unwrap();
        assert!(re.is_match("sub.example.com"), "subdomain should match");
        assert!(re.is_match("example.com"), "apex should match");
        assert!(!re.is_match("notexample.com"), "should NOT match substring");
    }
}
