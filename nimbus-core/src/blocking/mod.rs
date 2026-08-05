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
    /// Wildcard gravity entries (`*.example.com`) — O(labels) matching
    wildcard_deny: WildcardMatcher,
    /// Statistics
    total_blocked: usize,
    adlist_count: usize,
}

/// O(labels) wildcard domain matcher for `*.suffix` entries.
/// Stores reversed suffixes; `is_match` checks each label boundary of the
/// reversed query name against the set (hash lookup per boundary).
#[derive(Default)]
pub struct WildcardMatcher {
    suffixes: DashSet<String>,
}

impl WildcardMatcher {
    /// Add a `*.suffix` or `*suffix` pattern (e.g. `*.example.com`, `*example.com`).
    /// The suffix itself also matches (apex), matching the previous regex behavior.
    pub fn insert(&self, pattern: &str) {
        let trimmed = pattern.trim();
        let suffix = trimmed
            .strip_prefix("*.")
            .or_else(|| trimmed.strip_prefix('*'))
            .unwrap_or(trimmed);
        let mut labels: Vec<String> = suffix
            .split('.')
            .map(|label| label.to_lowercase())
            .collect();
        labels.reverse();
        self.suffixes.insert(labels.join("."));
    }

    /// Check whether `domain` (already lowercased) matches any stored wildcard.
    pub fn is_match(&self, domain_lower: &str) -> bool {
        let mut labels: Vec<&str> = domain_lower.split('.').collect();
        labels.reverse();
        let mut current = String::new();
        for (i, label) in labels.iter().enumerate() {
            if i > 0 {
                current.push('.');
            }
            current.push_str(label);
            if self.suffixes.contains(&current) {
                return true;
            }
        }
        false
    }
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
        let allowlist_domains = gravity.get_domainlist_by_type(0)?;
        for domain in allowlist_domains {
            allowlist_exact.insert(domain.to_lowercase());
        }
        info!("Loaded {} allowlist entries", allowlist_exact.len());

        // Load exact denylist (type = 1)
        let denylist_domains = gravity.get_domainlist_by_type(1)?;
        for domain in denylist_domains {
            denylist_exact.insert(domain.to_lowercase());
        }
        info!("Loaded {} denylist entries", denylist_exact.len());

        // Load regex allowlist patterns (type = 2)
        let allow_patterns = gravity.get_domainlist_by_type(2)?;
        for p in allow_patterns {
            match Self::compile_regex(&p) {
                Some(re) => allowlist_regex.push(re),
                None => warn!("Invalid allowlist regex pattern: {}", p),
            }
        }
        info!("Loaded {} allowlist regex patterns", allowlist_regex.len());

        // Load regex denylist patterns (type = 3)
        let deny_patterns = gravity.get_domainlist_by_type(3)?;
        for p in deny_patterns {
            match Self::compile_regex(&p) {
                Some(re) => denylist_regex.push(re),
                None => warn!("Invalid denylist regex pattern: {}", p),
            }
        }
        info!("Loaded {} denylist regex patterns", denylist_regex.len());

        // Load gravity (all blocked domains from adlists)
        let wildcard_deny = WildcardMatcher::default();
        let gravity_domains = gravity.get_all_gravity_domains()?;
        let mut wildcard_count = 0;
        for domain in gravity_domains {
            let trimmed = domain.trim();
            if trimmed.starts_with("*.") || trimmed.starts_with('*') {
                // Wildcard - store in O(labels) matcher (not regex)
                wildcard_deny.insert(trimmed);
                wildcard_count += 1;
            } else {
                gravity_exact.insert(trimmed.to_lowercase());
            }
        }
        info!("Loaded {} gravity domains ({} exact, {} wildcard)",
            gravity_exact.len() + wildcard_count, gravity_exact.len(), wildcard_count);

        // Count wildcards and deny regexes in the total so the metric shown
        // by the API matches what actually blocks (B8).
        let total_blocked = gravity_exact.len() + denylist_exact.len() + wildcard_count + denylist_regex.len();
        let adlist_count = gravity.adlist_count()? as usize;

        info!("Blocking lists loaded ({} total blocked, {} adlists)", total_blocked, adlist_count);

        Ok(Self {
            allowlist_exact,
            denylist_exact,
            allowlist_regex,
            denylist_regex,
            gravity_exact,
            wildcard_deny,
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

        // 3. Check exact denylist (O(1)) before regex scans
        if self.denylist_exact.contains(&domain_lower) {
            return BlockingDecision::Blocked("exact".into());
        }

        // 4. Check gravity exact (largest set, O(1)) before regex scans
        if self.gravity_exact.contains(&domain_lower) {
            return BlockingDecision::Blocked("gravity".into());
        }

        // 5. Check wildcard gravity (O(labels) hash lookups)
        if self.wildcard_deny.is_match(&domain_lower) {
            return BlockingDecision::Blocked("wildcard".into());
        }

        // 6. Check denylist regex patterns (raw /pattern/ entries only)
        for re in &self.denylist_regex {
            if re.is_match(&domain_lower) {
                return BlockingDecision::BlockedByRegex;
            }
        }

        BlockingDecision::NotBlocked
    }

    pub fn total_blocked(&self) -> u64 {
        self.total_blocked as u64
    }

    pub fn adlist_count(&self) -> u64 {
        self.adlist_count as u64
    }

    // =====================================================================
    // Delta updates — used by the API for single-domain mutations so we
    // don't reload the entire gravity list (100k+ rows) per change (C2).
    // =====================================================================

    pub fn add_allow_domain(&mut self, domain: &str) {
        self.allowlist_exact.insert(domain.trim().to_lowercase());
    }

    pub fn remove_allow_domain(&mut self, domain: &str) {
        self.allowlist_exact.remove(domain.trim());
    }

    pub fn add_deny_domain(&mut self, domain: &str) {
        let d = domain.trim().to_lowercase();
        if self.denylist_exact.insert(d) {
            self.total_blocked += 1;
        }
    }

    pub fn remove_deny_domain(&mut self, domain: &str) {
        if self.denylist_exact.remove(domain.trim()).is_some() {
            self.total_blocked = self.total_blocked.saturating_sub(1);
        }
    }

    pub fn add_gravity_domain(&mut self, domain: &str) {
        let d = domain.trim().to_lowercase();
        if self.gravity_exact.insert(d) {
            self.total_blocked += 1;
        }
    }

    pub fn remove_gravity_domain(&mut self, domain: &str) {
        if self.gravity_exact.remove(domain.trim()).is_some() {
            self.total_blocked = self.total_blocked.saturating_sub(1);
        }
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

    #[test]
    fn test_wildcard_matcher_basics() {
        let m = WildcardMatcher::default();
        m.insert("*.example.com");
        assert!(m.is_match("sub.example.com"));
        assert!(m.is_match("example.com"));
        assert!(!m.is_match("notexample.com"));
        assert!(!m.is_match("x.notexample.com"));
    }

    #[test]
    fn test_wildcard_matcher_multiple() {
        let m = WildcardMatcher::default();
        m.insert("*.tracker.io");
        m.insert("*.ads.cn");
        assert!(m.is_match("a.b.tracker.io"));
        assert!(m.is_match("deep.ads.cn"));
        assert!(!m.is_match("tracker.io.evil.com"));
        assert!(!m.is_match("safe.io"));
    }

    #[test]
    fn test_wildcard_matcher_bare_star() {
        let m = WildcardMatcher::default();
        m.insert("*foo.com");
        assert!(m.is_match("foo.com"), "apex should match *foo.com");
        assert!(m.is_match("sub.foo.com"), "subdomain should match *foo.com");
        assert!(!m.is_match("xfoo.com"), "should NOT match *foo.com");
        assert!(!m.is_match("other.foo.com.evil.com"), "should NOT match *foo.com");
    }

    #[test]
    fn test_wildcard_matcher_mixed_case() {
        let m = WildcardMatcher::default();
        m.insert("*.Example.COM");
        assert!(m.is_match("sub.example.com"), "mixed-case pattern should match lowercased query");
    }

    #[test]
    fn test_wildcard_matcher_bare_star_mixed_case() {
        // Cross-product: bare `*` + mixed case in one pattern
        let m = WildcardMatcher::default();
        m.insert("*Foo.COM");
        assert!(m.is_match("foo.com"), "apex should match *Foo.COM");
        assert!(m.is_match("sub.foo.com"), "subdomain should match *Foo.COM");
        assert!(!m.is_match("xfoo.com"), "should NOT match *Foo.COM");
        assert!(!m.is_match("foo.com.evil.net"), "should NOT match *Foo.COM");
    }

    #[test]
    fn test_wildcard_matcher_multi_label_suffix() {
        // Multi-label suffix: *.deep.example.co.uk
        let m = WildcardMatcher::default();
        m.insert("*.deep.example.co.uk");
        assert!(m.is_match("a.deep.example.co.uk"));
        assert!(m.is_match("deep.example.co.uk"), "apex of the pattern suffix matches");
        assert!(!m.is_match("example.co.uk"));
        assert!(!m.is_match("deep.example.co"));
    }

    // -- check_blocked integration: wildcard + ordering semantics ---------

    fn lists_with(
        allow_exact: &[&str],
        deny_exact: &[&str],
        gravity_domains: &[&str],
        wildcard: &[&str],
    ) -> BlockingLists {
        let allowlist_exact: DashSet<String> = DashSet::new();
        for d in allow_exact { allowlist_exact.insert(d.to_lowercase()); }
        let denylist_exact: DashSet<String> = DashSet::new();
        for d in deny_exact { denylist_exact.insert(d.to_lowercase()); }
        let gravity_exact: DashSet<String> = DashSet::new();
        for d in gravity_domains { gravity_exact.insert(d.to_lowercase()); }
        let wildcard_deny = WildcardMatcher::default();
        for w in wildcard { wildcard_deny.insert(w); }
        // Match production `BlockingLists::load`: wildcards + deny regexes count
        let total_blocked = gravity_exact.len() + denylist_exact.len() + wildcard.len();
        BlockingLists {
            allowlist_exact,
            denylist_exact,
            allowlist_regex: Vec::new(),
            denylist_regex: Vec::new(),
            gravity_exact,
            wildcard_deny,
            total_blocked,
            adlist_count: 0,
        }
    }

    #[test]
    fn test_check_blocked_wildcard_blocks_subdomains() {
        let lists = lists_with(&[], &[], &[], &["*.ads.example.com"]);
        assert_eq!(lists.check_blocked("ads.example.com"), BlockingDecision::Blocked("wildcard".into()));
        assert_eq!(lists.check_blocked("banner.ads.example.com"), BlockingDecision::Blocked("wildcard".into()));
        assert_eq!(lists.check_blocked("safe.example.com"), BlockingDecision::NotBlocked);
        // total_blocked must include the wildcard (B8)
        assert_eq!(lists.total_blocked(), 1);
    }

    #[test]
    fn test_total_blocked_counts_wildcards() {
        // 2 exact gravity + 3 wildcards + 2 exact deny = 7
        let lists = lists_with(&[], &["d1.com", "d2.com"], &["g1.com", "g2.com"],
            &["*.w1.com", "*.w2.com", "*.w3.com"]);
        assert_eq!(lists.total_blocked(), 7);
    }

    #[test]
    fn test_delta_deny_add_remove() {
        let mut lists = lists_with(&[], &[], &[], &[]);
        // Add a deny domain → blocked, total increments
        lists.add_deny_domain("ads.example.com");
        assert_eq!(lists.check_blocked("ads.example.com"), BlockingDecision::Blocked("exact".into()));
        assert_eq!(lists.total_blocked(), 1);
        // Remove → unblocked, total decrements
        lists.remove_deny_domain("ads.example.com");
        assert_eq!(lists.check_blocked("ads.example.com"), BlockingDecision::NotBlocked);
        assert_eq!(lists.total_blocked(), 0);
    }

    #[test]
    fn test_delta_gravity_add_remove() {
        let mut lists = lists_with(&[], &[], &[], &[]);
        lists.add_gravity_domain("tracker.example.com");
        assert_eq!(lists.check_blocked("tracker.example.com"), BlockingDecision::Blocked("gravity".into()));
        assert_eq!(lists.total_blocked(), 1);
        lists.remove_gravity_domain("tracker.example.com");
        assert_eq!(lists.check_blocked("tracker.example.com"), BlockingDecision::NotBlocked);
        assert_eq!(lists.total_blocked(), 0);
    }

    #[test]
    fn test_delta_allowlist_wins() {
        let mut lists = lists_with(&[], &[], &["blocked.example.com"], &[]);
        // Deny + allowlist the same domain → allowlist wins
        lists.add_deny_domain("blocked.example.com");
        lists.add_allow_domain("blocked.example.com");
        assert_eq!(lists.check_blocked("blocked.example.com"), BlockingDecision::Allowlisted);
        // Remove from allowlist → blocked again
        lists.remove_allow_domain("blocked.example.com");
        assert_eq!(lists.check_blocked("blocked.example.com"), BlockingDecision::Blocked("exact".into()));
    }

    #[test]
    fn test_check_blocked_allowlist_wins_over_wildcard_and_gravity() {
        // allowlist must win even when the domain is also a wildcard/gravity hit
        let lists = lists_with(&["safe.example.com"], &[], &["safe.example.com"], &["*.example.com"]);
        assert_eq!(lists.check_blocked("safe.example.com"), BlockingDecision::Allowlisted);
    }

    #[test]
    fn test_check_blocked_gravity_exact_blocks_before_deny_regex() {
        // gravity exact hit is reported before any regex scan (exact-first order)
        let lists = lists_with(&[], &[], &["tracker.example.com"], &[]);
        assert_eq!(lists.check_blocked("tracker.example.com"), BlockingDecision::Blocked("gravity".into()));
        assert_eq!(lists.check_blocked("tracker.example.net"), BlockingDecision::NotBlocked);
    }

    #[test]
    fn test_check_blocked_order_deny_exact_before_gravity() {
        // deny-exact reported before gravity-exact when both match
        let lists = lists_with(&[], &["both.example.com"], &["both.example.com"], &[]);
        assert_eq!(lists.check_blocked("both.example.com"), BlockingDecision::Blocked("exact".into()));
    }

    // ── reload: picks up new gravity domains from the DB ──────────────────

    #[test]
    fn test_reload_picks_up_new_gravity_domains() {
        use crate::database::gravity::GravityDb;
        use std::path::Path;

        let db = GravityDb::open(Path::new(":memory:"), 1000).unwrap();
        db.add_gravity_domain("before.example.com").unwrap();
        let cfg = crate::config::Config::default();
        let engine = BlockingEngine::load(&db, &cfg).unwrap();
        assert!(engine.is_blocked("before.example.com"));
        assert!(!engine.is_blocked("after.example.com"));

        // Add a domain after load and reload → the running engine must block it
        db.add_gravity_domain("after.example.com").unwrap();
        engine.reload(&db).unwrap();
        assert!(engine.is_blocked("after.example.com"), "reload must pick up new domains");
        assert!(engine.is_blocked("before.example.com"), "existing domains must survive reload");
    }
}
