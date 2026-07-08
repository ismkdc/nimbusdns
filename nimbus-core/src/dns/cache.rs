// =============================================================================
// DNS Response Cache - TTL-based expiration with O(1) get
// =============================================================================

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::{debug, trace};

/// A cached DNS response
#[derive(Debug)]
pub struct CachedResponse {
    /// The raw DNS response bytes (shared, cheap clone)
    pub data: Arc<[u8]>,
    /// When this entry was cached
    pub cached_at: Instant,
    /// Original TTL from the response (seconds)
    pub original_ttl: u32,
    /// Current effective TTL (may be adjusted)
    pub ttl: u32,
    /// Query type (A, AAAA, etc.)
    pub qtype: u16,
    /// Query class (IN = 1)
    pub qclass: u16,
    /// Number of times this cache entry was hit
    pub hits: AtomicU64,
}

impl Clone for CachedResponse {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            cached_at: self.cached_at,
            original_ttl: self.original_ttl,
            ttl: self.ttl,
            qtype: self.qtype,
            qclass: self.qclass,
            hits: AtomicU64::new(self.hits.load(Ordering::Relaxed)),
        }
    }
}

impl CachedResponse {
    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > Duration::from_secs(self.ttl as u64)
    }

    pub fn remaining_ttl(&self) -> Duration {
        let max = Duration::from_secs(self.ttl as u64);
        max.saturating_sub(self.cached_at.elapsed())
    }

    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }
}

/// DNS cache key
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CacheKey {
    pub domain: String,
    pub qtype: u16,
    pub qclass: u16,
    pub dnssec_ok: bool,
    pub ecs_subnet: Option<u32>,
}

/// DNS cache with TTL-based expiration and O(1) get.
/// No LRU queue maintenance on hot path - only periodic cleanup during insert.
pub struct DnsCache {
    entries: DashMap<CacheKey, CachedResponse>,
    max_entries: usize,
    total_hits: AtomicU64,
    total_misses: AtomicU64,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        debug!("DNS cache initialized (max {} entries, TTL eviction)", max_entries);
        Self {
            entries: DashMap::new(),
            max_entries,
            total_hits: AtomicU64::new(0),
            total_misses: AtomicU64::new(0),
        }
    }

    /// O(1) lookup - no LRU queue maintenance on hot path
    pub fn get(&self, key: &CacheKey) -> Option<CachedResponse> {
        let entry = self.entries.get(key)?;

        if entry.is_expired() {
            let key = entry.key().clone();
            drop(entry);
            self.entries.remove(&key);
            self.total_misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        entry.record_hit();
        self.total_hits.fetch_add(1, Ordering::Relaxed);
        Some(entry.value().clone())
    }

    /// Insert a new entry, evicting expired + oldest entries if over capacity
    pub fn insert(&self, key: CacheKey, response: CachedResponse) {
        // Remove old entry if exists (O(1) in DashMap)
        self.entries.remove(&key);

        // Evict expired entries and oldest if still over capacity
        if self.entries.len() >= self.max_entries {
            // Phase 1: remove all expired entries (O(n), rare)
            let expired: Vec<CacheKey> = self.entries.iter()
                .filter(|e| e.value().is_expired())
                .map(|e| e.key().clone())
                .collect();
            for k in expired {
                self.entries.remove(&k);
            }
        }

        // Phase 2: if still over capacity, remove oldest by cached_at
        if self.entries.len() >= self.max_entries {
            let mut oldest: Option<(CacheKey, Instant)> = None;
            for e in self.entries.iter() {
                let ca = e.value().cached_at;
                if oldest.as_ref().is_none_or(|(_, oa)| ca < *oa) {
                    oldest = Some((e.key().clone(), ca));
                }
            }
            if let Some((k, _)) = oldest {
                self.entries.remove(&k);
                trace!("Evicted oldest cache entry");
            }
        }

        self.entries.insert(key, response);
    }

    pub fn remove_domain(&self, domain: &str) -> usize {
        let keys: Vec<CacheKey> = self.entries.iter()
            .filter(|e| e.key().domain == domain)
            .map(|e| e.key().clone())
            .collect();
        let count = keys.len();
        for key in keys {
            self.entries.remove(&key);
        }
        count
    }

    pub fn clear(&self) {
        self.entries.clear();
        debug!("DNS cache cleared");
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            entries: self.entries.len(),
            hits: self.total_hits.load(Ordering::Relaxed),
            misses: self.total_misses.load(Ordering::Relaxed),
            max_entries: self.max_entries,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CacheStats {
    pub entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub max_entries: usize,
}

// =============================================================================
// Tests
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn make_key(domain: &str) -> CacheKey {
        CacheKey {
            domain: domain.to_string(),
            qtype: 1,   // A
            qclass: 1,  // IN
            dnssec_ok: false,
            ecs_subnet: None,
        }
    }

    fn make_response(ttl: u32) -> CachedResponse {
        CachedResponse {
            data: Arc::from(vec![0u8; 16]),
            cached_at: Instant::now(),
            original_ttl: ttl,
            ttl,
            qtype: 1,
            qclass: 1,
            hits: AtomicU64::new(0),
        }
    }

    // ── Test 14: insert → get hit, hits counter increments ──────────────
    #[test]
    fn test_insert_get_hit() {
        let cache = DnsCache::new(10);
        let key = make_key("example.com");
        let resp = make_response(60);
        cache.insert(key.clone(), resp);
        let got = cache.get(&key);
        assert!(got.is_some());
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 0);
    }

    // ── Test 15: miss on missing key → None ─────────────────────────────
    #[test]
    fn test_miss() {
        let cache = DnsCache::new(10);
        let key = make_key("missing.com");
        let got = cache.get(&key);
        assert!(got.is_none());
        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        // Misses only increment for expired entries, not non-existent keys
        assert_eq!(stats.misses, 0);
    }

    // ── Test 16: ttl=0 → is_expired, get → None, entry evicted ─────────
    #[test]
    fn test_expired_ttl_zero() {
        let cache = DnsCache::new(10);
        let key = make_key("gone.com");
        // TTL = 0 means already expired
        let resp = CachedResponse {
            data: Arc::from(vec![0u8; 16]),
            cached_at: Instant::now() - Duration::from_secs(1), // cached 1s ago
            original_ttl: 0,
            ttl: 0,
            qtype: 1,
            qclass: 1,
            hits: AtomicU64::new(0),
        };
        cache.insert(key.clone(), resp);
        // Get should return None and remove the entry
        let got = cache.get(&key);
        assert!(got.is_none());
        // Entry should be gone
        assert_eq!(cache.len(), 0);
    }

    // ── Test 17: remaining_ttl saturating (past → 0) ────────────────────
    #[test]
    fn test_remaining_ttl_saturating() {
        let resp = CachedResponse {
            data: Arc::from(vec![0u8; 16]),
            cached_at: Instant::now() - Duration::from_secs(10), // cached 10s ago
            original_ttl: 5,   // TTL was 5s, so expired
            ttl: 5,
            qtype: 1,
            qclass: 1,
            hits: AtomicU64::new(0),
        };
        // remaining_ttl should saturate to 0, not underflow
        assert_eq!(resp.remaining_ttl(), Duration::from_secs(0));
        assert!(resp.is_expired());
    }

    // ── Test 18: max_entries=2, insert 3 → oldest evicted, len ≤ 2 ─────
    #[test]
    fn test_max_entries_eviction() {
        let cache = DnsCache::new(2);
        let k1 = make_key("first.com");
        let k2 = make_key("second.com");
        let k3 = make_key("third.com");

        cache.insert(k1.clone(), make_response(60));
        cache.insert(k2.clone(), make_response(60));
        assert_eq!(cache.len(), 2);

        cache.insert(k3.clone(), make_response(60));
        // Should have evicted one (oldest) to stay at 2
        assert!(cache.len() <= 2);
        // third.com must be present
        assert!(cache.get(&k3).is_some());
    }

    // ── Test 19: remove_domain matches and returns count ────────────────
    #[test]
    fn test_remove_domain() {
        let cache = DnsCache::new(10);
        cache.insert(make_key("test.com"), make_response(60));
        cache.insert(make_key("test.com"), make_response(60)); // same key (A + IN)
        cache.insert(make_key("other.com"), make_response(60));
        // test.com has 1 unique key (second insert overwrites)
        assert_eq!(cache.len(), 2);
        let removed = cache.remove_domain("test.com");
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 1);
    }

    // ── Test 20: same key twice → single entry, last data wins ─────────
    #[test]
    fn test_reinsert_same_key() {
        let cache = DnsCache::new(10);
        let key = make_key("dup.com");

        let r1 = CachedResponse {
            data: Arc::from(b"first response".to_vec()),
            ..make_response(60)
        };
        cache.insert(key.clone(), r1);

        let r2 = CachedResponse {
            data: Arc::from(b"second response".to_vec()),
            ..make_response(60)
        };
        cache.insert(key.clone(), r2);

        assert_eq!(cache.len(), 1);
        let got = cache.get(&key).unwrap();
        assert_eq!(&*got.data, b"second response");
    }
}
