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
                if oldest.as_ref().map_or(true, |(_, oa)| ca < *oa) {
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
