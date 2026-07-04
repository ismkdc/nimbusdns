// =============================================================================
// DNS Response Cache — LRU with TTL expiration
// =============================================================================

use std::collections::VecDeque;
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

/// DNS cache with LRU eviction
pub struct DnsCache {
    entries: DashMap<CacheKey, CachedResponse>,
    max_entries: usize,
    /// Eviction queue: when accessed, key is moved to back (LRU)
    eviction_queue: parking_lot::Mutex<VecDeque<CacheKey>>,
    total_hits: AtomicU64,
    total_misses: AtomicU64,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        debug!("DNS cache initialized (max {} entries, LRU)", max_entries);
        Self {
            entries: DashMap::new(),
            max_entries,
            eviction_queue: parking_lot::Mutex::new(VecDeque::new()),
            total_hits: AtomicU64::new(0),
            total_misses: AtomicU64::new(0),
        }
    }

    pub fn get(&self, key: &CacheKey) -> Option<CachedResponse> {
        let entry = self.entries.get(key)?;

        if entry.is_expired() {
            drop(entry);
            self.entries.remove(key);
            self.total_misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        entry.record_hit();
        self.total_hits.fetch_add(1, Ordering::Relaxed);

        // LRU: remove from current position and push to back
        let mut queue = self.eviction_queue.lock();
        if let Some(pos) = queue.iter().position(|k| k == key) {
            queue.remove(pos);
            queue.push_back(key.clone());
        }

        Some(entry.value().clone())
    }

    pub fn insert(&self, key: CacheKey, response: CachedResponse) {
        // LRU: remove old entry if exists
        if self.entries.contains_key(&key) {
            self.entries.remove(&key);
        }

        // Evict oldest if at capacity
        while self.entries.len() >= self.max_entries {
            self.evict_one();
        }

        // Track in eviction queue (most recently used = back)
        let mut queue = self.eviction_queue.lock();
        queue.push_back(key.clone());

        self.entries.insert(key, response);
    }

    fn evict_one(&self) {
        let key = self.eviction_queue.lock().pop_front();
        if let Some(key) = key {
            self.entries.remove(&key);
            trace!("Evicted LRU cache entry");
        }
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
        self.eviction_queue.lock().clear();
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
