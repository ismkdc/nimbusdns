// =============================================================================
// overTime - In-Memory Time-Based Query Statistics
// =============================================================================
// Ported from original C (src/overTime.c, ~252 lines)
//
// Maintains a circular buffer of 10-minute time buckets covering the last
// 24 hours (144 buckets). Each bucket tracks total/blocked/cached/forwarded
// query counts. Also tracks per-client overTime data.
//
// This provides fast, real-time data for `/api/history` without DB queries.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};

use parking_lot::RwLock;
use serde::Serialize;

use crate::database::queries::QueryStatus;

// Number of 10-minute slots in 24 hours
const HISTORY_SLOTS: usize = 144;
// 10 minutes in seconds
const SLOT_INTERVAL: i64 = 600;

/// A single time bucket of query counts
#[derive(Debug, Clone, Copy, Serialize)]
#[derive(Default)]
pub struct TimeSlot {
    pub timestamp: i64,
    pub total: u64,
    pub blocked: u64,
    pub cached: u64,
    pub forwarded: u64,
}


/// Per-client overTime tracking
#[derive(Debug, Clone)]
struct ClientHistory {
    slots: Vec<TimeSlot>,
    last_slot_idx: usize,
}

/// The overTime engine
pub struct OverTime {
    /// Circular buffer of time slots (indexed by slot number % HISTORY_SLOTS)
    slots: RwLock<Vec<TimeSlot>>,
    /// The slot index that was last written to
    last_slot_idx: RwLock<usize>,
    /// Per-client history
    client_histories: RwLock<HashMap<String, ClientHistory>>,
    /// Total queries counter (atomic for fast read)
    total_queries: AtomicI64,
    /// Start time of the process (for uptime)
    start_time: std::time::Instant,
}

impl OverTime {
    /// Create a new overTime engine
    pub fn new() -> Self {
        Self {
            slots: RwLock::new(vec![TimeSlot::default(); HISTORY_SLOTS]),
            last_slot_idx: RwLock::new(0),
            client_histories: RwLock::new(HashMap::new()),
            total_queries: AtomicI64::new(0),
            start_time: std::time::Instant::now(),
        }
    }

    /// Get the current slot index for a given timestamp
    fn slot_index(timestamp: i64) -> usize {
        ((timestamp / SLOT_INTERVAL) as usize) % HISTORY_SLOTS
    }

    /// Get the slot timestamp (start of the 10-min window)
    fn slot_timestamp(timestamp: i64) -> i64 {
        (timestamp / SLOT_INTERVAL) * SLOT_INTERVAL
    }

    /// Record a DNS query result
    pub fn record_query(&self, timestamp: i64, client: Option<&str>, status: QueryStatus) {
        let slot_ts = Self::slot_timestamp(timestamp);
        let idx = Self::slot_index(timestamp);

        // Update total counter
        self.total_queries.fetch_add(1, Ordering::Relaxed);

        // Update the main slot
        {
            let mut slots = self.slots.write();
            let slot = &mut slots[idx];

            // If this slot has a different timestamp, reset it
            if slot.timestamp != slot_ts {
                *slot = TimeSlot {
                    timestamp: slot_ts,
                    ..Default::default()
                };
            }

            slot.total += 1;
            match status {
                QueryStatus::Blocked => slot.blocked += 1,
                QueryStatus::Cached => slot.cached += 1,
                QueryStatus::Forwarded => slot.forwarded += 1,
                _ => {}
            }
        }

        // Track last slot index
        {
            let mut last_idx = self.last_slot_idx.write();
            *last_idx = idx;
        }

        // Update per-client history
        if let Some(client_ip) = client {
            let mut clients = self.client_histories.write();
            let client_data = clients.entry(client_ip.to_string()).or_insert_with(|| ClientHistory {
                slots: vec![TimeSlot::default(); HISTORY_SLOTS],
                last_slot_idx: 0,
            });

            let cslot = &mut client_data.slots[idx];
            if cslot.timestamp != slot_ts {
                *cslot = TimeSlot {
                    timestamp: slot_ts,
                    ..Default::default()
                };
            }
            cslot.total += 1;
            match status {
                QueryStatus::Blocked => cslot.blocked += 1,
                QueryStatus::Cached => cslot.cached += 1,
                QueryStatus::Forwarded => cslot.forwarded += 1,
                _ => {}
            }
            client_data.last_slot_idx = idx;
        }
    }

    /// Get the current time slot's timestamp (for syncing)
    pub fn current_slot_timestamp(&self) -> i64 {
        Self::slot_timestamp(chrono::Utc::now().timestamp())
    }

    /// Get history slots for the last N intervals (default 24 hours = 144 slots)
    pub fn get_history(&self) -> Vec<TimeSlot> {
        let now = chrono::Utc::now().timestamp();
        let current_slot = Self::slot_timestamp(now);
        let current_idx = Self::slot_index(now);

        let slots = self.slots.read();
        let mut result = Vec::with_capacity(HISTORY_SLOTS);

        // Walk backwards from current slot to cover 24 hours
        for i in 0..HISTORY_SLOTS {
            let idx = (current_idx + HISTORY_SLOTS - i) % HISTORY_SLOTS;
            let slot = slots[idx];

            // Only include slots within the last 24 hours
            if slot.timestamp > 0 && current_slot - slot.timestamp <= 24 * 3600 {
                result.push(slot);
            }
        }

        // Sort by timestamp ascending
        result.sort_by_key(|a| a.timestamp);
        result
    }

    /// Get per-client history for a specific client IP
    pub fn get_client_history(&self, client_ip: &str) -> Vec<TimeSlot> {
        let now = chrono::Utc::now().timestamp();
        let current_slot = Self::slot_timestamp(now);
        let current_idx = Self::slot_index(now);

        let clients = self.client_histories.read();
        let Some(client_data) = clients.get(client_ip) else {
            return Vec::new();
        };

        let mut result = Vec::with_capacity(HISTORY_SLOTS);
        for i in 0..HISTORY_SLOTS {
            let idx = (current_idx + HISTORY_SLOTS - i) % HISTORY_SLOTS;
            let slot = client_data.slots[idx];
            if slot.timestamp > 0 && current_slot - slot.timestamp <= 24 * 3600 {
                result.push(slot);
            }
        }

        result.sort_by_key(|a| a.timestamp);
        result
    }

    /// Get total queries count
    pub fn total_queries(&self) -> i64 {
        self.total_queries.load(Ordering::Relaxed)
    }

    /// Get uptime in seconds
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Clear all data (for testing / flush)
    pub fn clear(&self) {
        let mut slots = self.slots.write();
        for slot in slots.iter_mut() {
            *slot = TimeSlot::default();
        }
        self.client_histories.write().clear();
        self.total_queries.store(0, Ordering::Relaxed);
    }
}

impl Default for OverTime {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_timestamp() {
        // 2024-01-15 12:34:56 UTC
        let ts = 1705322096;
        let slot = OverTime::slot_timestamp(ts);
        // Should be 12:30:00 = 1705321800
        assert_eq!(slot, 1705321800);
        assert_eq!(slot % SLOT_INTERVAL, 0);
    }

    #[test]
    fn test_record_and_retrieve() {
        let ot = OverTime::new();
        let now = chrono::Utc::now().timestamp();

        // Record a few queries
        ot.record_query(now, Some("192.168.1.1"), QueryStatus::Forwarded);
        ot.record_query(now, Some("192.168.1.1"), QueryStatus::Blocked);
        ot.record_query(now, Some("192.168.1.2"), QueryStatus::Cached);

        let history = ot.get_history();
        assert!(!history.is_empty(), "Should have at least one slot");

        let last = history.last().unwrap();
        assert_eq!(last.total, 3);
        assert_eq!(last.blocked, 1);
        assert_eq!(last.cached, 1);
        assert_eq!(last.forwarded, 1);

        // Check per-client
        let client1 = ot.get_client_history("192.168.1.1");
        let last_c1 = client1.last().unwrap();
        assert_eq!(last_c1.total, 2);
        assert_eq!(last_c1.blocked, 1);
        assert_eq!(last_c1.forwarded, 1);
    }

    #[test]
    fn test_clear() {
        let ot = OverTime::new();
        let now = chrono::Utc::now().timestamp();
        ot.record_query(now, None, QueryStatus::Forwarded);
        assert_eq!(ot.total_queries(), 1);

        ot.clear();
        assert_eq!(ot.total_queries(), 0);
        assert!(ot.get_history().is_empty() || ot.get_history().iter().all(|s| s.total == 0));
    }
}
