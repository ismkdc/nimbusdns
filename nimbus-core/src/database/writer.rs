// =============================================================================
// Background Database Writer
// =============================================================================
// Moves `store_query` out of the DNS hot path into a background task.
// Queries are batched and committed with a transaction every 100ms or
// every 100 queries (whichever comes first).
//
// This reduces DNS response latency by removing SQLite write I/O from
// the request processing path.

use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, error, info};

use super::queries::StoredQuery;
use super::{DatabaseError, QueryDb};

/// Maximum batch size before forcing a flush
const BATCH_SIZE: usize = 100;
/// Maximum time between flushes (milliseconds)
const FLUSH_INTERVAL_MS: u64 = 100;
/// Maximum queue depth before `store` returns an error (backpressure)
const CHANNEL_BOUND: usize = 4096;

/// The background database writer handle
#[derive(Clone)]
pub struct DbWriter {
    sender: mpsc::Sender<StoredQuery>,
}

impl DbWriter {
    /// Queue a query to be written to the database asynchronously.
    /// Returns an error if the queue is full (backpressure) or the task stopped.
    pub fn store(&self, query: StoredQuery) -> Result<(), DatabaseError> {
        self.sender.try_send(query).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => {
                DatabaseError::Migration("Database writer queue full".into())
            }
            mpsc::error::TrySendError::Closed(_) => {
                DatabaseError::Migration("Database writer task stopped".into())
            }
        })
    }
}

/// Start the background database writer task.
/// Returns a `DbWriter` handle and the background task's join handle.
pub fn start(db: Arc<QueryDb>, shutdown_rx: tokio::sync::watch::Receiver<bool>) -> DbWriter {
    let (tx, mut rx) = mpsc::channel::<StoredQuery>(CHANNEL_BOUND);

    tokio::spawn(async move {
        info!("Background database writer started");

        let mut batch: Vec<StoredQuery> = Vec::with_capacity(BATCH_SIZE);
        let mut flush_timer = tokio::time::interval(tokio::time::Duration::from_millis(FLUSH_INTERVAL_MS));
        let mut shutdown = shutdown_rx;

        loop {
            tokio::select! {
                // Receive a query
                query = rx.recv() => {
                    match query {
                        Some(q) => {
                            batch.push(q);
                            if batch.len() >= BATCH_SIZE {
                                flush_batch(db.clone(), &mut batch);
                            }
                        }
                        None => {
                            // Channel closed, flush remaining and exit
                            if !batch.is_empty() {
                                flush_batch(db.clone(), &mut batch);
                            }
                            info!("Background database writer stopped");
                            break;
                        }
                    }
                }
                // Timer-based flush (for low-traffic periods)
                _ = flush_timer.tick() => {
                    if !batch.is_empty() {
                        flush_batch(db.clone(), &mut batch);
                    }
                }
                // Shutdown signal
                _ = shutdown.changed() => {
                    if !batch.is_empty() {
                        flush_batch(db.clone(), &mut batch);
                    }
                    info!("Background database writer shutting down");
                    break;
                }
            }
        }
    });

    DbWriter { sender: tx }
}

/// Flush a batch of queries to the database in a single transaction.
/// Runs on the blocking pool so the tokio worker thread is never blocked
/// by SQLite I/O. Always clears the batch — even on failure — so a failed
/// batch can never accumulate unbounded memory or retry forever.
fn flush_batch(db: Arc<QueryDb>, batch: &mut Vec<StoredQuery>) {
    if batch.is_empty() {
        return;
    }
    let count = batch.len();
    let to_write = std::mem::take(batch);
    tokio::task::spawn_blocking(move || {
        match db.store_query_batch(&to_write) {
            Ok(()) => debug!("Wrote {} queries to database", count),
            Err(e) => error!("Failed to write {} queries: {}", count, e),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::queries::{QueryStatus, StoredQuery};

    fn stored(timestamp: i64) -> StoredQuery {
        StoredQuery {
            timestamp,
            domain: format!("d{}.com", timestamp),
            client: Some("192.0.2.1".into()),
            forward: None,
            query_type: 1,
            status: QueryStatus::Forwarded,
            reply_time: None,
            reply_type: 0,
            flags: 0,
            interface: None,
            elapsed_ms: Some(1),
            adlist_id: None,
            cache_id: None,
            regex_id: None,
            upstream_id: None,
        }
    }

    #[test]
    fn test_store_query_batch_roundtrip() {
        let db = Arc::new(QueryDb::open(
            std::path::Path::new(":memory:"), 1000,
        ).unwrap());
        let queries = vec![stored(1), stored(2)];
        db.store_query_batch(&queries).unwrap();
        let stats = db.get_stats().unwrap();
        assert_eq!(stats.total, 2);
    }
}
