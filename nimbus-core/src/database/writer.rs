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

/// The background database writer handle
#[derive(Clone)]
pub struct DbWriter {
    sender: mpsc::UnboundedSender<StoredQuery>,
}

impl DbWriter {
    /// Queue a query to be written to the database asynchronously.
    /// Returns an error if the background task has stopped.
    pub fn store(&self, query: StoredQuery) -> Result<(), DatabaseError> {
        self.sender.send(query).map_err(|_| {
            DatabaseError::Migration("Database writer task stopped".into())
        })
    }
}

/// Start the background database writer task.
/// Returns a `DbWriter` handle and the background task's join handle.
pub fn start(db: Arc<QueryDb>, shutdown_rx: tokio::sync::watch::Receiver<bool>) -> DbWriter {
    let (tx, mut rx) = mpsc::unbounded_channel::<StoredQuery>();

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
                                flush_batch(&db, &mut batch);
                            }
                        }
                        None => {
                            // Channel closed, flush remaining and exit
                            if !batch.is_empty() {
                                flush_batch(&db, &mut batch);
                            }
                            info!("Background database writer stopped");
                            break;
                        }
                    }
                }
                // Timer-based flush (for low-traffic periods)
                _ = flush_timer.tick() => {
                    if !batch.is_empty() {
                        flush_batch(&db, &mut batch);
                    }
                }
                // Shutdown signal
                _ = shutdown.changed() => {
                    if !batch.is_empty() {
                        flush_batch(&db, &mut batch);
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
fn flush_batch(db: &QueryDb, batch: &mut Vec<StoredQuery>) {
    if batch.is_empty() {
        return;
    }
    let count = batch.len();

    if let Err(e) = db.store_query_batch(batch) {
        error!("Failed to write {} queries: {}", count, e);
    } else {
        debug!("Wrote {} queries to database", count);
    }

    batch.clear();
}
