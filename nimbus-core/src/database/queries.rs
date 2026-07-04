// =============================================================================
// Query Database (query log, network table, sessions)
// =============================================================================

use std::path::Path;

use rusqlite::params;
use tracing::info;

use serde::Serialize;

use super::{DatabaseError, SafeConnection, run_migrations};

/// A counted item (domain, client, upstream) with count
#[derive(Debug, Clone, Serialize)]
pub struct CountedItem {
    pub name: String,
    pub count: i64,
}

/// Query type distribution entry
#[derive(Debug, Clone, Serialize)]
pub struct QueryTypeCount {
    pub query_type: i32,
    pub count: i64,
}

/// A recent blocked query
#[derive(Debug, Clone, Serialize)]
pub struct BlockedQuery {
    pub timestamp: i64,
    pub domain: String,
    pub client: Option<String>,
    pub forward: Option<String>,
    pub query_type: i32,
}

/// Query database manager
pub struct QueryDb {
    conn: SafeConnection,
}

impl QueryDb {
    /// Open the Query database
    pub fn open(path: &Path, busy_timeout: u64) -> Result<Self, DatabaseError> {
        let conn = SafeConnection::open(path, busy_timeout)?;

        // Run migrations
        conn.with_conn(|conn| run_migrations(conn))?;

        info!("Query database opened: {}", path.display());
        Ok(Self { conn })
    }

    /// Store a DNS query entry
    pub fn store_query(&self, query: StoredQuery) -> Result<i64, DatabaseError> {
        self.conn.with_conn(|conn| {
            conn.execute(
                "INSERT INTO queries (timestamp, dbl_domain, dbl_client, dbl_forward,
                 dbl_type, dbl_status, dbl_reply_time, dbl_reply_type, dbl_flags,
                 dbl_interface, dbl_elapsed_ms, dbl_adlist_id, dbl_cache_id,
                 dbl_regex_id, dbl_upstream_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    query.timestamp,
                    query.domain,
                    query.client,
                    query.forward,
                    query.query_type,
                    query.status as i32,
                    query.reply_time,
                    { query.reply_type },
                    query.flags,
                    query.interface,
                    query.elapsed_ms,
                    query.adlist_id,
                    query.cache_id,
                    query.regex_id,
                    query.upstream_id,
                ],
            )?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Store a batch of DNS query entries in a single transaction.
    pub fn store_query_batch(&self, queries: &[StoredQuery]) -> Result<(), DatabaseError> {
        if queries.is_empty() {
            return Ok(());
        }
        self.conn.with_conn(|conn| {
            let txn = conn.transaction()?;
            for query in queries {
                txn.execute(
                    "INSERT INTO queries (timestamp, dbl_domain, dbl_client, dbl_forward,
                     dbl_type, dbl_status, dbl_reply_time, dbl_reply_type, dbl_flags,
                     dbl_interface, dbl_elapsed_ms, dbl_adlist_id, dbl_cache_id,
                     dbl_regex_id, dbl_upstream_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    rusqlite::params![
                        query.timestamp,
                        query.domain,
                        query.client,
                        query.forward,
                        query.query_type,
                        query.status as i32,
                        query.reply_time,
                        query.reply_type as i32,
                        query.flags,
                        query.interface,
                        query.elapsed_ms,
                        query.adlist_id,
                        query.cache_id,
                        query.regex_id,
                        query.upstream_id,
                    ],
                )?;
            }
            txn.commit()?;
            Ok(())
        })
    }

    /// Delete queries older than max_age_secs, returns count of deleted rows
    pub fn delete_old_queries(&self, max_age_secs: i64) -> Result<i64, DatabaseError> {
        let cutoff = chrono::Utc::now().timestamp() - max_age_secs;

        self.conn.with_conn(|conn| {
            let count = conn.execute(
                "DELETE FROM queries WHERE timestamp < ?1",
                params![cutoff],
            )?;
            info!("Deleted {} old queries (cutoff: {})", count, cutoff);
            Ok(count as i64)
        })
    }

    /// Get query statistics
    pub fn get_stats(&self) -> Result<QueryStats, DatabaseError> {
        self.conn.with_conn(|conn| {
            let total: i64 = conn.query_row(
                "SELECT COUNT(*) FROM queries",
                [],
                |row| row.get(0),
            )?;

            let blocked: i64 = conn.query_row(
                "SELECT COUNT(*) FROM queries WHERE dbl_status = 1",
                [],
                |row| row.get(0),
            )?;

            let cached: i64 = conn.query_row(
                "SELECT COUNT(*) FROM queries WHERE dbl_status = 2",
                [],
                |row| row.get(0),
            )?;

            let forwarded: i64 = conn.query_row(
                "SELECT COUNT(*) FROM queries WHERE dbl_status = 3",
                [],
                |row| row.get(0),
            )?;

            Ok(QueryStats {
                total,
                blocked,
                cached,
                forwarded,
            })
        })
    }

    /// Run ANALYZE
    pub fn analyze(&self) -> Result<(), DatabaseError> {
        self.conn.analyze()
    }

    /// Get total number of queries today
    pub fn todays_queries(&self) -> Result<i64, DatabaseError> {
        let today = chrono::Utc::now().date_naive();
        let start_of_day = today.and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp();

        self.conn.with_conn(|conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM queries WHERE timestamp >= ?1",
                params![start_of_day],
                |row| row.get(0),
            )?;
            Ok(count)
        })
    }
}

/// A session entry for API authentication
#[derive(Debug, Clone, Serialize)]
pub struct Session {
    pub sid: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_used_at: Option<i64>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    #[serde(skip)]
    pub data: Option<Vec<u8>>,
}

impl QueryDb {
    /// Create a new session and return the SID
    pub fn create_session(&self, sid: &str, expires_at: i64, client_ip: Option<&str>,
                          user_agent: Option<&str>) -> Result<(), DatabaseError> {
        let now = chrono::Utc::now().timestamp();
        self.conn.with_conn(|conn| {
            conn.execute(
                "INSERT INTO sessions (sid, created_at, expires_at, last_used_at, client_ip, user_agent)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![sid, now, expires_at, now, client_ip, user_agent],
            )?;
            Ok(())
        })
    }

    /// Get a session by SID
    pub fn get_session(&self, sid: &str) -> Result<Option<Session>, DatabaseError> {
        self.conn.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT sid, created_at, expires_at, last_used_at, client_ip, user_agent, data
                 FROM sessions WHERE sid = ?1"
            )?;
            let mut rows = stmt.query(rusqlite::params![sid])?;
            match rows.next()? {
                Some(row) => Ok(Some(Session {
                    sid: row.get(0)?,
                    created_at: row.get(1)?,
                    expires_at: row.get(2)?,
                    last_used_at: row.get(3)?,
                    client_ip: row.get(4)?,
                    user_agent: row.get(5)?,
                    data: row.get(6)?,
                })),
                None => Ok(None),
            }
        })
    }

    /// Delete a session by SID
    pub fn delete_session(&self, sid: &str) -> Result<(), DatabaseError> {
        self.conn.with_conn(|conn| {
            conn.execute("DELETE FROM sessions WHERE sid = ?1", rusqlite::params![sid])?;
            Ok(())
        })
    }

    /// Update last_used_at for a session
    pub fn touch_session(&self, sid: &str) -> Result<(), DatabaseError> {
        let now = chrono::Utc::now().timestamp();
        self.conn.with_conn(|conn| {
            conn.execute(
                "UPDATE sessions SET last_used_at = ?1 WHERE sid = ?2",
                rusqlite::params![now, sid],
            )?;
            Ok(())
        })
    }

    /// Delete all expired sessions, returns count of deleted rows
    pub fn cleanup_expired_sessions(&self) -> Result<i64, DatabaseError> {
        let now = chrono::Utc::now().timestamp();
        self.conn.with_conn(|conn| {
            let count = conn.execute(
                "DELETE FROM sessions WHERE expires_at < ?1",
                rusqlite::params![now],
            )?;
            Ok(count as i64)
        })
    }

    /// Extend a session's expiry (for "remember me" / sliding expiry)
    pub fn refresh_session(&self, sid: &str, expires_at: i64) -> Result<(), DatabaseError> {
        let now = chrono::Utc::now().timestamp();
        self.conn.with_conn(|conn| {
            conn.execute(
                "UPDATE sessions SET expires_at = ?1, last_used_at = ?2 WHERE sid = ?3",
                rusqlite::params![expires_at, now, sid],
            )?;
            Ok(())
        })
    }

    // =========================================================================
    // Statistics Queries
    // =========================================================================

    /// Get top N domains by query count
    pub fn get_top_domains(&self, limit: usize) -> Result<Vec<CountedItem>, DatabaseError> {
        self.conn.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT dbl_domain, COUNT(*) as cnt FROM queries \
                 WHERE dbl_domain IS NOT NULL AND dbl_domain != '' \
                 GROUP BY dbl_domain ORDER BY cnt DESC LIMIT ?1"
            )?;
            let rows = stmt.query_map(rusqlite::params![limit as i64], |row| {
                Ok(CountedItem {
                    name: row.get(0)?,
                    count: row.get(1)?,
                })
            })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row?);
            }
            Ok(result)
        })
    }

    /// Get top N clients by query count
    pub fn get_top_clients(&self, limit: usize) -> Result<Vec<CountedItem>, DatabaseError> {
        self.conn.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT dbl_client, COUNT(*) as cnt FROM queries \
                 WHERE dbl_client IS NOT NULL AND dbl_client != '' \
                 GROUP BY dbl_client ORDER BY cnt DESC LIMIT ?1"
            )?;
            let rows = stmt.query_map(rusqlite::params![limit as i64], |row| {
                Ok(CountedItem {
                    name: row.get(0)?,
                    count: row.get(1)?,
                })
            })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row?);
            }
            Ok(result)
        })
    }

    /// Get top N upstreams by query count
    pub fn get_top_upstreams(&self, limit: usize) -> Result<Vec<CountedItem>, DatabaseError> {
        self.conn.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT dbl_forward, COUNT(*) as cnt FROM queries \
                 WHERE dbl_forward IS NOT NULL AND dbl_forward != '' \
                 GROUP BY dbl_forward ORDER BY cnt DESC LIMIT ?1"
            )?;
            let rows = stmt.query_map(rusqlite::params![limit as i64], |row| {
                Ok(CountedItem {
                    name: row.get(0)?,
                    count: row.get(1)?,
                })
            })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row?);
            }
            Ok(result)
        })
    }

    /// Get query type distribution
    pub fn get_query_type_distribution(&self) -> Result<Vec<QueryTypeCount>, DatabaseError> {
        self.conn.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT dbl_type, COUNT(*) as cnt FROM queries \
                 WHERE dbl_type IS NOT NULL \
                 GROUP BY dbl_type ORDER BY cnt DESC"
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(QueryTypeCount {
                    query_type: row.get(0)?,
                    count: row.get(1)?,
                })
            })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row?);
            }
            Ok(result)
        })
    }

    /// Get N most recently blocked queries
    pub fn get_recent_blocked(&self, limit: usize) -> Result<Vec<BlockedQuery>, DatabaseError> {
        self.conn.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT timestamp, dbl_domain, dbl_client, dbl_forward, dbl_type \
                 FROM queries WHERE dbl_status = 1 \
                 ORDER BY timestamp DESC LIMIT ?1"
            )?;
            let rows = stmt.query_map(rusqlite::params![limit as i64], |row| {
                Ok(BlockedQuery {
                    timestamp: row.get(0)?,
                    domain: row.get(1)?,
                    client: row.get(2)?,
                    forward: row.get(3)?,
                    query_type: row.get(4)?,
                })
            })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row?);
            }
            Ok(result)
        })
    }
}

/// Filter parameters for query log queries
#[derive(Debug, Default, Clone)]
pub struct QueryFilter {
    pub domain: Option<String>,
    pub client: Option<String>,
    pub status: Option<i32>,
    pub from: Option<i64>,
    pub until: Option<i64>,
    pub limit: i64,
    pub offset: i64,
}

/// A query log entry returned to the API
#[derive(Debug, Clone, Serialize)]
pub struct QueryLogEntry {
    pub id: i64,
    pub timestamp: i64,
    pub domain: String,
    pub client: Option<String>,
    pub forward: Option<String>,
    pub query_type: i32,
    pub status: i32,
    pub reply_time: Option<i64>,
    pub elapsed_ms: Option<i64>,
}

/// A 10-minute history slot
#[derive(Debug, Clone, Serialize)]
pub struct HistorySlot {
    pub timestamp: i64,
    pub total: i64,
    pub blocked: i64,
    pub cached: i64,
    pub forwarded: i64,
}

impl QueryDb {
    /// Get query log entries with filters and pagination.
    /// Returns (entries, total_count).
    pub fn get_queries(&self, filter: &QueryFilter) -> Result<(Vec<QueryLogEntry>, i64), DatabaseError> {
        self.conn.with_conn(|conn| {
            // Build WHERE clause dynamically
            let mut conditions = Vec::new();
            let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

            if let Some(ref domain) = filter.domain {
                conditions.push(format!("dbl_domain LIKE ?{}", param_values.len() + 1));
                param_values.push(Box::new(format!("%{}%", domain)));
            }
            if let Some(ref client) = filter.client {
                conditions.push(format!("dbl_client LIKE ?{}", param_values.len() + 1));
                param_values.push(Box::new(format!("%{}%", client)));
            }
            if let Some(status) = filter.status {
                conditions.push(format!("dbl_status = ?{}", param_values.len() + 1));
                param_values.push(Box::new(status));
            }
            if let Some(from) = filter.from {
                conditions.push(format!("timestamp >= ?{}", param_values.len() + 1));
                param_values.push(Box::new(from));
            }
            if let Some(until) = filter.until {
                conditions.push(format!("timestamp <= ?{}", param_values.len() + 1));
                param_values.push(Box::new(until));
            }

            let where_clause = if conditions.is_empty() {
                String::new()
            } else {
                format!("WHERE {}", conditions.join(" AND "))
            };

            // Count total matching rows
            let count_sql = format!("SELECT COUNT(*) FROM queries {}", where_clause);
            let count: i64 = {
                let mut stmt = conn.prepare(&count_sql)?;
                let params_refs: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();
                stmt.query_row(params_refs.as_slice(), |row| row.get(0))?
            };

            // Fetch paginated results
            let query_sql = format!(
                "SELECT id, timestamp, dbl_domain, dbl_client, dbl_forward, \
                 dbl_type, dbl_status, dbl_reply_time, dbl_elapsed_ms \
                 FROM queries {} ORDER BY timestamp DESC LIMIT ?{} OFFSET ?{}",
                where_clause,
                param_values.len() + 1,
                param_values.len() + 2,
            );

            let mut stmt = conn.prepare(&query_sql)?;
            let mut all_params: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();
            all_params.push(&filter.limit);
            all_params.push(&filter.offset);

            let rows = stmt.query_map(all_params.as_slice(), |row| {
                Ok(QueryLogEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    domain: row.get(2)?,
                    client: row.get(3)?,
                    forward: row.get(4)?,
                    query_type: row.get(5)?,
                    status: row.get(6)?,
                    reply_time: row.get(7)?,
                    elapsed_ms: row.get(8)?,
                })
            })?;

            let mut entries = Vec::new();
            for row in rows {
                entries.push(row?);
            }

            Ok((entries, count))
        })
    }

    /// Get 24-hour query history in 10-minute buckets.
    pub fn get_query_history(&self) -> Result<Vec<HistorySlot>, DatabaseError> {
        let cutoff = chrono::Utc::now().timestamp() - 86400; // 24 hours ago
        self.conn.with_conn(|conn| {
            // Aggregate into 10-minute buckets (600 seconds)
            let mut stmt = conn.prepare(
                "SELECT \
                 (timestamp / 600) * 600 as slot, \
                 COUNT(*) as total, \
                 SUM(CASE WHEN dbl_status = 1 THEN 1 ELSE 0 END) as blocked, \
                 SUM(CASE WHEN dbl_status = 2 THEN 1 ELSE 0 END) as cached, \
                 SUM(CASE WHEN dbl_status = 3 THEN 1 ELSE 0 END) as forwarded \
                 FROM queries WHERE timestamp >= ?1 \
                 GROUP BY slot ORDER BY slot ASC"
            )?;
            let rows = stmt.query_map(rusqlite::params![cutoff], |row| {
                Ok(HistorySlot {
                    timestamp: row.get(0)?,
                    total: row.get(1)?,
                    blocked: row.get(2)?,
                    cached: row.get(3)?,
                    forwarded: row.get(4)?,
                })
            })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row?);
            }
            Ok(result)
        })
    }

    /// Get autocomplete suggestions for domains.
    pub fn get_domain_suggestions(&self, query: &str, limit: i64) -> Result<Vec<String>, DatabaseError> {
        self.conn.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT dbl_domain FROM queries \
                 WHERE dbl_domain LIKE ?1 \
                 ORDER BY COUNT(*) OVER (PARTITION BY dbl_domain) DESC \
                 LIMIT ?2"
            )?;
            let rows = stmt.query_map(rusqlite::params![format!("%{}%", query), limit], |row| {
                row.get(0)
            })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row?);
            }
            Ok(result)
        })
    }

    /// Get autocomplete suggestions for clients.
    pub fn get_client_suggestions(&self, query: &str, limit: i64) -> Result<Vec<String>, DatabaseError> {
        self.conn.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT dbl_client FROM queries \
                 WHERE dbl_client IS NOT NULL AND dbl_client LIKE ?1 \
                 ORDER BY COUNT(*) OVER (PARTITION BY dbl_client) DESC \
                 LIMIT ?2"
            )?;
            let rows = stmt.query_map(rusqlite::params![format!("%{}%", query), limit], |row| {
                row.get(0)
            })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row?);
            }
            Ok(result)
        })
    }
}

/// A stored DNS query entry
#[derive(Debug, Clone)]
pub struct StoredQuery {
    pub timestamp: i64,
    pub domain: String,
    pub client: Option<String>,
    pub forward: Option<String>,
    pub query_type: i32,
    pub status: QueryStatus,
    pub reply_time: Option<i64>,
    pub reply_type: i32,
    pub flags: i32,
    pub interface: Option<String>,
    pub elapsed_ms: Option<i64>,
    pub adlist_id: Option<i32>,
    pub cache_id: Option<i32>,
    pub regex_id: Option<i32>,
    pub upstream_id: Option<i32>,
}

/// DNS query status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryStatus {
    /// Unknown / in progress
    Unknown = 0,
    /// Blocked by gravity/denylist
    Blocked = 1,
    /// Answered from cache
    Cached = 2,
    /// Forwarded to upstream
    Forwarded = 3,
    /// NXDOMAIN
    Nxdomain = 4,
    /// SERVFAIL
    Servfail = 5,
    /// Retried
    Retried = 6,
    /// Rate limited
    RateLimited = 7,
}

impl QueryStatus {
    pub fn from_i32(n: i32) -> Self {
        match n {
            1 => Self::Blocked,
            2 => Self::Cached,
            3 => Self::Forwarded,
            4 => Self::Nxdomain,
            5 => Self::Servfail,
            6 => Self::Retried,
            7 => Self::RateLimited,
            _ => Self::Unknown,
        }
    }
}

/// Query statistics summary
#[derive(Debug, Clone, Serialize)]
pub struct QueryStats {
    pub total: i64,
    pub blocked: i64,
    pub cached: i64,
    pub forwarded: i64,
}
