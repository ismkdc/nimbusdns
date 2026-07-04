// =============================================================================
// Gravity Database (adlist, domainlist, groups, clients)
// =============================================================================

use std::path::Path;

use rusqlite::params;
use serde::Serialize;
use tracing::{info, warn};

use super::{DatabaseError, SafeConnection};

/// A domain list entry (allow/deny/regex)
#[derive(Debug, Clone, Serialize)]
pub struct DomainListEntry {
    pub id: i32,
    #[serde(rename = "type")]
    pub domain_type: i32, // 0=allow, 1=deny, 2=regex_allow, 3=regex_deny
    pub domain: String,
    pub enabled: bool,
    pub date_added: i64,
    pub date_modified: i64,
    pub comment: Option<String>,
}

/// A group entry
#[derive(Debug, Clone, Serialize)]
pub struct GroupEntry {
    pub id: i32,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub date_added: i64,
    pub date_modified: i64,
}

/// A client entry
#[derive(Debug, Clone, Serialize)]
pub struct ClientEntry {
    pub id: i32,
    pub ip: String,
    pub comment: Option<String>,
    pub date_added: i64,
    pub date_modified: i64,
}

/// An adlist entry
#[derive(Debug, Clone, Serialize)]
pub struct AdlistEntry {
    pub id: i32,
    pub address: String,
    pub comment: Option<String>,
    pub enabled: bool,
    pub date_added: i64,
    pub date_modified: i64,
}

/// Gravity database manager — handles adlist blocking rules
pub struct GravityDb {
    conn: SafeConnection,
}

impl GravityDb {
    /// Open the gravity database
    pub fn open(path: &Path, busy_timeout: u64) -> Result<Self, DatabaseError> {
        let conn = SafeConnection::open(path, busy_timeout)?;

        // Ensure schema exists
        conn.with_conn(|c| {
            c.execute_batch(super::schema::GRAVITY_SCHEMA)?;
            Ok(())
        })?;

        info!("Gravity database opened: {}", path.display());
        Ok(Self { conn })
    }

    /// Check if a domain is blocked by any list (allowlist, denylist, regex, gravity)
    pub fn check_blocked(&self, domain: &str) -> Result<BlockingDecision, DatabaseError> {
        // 1. Check allowlist (type = 0)
        if self.is_allowlisted(domain)? {
            return Ok(BlockingDecision::Allowlisted);
        }

        // 2. Check exact denylist (type = 1)
        if self.is_exact_denied(domain)? {
            return Ok(BlockingDecision::Blocked("exact".into()));
        }

        // 3. Check regex allowlist (type = 2)
        if self.matches_regex_allowlist(domain)? {
            return Ok(BlockingDecision::Allowlisted);
        }

        // 4. Check regex denylist (type = 3)
        if let Some(regex_id) = self.matches_regex_denylist(domain)? {
            return Ok(BlockingDecision::BlockedByRegex(regex_id));
        }

        // 5. Check gravity (adlist domains)
        if self.in_gravity(domain)? {
            return Ok(BlockingDecision::Blocked("gravity".into()));
        }

        Ok(BlockingDecision::NotBlocked)
    }

    /// Check if a domain is in the exact allowlist
    fn is_allowlisted(&self, domain: &str) -> Result<bool, DatabaseError> {
        self.conn.with_conn(|conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM vw_allowlist WHERE domain = ?1",
                params![domain],
                |row| row.get(0),
            )?;
            Ok(count > 0)
        })
    }

    /// Check if a domain is in the exact denylist
    fn is_exact_denied(&self, domain: &str) -> Result<bool, DatabaseError> {
        self.conn.with_conn(|conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM vw_denylist WHERE domain = ?1",
                params![domain],
                |row| row.get(0),
            )?;
            Ok(count > 0)
        })
    }

    /// Check if a domain matches any regex in the allowlist
    fn matches_regex_allowlist(&self, domain: &str) -> Result<bool, DatabaseError> {
        // Get all regex allowlist entries
        let regexes: Vec<String> = self.conn.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT domain FROM vw_regex_allowlist")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            Ok(rows.filter_map(|r| r.ok()).collect::<Vec<_>>())
        })?;

        for pattern in &regexes {
            if domain_matches_pattern(domain, pattern) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Check if a domain matches any regex in the denylist, returning the regex ID
    fn matches_regex_denylist(&self, domain: &str) -> Result<Option<i32>, DatabaseError> {
        // Get all regex denylist entries with their IDs
        let regexes: Vec<(i32, String)> = self.conn.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT d.id, d.domain FROM domainlist d
                 JOIN domainlist_by_group dbg ON d.id = dbg.domainlist_id
                 JOIN group_table g ON dbg.group_id = g.id
                 WHERE d.type = 3 AND g.enabled = 1"
            )?;
            let rows = stmt.query_map([], |row| {
                let id: i32 = row.get(0)?;
                let pattern: String = row.get(1)?;
                Ok((id, pattern))
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect::<Vec<_>>())
        })?;

        for (id, pattern) in &regexes {
            if domain_matches_pattern(domain, pattern) {
                return Ok(Some(*id));
            }
        }
        Ok(None)
    }

    /// Check if a domain is in the gravity table
    fn in_gravity(&self, domain: &str) -> Result<bool, DatabaseError> {
        self.conn.with_conn(|conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM gravity WHERE domain = ?1",
                params![domain],
                |row| row.get(0),
            )?;
            Ok(count > 0)
        })
    }

    /// Get the total number of blocked domains
    pub fn total_blocked(&self) -> Result<i64, DatabaseError> {
        self.conn.with_conn(|conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM gravity",
                [],
                |row| row.get(0),
            )?;
            Ok(count)
        })
    }

    /// Replace all gravity domains with a new list using a transaction.
    pub fn replace_all_gravity(&self, domains: &[String]) -> Result<(), DatabaseError> {
        if domains.is_empty() {
            return Ok(());
        }
        self.conn.with_conn(|conn| {
            conn.execute_batch("BEGIN")?;
            conn.execute_batch("DELETE FROM gravity")?;
            for domain in domains {
                conn.execute(
                    "INSERT INTO gravity (domain, adlist_id) VALUES (?1, 0)",
                    rusqlite::params![domain],
                )?;
            }
            conn.execute_batch("COMMIT")?;
            Ok(())
        })
    }

    /// Get the number of adlists
    pub fn adlist_count(&self) -> Result<i64, DatabaseError> {
        self.conn.with_conn(|conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM adlist WHERE enabled = 1",
                [],
                |row| row.get(0),
            )?;
            Ok(count)
        })
    }

    /// Run ANALYZE
    pub fn analyze(&self) -> Result<(), DatabaseError> {
        self.conn.analyze()
    }

    /// Get all domains of a specific type from domainlist (for in-memory blocking)
    pub fn get_domainlist_by_type(&self, dtype: i32) -> Result<Vec<String>, DatabaseError> {
        self.conn.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT d.domain FROM domainlist d
                 JOIN domainlist_by_group dbg ON d.id = dbg.domainlist_id
                 JOIN group_table g ON dbg.group_id = g.id
                 WHERE d.type = ?1 AND g.enabled = 1 AND d.enabled = 1"
            )?;
            let rows = stmt.query_map(params![dtype], |row| row.get::<_, String>(0))?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        })
    }

    /// Get all gravity domains (the main adlist blocklist)
    pub fn get_all_gravity_domains(&self) -> Result<Vec<String>, DatabaseError> {
        self.conn.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT DISTINCT domain FROM gravity")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        })
    }

    /// Get gravity domains with pagination
    pub fn get_gravity_entries(&self, page: usize, limit: usize) -> Result<(Vec<String>, usize), DatabaseError> {
        self.conn.with_conn(|conn| {
            let total: i64 = conn.query_row("SELECT COUNT(*) FROM gravity", [], |row| row.get(0))?;
            let offset = page.saturating_sub(1) * limit;
            let mut stmt = conn.prepare(
                "SELECT domain FROM gravity ORDER BY domain ASC LIMIT ?1 OFFSET ?2"
            )?;
            let rows = stmt.query_map(rusqlite::params![limit as i64, offset as i64], |row| {
                row.get::<_, String>(0)
            })?;
            let mut domains = Vec::new();
            for row in rows {
                domains.push(row?);
            }
            Ok((domains, total as usize))
        })
    }

    /// Add a single domain to the gravity blocklist
    pub fn add_gravity_domain(&self, domain: &str) -> Result<(), DatabaseError> {
        self.conn.with_conn(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO gravity (domain, adlist_id) VALUES (?1, 0)",
                rusqlite::params![domain],
            )?;
            Ok(())
        })
    }

    /// Remove a single domain from the gravity blocklist
    pub fn remove_gravity_domain(&self, domain: &str) -> Result<(), DatabaseError> {
        self.conn.with_conn(|conn| {
            conn.execute("DELETE FROM gravity WHERE domain = ?1", rusqlite::params![domain])?;
            Ok(())
        })
    }

    // =========================================================================
    // Domain List CRUD
    // =========================================================================

    /// Get all entries of a specific type from domainlist
    pub fn get_domainlist(&self, dtype: i32) -> Result<Vec<DomainListEntry>, DatabaseError> {
        self.conn.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, type, domain, enabled, date_added, date_modified, comment \
                 FROM domainlist WHERE type = ?1 ORDER BY domain ASC"
            )?;
            let rows = stmt.query_map(params![dtype], |row| {
                Ok(DomainListEntry {
                    id: row.get(0)?,
                    domain_type: row.get(1)?,
                    domain: row.get(2)?,
                    enabled: row.get::<_, i32>(3)? != 0,
                    date_added: row.get(4)?,
                    date_modified: row.get(5)?,
                    comment: row.get(6)?,
                })
            })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row?);
            }
            Ok(result)
        })
    }

    /// Add a domain to the domainlist
    pub fn add_domainlist(&self, dtype: i32, domain: &str, comment: Option<&str>) -> Result<i32, DatabaseError> {
        let now = chrono::Utc::now().timestamp();
        self.conn.with_conn(|conn| {
            conn.execute(
                "INSERT INTO domainlist (type, domain, enabled, date_added, date_modified, comment) \
                 VALUES (?1, ?2, 1, ?3, ?4, ?5)",
                params![dtype, domain, now, now, comment],
            )?;
            Ok(conn.last_insert_rowid() as i32)
        })
    }

    /// Remove a domain from the domainlist by ID
    pub fn remove_domainlist(&self, id: i32) -> Result<(), DatabaseError> {
        self.conn.with_conn(|conn| {
            conn.execute("DELETE FROM domainlist WHERE id = ?1", params![id])?;
            Ok(())
        })
    }

    /// Update a domainlist entry
    pub fn update_domainlist(&self, id: i32, domain: Option<&str>, enabled: Option<bool>, comment: Option<&str>) -> Result<(), DatabaseError> {
        let now = chrono::Utc::now().timestamp();
        self.conn.with_conn(|conn| {
            let mut sets = Vec::new();
            let mut values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

            if let Some(d) = domain {
                sets.push(format!("domain = ?{}", values.len() + 1));
                values.push(Box::new(d.to_string()));
            }
            if let Some(e) = enabled {
                sets.push(format!("enabled = ?{}", values.len() + 1));
                values.push(Box::new(if e { 1i32 } else { 0i32 }));
            }
            if comment.is_some() {
                sets.push(format!("comment = ?{}", values.len() + 1));
                values.push(Box::new(comment.unwrap_or("").to_string()));
            }

            if sets.is_empty() {
                return Ok(());
            }

            sets.push(format!("date_modified = ?{}", values.len() + 1));
            values.push(Box::new(now));

            let sql = format!("UPDATE domainlist SET {} WHERE id = ?{}", sets.join(", "), values.len() + 1);
            values.push(Box::new(id));

            let params_refs: Vec<&dyn rusqlite::types::ToSql> = values.iter().map(|v| v.as_ref()).collect();
            conn.execute(&sql, params_refs.as_slice())?;
            Ok(())
        })
    }

    // =========================================================================
    // Group / Client / Adlist Queries
    // =========================================================================

    /// Create a new group
    pub fn create_group(&self, name: &str, description: Option<&str>) -> Result<i32, DatabaseError> {
        let now = chrono::Utc::now().timestamp();
        self.conn.with_conn(|conn| {
            conn.execute(
                "INSERT INTO group_table (name, description, enabled, date_added, date_modified) \
                 VALUES (?1, ?2, 1, ?3, ?4)",
                params![name, description, now, now],
            )?;
            Ok(conn.last_insert_rowid() as i32)
        })
    }

    /// Get all groups
    pub fn get_groups(&self) -> Result<Vec<GroupEntry>, DatabaseError> {
        self.conn.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, name, description, enabled, date_added, date_modified \
                 FROM group_table ORDER BY name ASC"
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(GroupEntry {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    enabled: row.get::<_, i32>(3)? != 0,
                    date_added: row.get(4)?,
                    date_modified: row.get(5)?,
                })
            })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row?);
            }
            Ok(result)
        })
    }

    /// Get all clients
    pub fn get_clients(&self) -> Result<Vec<ClientEntry>, DatabaseError> {
        self.conn.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, ip, comment, date_added, date_modified \
                 FROM client ORDER BY ip ASC"
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(ClientEntry {
                    id: row.get(0)?,
                    ip: row.get(1)?,
                    comment: row.get(2)?,
                    date_added: row.get(3)?,
                    date_modified: row.get(4)?,
                })
            })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row?);
            }
            Ok(result)
        })
    }

    /// Get all adlists
    pub fn get_adlists(&self) -> Result<Vec<AdlistEntry>, DatabaseError> {
        self.conn.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, address, comment, enabled, date_added, date_modified \
                 FROM adlist ORDER BY address ASC"
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(AdlistEntry {
                    id: row.get(0)?,
                    address: row.get(1)?,
                    comment: row.get(2)?,
                    enabled: row.get::<_, i32>(3)? != 0,
                    date_added: row.get(4)?,
                    date_modified: row.get(5)?,
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

/// Result of a domain blocking check
#[derive(Debug, Clone, PartialEq)]
pub enum BlockingDecision {
    /// Domain is not blocked
    NotBlocked,
    /// Domain is explicitly allowed (overrides other blocking)
    Allowlisted,
    /// Domain is blocked by exact match
    Blocked(String),
    /// Domain is blocked by regex
    BlockedByRegex(i32),
}

impl BlockingDecision {
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked(_) | Self::BlockedByRegex(_))
    }
}

/// Match a domain against a NimbusDNS pattern (wildcard/regex)
fn domain_matches_pattern(domain: &str, pattern: &str) -> bool {
    // Trim leading/trailing whitespace
    let pattern = pattern.trim();

    // Empty pattern never matches
    if pattern.is_empty() {
        return false;
    }

    // If pattern starts and ends with /, treat it as regex
    if pattern.starts_with('/') && pattern.ends_with('/') {
        let regex_body = &pattern[1..pattern.len() - 1];
        match regex::Regex::new(regex_body) {
            Ok(re) => re.is_match(domain),
            Err(e) => {
                warn!("Invalid regex pattern '{}': {}", pattern, e);
                false
            }
        }
    } else {
        // Wildcard matching:
        // "example.com"        → exact match
        // "*.example.com"      → suffix match (any subdomain of example.com)
        // "*example.com"       → suffix match
        if let Some(suffix) = pattern.strip_prefix("*.") {
            domain == suffix || domain.ends_with(&format!(".{}", suffix))
        } else if let Some(suffix) = pattern.strip_prefix('*') {
            domain == suffix || domain.ends_with(suffix)
        } else {
            // Exact match
            domain == pattern
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::blocking::BlockingLists;

    #[test]
    fn test_exact_match() {
        let re = BlockingLists::compile_regex("example.com").unwrap();
        assert!(re.is_match("example.com"));
        assert!(!re.is_match("test.example.com"));
    }

    #[test]
    fn test_wildcard_match() {
        let re = BlockingLists::compile_regex("*.example.com").unwrap();
        assert!(re.is_match("sub.example.com"));
        assert!(re.is_match("example.com"));
        assert!(!re.is_match("other.com"));
    }

    #[test]
    fn test_regex_match() {
        let re = BlockingLists::compile_regex("/^tracker\\..*\\.example\\.com$/").unwrap();
        assert!(re.is_match("tracker.sub.example.com"));
        assert!(!re.is_match("safe.example.com"));
    }

}
