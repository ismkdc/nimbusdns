// =============================================================================
// Database Schema Definitions
// =============================================================================

/// Initial Query database schema (migration v1)
pub const INITIAL_FTL_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    dbl_domain TEXT NOT NULL,
    dbl_client TEXT,
    dbl_forward TEXT,
    dbl_type INTEGER,
    dbl_status INTEGER,
    dbl_reply_time INTEGER,
    dbl_reply_type INTEGER,
    dbl_flags INTEGER,
    dbl_interface TEXT,
    dbl_elapsed_ms INTEGER,
    dbl_adlist_id INTEGER,
    dbl_cache_id INTEGER,
    dbl_regex_id INTEGER,
    dbl_upstream_id INTEGER,
    UNIQUE(timestamp, dbl_domain, dbl_client)
);

CREATE INDEX IF NOT EXISTS idx_queries_timestamp ON queries(timestamp);
CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries(dbl_domain);
CREATE INDEX IF NOT EXISTS idx_queries_client ON queries(dbl_client);

-- Network table for tracking active clients
CREATE TABLE IF NOT EXISTS network (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hwaddr TEXT UNIQUE,
    interface TEXT,
    first_seen INTEGER,
    last_seen INTEGER,
    num_queries INTEGER DEFAULT 0,
    mac_vendor TEXT,
    munged TEXT
);

-- Network addresses (IPv4/IPv6 per network entry)
CREATE TABLE IF NOT EXISTS network_addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL UNIQUE,
    last_seen INTEGER,
    name TEXT,
    name_updated INTEGER,
    FOREIGN KEY(network_id) REFERENCES network(id) ON DELETE CASCADE
);

-- Counter statistics
CREATE TABLE IF NOT EXISTS counters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    total_queries INTEGER DEFAULT 0,
    blocked_queries INTEGER DEFAULT 0,
    cached_queries INTEGER DEFAULT 0,
    forwarded_queries INTEGER DEFAULT 0
);

-- Alias clients (grouping multiple IPs as one client)
CREATE TABLE IF NOT EXISTS aliasclient (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    comment TEXT,
    addgid INTEGER,
    orderid INTEGER
);

-- NimbusDNS metadata
CREATE TABLE IF NOT EXISTS ftl (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version TEXT NOT NULL,
    build_time INTEGER,
    branch TEXT,
    commit_hash TEXT,
    tag TEXT
);

-- Gravity database schema (for reference)
-- This is managed separately by gravity-db
";

/// Gravity database schema
pub const GRAVITY_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS group_table (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    date_added INTEGER NOT NULL,
    date_modified INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS domainlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type INTEGER NOT NULL,
    domain TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    date_added INTEGER NOT NULL,
    date_modified INTEGER NOT NULL,
    comment TEXT,
    UNIQUE(type, domain)
);

CREATE TABLE IF NOT EXISTS domainlist_by_group (
    domainlist_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    PRIMARY KEY(domainlist_id, group_id),
    FOREIGN KEY(domainlist_id) REFERENCES domainlist(id) ON DELETE CASCADE,
    FOREIGN KEY(group_id) REFERENCES group_table(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS client (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    comment TEXT,
    date_added INTEGER NOT NULL,
    date_modified INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS client_by_group (
    client_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    PRIMARY KEY(client_id, group_id),
    FOREIGN KEY(client_id) REFERENCES client(id) ON DELETE CASCADE,
    FOREIGN KEY(group_id) REFERENCES group_table(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS adlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT UNIQUE NOT NULL,
    comment TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    date_added INTEGER NOT NULL,
    date_modified INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS adlist_by_group (
    adlist_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    PRIMARY KEY(adlist_id, group_id),
    FOREIGN KEY(adlist_id) REFERENCES adlist(id) ON DELETE CASCADE,
    FOREIGN KEY(group_id) REFERENCES group_table(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS gravity (
    domain TEXT NOT NULL,
    adlist_id INTEGER NOT NULL,
    PRIMARY KEY(domain, adlist_id)
);

-- Views
CREATE VIEW IF NOT EXISTS vw_allowlist AS
    SELECT d.* FROM domainlist d
    JOIN domainlist_by_group dbg ON d.id = dbg.domainlist_id
    JOIN group_table g ON dbg.group_id = g.id
    WHERE d.type = 0 AND g.enabled = 1;

CREATE VIEW IF NOT EXISTS vw_denylist AS
    SELECT d.* FROM domainlist d
    JOIN domainlist_by_group dbg ON d.id = dbg.domainlist_id
    JOIN group_table g ON dbg.group_id = g.id
    WHERE d.type = 1 AND g.enabled = 1;

CREATE VIEW IF NOT EXISTS vw_regex_allowlist AS
    SELECT d.* FROM domainlist d
    JOIN domainlist_by_group dbg ON d.id = dbg.domainlist_id
    JOIN group_table g ON dbg.group_id = g.id
    WHERE d.type = 2 AND g.enabled = 1;

CREATE VIEW IF NOT EXISTS vw_regex_denylist AS
    SELECT d.* FROM domainlist d
    JOIN domainlist_by_group dbg ON d.id = dbg.domainlist_id
    JOIN group_table g ON dbg.group_id = g.id
    WHERE d.type = 3 AND g.enabled = 1;
";
