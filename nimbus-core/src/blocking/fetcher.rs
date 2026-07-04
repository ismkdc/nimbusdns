// =============================================================================
// StevenBlack Hosts Fetcher
// =============================================================================
// Downloads blocklists from StevenBlack's unified hosts file and imports them
// into the gravity database. Runs periodically (default: every 24 hours).
//
// Format: `0.0.0.0 domain` (standard hosts file format)
// Lines starting with `#` are comments.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::database::gravity::GravityDb;

/// Minimum domains for a successful fetch (sanity check)
const MIN_DOMAINS: usize = 1000;

/// Start the background fetcher task.
/// Downloads on startup if gravity is empty, then refreshes periodically.
pub fn start(
    gravity: Arc<GravityDb>,
    source_url: String,
    refresh_interval: Duration,
    shutdown_rx: watch::Receiver<bool>,
    blocking_engine: Option<Arc<crate::blocking::BlockingEngine>>,
) {
    tokio::spawn(async move {
        info!("Blocklist fetcher started (source: {})", source_url);

        let do_fetch = || async {
            if let Err(e) = fetch_and_import(&gravity, &source_url).await {
                warn!("Blocklist fetch failed: {}", e);
            } else if let Some(ref engine) = blocking_engine {
                if let Err(e) = engine.reload(&gravity) {
                    warn!("Blocking engine reload after fetch failed: {}", e);
                }
            }
        };

        let domain_count = gravity.total_blocked().unwrap_or(0);
        if domain_count == 0 {
            info!("Gravity database is empty, fetching initial blocklist...");
            do_fetch().await;
        } else {
            info!("Gravity database has {} domains, skipping initial fetch", domain_count);
        }

        let mut interval = tokio::time::interval(refresh_interval);
        let mut rx = shutdown_rx;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    info!("Starting scheduled blocklist refresh...");
                    do_fetch().await;
                }
                _ = rx.changed() => {
                    info!("Blocklist fetcher shutting down");
                    break;
                }
            }
        }
    });
}

/// Fetch the blocklist from the given URL and import into gravity database.
pub async fn fetch_and_import(gravity: &GravityDb, source_url: &str) -> Result<(), anyhow::Error> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("NimbusDNS/0.1")
        .build()?;

    let response = client.get(source_url).send().await?;
    let body = response.text().await?;

    let domains = parse_hosts_file(&body);
    info!("Parsed {} domains from hosts file", domains.len());

    if domains.len() < MIN_DOMAINS {
        return Err(anyhow::anyhow!(
            "Too few domains ({}), possible parse error or empty response",
            domains.len()
        ));
    }

    // Import into gravity database
    // Strategy: clear existing gravity domains and bulk insert
    gravity.replace_all_gravity(&domains)?;

    info!("Successfully imported {} domains into gravity database", domains.len());
    Ok(())
}

/// Parse a hosts file format string and extract unique domains.
/// Lines: `0.0.0.0 domain.com` or `127.0.0.1 domain.com`
/// Ignores comments (`#`) and localhost entries.
fn parse_hosts_file(content: &str) -> Vec<String> {
    let mut domains = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in content.lines() {
        let line = line.trim();
        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse: "IP DOMAIN" or "IP DOMAIN # comment"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let ip = parts[0];
        let domain = parts[1];

        // Only block 0.0.0.0 and 127.0.0.1 entries
        if ip != "0.0.0.0" && ip != "127.0.0.1" {
            continue;
        }

        // Skip localhost and broadcast
        if domain == "localhost" || domain == "localhost.localdomain" || domain == "broadcasthost" {
            continue;
        }
        if domain == "255.255.255.255" || domain == "::1" || domain.starts_with("local") {
            continue;
        }

        // Normalize: lowercase, deduplicate
        let domain_lower = domain.to_lowercase();
        if seen.insert(domain_lower.clone()) {
            domains.push(domain_lower);
        }
    }

    domains
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hosts_file() {
        let content = "\
# This is a comment
0.0.0.0 example.com
127.0.0.1 trackertest.com
0.0.0.0 doubleclick.net # tracker
127.0.0.1 localhost
0.0.0.0 255.255.255.255
# another comment
0.0.0.0 Example.COM

some bad line
";
        let domains = parse_hosts_file(content);
        assert_eq!(domains.len(), 3);
        assert!(domains.contains(&"example.com".to_string()));
        assert!(domains.contains(&"trackertest.com".to_string()));
        assert!(domains.contains(&"doubleclick.net".to_string()));
        assert!(!domains.contains(&"localhost".to_string()));
    }

    #[test]
    fn test_parse_empty() {
        assert!(parse_hosts_file("").is_empty());
        assert!(parse_hosts_file("# only comment").is_empty());
    }

    #[test]
    fn test_deduplication() {
        let content = "\
0.0.0.0 example.com
0.0.0.0 Example.com
0.0.0.0 example.COM
";
        let domains = parse_hosts_file(content);
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0], "example.com");
    }
}
