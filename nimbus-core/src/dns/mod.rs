// =============================================================================
// DNS Forwarder with native DNS-over-TLS (DoT)
// =============================================================================

mod cache;
mod dot;
mod forwarder;
mod listener;
mod router;

use std::sync::Arc;

use tokio::sync::watch;
use tracing::info;

pub use forwarder::DnsForwarder;
pub use cache::DnsCache;
pub use dot::{DotError, DotManager};
pub use router::QueryRouter;

use crate::AppState;
use crate::DnsHandle;
use crate::blocking::BlockingEngine;
use crate::config::DnsUpstream;

/// Start the DNS subsystem
pub async fn start(
    state: Arc<AppState>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<DnsHandle> {
    // Scope the config read to drop the lock before any .await
    let dot_manager = Arc::new(DotManager::new());
    let (cache_entries, bind_addr, upstream_count, dot_count, blocking) = {
        let config_guard = state.config.read();
        let dns = &config_guard.dns;
        // Use pre-loaded blocking engine from AppState if available,
        // otherwise fall back to loading it here (first start)
        let blocking = state.blocking.clone().unwrap_or_else(|| {
            let engine = BlockingEngine::load(&state.database.gravity, &config_guard)
                .expect("Failed to load blocking lists");
            Arc::new(engine)
        });
        info!("Blocking engine loaded ({} total blocked, mode: {:?})", 
              blocking.stats().total_blocked, blocking.mode());
        (dns.cache_size, dns.bind, dns.upstreams.len(),
         dns.upstreams.iter().filter(|u| matches!(u, DnsUpstream::Tls { .. })).count(),
         blocking)
    };
    // config_guard dropped here - before async work

    // Initialize DNS cache (after releasing config lock)
    let cache = Arc::new(DnsCache::new(cache_entries));

    // Initialize query router (binds forwarding UDP socket)
    let mut router = QueryRouter::new(
        state.clone(),
        cache.clone(),
        dot_manager.clone(),
        blocking.clone(),
    );
    router.init().await?;
    let router = Arc::new(router);

    // Start DNS listener with graceful shutdown support
    listener::start(bind_addr, router.clone(), shutdown_rx.clone()).await?;

    info!(
        "DNS listener started on {} ({} upstreams, {} DoT enabled)",
        bind_addr, upstream_count, dot_count,
    );

    // Spawn shutdown monitor task
    let (dns_shutdown_tx, mut dns_shutdown_rx) = watch::channel(false);
    let dns_shutdown_tx_clone = dns_shutdown_tx.clone();

    tokio::spawn(async move {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                info!("DNS subsystem shutting down...");
                let _ = dns_shutdown_tx_clone.send(true);
            }
            _ = dns_shutdown_rx.changed() => {}
        }
    });

    Ok(DnsHandle { shutdown: Some(dns_shutdown_tx) })
}
