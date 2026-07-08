// =============================================================================
// DNS-over-TLS (DoT) - RFC 7858 Implementation
// =============================================================================
// Persistent TLS connection per upstream with ID-multiplexed pipelining.
//   - One tokio task per upstream manages the TLS connection lifecycle
//   - Queries are sent concurrently on the same connection
//   - Responses matched to pending queries by DNS transaction ID
//   - Auto-reconnect on connection failure, requeue pending queries

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info};

use crate::config::DnsUpstream;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
#[allow(dead_code)]
const TLS_IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_DNS_SIZE: usize = 4096;
const CHANNEL_BOUND: usize = 128;

/// A query in the DoT pipeline
struct DotQuery {
    /// Wire-format query ([2-byte len][DNS message])
    data: bytes::Bytes,
    /// Send response back to caller
    reply_tx: tokio::sync::oneshot::Sender<Result<Vec<u8>, DotError>>,
}

/// DoT error types
#[derive(Debug, thiserror::Error)]
pub enum DotError {
    #[error("TLS handshake failed: {0}")]
    TlsHandshake(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Connection closed")]
    ConnectionClosed,
    #[error("Timeout")]
    Timeout,
    #[error("Queue full")]
    QueueFull,
}

/// Manages all DoT upstream connections
pub struct DotManager {
    /// Per-upstream bounded channel senders
    upstreams: Mutex<HashMap<SocketAddr, mpsc::Sender<DotQuery>>>,
    tls_config: Arc<ClientConfig>,
}

impl Default for DotManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DotManager {
    pub fn new() -> Self {
        let tls_config = Self::build_tls_config();
        Self {
            upstreams: Mutex::new(HashMap::new()),
            tls_config: Arc::new(tls_config),
        }
    }

    /// Create a DotManager with a custom TLS config (e.g. for tests with
    /// a self-signed CA). Takes ownership of the given `ClientConfig`.
    pub fn with_tls_config(tls_config: ClientConfig) -> Self {
        Self {
            upstreams: Mutex::new(HashMap::new()),
            tls_config: Arc::new(tls_config),
        }
    }

    fn build_tls_config() -> ClientConfig {
        let mut root_store = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().expect("load native CA certs") {
            root_store.add(cert).ok();
        }
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    }

    /// Send a DNS query via DoT. Blocks until response or timeout.
    pub async fn send_query(
        &self,
        upstream: &DnsUpstream,
        query: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, DotError> {
        match upstream {
            DnsUpstream::Tls { address, port, hostname } => {
                let addr = SocketAddr::new(*address, *port);
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

                // Build wire format: [2-byte length][DNS message]
                let len = query.len() as u16;
                let mut wire = Vec::with_capacity(2 + query.len());
                wire.extend_from_slice(&len.to_be_bytes());
                wire.extend_from_slice(query);

                let dot_query = DotQuery {
                    data: bytes::Bytes::from(wire),
                    reply_tx,
                };

                // Get or create the channel sender for this upstream
                let sender = {
                    let mut upstreams = self.upstreams.lock();
                    match upstreams.get(&addr) {
                        Some(tx) => tx.clone(),
                        None => {
                            let (tx, rx) = mpsc::channel::<DotQuery>(CHANNEL_BOUND);
                            upstreams.insert(addr, tx.clone());
                            let cfg = self.tls_config.clone();
                            let srv_name = ServerName::try_from(hostname.to_string())
                                .unwrap_or_else(|_| ServerName::IpAddress(
                                    rustls::pki_types::IpAddr::from(addr.ip())
                                ));
                            tokio::spawn(async move {
                                tls_connection_task(cfg, srv_name, addr, rx).await;
                            });
                            tx
                        }
                    }
                };

                // Send query to the connection task (bounded channel)
                sender.send(dot_query).await
                    .map_err(|_| DotError::QueueFull)?;

                // Wait for response with timeout
                tokio::time::timeout(timeout, reply_rx)
                    .await
                    .map_err(|_| DotError::Timeout)?
                    .map_err(|_| DotError::ConnectionClosed)?
            }
            DnsUpstream::Plain { .. } => {
                Err(DotError::TlsHandshake("Not a TLS upstream".into()))
            }
        }
    }
}

/// Persistent TLS connection manager.
/// Maintains one TLS connection per upstream.
/// Reads queries from channel, writes to TLS, reads responses,
/// Per-connection atomic ID generator for unique transaction IDs.
fn next_conn_id() -> u16 {
    static NEXT_ID: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(1);
    NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Shared pending map between reader and writer tasks
/// A pending query: sender to reply to caller + original DNS ID to restore
struct PendingEntry {
    reply_tx: tokio::sync::oneshot::Sender<Result<Vec<u8>, DotError>>,
    original_dns_id: u16,
}

type PendingMap = Arc<Mutex<HashMap<u16, PendingEntry>>>;

/// maps by per-connection unique ID.
async fn tls_connection_task(
    tls_config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    address: SocketAddr,
    mut query_rx: mpsc::Receiver<DotQuery>,
) {
    info!("DoT task started for {}", address);

    loop {
        // Each connection gets its own pending map.
        // This prevents a stale (zombie) reader from draining the new connection's in-flight queries.
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        // Establish TLS connection
        let tls = match connect_tls(&tls_config, &server_name, &address).await {
            Ok(t) => t,
            Err(e) => {
                error!("DoT connect failed for {}: {}, retrying in 5s", address, e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        // Split TLS stream into reader + writer halves
        // Reader runs in its own task and is NEVER cancelled by select!
        // This prevents TLS stream desync (the main cause of "All upstreams failed")
        let (mut reader, mut writer) = tokio::io::split(tls);
        let pending_rd = pending.clone();
        let addr_rd = address;

        // Spawn reader task - it owns the read half and never gets cancelled
        let mut reader_handle = tokio::spawn(async move {
            loop {
                match read_dns_response(&mut reader).await {
                    Ok(mut response) => {
                        if response.len() >= 2 {
                            let resp_id = u16::from_be_bytes([response[0], response[1]]);
                            let mut map = pending_rd.lock();
                            if let Some(entry) = map.remove(&resp_id) {
                                // Restore original DNS ID before sending to caller
                                if response.len() >= 2 && entry.original_dns_id != resp_id {
                                    response[0] = (entry.original_dns_id >> 8) as u8;
                                    response[1] = entry.original_dns_id as u8;
                                }
                                let _ = entry.reply_tx.send(Ok(response));
                                debug!("DoT matched response id={} from {}", resp_id, addr_rd);
                            } else {
                                debug!("DoT unmatched response id={} from {}, discarding", resp_id, addr_rd);
                            }
                        }
                    }
                    Err(e) => {
                        debug!("DoT reader {}: {} (reconnecting)", addr_rd, e);
                        // Fail all pending queries
                        let mut map = pending_rd.lock();
                        for (_id, entry) in map.drain() {
                            let _ = entry.reply_tx.send(Err(DotError::ConnectionClosed));
                        }
                        break;
                    }
                }
            }
        });

        // Writer task: receives queries from channel, sends them, waits for reader
        use tokio::io::AsyncWriteExt;

        // Re-establish: drain the channel into writer until reader fails
        let mut pending_clean_counter: u32 = 0;
        loop {
            tokio::select! {
                query = query_rx.recv() => {
                    let query = match query {
                        Some(q) => q,
                        None => {
                            info!("DoT task channel closed for {}", address);
                            reader_handle.abort();
                            return;
                        }
                    };

                    // Assign unique per-connection ID to avoid collision
                    let conn_id = next_conn_id();
                    let reply_tx = query.reply_tx;

                    // Wire format: [2-byte length][DNS message] where DNS ID is at bytes 2-3
                    let mut data = query.data.to_vec();
                    let original_dns_id = if data.len() >= 4 {
                        let id = u16::from_be_bytes([data[2], data[3]]);
                        // Overwrite DNS ID with our unique connection ID (bytes 2-3)
                        data[2] = (conn_id >> 8) as u8;
                        data[3] = conn_id as u8;
                        id
                    } else {
                        // Invalid query, fail it
                        let _ = reply_tx.send(Err(DotError::ConnectionClosed));
                        continue;
                    };
                    match writer.write_all(&data).await {
                        Ok(_) => {
                            {
                                let mut map = pending.lock();
                                map.insert(conn_id, PendingEntry {
                                    reply_tx,
                                    original_dns_id,
                                });
                                // Periodically sweep stale entries whose caller timed out
                                // (reply_tx.is_closed() when the oneshot receiver was dropped)
                                pending_clean_counter = pending_clean_counter.wrapping_add(1);
                                if pending_clean_counter.is_multiple_of(64) {
                                    map.retain(|_id, entry| !entry.reply_tx.is_closed());
                                }
                            }
                            debug!("DoT sent query id={} to {}", conn_id, address);
                        }
                        Err(e) => {
                            error!("DoT write failed for {}: {}", address, e);
                            let _ = reply_tx.send(Err(DotError::Io(e)));
                            // Abort the reader so it doesn't hang around with its own pending reference
                            reader_handle.abort();
                            break;
                        }
                    }
                }
                _ = &mut reader_handle => {
                    // Reader exited, break out to reconnect
                    break;
                }
            }
        }

        // Reader exited; drain remaining pending queries
        {
            let mut map = pending.lock();
            for (_id, entry) in map.drain() {
                let _ = entry.reply_tx.send(Err(DotError::ConnectionClosed));
            }
        }
    }
}

/// Connect TCP + perform TLS handshake
async fn connect_tls(
    tls_config: &ClientConfig,
    server_name: &ServerName<'static>,
    address: &SocketAddr,
) -> Result<tokio_rustls::TlsStream<TcpStream>, DotError> {
    let tcp = TcpStream::connect(address).await?;
    let connector = TlsConnector::from(Arc::new(tls_config.clone()));
    let tls = tokio::time::timeout(
        TLS_HANDSHAKE_TIMEOUT,
        connector.connect(server_name.clone(), tcp),
    )
    .await
    .map_err(|_| DotError::TlsHandshake("timeout".into()))?
    .map_err(|e| DotError::TlsHandshake(e.to_string()))?;

    debug!("DoT connected to {}", address);
    Ok(tokio_rustls::TlsStream::Client(tls))
}

/// Read a DNS response from TLS stream: [2-byte len][payload]
async fn read_dns_response(
    reader: &mut tokio::io::ReadHalf<tokio_rustls::TlsStream<TcpStream>>,
) -> Result<Vec<u8>, DotError> {
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let response_len = u16::from_be_bytes(len_buf) as usize;

    if response_len == 0 || response_len > MAX_DNS_SIZE {
        return Err(DotError::ConnectionClosed);
    }

    let mut response = vec![0u8; response_len];
    reader.read_exact(&mut response).await?;

    Ok(response)
}
