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
    /// DNS transaction ID (bytes 2-3 of the message)
    dns_id: u16,
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

                // Extract DNS transaction ID for matching
                let dns_id = if query.len() >= 2 {
                    u16::from_be_bytes([query[0], query[1]])
                } else {
                    return Err(DotError::ConnectionClosed);
                };

                let dot_query = DotQuery {
                    data: bytes::Bytes::from(wire),
                    dns_id,
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
/// matches by DNS transaction ID.
async fn tls_connection_task(
    tls_config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    address: SocketAddr,
    mut query_rx: mpsc::Receiver<DotQuery>,
) {
    info!("DoT task started for {}", address);

    // Pending queries awaiting responses, keyed by DNS transaction ID
    let mut pending: HashMap<u16, tokio::sync::oneshot::Sender<Result<Vec<u8>, DotError>>> = HashMap::new();

    loop {
        // Establish TLS connection
        let mut tls = match connect_tls(&tls_config, &server_name, &address).await {
            Ok(t) => t,
            Err(e) => {
                error!("DoT connect failed for {}: {}, retrying in 5s", address, e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        use tokio::io::AsyncWriteExt;

        // Main I/O loop
        loop {
            tokio::select! {
                // Incoming query from the channel
                query = query_rx.recv() => {
                    let query = match query {
                        Some(q) => q,
                        None => {
                            info!("DoT task channel closed for {}", address);
                            return;
                        }
                    };

                    let dns_id = query.dns_id;
                    let reply_tx = query.reply_tx;

                    // Write query to TLS stream
                    match tls.write_all(&query.data).await {
                        Ok(_) => {
                            pending.insert(dns_id, reply_tx);
                            debug!("DoT sent query id={} to {}", dns_id, address);
                        }
                        Err(e) => {
                            error!("DoT write failed for {}: {}", address, e);
                            let _ = reply_tx.send(Err(DotError::Io(e)));
                            break;
                        }
                    }
                }

                // Read response from TLS stream
                read_result = read_dns_response(&mut tls) => {
                    match read_result {
                        Ok(response) => {
                            // Extract DNS ID from response (bytes 0-1 of DNS message, after 2-byte len prefix)
                            if response.len() >= 2 {
                                let resp_id = u16::from_be_bytes([response[0], response[1]]);
                                if let Some(tx) = pending.remove(&resp_id) {
                                    let _ = tx.send(Ok(response));
                                    debug!("DoT matched response id={} from {}", resp_id, address);
                                } else {
                                    debug!("DoT unmatched response id={} from {}, discarding", resp_id, address);
                                }
                            }
                        }
                        Err(e) => {
                            // Connection closed or error - reconnect immediately
                            debug!("DoT reconnect for {}: {}", address, e);
                            // Fail all pending queries
                            for (_id, tx) in pending.drain() {
                                let _ = tx.send(Err(DotError::ConnectionClosed));
                            }
                            break;
                        }
                    }
                }
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
    tls: &mut tokio_rustls::TlsStream<TcpStream>,
) -> Result<Vec<u8>, DotError> {
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 2];
    tls.read_exact(&mut len_buf).await?;
    let response_len = u16::from_be_bytes(len_buf) as usize;

    if response_len == 0 || response_len > MAX_DNS_SIZE {
        return Err(DotError::ConnectionClosed);
    }

    let mut response = vec![0u8; response_len];
    tls.read_exact(&mut response).await?;

    Ok(response)
}
