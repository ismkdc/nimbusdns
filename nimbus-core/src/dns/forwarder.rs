// =============================================================================
// DNS Forwarder — per-query ephemeral sockets to avoid race conditions
// =============================================================================

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::Message;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{info, warn};

use crate::config::DnsUpstream;

const MAX_DNS_SIZE: usize = 4096;

/// DNS forwarder — opens ephemeral UDP socket per query to avoid ID collisions
pub struct DnsForwarder {
    dot_manager: Arc<super::dot::DotManager>,
    upstreams: Vec<DnsUpstream>,
}

impl DnsForwarder {
    pub fn new(dot_manager: Arc<super::dot::DotManager>, upstreams: Vec<DnsUpstream>) -> Self {
        Self { dot_manager, upstreams }
    }

    pub async fn init(&mut self) -> anyhow::Result<()> {
        info!("DNS forwarder initialized ({} upstreams, ephemeral sockets)", self.upstreams.len());
        Ok(())
    }

    pub async fn forward(
        &self,
        query: &Message,
        upstream: &DnsUpstream,
        timeout_duration: Duration,
    ) -> Result<Message, ForwardError> {
        let query_bytes = query.to_vec().map_err(|e| ForwardError::Encode(e.to_string()))?;

        match upstream {
            DnsUpstream::Plain { address, port } => {
                self.forward_plain(&query_bytes, *address, *port, timeout_duration).await
            }
            DnsUpstream::Tls { .. } => {
                self.forward_tls(&query_bytes, upstream, timeout_duration).await
            }
        }
    }

    /// Each query gets its own ephemeral UDP socket — eliminates ID collision race
    async fn forward_plain(
        &self,
        query_bytes: &[u8],
        address: std::net::IpAddr,
        port: u16,
        timeout_duration: Duration,
    ) -> Result<Message, ForwardError> {
        let remote = SocketAddr::new(address, port);
        // Bind ephemeral socket — OS assigns random port
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(ForwardError::Io)?;

        let result = timeout(timeout_duration, async {
            socket.send_to(query_bytes, remote).await?;
            let mut buf = vec![0u8; MAX_DNS_SIZE];
            let (len, _) = socket.recv_from(&mut buf).await?;
            buf.truncate(len);
            drop(socket);
            Ok::<_, std::io::Error>(buf)
        }).await;

        match result {
            Ok(Ok(response_bytes)) => {
                Message::from_vec(&response_bytes)
                    .map_err(|e| ForwardError::Decode(e.to_string()))
            }
            Ok(Err(e)) => {
                // UDP failed, try TCP
                warn!("UDP query to {} failed: {}, trying TCP", remote, e);
                self.forward_tcp(query_bytes, remote, timeout_duration).await
            }
            Err(_) => Err(ForwardError::Timeout),
        }
    }

    async fn forward_tcp(
        &self,
        query_bytes: &[u8],
        remote: SocketAddr,
        timeout_duration: Duration,
    ) -> Result<Message, ForwardError> {
        timeout(timeout_duration, async {
            let mut stream = tokio::net::TcpStream::connect(remote).await
                .map_err(ForwardError::Io)?;

            let len = (query_bytes.len() as u16).to_be_bytes();
            let mut wire = Vec::with_capacity(2 + query_bytes.len());
            wire.extend_from_slice(&len);
            wire.extend_from_slice(query_bytes);

            use tokio::io::AsyncWriteExt;
            stream.write_all(&wire).await.map_err(ForwardError::Io)?;

            use tokio::io::AsyncReadExt;
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.map_err(ForwardError::Io)?;
            let response_len = u16::from_be_bytes(len_buf) as usize;

            let mut response_buf = vec![0u8; response_len];
            stream.read_exact(&mut response_buf).await.map_err(ForwardError::Io)?;

            Message::from_vec(&response_buf)
                .map_err(|e| ForwardError::Decode(e.to_string()))
        }).await
        .map_err(|_| ForwardError::Timeout)?
    }

    async fn forward_tls(
        &self,
        query_bytes: &[u8],
        upstream: &DnsUpstream,
        timeout_duration: Duration,
    ) -> Result<Message, ForwardError> {
        let response_bytes = self.dot_manager
            .send_query(upstream, query_bytes, timeout_duration)
            .await
            .map_err(|e| ForwardError::Dot(e.to_string()))?;

        Message::from_vec(&response_bytes)
            .map_err(|e| ForwardError::Decode(e.to_string()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("Query encoding failed: {0}")]
    Encode(String),
    #[error("Response decoding failed: {0}")]
    Decode(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Timeout")]
    Timeout,
    #[error("DoT error: {0}")]
    Dot(String),
    #[error("Forwarder not initialized")]
    NotInitialized,
}
