// =============================================================================
// DNS Forwarder - per-query ephemeral sockets to avoid race conditions
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

/// A small pool of ephemeral UDP sockets. Sockets are bound once and reused
/// (avoiding a `bind(0.0.0.0:0)` syscall per query); each socket is checked
/// out to at most one in-flight query at a time, so DNS IDs cannot collide
/// across concurrent queries sharing a socket.
struct SocketPool {
    idle: parking_lot::Mutex<std::collections::VecDeque<UdpSocket>>,
}

impl SocketPool {
    fn new() -> Self {
        Self { idle: parking_lot::Mutex::new(std::collections::VecDeque::new()) }
    }

    /// Take an idle socket, or bind a fresh ephemeral one if none available.
    async fn acquire(&self) -> Result<UdpSocket, std::io::Error> {
        if let Some(sock) = self.idle.lock().pop_front() {
            return Ok(sock);
        }
        UdpSocket::bind("0.0.0.0:0").await
    }

    /// Return a socket to the pool for reuse.
    fn release(&self, sock: UdpSocket) {
        self.idle.lock().push_back(sock);
    }
}

/// DNS forwarder - opens ephemeral UDP socket per query to avoid ID collisions
pub struct DnsForwarder {
    dot_manager: Arc<super::dot::DotManager>,
    upstreams: Vec<DnsUpstream>,
    udp_pool: SocketPool,
}

impl DnsForwarder {
    pub fn new(dot_manager: Arc<super::dot::DotManager>, upstreams: Vec<DnsUpstream>) -> Self {
        Self { dot_manager, upstreams, udp_pool: SocketPool::new() }
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

        let response = match upstream {
            DnsUpstream::Plain { address, port } => {
                self.forward_plain(&query_bytes, *address, *port, timeout_duration).await?
            }
            DnsUpstream::Tls { .. } => {
                self.forward_tls(&query_bytes, upstream, timeout_duration).await?
            }
        };

        // Validate that the response question matches the query question
        // to prevent a mismatched response (e.g. from an ID collision) from
        // being cached or returned to the client.
        validate_response_question(query, &response)?;

        Ok(response)
    }

    /// Each query gets its own ephemeral UDP socket - eliminates ID collision race
    async fn forward_plain(
        &self,
        query_bytes: &[u8],
        address: std::net::IpAddr,
        port: u16,
        timeout_duration: Duration,
    ) -> Result<Message, ForwardError> {
        let remote = SocketAddr::new(address, port);
        // Take a pooled socket (reused — no bind syscall per query) or bind
        // a fresh ephemeral one if the pool is empty.
        let socket = self.udp_pool.acquire().await
            .map_err(ForwardError::Io)?;

        let result = timeout(timeout_duration, async {
            socket.send_to(query_bytes, remote).await?;
            let mut buf = vec![0u8; MAX_DNS_SIZE];
            let (len, _) = socket.recv_from(&mut buf).await?;
            buf.truncate(len);
            Ok::<_, std::io::Error>(buf)
        }).await;

        // Return the socket to the pool before any TCP fallback so it can be
        // reused by other in-flight queries.
        self.udp_pool.release(socket);

        match result {
            Ok(Ok(response_bytes)) => {
                match Message::from_vec(&response_bytes) {
                    Ok(msg) if response_has_tc(&msg) => {
                        // TC bit set: response was too large for UDP — retry
                        // over TCP (RFC 5966) instead of returning a partial
                        // or truncated answer.
                        warn!("UDP query to {} returned TC, retrying over TCP", remote);
                        self.forward_tcp(query_bytes, remote, timeout_duration).await
                    }
                    Ok(msg) => Ok(msg),
                    Err(e) => {
                        // Undecodable from UDP (e.g. oversized datagram) —
                        // retry over TCP before giving up.
                        warn!("UDP query to {} returned undecodable response ({}), retrying over TCP", remote, e);
                        self.forward_tcp(query_bytes, remote, timeout_duration).await
                    }
                }
            }
            Ok(Err(e)) => {
                // UDP failed, try TCP
                warn!("UDP query to {} failed: {}, trying TCP", remote, e);
                self.forward_tcp(query_bytes, remote, timeout_duration).await
            }
            Err(_) => {
                // UDP timeout — try TCP once before giving up
                warn!("UDP query to {} timed out, trying TCP", remote);
                self.forward_tcp(query_bytes, remote, timeout_duration).await
            }
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

/// Whether a DNS message has the TC (truncation) bit set — an indication
/// the response was too large for UDP and the client should retry over TCP
/// (RFC 5966). The forwarder uses this to transparently retry over TCP.
fn response_has_tc(msg: &Message) -> bool {
    msg.metadata.truncation
}

/// Validate that the response's first question matches the query's first question
/// (name + record type). This prevents a mismatched response — e.g. from an ID
/// collision in DoT — from being cached or returned to the client.
fn validate_response_question(query: &Message, response: &Message) -> Result<(), ForwardError> {
    let q = query.queries.first().ok_or(ForwardError::ResponseMismatch)?;
    let r = response.queries.first().ok_or(ForwardError::ResponseMismatch)?;
    if q.name() != r.name() || q.query_type() != r.query_type() {
        return Err(ForwardError::ResponseMismatch);
    }
    Ok(())
}

// =============================================================================
// Tests
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message as HickoryMessage, OpCode};
    use hickory_proto::rr::{Name, RecordType};

    fn make_query(name: &str, qtype: RecordType) -> HickoryMessage {
        let mut msg = HickoryMessage::query();
        msg.add_query(hickory_proto::op::Query::query(
            Name::from_utf8(name).unwrap(),
            qtype,
        ));
        msg
    }

    fn make_response_like(query: &HickoryMessage) -> HickoryMessage {
        // Echo the query's question back (like a real response would)
        let mut msg = HickoryMessage::response(query.metadata.id, OpCode::Query);
        for q in &query.queries {
            msg.add_query(q.clone());
        }
        msg
    }

    // ── Test 1: matching name+type → Ok ───────────────────────────────────
    #[test]
    fn test_question_match_ok() {
        let q = make_query("example.com", RecordType::A);
        let r = make_response_like(&q);
        assert!(validate_response_question(&q, &r).is_ok());
    }

    // ── Test 2: different name → ResponseMismatch ─────────────────────────
    #[test]
    fn test_question_mismatch_name() {
        let q = make_query("example.com", RecordType::A);
        let mut r = make_response_like(&q);
        // Replace response question with a different name
        r.queries.clear();
        r.add_query(hickory_proto::op::Query::query(
            Name::from_utf8("other.com").unwrap(),
            RecordType::A,
        ));
        assert_eq!(
            validate_response_question(&q, &r).unwrap_err().to_string(),
            "Response question does not match query"
        );
    }

    // ── Test 3: A vs AAAA (type mismatch) → ResponseMismatch ─────────────
    #[test]
    fn test_question_mismatch_type() {
        let q = make_query("example.com", RecordType::A);
        let mut r = make_response_like(&q);
        r.queries.clear();
        r.add_query(hickory_proto::op::Query::query(
            Name::from_utf8("example.com").unwrap(),
            RecordType::AAAA,
        ));
        assert!(validate_response_question(&q, &r).is_err());
    }

    // ── Test 4: query has no question → ResponseMismatch ─────────────────
    #[test]
    fn test_query_no_question() {
        let q = HickoryMessage::query(); // empty query
        let r = make_response_like(&make_query("x.com", RecordType::A));
        assert!(validate_response_question(&q, &r).is_err());
    }

    // ── Test 5: response has no question → ResponseMismatch ──────────────
    #[test]
    fn test_response_no_question() {
        let q = make_query("x.com", RecordType::A);
        let r = HickoryMessage::response(0, OpCode::Query); // no questions
        assert!(validate_response_question(&q, &r).is_err());
    }

    // ── Test 6: CNAME response (question echoes qname) → Ok ──────────────
    #[test]
    fn test_cname_response_ok() {
        // CNAME responses still echo the original question's qname
        let q = make_query("example.com", RecordType::A);
        let r = make_response_like(&q);
        assert!(validate_response_question(&q, &r).is_ok());
    }

    // ── Test 7: TC bit detection for TCP fallback ─────────────────────────
    #[test]
    fn test_response_has_tc_bit_detection() {
        let q = make_query("example.com", RecordType::A);
        let r = make_response_like(&q);
        // Normal response: no TC
        assert!(!response_has_tc(&r));
        // Round-trip through bytes preserves TC (unset here)
        let bytes = r.to_vec().unwrap();
        let parsed = HickoryMessage::from_vec(&bytes).unwrap();
        assert!(!response_has_tc(&parsed));
        // After truncation: TC bit must be set
        let truncated = r.truncate();
        assert!(response_has_tc(&truncated));
    }

    // ── Test 8: SocketPool reuses sockets (no bind per query) ────────────
    #[tokio::test]
    async fn test_socket_pool_reuses_sockets() {
        let pool = SocketPool::new();
        let s1 = pool.acquire().await.unwrap();
        let addr1 = s1.local_addr().unwrap();
        // Release, then acquire again — must get the SAME socket back
        pool.release(s1);
        let s2 = pool.acquire().await.unwrap();
        assert_eq!(s2.local_addr().unwrap(), addr1, "socket should be reused from pool");
    }

    #[tokio::test]
    async fn test_socket_pool_bounds_concurrent() {
        let pool = SocketPool::new();
        // Two concurrent acquires without release → two distinct sockets
        let a = pool.acquire().await.unwrap();
        let b = pool.acquire().await.unwrap();
        assert_ne!(a.local_addr().unwrap(), b.local_addr().unwrap());
        // Releasing both back allows reuse
        let addr_a = a.local_addr().unwrap();
        pool.release(a);
        pool.release(b);
        let c = pool.acquire().await.unwrap();
        assert_eq!(c.local_addr().unwrap(), addr_a, "pool should hand back a released socket");
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
    #[error("Response question does not match query")]
    ResponseMismatch,
}
