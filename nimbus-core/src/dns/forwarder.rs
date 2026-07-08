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

/// DNS forwarder - opens ephemeral UDP socket per query to avoid ID collisions
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
        // Bind ephemeral socket - OS assigns random port
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
