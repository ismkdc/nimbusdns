// =============================================================================
// DNS Listener
// =============================================================================

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hickory_proto::op::{Message, OpCode, ResponseCode};
use tokio::net::{UdpSocket, TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{info, error, debug};

use crate::dns::router::{QueryRouter, QueryResult, truncate_if_needed};

const MAX_DNS_SIZE: usize = 4096;
/// How long a TCP client may be idle before its connection is dropped.
/// Prevents a client that connects and sends nothing from holding a
/// spawned task + fd open indefinitely (resource-exhaustion DoS).
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Bounds the number of concurrent in-flight queries. Guards against a
/// flood of UDP datagrams or TCP connections spawning an unbounded number
/// of tokio tasks (the `max_concurrent_queries` config knob).
#[derive(Clone)]
pub struct QueryLimiter {
    sem: Arc<Semaphore>,
}

impl QueryLimiter {
    fn new(max_concurrent: usize) -> Self {
        // `max(1)` so a zero/disabled limit never deadlocks the server to 0.
        Self {
            sem: Arc::new(Semaphore::new(max_concurrent.max(1))),
        }
    }

    /// Try to reserve a slot. Returns `None` when at capacity; the caller
    /// should drop the request rather than queue it unboundedly.
    fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        self.sem.clone().try_acquire_owned().ok()
    }
}

/// Read a length-prefixed DNS message ([2-byte len][payload]) from a TCP
/// stream. Returns `TimedOut` when nothing arrives within `IDLE_TIMEOUT`,
/// `InvalidData` for a zero or oversized length prefix.
async fn read_dns_message(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    read_dns_message_inner(stream, IDLE_TIMEOUT).await
}

/// Core length-prefixed read with an explicit idle timeout (testable with a
/// short duration).
async fn read_dns_message_inner(
    stream: &mut TcpStream,
    idle: std::time::Duration,
) -> io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    let result = tokio::time::timeout(idle, async {
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let query_len = u16::from_be_bytes(len_buf) as usize;
        if query_len == 0 || query_len > MAX_DNS_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid DNS message length",
            ));
        }
        let mut query_buf = vec![0u8; query_len];
        stream.read_exact(&mut query_buf).await?;
        Ok(query_buf)
    })
    .await;

    match result {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "TCP read timed out",
        )),
    }
}

/// Whether a response of `bytes_len` bytes needs truncation for a UDP client
/// whose EDNS max payload is `max_payload`. EDNS payloads are always >= 512
/// (RFC 6891), so anything <= 512 bytes can never require truncation.
fn needs_truncation(bytes_len: usize, max_payload: usize) -> bool {
    bytes_len > max_payload.max(512)
}

/// Start the DNS listener on the given address
pub async fn start(
    bind_addr: SocketAddr,
    router: Arc<QueryRouter>,
    max_concurrent_queries: usize,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    // Create UDP socket with SO_REUSEADDR for fast restart
    let udp_socket = {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(bind_addr),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_reuse_address(true)?;
        socket.bind(&socket2::SockAddr::from(bind_addr))?;
        socket.set_nonblocking(true)?;
        let std_socket = std::net::UdpSocket::from(socket);
        Arc::new(UdpSocket::from_std(std_socket)?)
    };
    info!("DNS UDP listener bound to {} (SO_REUSEADDR)", bind_addr);

    let tcp_listener = TcpListener::bind(bind_addr).await?;
    info!("DNS TCP listener bound to {}", bind_addr);

    let sock_udp = udp_socket.clone();
    let rtr_udp = router.clone();
    let rtr_tcp = router;
    let limiter = Arc::new(QueryLimiter::new(max_concurrent_queries));

    // Run UDP and TCP concurrently
    let udp_shutdown = shutdown_rx.clone();
    let udp_limiter = limiter.clone();
    tokio::spawn(async move {
        handle_udp(sock_udp, rtr_udp, udp_limiter, udp_shutdown).await;
    });
    tokio::spawn(async move {
        handle_tcp(tcp_listener, rtr_tcp, limiter, shutdown_rx).await;
    });

    Ok(())
}

async fn handle_udp(
    socket: Arc<UdpSocket>,
    router: Arc<QueryRouter>,
    limiter: Arc<QueryLimiter>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let mut buf = vec![0u8; MAX_DNS_SIZE];

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, src)) => {
                        // Bound concurrent queries: under extreme load the
                        // packet is dropped instead of spawning unbounded tasks.
                        let Some(_permit) = limiter.try_acquire() else {
                            debug!("Concurrency limit reached, dropping UDP query from {}", src);
                            continue;
                        };
                        let data = buf[..len].to_vec();
                        let sock = socket.clone();
                        let rtr = router.clone();
                        tokio::spawn(async move {
                            process_udp_query(sock, data, src, rtr).await.ok();
                            drop(_permit);
                        });
                    }
                    Err(e) => {
                        error!("UDP recv error: {}", e);
                        break;
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("UDP listener shutting down gracefully");
                break;
            }
        }
    }
}

async fn process_udp_query(
    socket: Arc<UdpSocket>,
    data: Vec<u8>,
    src: SocketAddr,
    router: Arc<QueryRouter>,
) -> Result<(), Box<dyn std::error::Error>> {
    let query = Message::from_vec(&data)?;
    let id = query.metadata.id;
    // Client's advertised EDNS payload size (RFC 6891): 512 if no EDNS.
    let client_max_payload = query.edns.as_ref().map(|e| e.max_payload()).unwrap_or(512) as usize;

    let result = router.route(query, src).await;

    match result {
        QueryResult::Response(mut bytes) => {
            // Fast path: responses <= 512 bytes (RFC 6891 minimum EDNS payload)
            // can never require truncation, so skip the parse entirely.
            if needs_truncation(bytes.len(), client_max_payload) {
                let msg = Message::from_vec(&bytes).ok();
                if let Some(ref msg) = msg
                    && let Some(truncated) = truncate_if_needed(msg, client_max_payload) {
                        bytes = truncated;
                    }
            }
            socket.send_to(&bytes, src).await?;
        }
        QueryResult::ServerFailure => {
            let msg = Message::error_msg(id, OpCode::Query, ResponseCode::ServFail);
            if let Ok(bytes) = msg.to_vec() {
                socket.send_to(&bytes, src).await?;
            }
        }
        QueryResult::Refused => {
            let msg = Message::error_msg(id, OpCode::Query, ResponseCode::Refused);
            if let Ok(bytes) = msg.to_vec() {
                socket.send_to(&bytes, src).await?;
            }
        }
    }
    Ok(())
}

async fn handle_tcp(
    listener: TcpListener,
    router: Arc<QueryRouter>,
    limiter: Arc<QueryLimiter>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    use tokio::io::AsyncWriteExt;

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((mut stream, src)) => {
                        // Bound concurrent connections: at capacity the new
                        // connection is dropped (TCP clients will retry).
                        let Some(_permit) = limiter.try_acquire() else {
                            debug!("Concurrency limit reached, dropping TCP connection from {}", src);
                            continue;
                        };
                        let rtr = router.clone();
                        tokio::spawn(async move {
                            // Read with an idle timeout so a silent client
                            // cannot hold the task + fd open forever.
                            let query_buf = match read_dns_message(&mut stream).await {
                                Ok(buf) => buf,
                                Err(e) => {
                                    if e.kind() != io::ErrorKind::TimedOut {
                                        debug!("TCP read from {} failed: {}", src, e);
                                    }
                                    return;
                                }
                            };

                            match Message::from_vec(&query_buf) {
                                Ok(query) => {
                                    let id = query.metadata.id;
                                    let result = rtr.route(query, src).await;

                                    let response_bytes = match result {
                                        QueryResult::Response(b) => b,
                                        QueryResult::ServerFailure => {
                                            Message::error_msg(id, OpCode::Query, ResponseCode::ServFail)
                                                .to_vec().unwrap_or_default()
                                        }
                                        QueryResult::Refused => {
                                            Message::error_msg(id, OpCode::Query, ResponseCode::Refused)
                                                .to_vec().unwrap_or_default()
                                        }
                                    };

                                    let len = (response_bytes.len() as u16).to_be_bytes();
                                    stream.write_all(&len).await.ok();
                                    stream.write_all(&response_bytes).await.ok();
                                }
                                Err(e) => debug!("TCP query parse failed from {}: {}", src, e),
                            }
                        });
                    }
                    Err(e) => {
                        error!("TCP accept error: {}", e);
                        break;
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("TCP listener shutting down gracefully");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_needs_truncation_logic() {
        // Payload sizes from EDNS are always >= 512; below that never truncate
        assert!(!needs_truncation(512, 512));
        assert!(!needs_truncation(100, 4096));
        assert!(needs_truncation(600, 512));
        assert!(needs_truncation(4097, 4096));
    }

    #[test]
    fn test_udp_fast_path_skips_parse_for_small() {
        // A response at or below the RFC 6891 minimum payload (512) is never truncated
        assert!(!needs_truncation(512, 4096));
        assert!(!needs_truncation(512, 512));
    }

    #[test]
    fn test_truncation_uses_client_payload() {
        use hickory_proto::op::{Message, OpCode};
        use hickory_proto::rr::{Name, RData, Record};

        // Build a response larger than 512 bytes with an EDNS of its own (4096)
        let mut msg = Message::response(1, OpCode::Query);
        for i in 0..40 {
            let name = Name::from_utf8(format!("r{i}.example.com")).unwrap();
            msg.add_answer(Record::from_rdata(
                name,
                300,
                RData::A(hickory_proto::rr::rdata::A::new(i as u8, 0, 0, 1)),
            ));
        }
        let bytes = msg.to_vec().unwrap();
        assert!(bytes.len() > 512, "test response must exceed 512 bytes");

        // Client advertised 512 → response must be truncated (TC bit)
        assert!(truncate_if_needed(&msg, 512).is_some());
        // Client advertised 4096 → response fits, no truncation
        assert!(truncate_if_needed(&msg, 4096).is_none());
    }

    // ── QueryLimiter: bounds concurrent in-flight queries ───────────────

    #[test]
    fn test_query_limiter_bounds_concurrency() {
        let limiter = QueryLimiter::new(2);
        let p1 = limiter.try_acquire().expect("first permit");
        let p2 = limiter.try_acquire().expect("second permit");
        // Third acquire must be rejected while two permits are held
        assert!(limiter.try_acquire().is_none(), "limit of 2 must be enforced");
        drop(p1);
        // One permit released → acquire succeeds again
        assert!(limiter.try_acquire().is_some());
        drop(p2);
    }

    #[test]
    fn test_query_limiter_zero_becomes_one() {
        // A zero/disabled limit must still allow queries (never deadlock to 0)
        let limiter = QueryLimiter::new(0);
        assert!(limiter.try_acquire().is_some());
    }

    // ── read_dns_message: length-prefixed TCP DNS read ──────────────────

    #[tokio::test]
    async fn test_read_dns_message_ok() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_dns_message(&mut stream).await
        });
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        use tokio::io::AsyncWriteExt;
        client.write_all(&[0x00, 0x02, 0xAB, 0xCD]).await.unwrap();
        let body = server.await.unwrap().unwrap();
        assert_eq!(body, vec![0xAB, 0xCD]);
    }

    #[tokio::test]
    async fn test_read_dns_message_rejects_bad_length() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_dns_message(&mut stream).await
        });
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        use tokio::io::AsyncWriteExt;
        // Zero-length prefix is invalid
        client.write_all(&[0x00, 0x00]).await.unwrap();
        let res = server.await.unwrap();
        assert!(res.is_err(), "zero-length DNS message must be rejected");
    }

    #[tokio::test]
    async fn test_tcp_read_times_out_on_silent_client() {
        // A client that connects and sends nothing must not hold the server
        // task forever — the read is bounded by the idle timeout.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_dns_message_inner(&mut stream, std::time::Duration::from_millis(200)).await
        });
        // Client connects but sends nothing
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let result = server.await.unwrap();
        assert!(
            matches!(&result, Err(e) if e.kind() == std::io::ErrorKind::TimedOut),
            "silent TCP client must time out, got: {:?}",
            result
        );
    }
}
