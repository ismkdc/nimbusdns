// =============================================================================
// DNS Listener
// =============================================================================

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use dashmap::DashMap;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use tokio::net::{UdpSocket, TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{info, error, debug};

use crate::dns::router::{QueryRouter, QueryResult, truncate_if_needed};

const MAX_DNS_SIZE: usize = 4096;
/// Pause after a socket-level recv/accept error before trying again. Errors
/// such as ENOBUFS or EMFILE are transient; exiting the loop instead would
/// leave the process running with DNS silently dead.
const SOCKET_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);
/// How long a TCP client may be idle before its connection is dropped.
/// Prevents a client that connects and sends nothing from holding a
/// spawned task + fd open indefinitely (resource-exhaustion DoS).
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Most queries served on one TCP connection before it is closed (RFC 7766
/// pipelining is supported; this only bounds how long one client keeps a
/// connection slot).
const MAX_QUERIES_PER_TCP_CONN: usize = 100;

/// Bounds in-flight queries, globally and per client IP.
///
/// The global cap stops a flood from spawning unbounded tokio tasks (the
/// `max_concurrent_queries` knob). The per-client cap stops one client from
/// taking every slot: a query to an upstream that never answers holds its
/// slot for the whole upstream timeout, so without it a few hundred such
/// queries from one device left no slots for anyone else on the network.
#[derive(Clone)]
pub struct QueryLimiter {
    sem: Arc<Semaphore>,
    per_client: usize,
    in_flight: Arc<DashMap<IpAddr, usize>>,
}

/// One reserved query slot; releases the global and per-client counts on drop.
pub struct QueryPermit {
    _global: OwnedSemaphorePermit,
    ip: IpAddr,
    in_flight: Arc<DashMap<IpAddr, usize>>,
}

impl Drop for QueryPermit {
    fn drop(&mut self) {
        // Decrement, and drop the entry at zero so the map only holds
        // clients with queries in flight.
        self.in_flight.remove_if_mut(&self.ip, |_, n| {
            *n -= 1;
            *n == 0
        });
    }
}

impl QueryLimiter {
    fn new(max_concurrent: usize, per_client: usize) -> Self {
        // `max(1)` so a zero/disabled limit never deadlocks the server to 0.
        Self {
            sem: Arc::new(Semaphore::new(max_concurrent.max(1))),
            per_client: per_client.max(1),
            in_flight: Arc::new(DashMap::new()),
        }
    }

    /// Try to reserve a slot for a query from `ip`. Returns `None` when the
    /// server or that client is at capacity; the caller should drop the
    /// request rather than queue it unboundedly.
    fn try_acquire(&self, ip: IpAddr) -> Option<QueryPermit> {
        {
            let mut n = self.in_flight.entry(ip).or_insert(0);
            if *n >= self.per_client {
                return None;
            }
            *n += 1;
        }
        match self.sem.clone().try_acquire_owned() {
            Ok(global) => Some(QueryPermit { _global: global, ip, in_flight: self.in_flight.clone() }),
            Err(_) => {
                self.in_flight.remove_if_mut(&ip, |_, n| {
                    *n -= 1;
                    *n == 0
                });
                None
            }
        }
    }
}

/// A DNS message with QR=1 is a response. A server must not answer one:
/// replying to responses is how two servers end up bouncing packets at each
/// other forever, and it turns the server into a reflector.
fn is_response(msg: &Message) -> bool {
    msg.metadata.message_type == MessageType::Response
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
    max_concurrent_per_client: usize,
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
    let limiter = Arc::new(QueryLimiter::new(max_concurrent_queries, max_concurrent_per_client));

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
                        let Some(_permit) = limiter.try_acquire(src.ip()) else {
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
                        error!("UDP recv error (retrying): {}", e);
                        tokio::time::sleep(SOCKET_ERROR_BACKOFF).await;
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
    if is_response(&query) {
        debug!("Ignoring DNS response (QR=1) sent to us by {}", src);
        return Ok(());
    }
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
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((mut stream, src)) => {
                        // Bound concurrent connections: at capacity the new
                        // connection is dropped (TCP clients will retry).
                        let Some(permit) = limiter.try_acquire(src.ip()) else {
                            debug!("Concurrency limit reached, dropping TCP connection from {}", src);
                            continue;
                        };
                        let rtr = router.clone();
                        tokio::spawn(async move {
                            serve_tcp_connection(&mut stream, src, &rtr).await;
                            drop(permit);
                        });
                    }
                    Err(e) => {
                        error!("TCP accept error (retrying): {}", e);
                        tokio::time::sleep(SOCKET_ERROR_BACKOFF).await;
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

/// Answer queries on one TCP connection until the client closes it, goes
/// idle, or hits `MAX_QUERIES_PER_TCP_CONN`. Pipelined queries (RFC 7766
/// §6.2.1) are answered in order. Serving only the first query and closing
/// with the rest unread made the kernel send RST, which could destroy the
/// first answer too, so glibc-style A+AAAA over TCP failed outright.
async fn serve_tcp_connection(stream: &mut TcpStream, src: SocketAddr, router: &Arc<QueryRouter>) {
    use tokio::io::AsyncWriteExt;

    for _ in 0..MAX_QUERIES_PER_TCP_CONN {
        // Read with an idle timeout so a silent client cannot hold the
        // task + fd open forever.
        let query_buf = match read_dns_message(stream).await {
            Ok(buf) => buf,
            Err(e) => {
                if e.kind() != io::ErrorKind::TimedOut && e.kind() != io::ErrorKind::UnexpectedEof {
                    debug!("TCP read from {} failed: {}", src, e);
                }
                return;
            }
        };
        let query = match Message::from_vec(&query_buf) {
            Ok(q) => q,
            Err(e) => {
                debug!("TCP query parse failed from {}: {}", src, e);
                return;
            }
        };
        if is_response(&query) {
            debug!("Ignoring DNS response (QR=1) sent to us over TCP by {}", src);
            continue;
        }
        let id = query.metadata.id;
        let response_bytes = match router.route(query, src).await {
            QueryResult::Response(b) => b,
            QueryResult::ServerFailure => Message::error_msg(id, OpCode::Query, ResponseCode::ServFail)
                .to_vec()
                .unwrap_or_default(),
            QueryResult::Refused => Message::error_msg(id, OpCode::Query, ResponseCode::Refused)
                .to_vec()
                .unwrap_or_default(),
        };
        // Length prefix and body in one write so they cannot be split
        // across interleaved writes.
        let mut out = Vec::with_capacity(response_bytes.len() + 2);
        out.extend_from_slice(&(response_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&response_bytes);
        if stream.write_all(&out).await.is_err() {
            return;
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
        let limiter = QueryLimiter::new(2, 10);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let other: IpAddr = "10.0.0.2".parse().unwrap();
        let p1 = limiter.try_acquire(ip).expect("first permit");
        let p2 = limiter.try_acquire(other).expect("second permit");
        // Third acquire must be rejected while two permits are held
        assert!(limiter.try_acquire(ip).is_none(), "global limit of 2 must be enforced");
        drop(p1);
        // One permit released → acquire succeeds again
        assert!(limiter.try_acquire(ip).is_some());
        drop(p2);
    }

    #[test]
    fn test_query_limiter_zero_becomes_one() {
        // A zero/disabled limit must still allow queries (never deadlock to 0)
        let limiter = QueryLimiter::new(0, 0);
        assert!(limiter.try_acquire("10.0.0.1".parse().unwrap()).is_some());
    }

    #[test]
    fn test_query_limiter_caps_each_client() {
        // One client filling its share must not use up the global slots.
        let limiter = QueryLimiter::new(100, 3);
        let greedy: IpAddr = "10.0.0.66".parse().unwrap();
        let polite: IpAddr = "10.0.0.7".parse().unwrap();
        let held: Vec<_> = (0..3).map(|_| limiter.try_acquire(greedy).expect("within share")).collect();
        assert!(limiter.try_acquire(greedy).is_none(), "4th from the same client is refused");
        assert!(limiter.try_acquire(polite).is_some(), "another client still gets a slot");
        drop(held);
        assert!(limiter.try_acquire(greedy).is_some(), "share is released with the permits");
    }

    #[test]
    fn test_query_limiter_releases_per_client_count_when_global_is_full() {
        // A refusal by the global cap must not leak the client's count.
        let limiter = QueryLimiter::new(1, 5);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let held = limiter.try_acquire(a).unwrap();
        for _ in 0..20 {
            assert!(limiter.try_acquire(b).is_none());
        }
        drop(held);
        assert!(limiter.in_flight.is_empty(), "no stale per-client entries: {:?}", limiter.in_flight);
        let _ = (0..5).map(|_| limiter.try_acquire(b)).collect::<Vec<_>>();
    }

    #[test]
    fn test_query_limiter_map_empties_after_release() {
        let limiter = QueryLimiter::new(10, 10);
        let ps: Vec<_> = (1..=5)
            .map(|i| limiter.try_acquire(format!("10.0.0.{i}").parse().unwrap()).unwrap())
            .collect();
        assert_eq!(limiter.in_flight.len(), 5);
        drop(ps);
        assert!(limiter.in_flight.is_empty());
    }

    // ── QR=1 and TCP pipelining against a real router ────────────────────

    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A one-socket upstream that answers every A query with 10.9.9.9.
    async fn fake_upstream() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                let Ok(q) = Message::from_vec(&buf[..n]) else { continue };
                let mut r = Message::response(q.metadata.id, OpCode::Query);
                r.metadata.authoritative = true; // the router must clear this
                r.metadata.recursion_desired = true;
                for query in &q.queries {
                    r.add_query(query.clone());
                    r.add_answer(Record::from_rdata(
                        query.name().clone(),
                        300,
                        RData::A("10.9.9.9".parse().unwrap()),
                    ));
                }
                let _ = sock.send_to(&r.to_vec().unwrap(), from).await;
            }
        });
        addr
    }

    async fn test_router() -> Arc<QueryRouter> {
        let up = fake_upstream().await;
        let cfg = crate::config::Config {
            dns: crate::config::DnsConfig {
                upstreams: vec![crate::config::DnsUpstream::Plain { address: up.ip(), port: up.port() }],
                ..Default::default()
            },
            database: crate::config::DatabaseConfig {
                gravity_db: ":memory:".into(),
                nimbus_db: ":memory:".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let db = crate::database::Database::open(&cfg.database).unwrap();
        let state = Arc::new(crate::AppState::new(cfg, db));
        let blocking = Arc::new(
            crate::blocking::BlockingEngine::load(&state.database.gravity, &state.config.read()).unwrap(),
        );
        Arc::new(QueryRouter::new(
            state,
            Arc::new(crate::dns::cache::DnsCache::new(100)),
            Arc::new(crate::dns::dot::DotManager::new()),
            blocking,
        ))
    }

    fn query_wire(name: &str, id: u16) -> Vec<u8> {
        let mut m = Message::query();
        m.metadata.id = id;
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        m.to_vec().unwrap()
    }

    fn framed(msgs: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for m in msgs {
            out.extend_from_slice(&(m.len() as u16).to_be_bytes());
            out.extend_from_slice(m);
        }
        out
    }

    async fn read_framed(stream: &mut TcpStream) -> Option<Message> {
        let mut len = [0u8; 2];
        tokio::time::timeout(std::time::Duration::from_secs(3), stream.read_exact(&mut len)).await.ok()?.ok()?;
        let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut body).await.ok()?;
        Message::from_vec(&body).ok()
    }

    /// Spawn `serve_tcp_connection` behind a real listener; return its address.
    async fn tcp_server(router: Arc<QueryRouter>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, src)) = listener.accept().await {
                let r = router.clone();
                tokio::spawn(async move { serve_tcp_connection(&mut s, src, &r).await });
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_tcp_pipelined_queries_are_all_answered_in_order() {
        let addr = tcp_server(test_router().await).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        // glibc sends A and AAAA back to back on one connection; send five.
        let qs: Vec<_> = (0..5u16).map(|i| query_wire(&format!("pipe{i}.example."), 100 + i)).collect();
        c.write_all(&framed(&qs)).await.unwrap();
        for i in 0..5u16 {
            let r = read_framed(&mut c).await.unwrap_or_else(|| panic!("answer {i} missing"));
            assert_eq!(r.metadata.id, 100 + i, "answers come back in order");
            assert_eq!(r.answers.len(), 1);
        }
    }

    #[tokio::test]
    async fn test_tcp_connection_serves_sequential_queries() {
        let addr = tcp_server(test_router().await).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        for i in 0..3u16 {
            c.write_all(&framed(&[query_wire("seq.example.", i)])).await.unwrap();
            assert_eq!(read_framed(&mut c).await.expect("answer").metadata.id, i);
        }
    }

    #[tokio::test]
    async fn test_tcp_response_packets_are_ignored() {
        let addr = tcp_server(test_router().await).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        let mut resp = Message::from_vec(&query_wire("loop.example.", 7)).unwrap();
        resp.metadata.message_type = MessageType::Response;
        // A response, then a real query: only the query is answered.
        c.write_all(&framed(&[resp.to_vec().unwrap(), query_wire("real.example.", 8)])).await.unwrap();
        let r = read_framed(&mut c).await.expect("the real query is answered");
        assert_eq!(r.metadata.id, 8, "nothing was sent back for the QR=1 packet");
    }

    #[tokio::test]
    async fn test_udp_response_packets_are_ignored() {
        let router = test_router().await;
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let src = client.local_addr().unwrap();
        let mut resp = Message::from_vec(&query_wire("loop.example.", 9)).unwrap();
        resp.metadata.message_type = MessageType::Response;
        process_udp_query(server.clone(), resp.to_vec().unwrap(), src, router.clone()).await.unwrap();
        let mut buf = [0u8; 512];
        let got = tokio::time::timeout(std::time::Duration::from_millis(300), client.recv_from(&mut buf)).await;
        assert!(got.is_err(), "a QR=1 packet must get no reply");

        // A normal query on the same path is still answered.
        process_udp_query(server.clone(), query_wire("ok.example.", 10), src, router).await.unwrap();
        let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(3), client.recv_from(&mut buf))
            .await
            .expect("query answered")
            .unwrap();
        assert_eq!(Message::from_vec(&buf[..n]).unwrap().metadata.id, 10);
    }

    #[tokio::test]
    async fn test_forwarded_answers_are_recursive_not_authoritative() {
        // The fake upstream sets AA and leaves RA clear; as a forwarder we
        // must report RA=1 and AA=0, also when the answer comes from cache.
        let router = test_router().await;
        let src: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        for pass in ["upstream", "cache"] {
            let q = Message::from_vec(&query_wire("flags.example.", 11)).unwrap();
            let QueryResult::Response(bytes) = router.route(q, src).await else { panic!("no response ({pass})") };
            let r = Message::from_vec(&bytes).unwrap();
            assert!(r.metadata.recursion_available, "RA must be set ({pass})");
            assert!(!r.metadata.authoritative, "AA must be clear ({pass})");
        }
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
