// =============================================================================
// Query Router
// =============================================================================

use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{
    Message, OpCode, ResponseCode,
};
use hickory_proto::rr::{RecordType, DNSClass, RData};
use tracing::{warn, debug};

use crate::AppState;
use crate::config::{BlockingMode, DnsUpstream};
use crate::blocking::BlockingEngine;
use crate::database::StoredQuery;

use crate::dns::cache::{CacheKey, CachedResponse, DnsCache};
use crate::dns::dot::DotManager;
use crate::dns::forwarder::DnsForwarder;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Query result
#[derive(Debug)]
pub enum QueryResult {
    Response(Vec<u8>),
    ServerFailure,
    Refused,
}

/// Routes and processes DNS queries
pub struct QueryRouter {
    state: Arc<AppState>,
    cache: Arc<DnsCache>,
    forwarder: DnsForwarder,
    rate_limiter: RateLimiter,
    blocking: Arc<BlockingEngine>,
}

impl QueryRouter {
    pub fn new(
        state: Arc<AppState>,
        cache: Arc<DnsCache>,
        dot_manager: Arc<DotManager>,
        blocking: Arc<BlockingEngine>,
    ) -> Self {
        let upstreams = state.config.read().dns.upstreams.clone();
        let rate_limit = state.config.read().dns.rate_limit;
        let forwarder = DnsForwarder::new(dot_manager, upstreams);
        Self {
            state,
            cache,
            forwarder,
            rate_limiter: RateLimiter::new(rate_limit),
            blocking,
        }
    }

    pub async fn init(&mut self) -> anyhow::Result<()> {
        self.forwarder.init().await
    }

    pub async fn route(&self, query: Message, client_addr: std::net::SocketAddr) -> QueryResult {
        let start = Instant::now();
        let id = query.metadata.id;

        let question = match query.queries.first() {
            Some(q) => q,
            None => return make_error_response(id, &query, ResponseCode::FormErr),
        };

        let domain = question.name().to_utf8();
        let qtype = question.query_type();

        debug!("Query: {} {} from {} (id={})", domain, qtype, client_addr, id);

        // Snapshot the live config values once per query — one read lock
        // instead of a separate read per lookup below. Values are still read
        // fresh on every query, so runtime changes (API / SIGHUP) take effect.
        let (blocking_mode, blocking_ip, query_log, upstreams) = {
            let cfg = self.state.config.read();
            (
                cfg.dns.blocking_mode,
                cfg.dns.blocking_ip,
                cfg.dns.query_log,
                cfg.dns.upstreams.clone(),
            )
        };

        // 1. Rate limiting
        if self.rate_limiter.is_rate_limited(&client_addr) {
            debug!("Rate limited: {} from {}", domain, client_addr);
            // Log with RateLimited status (7) so query stats reflect it
            self.log_query(query_log, id, &domain, qtype, &client_addr, 7, start.elapsed());
            return make_error_response(id, &query, ResponseCode::Refused);
        }

        // 2. Blocking check - in-memory (no SQLite per query)
        // Skip entirely when blocking is disabled (mode == Disabled)
        if blocking_applies(blocking_mode) && self.blocking.is_blocked(&domain) {
            debug!("Blocked: {}", domain);
            let response = make_blocked_response(id, &query, blocking_mode, qtype, blocking_ip);
            self.log_query(query_log, id, &domain, qtype, &client_addr, 1, start.elapsed());
            return response;
        }

        // 3. Cache lookup
        let cache_key = CacheKey {
            domain: domain.to_lowercase(),
            qtype: qtype.into(),
            qclass: DNSClass::IN.into(),
            dnssec_ok: query.edns.as_ref().map(|e| e.flags().dnssec_ok).unwrap_or(false),
            ecs_subnet: None,
        };

        if let Some(cached) = self.cache.get(&cache_key) {
            debug!("Cache hit: {} {} from {} (hits={})", domain, qtype, client_addr, cached.hits.load(std::sync::atomic::Ordering::Relaxed));
            self.log_query(query_log, id, &domain, qtype, &client_addr, 2, start.elapsed());
            // Rewrite response: update transaction ID + TTLs
            let mut resp = cached.data.to_vec();
            if resp.len() >= 2 {
                resp[0] = (id >> 8) as u8;
                resp[1] = (id & 0xFF) as u8;
            }
            // Decrement TTLs by elapsed time since caching (RFC 1035 §4.1.3)
            let elapsed_secs = cached.cached_at.elapsed().as_secs() as u32;
            if elapsed_secs > 0
                && let Ok(mut msg) = Message::from_vec(&resp) {
                    decrement_ttls(&mut msg, elapsed_secs);
                    if let Ok(updated) = msg.to_vec() {
                        resp = updated;
                    }
                }
            return QueryResult::Response(resp);
        }

        // 4. Forward to upstream — the WHOLE attempt (all upstreams, plus each
        // upstream's UDP→TCP fallback) is bounded by one overall deadline so
        // timeouts can't compound to tens of seconds when upstreams fail.
        let response = self
            .forward_attempt(&query, upstreams, DEFAULT_TIMEOUT, DEFAULT_TIMEOUT)
            .await;

        let response = match response {
            Some(response) => response,
            None => {
                warn!("All upstreams failed for {} {} from {}", domain, qtype, client_addr);
                self.log_query(query_log, id, &domain, qtype, &client_addr, 5, start.elapsed());
                return make_error_response(id, &query, ResponseCode::ServFail);
            }
        };

        let response_bytes = match response.to_vec() {
            Ok(b) => b,
            Err(_) => {
                self.log_query(query_log, id, &domain, qtype, &client_addr, 5, start.elapsed());
                return make_error_response(id, &query, ResponseCode::ServFail);
            }
        };

        // Compute cache TTL: min answer TTL, SOA TTL on negative
        // responses (RFC 2308), or 0 (no cache) on SERVFAIL.
        let elapsed_secs = start.elapsed().as_secs() as u32;
        let ttl = cache_ttl_secs(&response).saturating_sub(elapsed_secs);

        // Don't cache SERVFAIL or zero-TTL responses
        if ttl > 0 {
            let cached = CachedResponse {
                data: Arc::from(response_bytes.as_slice()),
                cached_at: Instant::now(),
                original_ttl: ttl,
                ttl,
                qtype: qtype.into(),
                qclass: DNSClass::IN.into(),
                hits: Default::default(),
            };
            self.cache.insert(cache_key.clone(), cached);
        }

        debug!("Forwarded {} {} in {:?} (cached_ttl={}s)",
            domain, qtype, start.elapsed(), ttl);

        self.log_query(query_log, id, &domain, qtype, &client_addr, 3, start.elapsed());
        QueryResult::Response(response_bytes)
    }

    /// Try every configured upstream for `query`, returning the first success.
    /// The whole attempt is bounded by an `overall` deadline so per-attempt
    /// UDP→TCP fallback and multiple upstreams cannot compound the worst-case
    /// latency when upstreams are slow or failing. Each upstream gets at most
    /// `per_attempt` (capped by the remaining overall budget), so a fast
    /// failing upstream still leaves time for the next one.
    async fn forward_attempt(
        &self,
        query: &Message,
        upstreams: Vec<DnsUpstream>,
        per_attempt: Duration,
        overall: Duration,
    ) -> Option<Message> {
        let start = Instant::now();
        let deadline = Instant::now() + overall;
        let attempt = async {
            for upstream in &upstreams {
                if Instant::now() >= deadline {
                    return None;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                let budget = per_attempt.min(remaining);
                match self.forwarder.forward(query, upstream, budget).await {
                    Ok(response) => {
                        debug!("Upstream {} answered in {:?}",
                            upstream_label(upstream), start.elapsed());
                        return Some(response);
                    }
                    Err(e) => {
                        debug!("Upstream {} failed: {} ({:?})",
                            upstream_label(upstream), e, start.elapsed());
                    }
                }
            }
            None
        };
        // The outer timeout is the hard cap; cancelling the attempt drops any
        // in-flight forward (safe: sockets and streams are closed on drop; a
        // DoT query left in the pipeline is swept by its stale-pending timer).
        tokio::time::timeout(overall, attempt).await.ok().flatten()
    }

    #[allow(clippy::too_many_arguments)]
    fn log_query(&self, query_log: bool, _id: u16, domain: &str, qtype: RecordType, client: &std::net::SocketAddr, status: i32, elapsed: Duration) {
        let stored = StoredQuery {
            timestamp: chrono::Utc::now().timestamp(),
            domain: domain.to_string(),
            client: Some(client.ip().to_string()),
            forward: None,
            query_type: u16::from(qtype) as i32, // Fix: was `id as i32` (wrong!)
            status: crate::database::QueryStatus::from_i32(status),
            reply_time: None,
            reply_type: 0,
            flags: 0,
            interface: None,
            elapsed_ms: Some(elapsed.as_millis() as i64),
            adlist_id: None,
            cache_id: None,
            regex_id: None,
            upstream_id: None,
        };
        // Store query via background writer (if query_log is enabled)
        if query_log {
            if let Some(ref writer) = self.state.db_writer {
                if let Err(e) = writer.store(stored) {
                    // Queue full (backpressure) or writer stopped — the query
                    // log entry is dropped. Warn (not debug) so silent data
                    // loss under high QPS is visible in logs.
                    warn!("Failed to queue query (dropped from log): {}", e);
                }
            } else {
                // Fallback: direct DB write (blocking)
                if let Err(e) = self.state.database.nimbus_db.store_query(stored) {
                    warn!("Failed to store query: {}", e);
                }
            }
        }

        // Record in overTime for real-time stats
        let qs = crate::database::QueryStatus::from_i32(status);
        self.state.over_time.record_query(
            chrono::Utc::now().timestamp(),
            Some(&client.ip().to_string()),
            qs,
        );
    }
}

/// Whether blocking should be applied for the given mode.
/// When `Disabled`, blocked domains are forwarded normally instead of
/// being answered with a blocking response.
fn blocking_applies(mode: BlockingMode) -> bool {
    mode != BlockingMode::Disabled
}

/// Compute the cache TTL (seconds) for an upstream response.
/// - Positive answers: min TTL across answers (minus elapsed, caller handles).
/// - Negative responses (NXDOMAIN/NODATA): SOA TTL from authority (RFC 2308).
/// - SERVFAIL: 0 (must not be cached — a transient upstream failure should
///   not be served to clients for 60s).
fn cache_ttl_secs(response: &Message) -> u32 {
    if response.metadata.response_code == ResponseCode::ServFail {
        return 0;
    }
    if !response.answers.is_empty() {
        return response.answers.iter().map(|r| r.ttl).min().unwrap_or(0);
    }
    // Negative response: use SOA TTL (or 0 if absent → don't cache)
    response.authorities.iter()
        .filter(|r| r.record_type() == RecordType::SOA)
        .map(|r| r.ttl)
        .min()
        .unwrap_or(0)
}

/// Decrement TTLs across answers, authorities and additionals by `elapsed`
/// seconds (saturating at 0), per RFC 1035 §4.1.3. All three sections must
/// age so the client sees consistent TTLs.
fn decrement_ttls(msg: &mut Message, elapsed: u32) {
    for rec in msg.answers.iter_mut().chain(msg.authorities.iter_mut()).chain(msg.additionals.iter_mut()) {
        rec.ttl = rec.ttl.saturating_sub(elapsed);
    }
}

fn make_blocked_response(id: u16, query: &Message, mode: BlockingMode, qtype: RecordType, blocking_ip: std::net::IpAddr) -> QueryResult {
    let mut response = Message::error_msg(id, OpCode::Query, ResponseCode::NoError);
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;

    for q in &query.queries {
        response.add_query(q.clone());
    }

    let domain_name = query.queries.first().map(|q| q.name().clone());

    let make_a_record = |name: hickory_proto::rr::Name| -> hickory_proto::rr::Record {
        hickory_proto::rr::Record::from_rdata(name, 2, RData::A(hickory_proto::rr::rdata::A::new(0, 0, 0, 0)))
    };
    let make_aaaa_record = |name: hickory_proto::rr::Name| -> hickory_proto::rr::Record {
        hickory_proto::rr::Record::from_rdata(name, 2, RData::AAAA(
            hickory_proto::rr::rdata::AAAA::new(0, 0, 0, 0, 0, 0, 0, 0),
        ))
    };

    match mode {
        BlockingMode::Null => {
            if qtype == RecordType::A {
                if let Some(ref name) = domain_name {
                    response.add_answer(make_a_record(name.clone()));
                }
            } else if qtype == RecordType::AAAA
                && let Some(ref name) = domain_name {
                    response.add_answer(make_aaaa_record(name.clone()));
                }
        }
        BlockingMode::Nxdomain => {
            response.metadata.response_code = ResponseCode::NXDomain;
        }
        BlockingMode::Refused => {
            response.metadata.response_code = ResponseCode::Refused;
        }
        BlockingMode::Nodata => {}
        BlockingMode::Ip => {
            if (qtype == RecordType::A || qtype == RecordType::AAAA)
                && let Some(ref name) = domain_name {
                    if qtype == RecordType::A {
                        match blocking_ip {
                            std::net::IpAddr::V4(ipv4) => {
                                let octets = ipv4.octets();
                                response.add_answer(hickory_proto::rr::Record::from_rdata(
                                    name.clone(), 2,
                                    RData::A(hickory_proto::rr::rdata::A::new(octets[0], octets[1], octets[2], octets[3])),
                                ));
                            }
                            std::net::IpAddr::V6(_) => {
                                // IPv6 blocking IP for A query - use NULL
                                response.add_answer(make_a_record(name.clone()));
                            }
                        }
                    } else {
                        match blocking_ip {
                            std::net::IpAddr::V6(ipv6) => {
                                let segments = ipv6.segments();
                                response.add_answer(hickory_proto::rr::Record::from_rdata(
                                    name.clone(), 2,
                                    RData::AAAA(hickory_proto::rr::rdata::AAAA::new(
                                        segments[0], segments[1], segments[2], segments[3],
                                        segments[4], segments[5], segments[6], segments[7],
                                    )),
                                ));
                            }
                            std::net::IpAddr::V4(_) => {
                                // IPv4 blocking IP for AAAA query - use NULL
                                response.add_answer(make_aaaa_record(name.clone()));
                            }
                        }
                    }
                }
        }
        BlockingMode::Disabled => {}
    }

    // Add EDNS0 OPT pseudo-record for DNSSEC OK and UDP payload size
    add_edns0(&mut response);

    match response.to_vec() {
        Ok(bytes) => QueryResult::Response(bytes),
        Err(_) => make_error_response(id, query, ResponseCode::ServFail),
    }
}

fn make_error_response(id: u16, query: &Message, rcode: ResponseCode) -> QueryResult {
    let mut response = Message::error_msg(id, OpCode::Query, rcode);
    // Echo the question(s) back so strict clients can match the response
    // (RFC 1035 §4.1.3 — the response question must mirror the query).
    for q in &query.queries {
        response.add_query(q.clone());
    }
    // Add EDNS0 OPT pseudo-record
    add_edns0(&mut response);
    match response.to_vec() {
        Ok(bytes) => QueryResult::Response(bytes),
        Err(_) => QueryResult::ServerFailure,
    }
}

/// If a response exceeds the client's max UDP payload, truncate it with TC
/// bit set. `client_max_payload` is the payload size the CLIENT advertised in
/// its EDNS OPT record (or 512 if it sent none, per RFC 6891). Using the
/// response's own EDNS value would be wrong: a client with a 512-byte buffer
/// would receive an oversized datagram that its kernel silently truncates,
/// producing a broken (non-TC) DNS response.
/// Uses hickory-proto's built-in `Message::truncate()` which keeps questions
/// and sets the TC (Truncated) bit. The client will retry over TCP.
pub fn truncate_if_needed(msg: &Message, client_max_payload: usize) -> Option<Vec<u8>> {
    let max_size = client_max_payload.max(512);
    if let Ok(bytes) = msg.to_vec()
        && bytes.len() <= max_size {
            return None; // No truncation needed
        }
    // Use hickory-proto's built-in truncation (sets TC bit, keeps questions)
    let truncated = msg.truncate();
    truncated.to_vec().ok()
}

/// Add EDNS0 OPT pseudo-record to a DNS message.
/// Sets DNSSEC OK bit and maximum UDP payload size (4096 bytes).
fn add_edns0(msg: &mut Message) {
    use hickory_proto::op::Edns;
    let mut edns = Edns::new();
    // Set maximum UDP payload size (RFC 6891)
    edns.set_max_payload(4096);
    // Set DNSSEC OK (DO) bit
    edns.set_dnssec_ok(true);
    // Set version to 0
    edns.set_version(0);
    msg.set_edns(edns);
}

fn upstream_label(upstream: &DnsUpstream) -> String {
    match upstream {
        DnsUpstream::Plain { address, port } => format!("{}:{}", address, port),
        DnsUpstream::Tls { address, port, hostname } => format!("tls://{}:{}#{}", address, port, hostname),
    }
}

// =============================================================================
// Rate Limiter
// =============================================================================

use dashmap::DashMap;

struct RateLimiter {
    max_qps: u32,
    clients: DashMap<std::net::IpAddr, (u32, Instant)>,
    /// Last cleanup time - stale entries removed periodically
    last_cleanup: parking_lot::Mutex<Instant>,
}

impl RateLimiter {
    fn new(max_qps: u32) -> Self {
        Self {
            max_qps,
            clients: DashMap::new(),
            last_cleanup: parking_lot::Mutex::new(Instant::now()),
        }
    }
    fn is_rate_limited(&self, client: &std::net::SocketAddr) -> bool {
        let ip = client.ip();
        let now = Instant::now();

        // Periodic cleanup of stale entries (every 60s)
        {
            let mut last = self.last_cleanup.lock();
            if now.duration_since(*last) > Duration::from_secs(60) {
                self.clients.retain(|_ip, (_count, seen)| {
                    now.duration_since(*seen) < Duration::from_secs(2)
                });
                *last = now;
            }
        }

        let mut entry = self.clients.entry(ip).or_insert_with(|| (0, now));
        if now.duration_since(entry.1) > Duration::from_secs(1) {
            *entry = (1, now);
            false
        } else {
            entry.0 += 1;
            entry.0 > self.max_qps
        }
    }
}

// =============================================================================
// Tests
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::{Name, RecordType};

    fn query_a(domain: &str) -> Message {
        let mut msg = Message::query();
        msg.add_query(hickory_proto::op::Query::query(
            Name::from_utf8(domain).unwrap(),
            RecordType::A,
        ));
        msg
    }

    fn query_aaaa(domain: &str) -> Message {
        let mut msg = Message::query();
        msg.add_query(hickory_proto::op::Query::query(
            Name::from_utf8(domain).unwrap(),
            RecordType::AAAA,
        ));
        msg
    }

    fn decode_response(result: QueryResult) -> Message {
        match result {
            QueryResult::Response(bytes) => Message::from_vec(&bytes).unwrap(),
            _ => panic!("expected Response, got {:?}", result),
        }
    }

    // ── Test: blocking_applies respects Disabled mode ────────────────────
    #[test]
    fn test_blocking_applies_mode() {
        assert!(blocking_applies(BlockingMode::Null));
        assert!(blocking_applies(BlockingMode::Nxdomain));
        assert!(blocking_applies(BlockingMode::Refused));
        assert!(blocking_applies(BlockingMode::Nodata));
        assert!(blocking_applies(BlockingMode::Ip));
        assert!(!blocking_applies(BlockingMode::Disabled));
    }

    fn soa_record(ttl: u32) -> hickory_proto::rr::Record {
        use hickory_proto::rr::rdata::SOA;
        use hickory_proto::rr::{Name as RrName, RData};
        hickory_proto::rr::Record::from_rdata(
            RrName::from_utf8("example.com").unwrap(),
            ttl,
            RData::SOA(SOA::new(
                RrName::from_utf8("ns1.example.com").unwrap(),
                RrName::from_utf8("hostmaster.example.com").unwrap(),
                1, 3600, 600, 86400, ttl,
            )),
        )
    }

    // ── Test: negative responses use SOA TTL (RFC 2308) ─────────────────
    #[test]
    fn test_cache_ttl_uses_soa_on_negative() {
        // NXDOMAIN with SOA (TTL=300) in authority
        let mut msg = Message::response(1, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NXDomain;
        msg.add_authority(soa_record(300));
        assert_eq!(cache_ttl_secs(&msg), 300, "NXDOMAIN should use SOA TTL");

        // NODATA (NoError, no answers) with SOA (TTL=120)
        let mut nodata = Message::response(1, OpCode::Query);
        nodata.metadata.response_code = ResponseCode::NoError;
        nodata.add_authority(soa_record(120));
        assert_eq!(cache_ttl_secs(&nodata), 120, "NODATA should use SOA TTL");
    }

    // ── Test: SERVFAIL must not be cached ────────────────────────────────
    #[test]
    fn test_cache_ttl_servfail_not_cached() {
        let mut msg = Message::response(1, OpCode::Query);
        msg.metadata.response_code = ResponseCode::ServFail;
        assert_eq!(cache_ttl_secs(&msg), 0, "SERVFAIL must not be cached");
    }

    // ── Test: positive answers use min answer TTL ────────────────────────
    #[test]
    fn test_cache_ttl_positive_uses_min_answer() {
        use hickory_proto::rr::RData;
        let mut msg = Message::response(1, OpCode::Query);
        msg.add_answer(hickory_proto::rr::Record::from_rdata(
            Name::from_utf8("example.com").unwrap(),
            300,
            RData::A(hickory_proto::rr::rdata::A::new(1, 2, 3, 4)),
        ));
        msg.add_answer(hickory_proto::rr::Record::from_rdata(
            Name::from_utf8("example.com").unwrap(),
            120,
            RData::A(hickory_proto::rr::rdata::A::new(5, 6, 7, 8)),
        ));
        assert_eq!(cache_ttl_secs(&msg), 120, "min answer TTL wins");
    }

    // ── Test: empty response without SOA → no cache ─────────────────────
    #[test]
    fn test_cache_ttl_negative_without_soa_not_cached() {
        let mut msg = Message::response(1, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NXDomain;
        assert_eq!(cache_ttl_secs(&msg), 0, "negative response without SOA must not be cached");
    }

    // ── Test: TTL decrement applies to answers, authorities, additionals ─
    #[test]
    fn test_decrement_ttls_all_sections() {
        use hickory_proto::rr::RData;
        let mut msg = Message::response(1, OpCode::Query);
        msg.add_answer(hickory_proto::rr::Record::from_rdata(
            Name::from_utf8("a.example.com").unwrap(), 100,
            RData::A(hickory_proto::rr::rdata::A::new(1, 2, 3, 4)),
        ));
        msg.add_authority(hickory_proto::rr::Record::from_rdata(
            Name::from_utf8("ns.example.com").unwrap(), 200,
            RData::A(hickory_proto::rr::rdata::A::new(9, 9, 9, 9)),
        ));
        msg.add_additional(hickory_proto::rr::Record::from_rdata(
            Name::from_utf8("ns.example.com").unwrap(), 300,
            RData::A(hickory_proto::rr::rdata::A::new(5, 6, 7, 8)),
        ));

        decrement_ttls(&mut msg, 30);
        assert_eq!(msg.answers[0].ttl, 70, "answer TTL decremented");
        assert_eq!(msg.authorities[0].ttl, 170, "authority TTL decremented");
        assert_eq!(msg.additionals[0].ttl, 270, "additional TTL decremented");

        // Saturating: TTL smaller than elapsed → 0
        decrement_ttls(&mut msg, 1000);
        assert_eq!(msg.answers[0].ttl, 0);
        assert_eq!(msg.authorities[0].ttl, 0);
        assert_eq!(msg.additionals[0].ttl, 0);
    }

    // ── Test: error responses echo the question (B13) ────────────────────
    #[test]
    fn test_error_response_echoes_question() {
        let q = query_a("echo.example.com");
        let result = make_error_response(42, &q, ResponseCode::ServFail);
        let resp = decode_response(result);
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(resp.queries.len(), 1, "error response must echo the question");
        assert_eq!(
            resp.queries[0].name().to_utf8().trim_end_matches('.'),
            "echo.example.com"
        );
    }

    // ── Test: null + A → 0.0.0.0, NoError ────────────────────────────
    #[test]
    fn test_null_a() {
        let q = query_a("blocked.test");
        let result = make_blocked_response(
            1234, &q, BlockingMode::Null, RecordType::A,
            "0.0.0.0".parse().unwrap(),
        );
        let resp = decode_response(result);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        // Should have one A answer with 0.0.0.0
        assert_eq!(resp.answers.len(), 1);
        let ans = &resp.answers[0];
        assert_eq!(ans.record_type(), RecordType::A);
        if let RData::A(a) = &ans.data {
            assert_eq!(a.0, std::net::Ipv4Addr::new(0, 0, 0, 0));
        } else {
            panic!("expected A record");
        }
    }

    // ── Test 27: Null + AAAA → :: ────────────────────────────────────────
    #[test]
    fn test_null_aaaa() {
        let q = query_aaaa("blocked.test");
        let result = make_blocked_response(
            1, &q, BlockingMode::Null, RecordType::AAAA,
            "::".parse().unwrap(),
        );
        let resp = decode_response(result);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].record_type(), RecordType::AAAA);
    }

    // ── Test 28: NXDOMAIN code ───────────────────────────────────────────
    #[test]
    fn test_nxdomain() {
        let q = query_a("blocked.test");
        let result = make_blocked_response(
            1, &q, BlockingMode::Nxdomain, RecordType::A,
            "0.0.0.0".parse().unwrap(),
        );
        let resp = decode_response(result);
        assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(resp.answers.len(), 0);
    }

    // ── Test 29: Refused code ────────────────────────────────────────────
    #[test]
    fn test_refused() {
        let q = query_a("blocked.test");
        let result = make_blocked_response(
            1, &q, BlockingMode::Refused, RecordType::A,
            "0.0.0.0".parse().unwrap(),
        );
        let resp = decode_response(result);
        assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
    }

    // ── Test 30: Nodata → no answers, NoError ────────────────────────────
    #[test]
    fn test_nodata() {
        let q = query_a("blocked.test");
        let result = make_blocked_response(
            1, &q, BlockingMode::Nodata, RecordType::A,
            "0.0.0.0".parse().unwrap(),
        );
        let resp = decode_response(result);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 0);
    }

    // ── Test 31: IP mode + A + v4 IP → that IP ──────────────────────────
    #[test]
    fn test_ip_a_v4() {
        let q = query_a("blocked.test");
        let result = make_blocked_response(
            1, &q, BlockingMode::Ip, RecordType::A,
            "192.0.2.1".parse().unwrap(),
        );
        let resp = decode_response(result);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        if let RData::A(a) = &resp.answers[0].data {
            assert_eq!(a.0, std::net::Ipv4Addr::new(192, 0, 2, 1));
        } else {
            panic!("expected A record");
        }
    }

    // ── Test 32: IP mode + AAAA + v6 IP → that IP ─────────────────────────
    #[test]
    fn test_ip_aaaa_v6() {
        let q = query_aaaa("blocked.test");
        let result = make_blocked_response(
            1, &q, BlockingMode::Ip, RecordType::AAAA,
            "2001:db8::1".parse().unwrap(),
        );
        let resp = decode_response(result);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        if let RData::AAAA(a) = &resp.answers[0].data {
            assert_eq!(a.0, std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        } else {
            panic!("expected AAAA record");
        }
    }

    // ── Test 33: IP mode + family mismatch (A query + v6 IP) → NULL ──────
    #[test]
    fn test_ip_family_mismatch_a_v6() {
        let q = query_a("blocked.test");
        let result = make_blocked_response(
            1, &q, BlockingMode::Ip, RecordType::A,
            "2001:db8::1".parse().unwrap(), // v6 IP, but query is A (v4)
        );
        let resp = decode_response(result);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        // Should fall back to NULL (0.0.0.0)
        assert_eq!(resp.answers.len(), 1);
        if let RData::A(a) = &resp.answers[0].data {
            assert_eq!(a.0, std::net::Ipv4Addr::new(0, 0, 0, 0));
        } else {
            panic!("expected A record (NULL fallback)");
        }
    }

    // ── Test 34: forward_attempt is bounded by an OVERALL deadline ────────
    // A blackhole UDP endpoint accepts datagrams but never replies; TCP to the
    // same port is refused. Without an overall deadline, two such upstreams
    // would each burn the full per-attempt timeout (2× per_attempt); with the
    // deadline the attempt must give up at ~overall regardless of per_attempt.
    #[tokio::test]
    async fn test_forward_attempt_bounded_by_overall_deadline() {
        let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        blackhole.set_nonblocking(true).unwrap();
        let addr = blackhole.local_addr().unwrap();

        let cfg = crate::config::Config {
            dns: crate::config::DnsConfig {
                upstreams: vec![
                    crate::config::DnsUpstream::Plain { address: addr.ip(), port: addr.port() },
                    crate::config::DnsUpstream::Plain { address: addr.ip(), port: addr.port() },
                ],
                ..Default::default()
            },
            database: crate::config::DatabaseConfig {
                gravity_db: ":memory:".into(),
                nimbus_db: ":memory:".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let upstreams = cfg.dns.upstreams.clone();
        let db = crate::database::Database::open(&cfg.database).unwrap();
        let state = std::sync::Arc::new(crate::AppState::new(cfg, db));
        let blocking = std::sync::Arc::new(
            crate::blocking::BlockingEngine::load(&state.database.gravity, &state.config.read()).unwrap(),
        );
        let cache = std::sync::Arc::new(DnsCache::new(100));
        let dot = std::sync::Arc::new(DotManager::new());
        let router = QueryRouter::new(state, cache, dot, blocking);

        let query = query_a("deadline.test");
        let start = std::time::Instant::now();
        // per_attempt (1s) is far larger than the overall deadline (300ms);
        // the sequential per-upstream loop would take ~2s.
        let result = router
            .forward_attempt(&query, upstreams, Duration::from_secs(1), Duration::from_millis(300))
            .await;
        assert!(result.is_none(), "blackhole upstreams must yield no response");
        assert!(
            start.elapsed() < Duration::from_millis(900),
            "overall deadline must bound the attempt, took {:?}",
            start.elapsed()
        );
    }

    // ── RateLimiter: per-client QPS window ────────────────────────────────

    #[test]
    fn test_rate_limiter_allows_then_blocks_per_client() {
        let limiter = RateLimiter::new(2);
        let client: std::net::SocketAddr = "10.0.0.1:1234".parse().unwrap();
        assert!(!limiter.is_rate_limited(&client), "1st within window");
        assert!(!limiter.is_rate_limited(&client), "2nd within window");
        assert!(limiter.is_rate_limited(&client), "3rd within window must be limited");
        // A different client is not affected
        let other: std::net::SocketAddr = "10.0.0.2:1234".parse().unwrap();
        assert!(!limiter.is_rate_limited(&other));
    }

    #[test]
    fn test_rate_limiter_single_slot() {
        // max_qps = 1 → the 2nd call in the same window is limited
        let limiter = RateLimiter::new(1);
        let client: std::net::SocketAddr = "10.0.0.1:1234".parse().unwrap();
        assert!(!limiter.is_rate_limited(&client));
        assert!(limiter.is_rate_limited(&client));
    }
}
