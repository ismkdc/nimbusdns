// =============================================================================
// Query Router
// =============================================================================

use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{
    Message, OpCode, ResponseCode,
};
use hickory_proto::rr::{RecordType, DNSClass, RData};
use tracing::{error, debug, trace};

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
            None => return make_error_response(id, ResponseCode::FormErr),
        };

        let domain = question.name().to_utf8();
        let qtype = question.query_type();

        trace!("Query: {} {} from {}", domain, qtype, client_addr);

        // 1. Rate limiting
        if self.rate_limiter.is_rate_limited(&client_addr) {
            debug!("Rate limited: {} from {}", domain, client_addr);
            return make_error_response(id, ResponseCode::Refused);
        }

        // 2. Blocking check - in-memory (no SQLite per query)
        if self.blocking.is_blocked(&domain) {
            debug!("Blocked: {}", domain);
            let blocking_ip = self.state.config.read().dns.blocking_ip;
            let response = make_blocked_response(id, &query, self.state.config.read().dns.blocking_mode, qtype, blocking_ip);
            self.log_query(id, &domain, qtype, &client_addr, 1, start.elapsed());
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
            trace!("Cache hit: {} {}", domain, qtype);
            self.log_query(id, &domain, qtype, &client_addr, 2, start.elapsed());
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
                    for ans in &mut msg.answers {
                        if ans.ttl > elapsed_secs {
                            ans.ttl -= elapsed_secs;
                        } else {
                            ans.ttl = 0;
                        }
                    }
                    if let Ok(updated) = msg.to_vec() {
                        resp = updated;
                    }
                }
            return QueryResult::Response(resp);
        }

        // 4. Forward to upstream
        // Clone upstreams out of RwLock guard so the guard is dropped before .await
        let upstreams = self.state.config.read().dns.upstreams.clone();
        for upstream in &upstreams {
            match self.forwarder.forward(&query, upstream, DEFAULT_TIMEOUT).await {
                Ok(response) => {
                    // Check for truncation (TC bit) if response exceeds UDP max
                    let response_bytes = match truncate_if_needed(&response) {
                        Some(truncated) => truncated,
                        None => match response.to_vec() {
                            Ok(b) => b,
                            Err(_) => continue,
                        },
                    };

                    // Fix: rewrite TTL before caching (subtract elapsed time)
                    let elapsed_secs = start.elapsed().as_secs() as u32;
                    let ttl = response.answers.iter()
                        .map(|r| r.ttl.saturating_sub(elapsed_secs))
                        .min()
                        .unwrap_or(60);

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

                    self.log_query(id, &domain, qtype, &client_addr, 3, start.elapsed());
                    return QueryResult::Response(response_bytes);
                }
                Err(e) => {
                    debug!("Upstream {} failed: {}", upstream_label(upstream), e);
                }
            }
        }

        error!("All upstreams failed for {} {} from {}", domain, qtype, client_addr);
        self.log_query(id, &domain, qtype, &client_addr, 5, start.elapsed());
        make_error_response(id, ResponseCode::ServFail)
    }

    fn log_query(&self, _id: u16, domain: &str, qtype: RecordType, client: &std::net::SocketAddr, status: i32, elapsed: Duration) {
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
        if self.state.config.read().dns.query_log {
            if let Some(ref writer) = self.state.db_writer {
                if let Err(e) = writer.store(stored) {
                    debug!("Failed to queue query: {}", e);
                }
            } else {
                // Fallback: direct DB write (blocking)
                if let Err(e) = self.state.database.nimbus.store_query(stored) {
                    debug!("Failed to store query: {}", e);
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
        Err(_) => make_error_response(id, ResponseCode::ServFail),
    }
}

fn make_error_response(id: u16, rcode: ResponseCode) -> QueryResult {
    let mut response = Message::error_msg(id, OpCode::Query, rcode);
    // Add EDNS0 OPT pseudo-record
    add_edns0(&mut response);
    match response.to_vec() {
        Ok(bytes) => QueryResult::Response(bytes),
        Err(_) => QueryResult::ServerFailure,
    }
}

/// If a response exceeds the max UDP payload, truncate it with TC bit set.
/// Uses hickory-proto's built-in `Message::truncate()` which keeps questions
/// and sets the TC (Truncated) bit. The client will retry over TCP.
fn truncate_if_needed(msg: &Message) -> Option<Vec<u8>> {
    let max_size = msg.max_payload() as usize;
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
