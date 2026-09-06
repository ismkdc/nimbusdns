// =============================================================================
// NimbusDNS DHCP Server (IPv4, RFC 2131)
// =============================================================================
// Minimal DHCP server implementation using dhcproto 0.15.
// Handles DISCOVER → OFFER, REQUEST → ACK cycle.
// IP pool management with in-memory lease storage.

use std::collections::{HashMap, HashSet};
use std::io::{self, IoSlice};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Arc;

const OFFER_TIMEOUT: i64 = 30; // seconds

/// An outstanding offer: (expiry_timestamp, mac_address)
type OfferEntry = (i64, [u8; 6]);

use dhcproto::v4::{DhcpOptions, Message, MessageType, Opcode};
use dhcproto::{Decodable, Encodable, Encoder};
use nix::sys::socket::{ControlMessage, MsgFlags, SockaddrIn, sendmsg};
use parking_lot::{Mutex, RwLock};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config::DhcpConfig;

const SERVER_PORT: u16 = 67;
const CLIENT_PORT: u16 = 68;

/// Resolve interface name to kernel index (0 = auto).
/// Returns libc::c_uint which matches if_nametoindex return type.
fn resolve_ifindex(name: &Option<String>) -> libc::c_uint {
    name.as_ref()
        .and_then(|n| {
            let c = std::ffi::CString::new(n.as_str()).ok()?;
            let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
            if idx == 0 { None } else { Some(idx) }
        })
        .unwrap_or(0)
}

/// Enable IP_PKTINFO on a socket so sendmsg can set source IP per packet.
fn enable_ip_pktinfo(fd: std::os::fd::RawFd) -> io::Result<()> {
    let enable: libc::c_int = 1;
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Send a DHCP datagram with explicit source IP (via IP_PKTINFO) so
/// the IP header source matches ServerIdentifier for iOS compatibility.
fn send_dhcp_pktinfo(
    fd: std::os::fd::RawFd,
    bytes: &[u8],
    dest: SocketAddrV4,
    src_ip: Ipv4Addr,
    ifindex: u32,
) -> io::Result<usize> {
    let mut pktinfo: libc::in_pktinfo = unsafe { std::mem::zeroed() };
    pktinfo.ipi_ifindex = ifindex as _;
    pktinfo.ipi_spec_dst = libc::in_addr {
        s_addr: u32::from_ne_bytes(src_ip.octets()),
    };
    let iov = [IoSlice::new(bytes)];
    let cmsgs = [ControlMessage::Ipv4PacketInfo(&pktinfo)];
    let dest_addr = SockaddrIn::from(dest);
    match sendmsg::<SockaddrIn>(fd, &iov, &cmsgs, MsgFlags::empty(), Some(&dest_addr)) {
        Ok(n) => Ok(n),
        Err(nix::errno::Errno::EAGAIN) => Err(io::ErrorKind::WouldBlock.into()),
        Err(e) => Err(io::Error::from_raw_os_error(e as i32)),
    }
}

/// Async wrapper for send_dhcp_pktinfo with retry on EAGAIN.
async fn send_dhcp(
    socket: &UdpSocket,
    bytes: &[u8],
    dest: SocketAddrV4,
    src_ip: Ipv4Addr,
    ifindex: u32,
) -> io::Result<usize> {
    socket
        .async_io(tokio::io::Interest::WRITABLE, || {
            send_dhcp_pktinfo(socket.as_raw_fd(), bytes, dest, src_ip, ifindex)
        })
        .await
}

/// A DHCP lease entry
#[derive(Debug, Clone, serde::Serialize)]
pub struct Lease {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub expires_at: i64,
}

/// DHCP server state (pub for API access)
pub struct DhcpServer {
    /// Serializes a complete packet transaction against lease/offer reclamation.
    mutation: Mutex<()>,
    /// Conflicting addresses stay excluded until the server is restarted.
    excluded: RwLock<HashSet<u32>>,
    config: Arc<RwLock<DhcpConfig>>,
    leases: Arc<RwLock<HashMap<[u8; 6], Lease>>>,
    pool: Arc<RwLock<IpPool>>,
    /// Temporary offers (IP → (expiry, mac)), cleaned up periodically
    offered: Arc<RwLock<HashMap<u32, OfferEntry>>>,
    /// Declined IPs in quarantine (IP → expiry), not re-offered for 10 min
    declined: Arc<RwLock<HashMap<u32, i64>>>,
    /// Database for lease persistence
    db: Option<Arc<crate::database::queries::QueryDb>>,
}

impl DhcpServer {
    /// Atomically: conflict-check + lease-insert under a single write lock.
    /// Returns `true` if the lease was committed, `false` if there was a
    /// conflict (IP already leased to a different MAC with active lease).
    /// If the MAC moves to a new IP, the previous IP is released back to the
    /// pool so it can be reused (otherwise the pool silently drains).
    fn try_commit_lease(
        &self,
        mac: [u8; 6],
        ip: Ipv4Addr,
        expires_at: i64,
        hostname: Option<String>,
    ) -> bool {
        let mut leases = self.leases.write();
        let now = chrono::Utc::now().timestamp();
        // Capture the MAC's previous IP before overwriting the lease entry
        let old_ip = leases.get(&mac).map(|l| l.ip);
        let conflict = leases
            .iter()
            .any(|(&k, lease)| lease.ip == ip && k != mac && lease.expires_at > now);
        if conflict {
            return false;
        }
        leases.insert(
            mac,
            Lease {
                ip,
                mac,
                hostname,
                vendor: None,
                expires_at,
            },
        );
        self.pool.write().mark_allocated(ip);
        // Release the old IP back into the pool on IP change
        if let Some(old) = old_ip
            && old != ip
            && !leases
                .values()
                .any(|lease| lease.ip == old && lease.expires_at > now)
            && !self.offered.read().contains_key(&u32::from(old))
            && !self.excluded.read().contains(&u32::from(old))
        {
            self.pool.write().release(old);
        }
        true
    }

    /// Whether a REQUEST for `ip` from `mac` is legitimate (RFC 2131 §4.3.2).
    /// The requested IP must either be an active offer made to this MAC, or
    /// this MAC's own active lease — and it must NOT be quarantined (declined).
    /// Without this, any client could "steal" an in-pool IP that was offered
    /// to (or leased to) a different MAC, or reuse an IP the server was told
    /// is already in use elsewhere.
    fn can_client_request(&self, mac: [u8; 6], ip: Ipv4Addr) -> bool {
        let now = chrono::Utc::now().timestamp();
        if self.excluded.read().contains(&u32::from(ip)) {
            return false;
        }
        // A quarantined (declined) IP is never requestable, even if offered
        if let Some(until) = self.declined.read().get(&u32::from(ip))
            && *until > now
        {
            return false;
        }
        // 1. Active lease for this MAC with this IP
        if let Some(lease) = self.leases.read().get(&mac)
            && lease.ip == ip
            && lease.expires_at > now
        {
            return true;
        }
        // 2. Active (non-expired) offer of this exact IP to this MAC
        if let Some((expiry, offer_mac)) = self.offered.read().get(&u32::from(ip))
            && *offer_mac == mac
            && *expiry > now
        {
            return true;
        }
        false
    }

    /// Handle a client's DECLINE (the client found the IP already in use via
    /// ARP probe). The IP is quarantined for 10 minutes AND permanently marked
    /// allocated so that once the quarantine expires it is NOT handed out
    /// again — otherwise a genuinely in-use IP (e.g. a static/VM host) causes
    /// an endless DISCOVER→OFFER→REQUEST→ACK→DECLINE loop.
    fn handle_decline(&self, mac: [u8; 6], ip: Ipv4Addr, now: i64) {
        if !self.can_client_request(mac, ip) {
            warn!(
                "DHCP DECLINE ignored: address {} was not assigned to {:?}",
                ip, mac
            );
            return;
        }
        let ip_u32 = u32::from(ip);
        self.excluded.write().insert(ip_u32);
        // Short-term quarantine: skip it for 10 minutes
        self.declined.write().insert(ip_u32, now + 600);
        // PERMANENT: never offer this IP again (survives quarantine expiry).
        // reclaim_expired only cleans `declined`, not `pool.allocated`.
        self.pool.write().mark_allocated(ip);
        self.leases.write().remove(&mac);
        self.offered.write().remove(&ip_u32);
        delete_persisted_lease(self, &mac);
        info!(
            "DHCP DECLINE {} from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (quarantined 10min, permanently skipped)",
            ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
    }
}

struct IpPool {
    start: u32,
    end: u32,
    allocated: HashSet<u32>,
}

impl IpPool {
    fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        Self {
            start: u32::from(start),
            end: u32::from(end),
            allocated: HashSet::new(),
        }
    }
    fn contains(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        ip_u32 >= self.start && ip_u32 <= self.end
    }
    /// Return the next available IP, or None if full (O(1) average)
    /// Skips declined (quarantined) IPs.
    fn next_available(&mut self, declined: &HashSet<u32>) -> Option<Ipv4Addr> {
        for ip_u32 in self.start..=self.end {
            if !self.allocated.contains(&ip_u32) && !declined.contains(&ip_u32) {
                self.allocated.insert(ip_u32);
                return Some(Ipv4Addr::from(ip_u32));
            }
        }
        None
    }
    fn mark_allocated(&mut self, ip: Ipv4Addr) {
        let ip_u32 = u32::from(ip);
        if ip_u32 >= self.start && ip_u32 <= self.end {
            self.allocated.insert(ip_u32);
        }
    }
    fn release(&mut self, ip: Ipv4Addr) {
        self.allocated.remove(&u32::from(ip));
    }
}

/// Encode a DHCP message to bytes using dhcproto's Encoder.
fn encode_message(msg: &Message) -> Result<Vec<u8>, String> {
    let mut buf = Vec::with_capacity(512);
    let mut encoder = Encoder::new(&mut buf);
    msg.encode(&mut encoder)
        .map_err(|e| format!("DHCP encode: {}", e))?;
    Ok(encoder.buffer_filled().to_vec())
}

/// Start the DHCP server. Returns an Arc to the server state (for API access to leases).
pub async fn start(
    config: Arc<RwLock<DhcpConfig>>,
    shutdown_rx: watch::Receiver<bool>,
    db: Option<Arc<crate::database::queries::QueryDb>>,
) -> Option<Arc<DhcpServer>> {
    let (pool_start, pool_end) = {
        let cfg = config.read();
        if !cfg.enabled {
            info!("DHCP server is disabled in config");
            return None;
        }
        (
            cfg.pool_start
                .unwrap_or_else(|| Ipv4Addr::new(192, 168, 1, 100)),
            cfg.pool_end
                .unwrap_or_else(|| Ipv4Addr::new(192, 168, 1, 200)),
        )
    };

    info!("DHCP server starting: pool {} - {}", pool_start, pool_end);

    // Source IP for responses (must match ServerIdentifier option for iOS)
    let (src_ip, ifindex) = {
        let cfg = config.read();
        let ip = cfg.router.unwrap_or(Ipv4Addr::new(192, 168, 1, 1));
        let idx = resolve_ifindex(&cfg.interface);
        (ip, idx)
    };
    info!(
        "DHCP server starting: src_ip={}, ifindex={}",
        src_ip, ifindex
    );

    // Load persisted leases from DB on startup
    let leases_map = if let Some(ref db) = db {
        load_persisted_leases(db, pool_start, pool_end)
    } else {
        HashMap::new()
    };
    let pool = Arc::new(RwLock::new(IpPool::new(pool_start, pool_end)));
    // Mark persisted lease IPs as allocated
    for lease in leases_map.values() {
        pool.write().mark_allocated(lease.ip);
    }

    let server = Arc::new(DhcpServer {
        mutation: Mutex::new(()),
        excluded: RwLock::new(HashSet::new()),
        config,
        leases: Arc::new(RwLock::new(leases_map)),
        pool,
        offered: Arc::new(RwLock::new(HashMap::new())),
        declined: Arc::new(RwLock::new(HashMap::new())),
        db,
    });

    // Socket: create via socket2 for full option control, then convert to tokio.
    let socket = {
        let sock = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
            Ok(s) => s,
            Err(e) => {
                warn!("DHCP socket create: {}", e);
                return None;
            }
        };
        let _ = sock.set_reuse_address(true);
        let _ = sock.set_broadcast(true);
        if let Err(e) = sock.set_nonblocking(true) {
            warn!("DHCP set_nonblocking: {}", e);
            return None;
        }
        let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, SERVER_PORT);
        if let Err(e) = sock.bind(&SockAddr::from(bind_addr)) {
            warn!("DHCP bind {}: {}", bind_addr, e);
            return None;
        }
        // Enable IP_PKTINFO so sendmsg can set source IP per-packet
        let std_sock: std::net::UdpSocket = sock.into();
        if let Err(e) = enable_ip_pktinfo(std_sock.as_raw_fd()) {
            warn!("DHCP IP_PKTINFO: {}", e);
            return None;
        }
        match tokio::net::UdpSocket::from_std(std_sock) {
            Ok(s) => {
                info!(
                    "DHCP listening on 0.0.0.0:{} (IP_PKTINFO, src={})",
                    SERVER_PORT, src_ip
                );
                Arc::new(s)
            }
            Err(e) => {
                warn!("DHCP from_std: {}", e);
                return None;
            }
        }
    };

    let mut buf = vec![0u8; 1024];
    let mut shutdown = shutdown_rx;
    let svr = server.clone();
    let cfg_check = server.config.clone();
    let src_ip_h = src_ip;
    let ifindex_h = ifindex;

    tokio::spawn(async move {
        let mut check = tokio::time::interval(tokio::time::Duration::from_secs(10));
        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    if let Ok((len, src)) = result {
                        let data = buf[..len].to_vec();
                        let s = svr.clone();
                        let sock = socket.clone();
                        tokio::spawn(async move {
                            handle_dhcp_packet(s, sock, data, src, src_ip_h, ifindex_h).await;
                        });
                    }
                }
                _ = check.tick() => {
                    // Check if DHCP is still enabled
                    if !cfg_check.read().enabled {
                        info!("DHCP server stopped by config change");
                        break;
                    }
                    // Reclaim expired leases + offers
                    reclaim_expired(&svr);
                }
                _ = shutdown.changed() => {
                    info!("DHCP server shutting down");
                    break;
                }
            }
        }
    });

    Some(server)
}

async fn handle_dhcp_packet(
    server: Arc<DhcpServer>,
    socket: Arc<UdpSocket>,
    data: Vec<u8>,
    src: std::net::SocketAddr,
    src_ip: Ipv4Addr,
    ifindex: u32,
) {
    let mut decoder = dhcproto::Decoder::new(&data);
    let msg = match Message::decode(&mut decoder) {
        Ok(msg) if msg.opcode() == Opcode::BootRequest && msg.chaddr().len() == 6 => msg,
        Ok(_) => return,
        Err(e) => {
            warn!("DHCP decode error from {}: {}", src, e);
            return;
        }
    };
    debug!(
        "DHCP request src={} xid={} ciaddr={} giaddr={} options={:?}",
        src,
        msg.xid(),
        msg.ciaddr(),
        msg.giaddr(),
        msg.opts()
    );
    let response = tokio::task::spawn_blocking(move || process_dhcp_message(&server, &msg)).await;
    let response = match response {
        Ok(Some(response)) => response,
        Ok(None) => return,
        Err(e) => {
            warn!("DHCP processing failed: {}", e);
            return;
        }
    };
    let dest = response_destination(&response);
    let bytes = match encode_message(&response) {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!("{}", e);
            return;
        }
    };
    let kind = response.opts().get(dhcproto::v4::OptionCode::MessageType);
    if let Err(e) = send_dhcp(&socket, &bytes, dest, src_ip, ifindex).await {
        warn!("DHCP {:?} send error to {}: {}", kind, dest, e);
    } else {
        info!(
            "DHCP {:?} ip={} mac={:02x?} xid={} destination={}",
            kind,
            response.yiaddr(),
            response.chaddr(),
            response.xid(),
            dest
        );
    }
}

/// Process one transaction without network I/O. All state and persistence changes
/// happen under the same lock on a blocking worker, before emitting the reply.
fn process_dhcp_message(server: &DhcpServer, msg: &Message) -> Option<Message> {
    if msg.opcode() != Opcode::BootRequest || msg.chaddr().len() != 6 {
        return None;
    }
    let mac: [u8; 6] = msg.chaddr().try_into().ok()?;
    let kind = match msg.opts().get(dhcproto::v4::OptionCode::MessageType)? {
        dhcproto::v4::DhcpOption::MessageType(kind) => *kind,
        _ => return None,
    };
    let cfg = server.config.read().clone();
    let sid = cfg.router.unwrap_or(Ipv4Addr::new(192, 168, 1, 1));
    let selected = match msg.opts().get(dhcproto::v4::OptionCode::ServerIdentifier) {
        Some(dhcproto::v4::DhcpOption::ServerIdentifier(ip)) => Some(*ip),
        _ => None,
    };
    // SELECTING requests are broadcast to all servers, but only the selected
    // server may ACK/NAK. RELEASE and DECLINE also identify their server.
    if selected.is_some_and(|ip| ip != sid) {
        return None;
    }
    let requested = match msg.opts().get(dhcproto::v4::OptionCode::RequestedIpAddress) {
        Some(dhcproto::v4::DhcpOption::RequestedIpAddress(ip)) => Some(*ip),
        _ => None,
    };
    let _transaction = server.mutation.lock();
    reclaim_expired_locked(server);
    match kind {
        MessageType::Discover => {
            let now = chrono::Utc::now().timestamp();
            let existing = server
                .leases
                .read()
                .get(&mac)
                .filter(|l| l.expires_at > now)
                .map(|l| l.ip);
            let ip = if let Some(ip) = existing {
                ip
            } else {
                let mut offers = server.offered.write();
                let existing = offers
                    .iter()
                    .find(|(_, entry)| entry.1 == mac && entry.0 > now)
                    .map(|(&ip, _)| Ipv4Addr::from(ip));
                let ip = match existing {
                    Some(ip) => ip,
                    None => {
                        let excluded = server.excluded.read();
                        match server.pool.write().next_available(&excluded) {
                            Some(ip) => ip,
                            None => {
                                warn!("DHCP pool exhausted for {:02x?}", mac);
                                return None;
                            }
                        }
                    }
                };
                offers.insert(u32::from(ip), (now + OFFER_TIMEOUT, mac));
                ip
            };
            // Even a reused lease gets an offer reservation: it may expire
            // between DISCOVER and REQUEST.
            server
                .offered
                .write()
                .insert(u32::from(ip), (now + OFFER_TIMEOUT, mac));
            Some(build_offer(msg, ip, server))
        }
        MessageType::Request => {
            let ciaddr = msg.ciaddr();
            if selected.is_some() && (requested.is_none() || !ciaddr.is_unspecified()) {
                return None;
            }
            if !ciaddr.is_unspecified() && requested.is_some() {
                return None;
            }
            let ip = requested.or_else(|| (!ciaddr.is_unspecified()).then_some(ciaddr))?;
            // INIT-REBOOT: an unknown client on our subnet must not receive a
            // destructive NAK merely because its lease is not in our database.
            let subnet_matches = (u32::from(ip) & u32::from(cfg.netmask))
                == (u32::from(sid) & u32::from(cfg.netmask));
            if selected.is_none()
                && ciaddr.is_unspecified()
                && subnet_matches
                && !server.leases.read().contains_key(&mac)
            {
                return None;
            }
            if !server.pool.read().contains(ip) || !server.can_client_request(mac, ip) {
                warn!(
                    "DHCP NAK ip={} mac={:02x?} xid={} (no valid offer/lease)",
                    ip,
                    mac,
                    msg.xid()
                );
                return Some(build_nak(msg, server));
            }
            let hostname = match msg.opts().get(dhcproto::v4::OptionCode::Hostname) {
                Some(dhcproto::v4::DhcpOption::Hostname(host)) => Some(host.clone()),
                _ => server
                    .leases
                    .read()
                    .get(&mac)
                    .and_then(|l| l.hostname.clone()),
            };
            let expires = chrono::Utc::now().timestamp() + i64::from(cfg.lease_time);
            if !server.try_commit_lease(mac, ip, expires, hostname.clone()) {
                warn!("DHCP NAK ip={} mac={:02x?} (IP conflict)", ip, mac);
                return Some(build_nak(msg, server));
            }
            server.pool.write().mark_allocated(ip);
            server.offered.write().remove(&u32::from(ip));
            persist_lease(server, &mac, ip, &hostname, expires);
            Some(build_ack(msg, ip, server))
        }
        MessageType::Release => {
            let ip = msg.ciaddr();
            let owns = server.leases.read().get(&mac).is_some_and(|l| l.ip == ip);
            if owns && !ip.is_unspecified() {
                server.leases.write().remove(&mac);
                server.offered.write().retain(|_, entry| entry.1 != mac);
                if !server.excluded.read().contains(&u32::from(ip)) {
                    server.pool.write().release(ip);
                }
                delete_persisted_lease(server, &mac);
            }
            None
        }
        MessageType::Decline => {
            if let Some(ip) = requested {
                server.handle_decline(mac, ip, chrono::Utc::now().timestamp());
            }
            None
        }
        _ => None,
    }
}

fn response_destination(response: &Message) -> SocketAddrV4 {
    if !response.giaddr().is_unspecified() {
        return SocketAddrV4::new(response.giaddr(), SERVER_PORT);
    }
    let is_nak = matches!(
        response.opts().get(dhcproto::v4::OptionCode::MessageType),
        Some(dhcproto::v4::DhcpOption::MessageType(MessageType::Nak))
    );
    if !is_nak && !response.ciaddr().is_unspecified() {
        SocketAddrV4::new(response.ciaddr(), CLIENT_PORT)
    } else {
        // Without a configured client address, use broadcast rather than an
        // IP unicast that would require resolving an unconfigured host by ARP.
        SocketAddrV4::new(Ipv4Addr::BROADCAST, CLIENT_PORT)
    }
}

fn make_msg(xid: u32, yiaddr: Ipv4Addr, siaddr: Ipv4Addr, chaddr: &[u8]) -> Message {
    Message::new_with_id(
        xid,
        Ipv4Addr::UNSPECIFIED, // ciaddr
        yiaddr,
        siaddr,                // siaddr = server IP (must match ServerIdentifier)
        Ipv4Addr::UNSPECIFIED, // giaddr
        chaddr,
    )
}

fn build_offer(discover: &Message, offered_ip: Ipv4Addr, server: &DhcpServer) -> Message {
    let cfg = server.config.read();
    let sid = cfg.router.unwrap_or(Ipv4Addr::new(192, 168, 1, 1));
    let mut msg = make_msg(discover.xid(), offered_ip, sid, &discover.chaddr()[..6]);
    msg.set_opcode(Opcode::BootReply);
    // Use client's broadcast flag (don't force broadcast)
    msg.set_flags(discover.flags());
    msg.set_giaddr(discover.giaddr());
    msg.set_ciaddr(discover.ciaddr());

    let mut opts = DhcpOptions::new();
    opts.insert(dhcproto::v4::DhcpOption::MessageType(MessageType::Offer));
    opts.insert(dhcproto::v4::DhcpOption::ServerIdentifier(sid));
    opts.insert(dhcproto::v4::DhcpOption::SubnetMask(cfg.netmask));
    // DNS server: if configured, use it; otherwise use ourselves (the router/gateway)
    if let Some(dns) = cfg.dns_server {
        opts.insert(dhcproto::v4::DhcpOption::DomainNameServer(vec![dns]));
    } else {
        opts.insert(dhcproto::v4::DhcpOption::DomainNameServer(vec![sid]));
    }
    // Always send Router option (use sid as fallback)
    opts.insert(dhcproto::v4::DhcpOption::Router(vec![
        cfg.router.unwrap_or(sid),
    ]));
    opts.insert(dhcproto::v4::DhcpOption::AddressLeaseTime(cfg.lease_time));
    opts.insert(dhcproto::v4::DhcpOption::Renewal(cfg.lease_time / 2));
    opts.insert(dhcproto::v4::DhcpOption::Rebinding(
        ((u64::from(cfg.lease_time) * 7) / 8) as u32,
    ));
    if let Some(ref domain) = cfg.domain {
        opts.insert(dhcproto::v4::DhcpOption::DomainName(domain.clone()));
    }
    msg.set_opts(opts);
    drop(cfg);
    msg
}

fn build_ack(request: &Message, offered_ip: Ipv4Addr, server: &DhcpServer) -> Message {
    let cfg = server.config.read();
    let sid = cfg.router.unwrap_or(Ipv4Addr::new(192, 168, 1, 1));
    let mut msg = make_msg(request.xid(), offered_ip, sid, &request.chaddr()[..6]);
    msg.set_opcode(Opcode::BootReply);
    // Use client's broadcast flag
    msg.set_flags(request.flags());
    msg.set_giaddr(request.giaddr());
    msg.set_ciaddr(request.ciaddr());

    let mut opts = DhcpOptions::new();
    opts.insert(dhcproto::v4::DhcpOption::MessageType(MessageType::Ack));
    opts.insert(dhcproto::v4::DhcpOption::ServerIdentifier(sid));
    opts.insert(dhcproto::v4::DhcpOption::SubnetMask(cfg.netmask));
    // DNS server: use ourselves (the router) if not explicitly configured
    if let Some(dns) = cfg.dns_server {
        opts.insert(dhcproto::v4::DhcpOption::DomainNameServer(vec![dns]));
    } else {
        opts.insert(dhcproto::v4::DhcpOption::DomainNameServer(vec![sid]));
    }
    // Always send Router option (use sid as fallback)
    opts.insert(dhcproto::v4::DhcpOption::Router(vec![
        cfg.router.unwrap_or(sid),
    ]));
    opts.insert(dhcproto::v4::DhcpOption::AddressLeaseTime(cfg.lease_time));
    opts.insert(dhcproto::v4::DhcpOption::Renewal(cfg.lease_time / 2));
    opts.insert(dhcproto::v4::DhcpOption::Rebinding(
        ((u64::from(cfg.lease_time) * 7) / 8) as u32,
    ));
    if let Some(ref domain) = cfg.domain {
        opts.insert(dhcproto::v4::DhcpOption::DomainName(domain.clone()));
    }
    msg.set_opts(opts);
    drop(cfg);
    msg
}

fn build_nak(request: &Message, server: &DhcpServer) -> Message {
    let cfg = server.config.read();
    let sid = cfg.router.unwrap_or(Ipv4Addr::new(192, 168, 1, 1));
    let mut msg = make_msg(
        request.xid(),
        Ipv4Addr::UNSPECIFIED,
        sid,
        &request.chaddr()[..6],
    );
    msg.set_opcode(Opcode::BootReply);
    msg.set_flags(request.flags());
    msg.set_giaddr(request.giaddr());
    msg.set_ciaddr(request.ciaddr());
    let mut opts = DhcpOptions::new();
    opts.insert(dhcproto::v4::DhcpOption::MessageType(MessageType::Nak));
    opts.insert(dhcproto::v4::DhcpOption::ServerIdentifier(sid));
    msg.set_opts(opts);
    drop(cfg);
    msg
}

/// Reclaim expired leases and offered IPs (call periodically from check.tick)
fn reclaim_expired(server: &DhcpServer) {
    let _transaction = server.mutation.lock();
    reclaim_expired_locked(server);
}

fn reclaim_expired_locked(server: &DhcpServer) {
    let now = chrono::Utc::now().timestamp();

    // 1. Clean expired leases
    let mut expired_ips = Vec::new();
    {
        let mut leases = server.leases.write();
        leases.retain(|_mac, lease| {
            if lease.expires_at <= now {
                expired_ips.push(u32::from(lease.ip));
                false
            } else {
                true
            }
        });
    }
    if !expired_ips.is_empty() {
        // Only release an IP if no OTHER active lease still holds it. A
        // previous double-allocation (MAC B stole an IP from expired MAC A)
        // must not hand the IP back to the pool while B is still using it.
        let active_ips: HashSet<u32> = {
            let leases = server.leases.read();
            leases.values().map(|l| u32::from(l.ip)).collect()
        };
        let mut pool = server.pool.write();
        for ip in &expired_ips {
            if !active_ips.contains(ip)
                && !server.offered.read().contains_key(ip)
                && !server.excluded.read().contains(ip)
            {
                pool.release(Ipv4Addr::from(*ip));
            }
        }
        debug!("DHCP reclaimed {} expired leases", expired_ips.len());
    }

    // 2. Clean expired offers (30s timeout)
    let mut expired_offers = Vec::new();
    {
        let mut offers = server.offered.write();
        offers.retain(|ip, entry| {
            if entry.0 <= now {
                expired_offers.push(*ip);
                false
            } else {
                true
            }
        });
    }
    if !expired_offers.is_empty() {
        let mut pool = server.pool.write();
        for ip in &expired_offers {
            if !server
                .leases
                .read()
                .values()
                .any(|lease| u32::from(lease.ip) == *ip && lease.expires_at > now)
                && !server.excluded.read().contains(ip)
            {
                pool.release(Ipv4Addr::from(*ip));
            }
        }
        debug!("DHCP reclaimed {} expired offers", expired_offers.len());
    }

    // 3. Clean expired declined (quarantine) IPs — 10 min timeout
    let mut expired_declined = Vec::new();
    {
        let mut declined = server.declined.write();
        declined.retain(|ip, expiry| {
            if *expiry <= now {
                expired_declined.push(*ip);
                false
            } else {
                true
            }
        });
    }
    if !expired_declined.is_empty() {
        // Quarantine metadata expires; confirmed conflicts remain excluded.
        debug!(
            "DHCP reclaimed {} expired declined IPs",
            expired_declined.len()
        );
    }
}

/// Persist a lease to the database. Runs on the blocking pool so the tokio
/// worker thread that processed the DHCP packet is never blocked by SQLite
/// I/O (P2).
fn persist_lease(
    server: &DhcpServer,
    mac: &[u8; 6],
    ip: Ipv4Addr,
    hostname: &Option<String>,
    expires_at: i64,
) {
    if let Some(ref db) = server.db {
        let db = db.clone();
        let mac_str = mac
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        let ip_u32 = u32::from(ip);
        let hostname_str = hostname.clone().unwrap_or_default();
        if let Err(e) = crate::database::queries::persist_dhcp_lease(
            &db,
            &mac_str,
            ip_u32,
            &hostname_str,
            expires_at,
        ) {
            warn!("DHCP lease persistence failed for {}: {}", mac_str, e);
        }
    }
}

/// Delete a persisted lease. Runs on the blocking pool (P2).
fn delete_persisted_lease(server: &DhcpServer, mac: &[u8; 6]) {
    if let Some(ref db) = server.db {
        let db = db.clone();
        let mac_str = mac
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        if let Err(e) = crate::database::queries::delete_dhcp_lease(&db, &mac_str) {
            warn!("DHCP lease deletion failed for {}: {}", mac_str, e);
        }
    }
}

/// Load persisted leases from database, filtering out expired ones
fn load_persisted_leases(
    db: &Arc<crate::database::queries::QueryDb>,
    pool_start: Ipv4Addr,
    pool_end: Ipv4Addr,
) -> HashMap<[u8; 6], Lease> {
    // Ensure the table exists
    let _ = crate::database::queries::ensure_dhcp_leases_table(db);
    let now = chrono::Utc::now().timestamp();
    let mut leases = HashMap::new();
    if let Ok(rows) = crate::database::queries::load_dhcp_leases(db) {
        for (mac_str, ip_u32, hostname, expires_at) in rows {
            if expires_at <= now {
                continue;
            }
            let ip = Ipv4Addr::from(ip_u32);
            if ip < pool_start || ip > pool_end {
                continue;
            }
            let mac: [u8; 6] = mac_str
                .split(':')
                .filter_map(|b| u8::from_str_radix(b, 16).ok())
                .collect::<Vec<_>>()
                .try_into()
                .ok()
                .unwrap_or_default();
            if mac == [0u8; 6] {
                continue;
            }
            leases.insert(
                mac,
                Lease {
                    ip,
                    mac,
                    hostname: if hostname.is_empty() {
                        None
                    } else {
                        Some(hostname)
                    },
                    vendor: None,
                    expires_at,
                },
            );
        }
    }
    info!("Loaded {} persisted DHCP leases", leases.len());
    leases
}

/// Get current leases (for API), after reclaiming expired ones
pub fn get_leases(server: &DhcpServer) -> Vec<Lease> {
    reclaim_expired(server);
    server.leases.read().values().cloned().collect()
}

pub fn get_lease_count(server: &DhcpServer) -> usize {
    let now = chrono::Utc::now().timestamp();
    reclaim_expired(server);
    server
        .leases
        .read()
        .values()
        .filter(|l| l.expires_at > now)
        .count()
}

// =============================================================================
// Tests
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ── helpers ──────────────────────────────────────────────────────────
    fn pool(start: &str, end: &str) -> IpPool {
        IpPool::new(start.parse().unwrap(), end.parse().unwrap())
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }
    fn ipu(s: &str) -> u32 {
        u32::from(ip(s))
    }

    fn make_server() -> DhcpServer {
        DhcpServer {
            mutation: Mutex::new(()),
            excluded: RwLock::new(HashSet::new()),
            config: Arc::new(RwLock::new(crate::config::DhcpConfig {
                router: Some(ip("192.168.1.1")),
                netmask: ip("255.255.255.0"),
                lease_time: 86400,
                domain: Some("lan".into()),
                ..Default::default()
            })),
            leases: Arc::new(RwLock::new(HashMap::new())),
            pool: Arc::new(RwLock::new(IpPool::new(
                ip("192.168.1.100"),
                ip("192.168.1.200"),
            ))),
            offered: Arc::new(RwLock::new(HashMap::new())),
            declined: Arc::new(RwLock::new(HashMap::new())),
            db: None,
        }
    }

    // ======================================================================
    // can_client_request tests (K3: REQUEST ownership check)
    // ======================================================================

    fn mac(a: u8, b: u8) -> [u8; 6] {
        [0x02, 0x00, 0x00, a, b, 0x00]
    }

    fn request_for(discover: &Message, addr: Ipv4Addr, server_id: Option<Ipv4Addr>) -> Message {
        let mut request = discover.clone();
        request
            .opts_mut()
            .insert(dhcproto::v4::DhcpOption::MessageType(MessageType::Request));
        request
            .opts_mut()
            .insert(dhcproto::v4::DhcpOption::RequestedIpAddress(addr));
        if let Some(sid) = server_id {
            request
                .opts_mut()
                .insert(dhcproto::v4::DhcpOption::ServerIdentifier(sid));
        }
        request
    }

    fn assert_kind(msg: &Message, expected: MessageType) {
        assert!(
            matches!(msg.opts().get(dhcproto::v4::OptionCode::MessageType),
            Some(dhcproto::v4::DhcpOption::MessageType(kind)) if *kind == expected)
        );
    }

    #[test]
    fn selecting_another_server_is_silent_even_for_invalid_ip() {
        let server = make_server();
        let discover = sample_discover();
        let offer = process_dhcp_message(&server, &discover).unwrap();
        for addr in [offer.yiaddr(), ip("10.99.0.2")] {
            let request = request_for(&discover, addr, Some(ip("192.168.1.2")));
            assert!(process_dhcp_message(&server, &request).is_none());
        }
        assert!(server.leases.read().is_empty());
    }

    #[test]
    fn unknown_init_reboot_is_silent_on_same_subnet() {
        let server = make_server();
        let request = request_for(&sample_discover(), ip("192.168.1.150"), None);
        assert!(process_dhcp_message(&server, &request).is_none());
        let request = request_for(&sample_discover(), ip("10.99.0.2"), None);
        assert_kind(
            &process_dhcp_message(&server, &request).unwrap(),
            MessageType::Nak,
        );
    }

    #[test]
    fn expired_lease_discover_receives_requestable_offer() {
        let server = make_server();
        let discover = sample_discover();
        let mac = discover.chaddr().try_into().unwrap();
        let now = chrono::Utc::now().timestamp();
        assert!(server.try_commit_lease(mac, ip("192.168.1.100"), now - 1, None));
        server.pool.write().mark_allocated(ip("192.168.1.100"));
        let offer = process_dhcp_message(&server, &discover).unwrap();
        let request = request_for(&discover, offer.yiaddr(), Some(ip("192.168.1.1")));
        assert_kind(
            &process_dhcp_message(&server, &request).unwrap(),
            MessageType::Ack,
        );
    }

    #[test]
    fn reused_lease_offer_survives_lease_expiry() {
        let server = make_server();
        let discover = sample_discover();
        let mac = discover.chaddr().try_into().unwrap();
        let now = chrono::Utc::now().timestamp();
        assert!(server.try_commit_lease(mac, ip("192.168.1.100"), now + 10, None));
        let offer = process_dhcp_message(&server, &discover).unwrap();
        server.leases.write().get_mut(&mac).unwrap().expires_at = now - 1;
        reclaim_expired(&server);
        assert!(server.can_client_request(mac, offer.yiaddr()));
        assert_ne!(
            server.pool.write().next_available(&HashSet::new()),
            Some(offer.yiaddr())
        );
        let request = request_for(&discover, offer.yiaddr(), Some(ip("192.168.1.1")));
        assert_kind(
            &process_dhcp_message(&server, &request).unwrap(),
            MessageType::Ack,
        );
    }

    #[test]
    fn expired_offer_does_not_free_committed_lease() {
        let server = make_server();
        let addr = ip("192.168.1.100");
        let now = chrono::Utc::now().timestamp();
        server
            .offered
            .write()
            .insert(u32::from(addr), (now - 1, mac(1, 1)));
        server.pool.write().mark_allocated(addr);
        assert!(server.try_commit_lease(mac(1, 1), addr, now + 86400, None));
        reclaim_expired(&server);
        assert_ne!(
            server.pool.write().next_available(&HashSet::new()),
            Some(addr)
        );
    }

    #[test]
    fn lease_move_does_not_free_another_clients_active_ip() {
        let server = make_server();
        let now = chrono::Utc::now().timestamp();
        let addr = ip("192.168.1.100");
        assert!(server.try_commit_lease(mac(1, 1), addr, now - 1, None));
        assert!(server.try_commit_lease(mac(2, 2), addr, now + 86400, None));
        server.pool.write().mark_allocated(addr);
        assert!(server.try_commit_lease(mac(1, 1), ip("192.168.1.101"), now + 86400, None));
        assert_ne!(
            server.pool.write().next_available(&HashSet::new()),
            Some(addr)
        );
    }

    #[test]
    fn unowned_decline_cannot_delete_valid_lease_or_quarantine_address() {
        let server = make_server();
        let now = chrono::Utc::now().timestamp();
        let addr = ip("192.168.1.100");
        assert!(server.try_commit_lease(mac(1, 1), addr, now + 86400, None));
        server.handle_decline(mac(1, 1), ip("192.168.1.150"), now);
        assert!(server.can_client_request(mac(1, 1), addr));
        assert!(server.declined.read().is_empty());
        assert!(server.excluded.read().is_empty());
    }

    #[test]
    fn renew_and_relay_replies_use_correct_destination() {
        let server = make_server();
        let discover = sample_discover();
        let offer = process_dhcp_message(&server, &discover).unwrap();
        let request = request_for(&discover, offer.yiaddr(), Some(ip("192.168.1.1")));
        process_dhcp_message(&server, &request).unwrap();
        let mut renew = discover.clone();
        renew
            .opts_mut()
            .insert(dhcproto::v4::DhcpOption::MessageType(MessageType::Request));
        renew.set_ciaddr(offer.yiaddr());
        let ack = process_dhcp_message(&server, &renew).unwrap();
        assert_kind(&ack, MessageType::Ack);
        assert_eq!(
            response_destination(&ack),
            SocketAddrV4::new(offer.yiaddr(), 68)
        );
        renew.set_giaddr(ip("192.168.1.2"));
        let ack = process_dhcp_message(&server, &renew).unwrap();
        assert_eq!(
            response_destination(&ack),
            SocketAddrV4::new(ip("192.168.1.2"), 67)
        );
    }

    #[test]
    fn maximum_lease_time_does_not_overflow_rebinding() {
        let server = make_server();
        server.config.write().lease_time = u32::MAX;
        let ack = build_ack(&sample_discover(), ip("192.168.1.100"), &server);
        assert!(matches!(
            ack.opts().get(dhcproto::v4::OptionCode::Rebinding),
            Some(dhcproto::v4::DhcpOption::Rebinding(3758096383))
        ));
    }

    #[test]
    fn packet_transactions_and_cleanup_preserve_pool_ownership() {
        let server = Arc::new(make_server());
        std::thread::scope(|scope| {
            let server_ref = &server;
            scope.spawn(move || {
                for _ in 0..200 {
                    reclaim_expired(server_ref);
                }
            });
            for i in 0..20u32 {
                let server = server.clone();
                scope.spawn(move || {
                    let mut discover = Message::new_with_id(
                        i,
                        Ipv4Addr::UNSPECIFIED,
                        Ipv4Addr::UNSPECIFIED,
                        Ipv4Addr::UNSPECIFIED,
                        Ipv4Addr::UNSPECIFIED,
                        &mac(i as u8, 1),
                    );
                    discover.set_opcode(Opcode::BootRequest);
                    discover
                        .opts_mut()
                        .insert(dhcproto::v4::DhcpOption::MessageType(MessageType::Discover));
                    let offer = process_dhcp_message(&server, &discover).unwrap();
                    let request = request_for(&discover, offer.yiaddr(), Some(ip("192.168.1.1")));
                    assert_kind(
                        &process_dhcp_message(&server, &request).unwrap(),
                        MessageType::Ack,
                    );
                });
            }
        });
        let leases = server.leases.read();
        assert_eq!(leases.len(), 20);
        let addresses: HashSet<_> = leases.values().map(|l| l.ip).collect();
        assert_eq!(addresses.len(), 20);
        let pool = server.pool.read();
        assert!(
            addresses
                .iter()
                .all(|ip| pool.allocated.contains(&u32::from(*ip)))
        );
    }

    #[test]
    fn test_request_allowed_for_own_offer() {
        let server = make_server();
        let now = chrono::Utc::now().timestamp();
        server
            .offered
            .write()
            .insert(u32::from(ip("192.168.1.100")), (now + 30, mac(1, 1)));
        // MAC that received the offer may request that exact IP
        assert!(server.can_client_request(mac(1, 1), ip("192.168.1.100")));
        // A different MAC may NOT steal the offered IP
        assert!(!server.can_client_request(mac(2, 2), ip("192.168.1.100")));
    }

    #[test]
    fn test_request_allowed_for_own_lease() {
        let server = make_server();
        let now = chrono::Utc::now().timestamp();
        assert!(server.try_commit_lease(mac(1, 1), ip("192.168.1.100"), now + 3600, None));
        assert!(server.can_client_request(mac(1, 1), ip("192.168.1.100")));
        assert!(!server.can_client_request(mac(2, 2), ip("192.168.1.100")));
    }

    #[test]
    fn test_request_rejected_without_offer_or_lease() {
        let server = make_server();
        // No offer, no lease — a random in-pool IP must be rejected
        assert!(!server.can_client_request(mac(1, 1), ip("192.168.1.150")));
    }

    #[test]
    fn test_request_expired_offer_rejected() {
        let server = make_server();
        let now = chrono::Utc::now().timestamp();
        server
            .offered
            .write()
            .insert(u32::from(ip("192.168.1.100")), (now - 1, mac(1, 1)));
        assert!(!server.can_client_request(mac(1, 1), ip("192.168.1.100")));
    }

    #[test]
    fn test_lease_move_releases_old_pool_ip() {
        let server = make_server();
        let now = chrono::Utc::now().timestamp();
        // Client leases 192.168.1.100
        assert!(server.try_commit_lease(mac(1, 1), ip("192.168.1.100"), now + 3600, None));
        server.pool.write().mark_allocated(ip("192.168.1.100"));
        // Client moves to a new IP
        assert!(server.try_commit_lease(mac(1, 1), ip("192.168.1.101"), now + 3600, None));
        server.pool.write().mark_allocated(ip("192.168.1.101"));
        // Old IP must be released back to the pool (free again)
        let mut p = server.pool.write();
        let free = p.next_available(&HashSet::new());
        assert_eq!(
            free,
            Some(ip("192.168.1.100")),
            "old IP should be reusable after lease move"
        );
        let free2 = p.next_available(&HashSet::new());
        assert_eq!(
            free2,
            Some(ip("192.168.1.102")),
            "next free should be the following IP"
        );
    }

    // ======================================================================
    // RELEASE ownership + DECLINE quarantine (B3/B4)
    // ======================================================================

    #[test]
    fn test_declined_ip_not_requestable() {
        let server = make_server();
        let now = chrono::Utc::now().timestamp();
        // Quarantine an IP
        server
            .declined
            .write()
            .insert(u32::from(ip("192.168.1.100")), now + 600);
        // Even with a fresh offer to this MAC, a quarantined IP must not be
        // grantable via REQUEST.
        server
            .offered
            .write()
            .insert(u32::from(ip("192.168.1.100")), (now + 30, mac(1, 1)));
        assert!(
            !server.can_client_request(mac(1, 1), ip("192.168.1.100")),
            "quarantined IP must not be requestable"
        );
    }

    #[test]
    fn test_declined_ip_skipped_by_pool() {
        let server = make_server();
        let now = chrono::Utc::now().timestamp();
        server
            .declined
            .write()
            .insert(u32::from(ip("192.168.1.100")), now + 600);
        // Pool must hand out a different IP first
        let mut p = server.pool.write();
        let declined: HashSet<u32> = server.declined.read().keys().copied().collect();
        let next = p.next_available(&declined);
        assert_ne!(
            next,
            Some(ip("192.168.1.100")),
            "declined IP must be skipped"
        );
    }

    #[test]
    fn test_reclaim_does_not_release_double_allocated_ip() {
        let server = make_server();
        let now = chrono::Utc::now().timestamp();
        // MAC A leases .100 (expired), MAC B later steals the same IP (still
        // active). Reclaim must NOT release .100 back to the pool, because B
        // still uses it — otherwise it could be handed to a third client.
        assert!(server.try_commit_lease(mac(1, 1), ip("192.168.1.100"), now - 10, None));
        assert!(server.try_commit_lease(mac(2, 2), ip("192.168.1.100"), now + 3600, None));
        server.pool.write().mark_allocated(ip("192.168.1.100"));

        reclaim_expired(&server);

        // .100 must remain allocated (B's active lease holds it)
        let mut p = server.pool.write();
        let declined = HashSet::new();
        let next = p.next_available(&declined);
        assert_ne!(
            next,
            Some(ip("192.168.1.100")),
            "double-allocated IP must not be released"
        );
        // The next free IP is .101 (not .100)
        assert_eq!(next, Some(ip("192.168.1.101")));
    }

    #[test]
    fn test_declined_ip_permanently_removed_from_pool() {
        // Regression: a DECLINE'd IP used to be re-allocated after the 10-min
        // quarantine expired, causing an endless DECLINE loop for IPs that are
        // genuinely in use by another device (e.g. a static/VM host). Once
        // declined, the IP must stay out of the pool permanently.
        let server = make_server();
        let now = chrono::Utc::now().timestamp();
        // Simulate the real DECLINE handler on a quarantined IP
        server
            .offered
            .write()
            .insert(ipu("192.168.1.100"), (now + 30, mac(1, 1)));
        server.handle_decline(mac(1, 1), ip("192.168.1.100"), now - 601);

        // Quarantine expires (past the 10-min window)
        reclaim_expired(&server);

        // Even after reclaim, the declined IP must NOT come back to the pool
        let mut p = server.pool.write();
        let declined_now = HashSet::new(); // quarantine is gone, only permanent mark remains
        let next = p.next_available(&declined_now);
        assert_ne!(
            next,
            Some(ip("192.168.1.100")),
            "declined IP must stay out of the pool"
        );
        assert_eq!(
            next,
            Some(ip("192.168.1.101")),
            "next free IP after permanent decline"
        );
    }

    // ── Test 7: next_available returns start, start+1 … ──────────────────
    #[test]
    fn test_pool_next_available_sequential() {
        let mut p = pool("10.0.0.1", "10.0.0.3");
        assert_eq!(p.next_available(&HashSet::new()), Some(ip("10.0.0.1")));
        assert_eq!(p.next_available(&HashSet::new()), Some(ip("10.0.0.2")));
        assert_eq!(p.next_available(&HashSet::new()), Some(ip("10.0.0.3")));
        assert_eq!(p.next_available(&HashSet::new()), None);
    }

    // ── Test 8: allocated IPs are skipped ───────────────────────────────
    #[test]
    fn test_pool_skips_allocated() {
        let mut p = pool("10.0.0.1", "10.0.0.3");
        p.mark_allocated(ip("10.0.0.2"));
        assert_eq!(p.next_available(&HashSet::new()), Some(ip("10.0.0.1")));
        assert_eq!(p.next_available(&HashSet::new()), Some(ip("10.0.0.3")));
        assert_eq!(p.next_available(&HashSet::new()), None);
    }

    // ── Test 9: declined (quarantined) IPs are skipped ──────────────────
    #[test]
    fn test_pool_skips_declined() {
        let mut p = pool("10.0.0.1", "10.0.0.3");
        let declined = HashSet::from([ipu("10.0.0.2")]);
        assert_eq!(p.next_available(&declined), Some(ip("10.0.0.1")));
        assert_eq!(p.next_available(&declined), Some(ip("10.0.0.3")));
        assert_eq!(p.next_available(&declined), None);
    }

    // ── Test 10: full pool → None ───────────────────────────────────────
    #[test]
    fn test_pool_full() {
        let mut p = pool("10.0.0.1", "10.0.0.2");
        assert!(p.next_available(&HashSet::new()).is_some());
        assert!(p.next_available(&HashSet::new()).is_some());
        assert!(p.next_available(&HashSet::new()).is_none());
    }

    // ── Test 11: release → IP available again ───────────────────────────
    #[test]
    fn test_pool_release() {
        let mut p = pool("10.0.0.1", "10.0.0.1");
        let allocated = p.next_available(&HashSet::new()).unwrap();
        assert_eq!(allocated, ip("10.0.0.1"));
        // After release it's available again
        p.release(allocated);
        assert_eq!(p.next_available(&HashSet::new()), Some(ip("10.0.0.1")));
    }

    // ── Test 12: contains boundaries ─────────────────────────────────────
    #[test]
    fn test_pool_contains_boundaries() {
        let p = pool("10.0.0.10", "10.0.0.20");
        assert!(!p.contains(ip("10.0.0.9")));
        assert!(p.contains(ip("10.0.0.10")));
        assert!(p.contains(ip("10.0.0.15")));
        assert!(p.contains(ip("10.0.0.20")));
        assert!(!p.contains(ip("10.0.0.21")));
    }

    // ── Test 13: mark_allocated out-of-range → no-op ─────────────────────
    #[test]
    fn test_pool_mark_allocated_out_of_range() {
        let mut p = pool("10.0.0.1", "10.0.0.5");
        p.mark_allocated(ip("10.0.0.255")); // outside range
        // Should not affect allocation — next_available still starts at 10.0.0.1
        assert_eq!(p.next_available(&HashSet::new()), Some(ip("10.0.0.1")));
    }

    // ======================================================================
    // build_offer / build_ack / build_nak tests (P0)
    // ======================================================================

    fn sample_discover() -> dhcproto::v4::Message {
        // Build a minimal DISCOVER message
        let mut msg = dhcproto::v4::Message::new_with_id(
            12345,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        );
        msg.set_opcode(dhcproto::v4::Opcode::BootRequest);
        let mut opts = dhcproto::v4::DhcpOptions::new();
        opts.insert(dhcproto::v4::DhcpOption::MessageType(
            dhcproto::v4::MessageType::Discover,
        ));
        msg.set_opts(opts);
        msg
    }

    // ── Test 21: offer contains correct lease_time, renewal, rebinding ──
    #[test]
    fn test_build_offer_timing_options() {
        let server = make_server();
        let discover = sample_discover();
        let offer = build_offer(&discover, ip("192.168.1.50"), &server);
        let opts = offer.opts();
        let lt = match opts
            .get(dhcproto::v4::OptionCode::AddressLeaseTime)
            .unwrap()
        {
            dhcproto::v4::DhcpOption::AddressLeaseTime(v) => *v,
            _ => panic!("missing AddressLeaseTime"),
        };
        assert_eq!(lt, 86400);
        let renewal = match opts.get(dhcproto::v4::OptionCode::Renewal).unwrap() {
            dhcproto::v4::DhcpOption::Renewal(v) => *v,
            _ => panic!("missing Renewal"),
        };
        assert_eq!(renewal, 43200); // 86400/2
        let rebind = match opts.get(dhcproto::v4::OptionCode::Rebinding).unwrap() {
            dhcproto::v4::DhcpOption::Rebinding(v) => *v,
            _ => panic!("missing Rebinding"),
        };
        assert_eq!(rebind, 75600); // 86400*7/8
    }

    // ── Test 22: offer contains SubnetMask, Router, ServerIdentifier ────
    #[test]
    fn test_build_offer_required_options() {
        let server = make_server();
        let discover = sample_discover();
        let offer = build_offer(&discover, ip("192.168.1.50"), &server);
        let opts = offer.opts();
        assert!(opts.get(dhcproto::v4::OptionCode::SubnetMask).is_some());
        assert!(opts.get(dhcproto::v4::OptionCode::Router).is_some());
        assert!(
            opts.get(dhcproto::v4::OptionCode::ServerIdentifier)
                .is_some()
        );
        match opts.get(dhcproto::v4::OptionCode::MessageType).unwrap() {
            dhcproto::v4::DhcpOption::MessageType(mt) => {
                assert_eq!(*mt, dhcproto::v4::MessageType::Offer)
            }
            _ => panic!("wrong type"),
        }
    }

    // ── Test 23: offer DNS — None→[router], Some→[dns] ─────────────────
    #[test]
    fn test_build_offer_dns_server() {
        let server = make_server();
        // Without explicit DNS
        {
            let mut cfg = server.config.write();
            cfg.dns_server = None;
        }
        let offer = build_offer(&sample_discover(), ip("192.168.1.50"), &server);
        let opts = offer.opts();
        let dns = match opts
            .get(dhcproto::v4::OptionCode::DomainNameServer)
            .unwrap()
        {
            dhcproto::v4::DhcpOption::DomainNameServer(v) => v.clone(),
            _ => panic!("missing DNS"),
        };
        assert_eq!(dns, vec![ip("192.168.1.1")]); // router fallback

        // With explicit DNS
        {
            let mut cfg = server.config.write();
            cfg.dns_server = Some(ip("1.1.1.1"));
        }
        let offer = build_offer(&sample_discover(), ip("192.168.1.50"), &server);
        let opts = offer.opts();
        let dns = match opts
            .get(dhcproto::v4::OptionCode::DomainNameServer)
            .unwrap()
        {
            dhcproto::v4::DhcpOption::DomainNameServer(v) => v.clone(),
            _ => panic!("missing DNS"),
        };
        assert_eq!(dns, vec![ip("1.1.1.1")]);
    }

    // ── Test 24: ACK carries correct options + MessageType::Ack ─────────
    #[test]
    fn test_build_ack() {
        let server = make_server();
        let request = sample_discover();
        let ack = build_ack(&request, ip("192.168.1.50"), &server);
        let opts = ack.opts();
        match opts.get(dhcproto::v4::OptionCode::MessageType).unwrap() {
            dhcproto::v4::DhcpOption::MessageType(mt) => {
                assert_eq!(*mt, dhcproto::v4::MessageType::Ack)
            }
            _ => panic!("wrong type"),
        }
        assert!(opts.get(dhcproto::v4::OptionCode::SubnetMask).is_some());
        assert!(opts.get(dhcproto::v4::OptionCode::Router).is_some());
        assert!(
            opts.get(dhcproto::v4::OptionCode::ServerIdentifier)
                .is_some()
        );
        assert!(
            opts.get(dhcproto::v4::OptionCode::AddressLeaseTime)
                .is_some()
        );
        // yiaddr should be the offered IP
        assert_eq!(ack.yiaddr(), ip("192.168.1.50"));
    }

    // ── Test 25: NAK has correct MessageType, yiaddr=0, ServerIdentifier ─
    #[test]
    fn test_build_nak() {
        let server = make_server();
        let request = sample_discover();
        let nak = build_nak(&request, &server);
        let opts = nak.opts();
        match opts.get(dhcproto::v4::OptionCode::MessageType).unwrap() {
            dhcproto::v4::DhcpOption::MessageType(mt) => {
                assert_eq!(*mt, dhcproto::v4::MessageType::Nak)
            }
            _ => panic!("wrong type"),
        }
        assert!(
            opts.get(dhcproto::v4::OptionCode::ServerIdentifier)
                .is_some()
        );
        // yiaddr must be 0.0.0.0 for NAK
        assert_eq!(nak.yiaddr(), Ipv4Addr::UNSPECIFIED);
    }

    // ======================================================================
    // try_commit_lease tests (P1) — #4 fix regression tests
    // ======================================================================

    fn mac_a() -> [u8; 6] {
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]
    }
    fn mac_b() -> [u8; 6] {
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02]
    }

    // ── Test 34: empty IP → committed, lease exists ─────────────────────
    #[test]
    fn test_commit_empty() {
        let server = make_server();
        let ok = server.try_commit_lease(mac_a(), ip("192.168.1.50"), 9999999999, None);
        assert!(ok);
        let leases = server.leases.read();
        assert!(leases.contains_key(&mac_a()));
        assert_eq!(leases.get(&mac_a()).unwrap().ip, ip("192.168.1.50"));
    }

    // ── Test 35: IP on different MAC → conflict, not overwritten ────────
    #[test]
    fn test_commit_conflict() {
        let server = make_server();
        // First MAC commits the IP
        assert!(server.try_commit_lease(mac_a(), ip("192.168.1.50"), 9999999999, None));
        // Second MAC tries same IP → conflict
        assert!(!server.try_commit_lease(mac_b(), ip("192.168.1.50"), 9999999999, None));
        // Lease should still belong to mac_a
        let leases = server.leases.read();
        assert_eq!(leases.get(&mac_a()).unwrap().ip, ip("192.168.1.50"));
        assert!(leases.get(&mac_b()).is_none());
    }

    // ── Test 36: same MAC → renewal (expiry refreshed) ──────────────────
    #[test]
    fn test_commit_renew() {
        let server = make_server();
        assert!(server.try_commit_lease(mac_a(), ip("192.168.1.50"), 100, None));
        // Renew with later expiry
        assert!(server.try_commit_lease(mac_a(), ip("192.168.1.50"), 9999999999, None));
        let leases = server.leases.read();
        assert_eq!(leases.get(&mac_a()).unwrap().expires_at, 9999999999);
    }

    // ── Test 37: concurrent N threads, same IP → exactly 1 winner ────
    // Uses real OS threads to actually race for the write lock.
    #[test]
    fn test_commit_concurrent_same_ip_single_winner() {
        let server = Arc::new(make_server());
        const N: usize = 20;
        let winner = std::sync::atomic::AtomicUsize::new(0);

        std::thread::scope(|s| {
            for i in 0..N {
                let sv = Arc::clone(&server);
                let w = &winner;
                s.spawn(move || {
                    let mac = [i as u8, 0, 0, 0, 0, 0];
                    if sv.try_commit_lease(mac, ip("192.168.1.50"), 9999999999, None) {
                        w.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                });
            }
        });

        assert_eq!(winner.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(server.leases.read().len(), 1);
    }

    // ======================================================================
    // reclaim_expired tests (P1)
    // ======================================================================

    // ── Test 38: expired lease removed, IP released ─────────────────────
    #[test]
    fn test_reclaim_expired_lease() {
        let server = make_server();
        // Insert a lease with past expiry
        server.leases.write().insert(
            mac_a(),
            Lease {
                ip: ip("192.168.1.100"),
                mac: mac_a(),
                hostname: None,
                vendor: None,
                expires_at: 1, // expired
            },
        );
        server.pool.write().mark_allocated(ip("192.168.1.100"));
        reclaim_expired(&server);
        // Lease removed, IP back in pool
        assert!(server.leases.read().is_empty());
        // Pool should have released it: next_available returns it
        let mut pool = server.pool.write();
        let declined = HashSet::new();
        assert_eq!(pool.next_available(&declined), Some(ip("192.168.1.100")));
    }

    // ── Test 39: expired offer removed, IP released ─────────────────────
    #[test]
    fn test_reclaim_expired_offer() {
        let server = make_server();
        let now = chrono::Utc::now().timestamp();
        server
            .offered
            .write()
            .insert(ipu("192.168.1.100"), (now - 10, mac_a())); // expired offer
        server.pool.write().mark_allocated(ip("192.168.1.100"));
        reclaim_expired(&server);
        // Offer removed
        assert!(server.offered.read().is_empty());
        // Pool released
        let mut pool = server.pool.write();
        let declined = HashSet::new();
        assert_eq!(pool.next_available(&declined), Some(ip("192.168.1.100")));
    }

    // ── Test 40: expired declined entry removed ─────────────────────────
    #[test]
    fn test_reclaim_expired_declined() {
        let server = make_server();
        server.declined.write().insert(ipu("192.168.1.100"), 1); // expired
        // Also insert a lease so pool allocates this IP
        server.pool.write().mark_allocated(ip("192.168.1.100"));
        reclaim_expired(&server);
        // Declined entry removed
        assert!(server.declined.read().is_empty());
        // IP back in pool
        let mut pool = server.pool.write();
        let declined = HashSet::new();
        assert_ne!(pool.next_available(&declined), Some(ip("192.168.1.100")));
    }
}
