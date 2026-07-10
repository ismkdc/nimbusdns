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
use dhcproto::{Decodable, Encoder, Encodable};
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, SockaddrIn};
use parking_lot::RwLock;
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
    name.as_ref().and_then(|n| {
        let c = std::ffi::CString::new(n.as_str()).ok()?;
        let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
        if idx == 0 { None } else { Some(idx) }
    }).unwrap_or(0)
}

/// Enable IP_PKTINFO on a socket so sendmsg can set source IP per packet.
fn enable_ip_pktinfo(fd: std::os::fd::RawFd) -> io::Result<()> {
    let enable: libc::c_int = 1;
    let r = unsafe {
        libc::setsockopt(
            fd, libc::IPPROTO_IP, libc::IP_PKTINFO,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r != 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Send a DHCP datagram with explicit source IP (via IP_PKTINFO) so
/// the IP header source matches ServerIdentifier for iOS compatibility.
fn send_dhcp_pktinfo(
    fd: std::os::fd::RawFd, bytes: &[u8],
    dest: SocketAddrV4, src_ip: Ipv4Addr, ifindex: u32,
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
    socket: &UdpSocket, bytes: &[u8],
    dest: SocketAddrV4, src_ip: Ipv4Addr, ifindex: u32,
) -> io::Result<usize> {
    let fd = socket.as_raw_fd();
    loop {
        match send_dhcp_pktinfo(fd, bytes, dest, src_ip, ifindex) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                socket.writable().await?;
            }
            Err(e) => return Err(e),
        }
    }
}

/// A DHCP lease entry
#[derive(Debug, Clone, serde::Serialize)]
pub struct Lease {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub hostname: Option<String>,
    pub expires_at: i64,
}

/// DHCP server state (pub for API access)
pub struct DhcpServer {
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
    pub fn try_commit_lease(
        &self,
        mac: [u8; 6],
        ip: Ipv4Addr,
        expires_at: i64,
        hostname: Option<String>,
    ) -> bool {
        let mut leases = self.leases.write();
        let now = chrono::Utc::now().timestamp();
        let conflict = leases.iter().any(|(&k, lease)| {
            lease.ip == ip && k != mac && lease.expires_at > now
        });
        if conflict {
            return false;
        }
        leases.insert(mac, Lease { ip, mac, hostname, expires_at });
        true
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
    msg.encode(&mut encoder).map_err(|e| format!("DHCP encode: {}", e))?;
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
        (cfg.pool_start.unwrap_or_else(|| Ipv4Addr::new(192, 168, 1, 100)),
         cfg.pool_end.unwrap_or_else(|| Ipv4Addr::new(192, 168, 1, 200)))
    };

    info!("DHCP server starting: pool {} - {}", pool_start, pool_end);

    // Source IP for responses (must match ServerIdentifier option for iOS)
    let (src_ip, ifindex) = {
        let cfg = config.read();
        let ip = cfg.router.unwrap_or(Ipv4Addr::new(192, 168, 1, 1));
        let idx = resolve_ifindex(&cfg.interface);
        (ip, idx)
    };
    info!("DHCP server starting: src_ip={}, ifindex={}", src_ip, ifindex);

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
            Err(e) => { warn!("DHCP socket create: {}", e); return None; }
        };
        let _ = sock.set_reuse_address(true);
        let _ = sock.set_broadcast(true);
        if let Err(e) = sock.set_nonblocking(true) {
            warn!("DHCP set_nonblocking: {}", e); return None;
        }
        let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, SERVER_PORT);
        if let Err(e) = sock.bind(&SockAddr::from(bind_addr)) {
            warn!("DHCP bind {}: {}", bind_addr, e); return None;
        }
        // Enable IP_PKTINFO so sendmsg can set source IP per-packet
        let std_sock: std::net::UdpSocket = sock.into();
        if let Err(e) = enable_ip_pktinfo(std_sock.as_raw_fd()) {
            warn!("DHCP IP_PKTINFO: {}", e); return None;
        }
        match tokio::net::UdpSocket::from_std(std_sock) {
            Ok(s) => {
                info!("DHCP listening on 0.0.0.0:{} (IP_PKTINFO, src={})", SERVER_PORT, src_ip);
                Arc::new(s)
            }
            Err(e) => { warn!("DHCP from_std: {}", e); return None; }
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
    _src: std::net::SocketAddr,
    src_ip: Ipv4Addr,
    ifindex: u32,
) {
    let mut decoder = dhcproto::Decoder::new(&data);
    let msg = match Message::decode(&mut decoder) {
        Ok(m) => m,
        Err(e) => {
            warn!("DHCP failed to decode message: {:?}", e);
            return;
        }
    };

    let chaddr = msg.chaddr();
    if chaddr.len() < 6 { return; }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&chaddr[..6]);

    let msg_type = match msg.opts().get(dhcproto::v4::OptionCode::MessageType) {
        Some(dhcproto::v4::DhcpOption::MessageType(mt)) => *mt,
        _ => {
            warn!("DHCP message missing MessageType option");
            return;
        }
    };
    match msg_type {
        MessageType::Discover => {
            let now = chrono::Utc::now().timestamp();
            // Atomically: check lease → check offered → allocate under offered.write() lock
            let (offered_ip, _is_new) = {
                let leases = server.leases.read();
                if let Some(l) = leases.get(&mac) {
                    (Some(l.ip), false)
                } else {
                    let mut offers = server.offered.write();
                    // Check for existing non-expired offer to this MAC
                    let existing = offers.iter().find(|(_, val)| val.1 == mac && val.0 > now)
                        .map(|(&ip, _)| ip);
                    match existing {
                        Some(ip) => {
                            // Refresh TTL on reuse
                            offers.insert(ip, (now + OFFER_TIMEOUT, mac));
                            (Some(Ipv4Addr::from(ip)), false)
                        }
                        None => {
                            // Allocate new IP
                            let declined: HashSet<u32> = server.declined.read().keys().copied().collect();
                            if let Some(ip) = server.pool.write().next_available(&declined) {
                                let ip_u32 = u32::from(ip);
                                offers.insert(ip_u32, (now + OFFER_TIMEOUT, mac));
                                (Some(ip), true)
                            } else {
                                (None, false)
                            }
                        }
                    }
                }
            };
            match offered_ip {
                Some(ip) => {
                    let response = build_offer(&msg, ip, &server);
                    match encode_message(&response) {
                        Ok(bytes) => {
                            let dest = SocketAddrV4::new(Ipv4Addr::BROADCAST, CLIENT_PORT);
                            if let Err(e) = send_dhcp(&socket, &bytes, dest, src_ip, ifindex).await {
                                warn!("DHCP OFFER send error: {}", e);
                            } else {
                                info!("DHCP OFFER {} to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                    ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                            }
                        }
                        Err(e) => warn!("DHCP encode OFFER error: {}", e),
                    }
                }
                None => warn!("DHCP no available IP for {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]),
            }
        }
        MessageType::Request => {
            // SELECTING (initial): client provides RequestedIpAddress option
            // RENEWING/REBINDING: client sets ciaddr, no RequestedIpAddress
            let requested_ip = msg.opts().get(dhcproto::v4::OptionCode::RequestedIpAddress)
                .and_then(|o| match o {
                    dhcproto::v4::DhcpOption::RequestedIpAddress(ip) => Some(*ip),
                    _ => None,
                }).or_else(|| {
                    let ciaddr = msg.ciaddr();
                    if ciaddr != Ipv4Addr::UNSPECIFIED { Some(ciaddr) } else { None }
                });

            if let Some(ip) = requested_ip {
                // Validate: IP must be in pool range
                let valid = { server.pool.read().contains(ip) };

                if !valid {
                    warn!("DHCP NAK for {} to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (IP not in pool)",
                        ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                    let nak = build_nak(&msg, &server);
                    if let Ok(bytes) = encode_message(&nak) {
                        let dest = SocketAddrV4::new(Ipv4Addr::BROADCAST, CLIENT_PORT);
                        let _ = send_dhcp(&socket, &bytes, dest, src_ip, ifindex).await;
                    }
                    return;
                }

                let (_lease_time, expires, hostname) = {
                    let cfg = server.config.read();
                    let lt = cfg.lease_time;
                    let host = msg.opts().get(dhcproto::v4::OptionCode::Hostname)
                        .and_then(|o| match o {
                            dhcproto::v4::DhcpOption::Hostname(h) => Some(h.clone()),
                            _ => None,
                        });
                    (lt, chrono::Utc::now().timestamp() + lt as i64, host)
                };

                // Atomically: conflict-check + lease-insert under a single write lock.
                if !server.try_commit_lease(mac, ip, expires, hostname.clone()) {
                    warn!("DHCP NAK for {} to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (IP conflict)",
                        ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                    let nak = build_nak(&msg, &server);
                    if let Ok(bytes) = encode_message(&nak) {
                        let dest = SocketAddrV4::new(Ipv4Addr::BROADCAST, CLIENT_PORT);
                        let _ = send_dhcp(&socket, &bytes, dest, src_ip, ifindex).await;
                    }
                    return;
                }

                // Sync pool: mark IP as allocated (in case it was free)
                server.pool.write().mark_allocated(ip);
                // Remove from offered table (if it was an initial offer)
                server.offered.write().remove(&u32::from(ip));
                persist_lease(&server, &mac, ip, &hostname, expires);

                let response = build_ack(&msg, ip, &server);
                if let Ok(bytes) = encode_message(&response) {
                    // If client set broadcast flag, always broadcast regardless of ciaddr
                    let flags: u16 = msg.flags().into();
                    let broadcast_flag = flags & 0x8000 != 0;
                    let dest = if !broadcast_flag && msg.ciaddr() != Ipv4Addr::UNSPECIFIED {
                        SocketAddrV4::new(msg.ciaddr(), CLIENT_PORT)
                    } else {
                        SocketAddrV4::new(Ipv4Addr::BROADCAST, CLIENT_PORT)
                    };
                    if let Err(e) = send_dhcp(&socket, &bytes, dest, src_ip, ifindex).await {
                        warn!("DHCP ACK send error: {}", e);
                    } else {
                        info!("DHCP ACK {} to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                    }
                }
            }
        }
        MessageType::Release => {
            let ciaddr = msg.ciaddr();
            if ciaddr != Ipv4Addr::UNSPECIFIED {
                server.pool.write().release(ciaddr);
                server.leases.write().remove(&mac);
                delete_persisted_lease(&server, &mac);
                debug!("DHCP RELEASE {} from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    ciaddr, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            }
        }
        MessageType::Decline => {
            // Windows sends DECLINE when ARP probe finds a conflict (RFC 2131 §4.3.3)
            // The rejected IP is in RequestedIpAddress option (Option 50), NOT ciaddr
            let declined_ip = msg.opts().get(dhcproto::v4::OptionCode::RequestedIpAddress)
                .and_then(|o| match o {
                    dhcproto::v4::DhcpOption::RequestedIpAddress(ip) => Some(*ip),
                    _ => None,
                }).or_else(|| {
                    let ciaddr = msg.ciaddr();
                    if ciaddr != Ipv4Addr::UNSPECIFIED { Some(ciaddr) } else { None }
                });
            if let Some(ip) = declined_ip {
                let ip_u32 = u32::from(ip);
                let now = chrono::Utc::now().timestamp();
                // DO NOT release back to pool — quarantine for 10 minutes
                // so next_available() skips it and offers a different IP
                server.declined.write().insert(ip_u32, now + 600);
                server.leases.write().remove(&mac);
                server.offered.write().remove(&ip_u32);
                delete_persisted_lease(&server, &mac);
                info!("DHCP DECLINE {} from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (quarantined 10min)",
                    ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            }
        }
        _ => {}
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
    opts.insert(dhcproto::v4::DhcpOption::Router(vec![cfg.router.unwrap_or(sid)]));
    opts.insert(dhcproto::v4::DhcpOption::AddressLeaseTime(cfg.lease_time));
    opts.insert(dhcproto::v4::DhcpOption::Renewal(cfg.lease_time / 2));
    opts.insert(dhcproto::v4::DhcpOption::Rebinding((cfg.lease_time * 3) / 4));
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
    opts.insert(dhcproto::v4::DhcpOption::Router(vec![cfg.router.unwrap_or(sid)]));
    opts.insert(dhcproto::v4::DhcpOption::AddressLeaseTime(cfg.lease_time));
    opts.insert(dhcproto::v4::DhcpOption::Renewal(cfg.lease_time / 2));
    opts.insert(dhcproto::v4::DhcpOption::Rebinding((cfg.lease_time * 3) / 4));
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
    let mut msg = make_msg(request.xid(), Ipv4Addr::UNSPECIFIED, sid, &request.chaddr()[..6]);
    msg.set_opcode(Opcode::BootReply);
    msg.set_flags(request.flags());
    let mut opts = DhcpOptions::new();
    opts.insert(dhcproto::v4::DhcpOption::MessageType(MessageType::Nak));
    opts.insert(dhcproto::v4::DhcpOption::ServerIdentifier(sid));
    msg.set_opts(opts);
    drop(cfg);
    msg
}

/// Reclaim expired leases and offered IPs (call periodically from check.tick)
fn reclaim_expired(server: &DhcpServer) {
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
        let mut pool = server.pool.write();
        for ip in &expired_ips {
            pool.release(Ipv4Addr::from(*ip));
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
            pool.release(Ipv4Addr::from(*ip));
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
        let mut pool = server.pool.write();
        for ip in &expired_declined {
            pool.release(Ipv4Addr::from(*ip));
        }
        debug!("DHCP reclaimed {} expired declined IPs", expired_declined.len());
    }
}

/// Persist a lease to the database
fn persist_lease(server: &DhcpServer, mac: &[u8; 6], ip: Ipv4Addr, hostname: &Option<String>, expires_at: i64) {
    if let Some(ref db) = server.db {
        let mac_str = mac.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":");
        let ip_u32 = u32::from(ip);
        let hostname_str = hostname.as_deref().unwrap_or("");
        let _ = crate::database::queries::persist_dhcp_lease(db, &mac_str, ip_u32, hostname_str, expires_at);
    }
}

/// Delete a persisted lease
fn delete_persisted_lease(server: &DhcpServer, mac: &[u8; 6]) {
    if let Some(ref db) = server.db {
        let mac_str = mac.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":");
        let _ = crate::database::queries::delete_dhcp_lease(db, &mac_str);
    }
}

/// Load persisted leases from database, filtering out expired ones
fn load_persisted_leases(db: &Arc<crate::database::queries::QueryDb>, pool_start: Ipv4Addr, pool_end: Ipv4Addr) -> HashMap<[u8; 6], Lease> {
    // Ensure the table exists
    let _ = crate::database::queries::ensure_dhcp_leases_table(db);
    let now = chrono::Utc::now().timestamp();
    let mut leases = HashMap::new();
    if let Ok(rows) = crate::database::queries::load_dhcp_leases(db) {
        for (mac_str, ip_u32, hostname, expires_at) in rows {
            if expires_at <= now { continue; }
            let ip = Ipv4Addr::from(ip_u32);
            if ip < pool_start || ip > pool_end { continue; }
            let mac: [u8; 6] = mac_str.split(':')
                .filter_map(|b| u8::from_str_radix(b, 16).ok())
                .collect::<Vec<_>>()
                .try_into()
                .ok()
                .unwrap_or_default();
            if mac == [0u8; 6] { continue; }
            leases.insert(mac, Lease {
                ip,
                mac,
                hostname: if hostname.is_empty() { None } else { Some(hostname) },
                expires_at,
            });
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
    server.leases.read().values().filter(|l| l.expires_at > now).count()
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

    fn ip(s: &str) -> Ipv4Addr { s.parse().unwrap() }
    fn ipu(s: &str) -> u32 { u32::from(ip(s)) }

    fn make_server() -> DhcpServer {
        DhcpServer {
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
    // IpPool tests (P0)
    // ======================================================================

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
        opts.insert(dhcproto::v4::DhcpOption::MessageType(dhcproto::v4::MessageType::Discover));
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
        let lt = match opts.get(dhcproto::v4::OptionCode::AddressLeaseTime).unwrap() {
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
        assert_eq!(rebind, 64800); // 86400*3/4
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
        assert!(opts.get(dhcproto::v4::OptionCode::ServerIdentifier).is_some());
        match opts.get(dhcproto::v4::OptionCode::MessageType).unwrap() {
            dhcproto::v4::DhcpOption::MessageType(mt) => assert_eq!(*mt, dhcproto::v4::MessageType::Offer),
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
        let dns = match opts.get(dhcproto::v4::OptionCode::DomainNameServer).unwrap() {
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
        let dns = match opts.get(dhcproto::v4::OptionCode::DomainNameServer).unwrap() {
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
            dhcproto::v4::DhcpOption::MessageType(mt) => assert_eq!(*mt, dhcproto::v4::MessageType::Ack),
            _ => panic!("wrong type"),
        }
        assert!(opts.get(dhcproto::v4::OptionCode::SubnetMask).is_some());
        assert!(opts.get(dhcproto::v4::OptionCode::Router).is_some());
        assert!(opts.get(dhcproto::v4::OptionCode::ServerIdentifier).is_some());
        assert!(opts.get(dhcproto::v4::OptionCode::AddressLeaseTime).is_some());
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
            dhcproto::v4::DhcpOption::MessageType(mt) => assert_eq!(*mt, dhcproto::v4::MessageType::Nak),
            _ => panic!("wrong type"),
        }
        assert!(opts.get(dhcproto::v4::OptionCode::ServerIdentifier).is_some());
        // yiaddr must be 0.0.0.0 for NAK
        assert_eq!(nak.yiaddr(), Ipv4Addr::UNSPECIFIED);
    }

    // ======================================================================
    // try_commit_lease tests (P1) — #4 fix regression tests
    // ======================================================================

    fn mac_a() -> [u8; 6] { [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01] }
    fn mac_b() -> [u8; 6] { [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02] }

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
        server.leases.write().insert(mac_a(), Lease {
            ip: ip("192.168.1.100"),
            mac: mac_a(),
            hostname: None,
            expires_at: 1, // expired
        });
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
        server.offered.write().insert(ipu("192.168.1.100"), (now - 10, mac_a())); // expired offer
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
        assert_eq!(pool.next_available(&declined), Some(ip("192.168.1.100")));
    }
}


