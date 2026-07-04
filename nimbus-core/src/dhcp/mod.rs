// =============================================================================
// NimbusDNS DHCP Server (IPv4, RFC 2131)
// =============================================================================
// Minimal DHCP server implementation using dhcproto 0.15.
// Handles DISCOVER → OFFER, REQUEST → ACK cycle.
// IP pool management with in-memory lease storage.

use std::collections::HashMap;
use std::io::{self, IoSlice};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Arc;

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
}

struct IpPool {
    start: Ipv4Addr,
    end: Ipv4Addr,
    allocated: Vec<Ipv4Addr>,
}

impl IpPool {
    fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        Self { start, end, allocated: Vec::new() }
    }
    /// Check if an IP is within the pool range
    fn contains(&self, ip: Ipv4Addr) -> bool {
        ip >= self.start && ip <= self.end
    }
    /// Return the next available IP, or None if pool is full
    fn next_available(&mut self) -> Option<Ipv4Addr> {
        let mut ip = self.start;
        while ip <= self.end {
            if !self.allocated.contains(&ip) {
                self.allocated.push(ip);
                return Some(ip);
            }
            ip = next_ipv4(ip, self.end);
            if ip > self.end { break; }
        }
        None
    }
    /// Mark an IP as allocated (used when ACKing a renewal/request)
    fn mark_allocated(&mut self, ip: Ipv4Addr) {
        if self.contains(ip) && !self.allocated.contains(&ip) {
            self.allocated.push(ip);
        }
    }
    fn release(&mut self, ip: Ipv4Addr) {
        self.allocated.retain(|&a| a != ip);
    }
    /// Check if an IP is currently allocated
    fn is_allocated(&self, ip: Ipv4Addr) -> bool {
        self.allocated.contains(&ip)
    }
}

fn next_ipv4(ip: Ipv4Addr, end: Ipv4Addr) -> Ipv4Addr {
    let octets = ip.octets();
    let next = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3].wrapping_add(1));
    if next > end { end } else { next }
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

    let server = Arc::new(DhcpServer {
        config,
        leases: Arc::new(RwLock::new(HashMap::new())),
        pool: Arc::new(RwLock::new(IpPool::new(pool_start, pool_end))),
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
                    if !cfg_check.read().enabled {
                        info!("DHCP server stopped by config change");
                        break;
                    }
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
            // Reuse existing lease IP if MAC already has one
            let offered_ip = {
                let leases = server.leases.read();
                leases.get(&mac).map(|l| l.ip)
            };
            let offered_ip = offered_ip.or_else(|| {
                server.pool.write().next_available()
            });
            match offered_ip {
                Some(ip) => {
                    // Extend lease time on rediscovery
                    if server.leases.read().contains_key(&mac) {
                        let expires = chrono::Utc::now().timestamp()
                            + server.config.read().lease_time as i64;
                        server.leases.write().get_mut(&mac).map(|l| l.expires_at = expires);
                    }
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

                // Sync pool: mark IP as allocated (in case it was free)
                server.pool.write().mark_allocated(ip);
                let lease = Lease { ip, mac, hostname, expires_at: expires };
                server.leases.write().insert(mac, lease);

                let response = build_ack(&msg, ip, &server);
                if let Ok(bytes) = encode_message(&response) {
                    // Renewal ACK goes to ciaddr (unicast), initial ACK is broadcast
                    let dest = if msg.ciaddr() != Ipv4Addr::UNSPECIFIED {
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
                debug!("DHCP RELEASE {} from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    ciaddr, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
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

/// Get current leases (for API), filtering out expired ones
pub fn get_leases(server: &DhcpServer) -> Vec<Lease> {
    let now = chrono::Utc::now().timestamp();
    let mut leases = server.leases.write();
    // Remove expired leases and release their IPs back to pool
    leases.retain(|_mac, lease| {
        if lease.expires_at <= now {
            server.pool.write().release(lease.ip);
            false
        } else {
            true
        }
    });
    leases.values().cloned().collect()
}

pub fn get_lease_count(server: &DhcpServer) -> usize {
    let now = chrono::Utc::now().timestamp();
    server.leases.read().values().filter(|l| l.expires_at > now).count()
}


