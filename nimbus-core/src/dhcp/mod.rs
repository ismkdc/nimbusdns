// =============================================================================
// NimbusDNS DHCP Server (IPv4, RFC 2131)
// =============================================================================
// Minimal DHCP server implementation using dhcproto 0.15.
// Handles DISCOVER → OFFER, REQUEST → ACK cycle.
// IP pool management with in-memory lease storage.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use dhcproto::v4::{DhcpOptions, Message, MessageType, Opcode};
use dhcproto::{Decodable, Encoder, Encodable};
use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config::DhcpConfig;

const SERVER_PORT: u16 = 67;
const CLIENT_PORT: u16 = 68;

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
    fn next_available(&mut self) -> Option<Ipv4Addr> {
        let mut ip = self.start;
        while ip <= self.end {
            if !self.allocated.contains(&ip) {
                self.allocated.push(ip);
                return Some(ip);
            }
            ip = next_ipv4(ip);
        }
        None
    }
    fn release(&mut self, ip: Ipv4Addr) {
        self.allocated.retain(|&a| a != ip);
    }
}

fn next_ipv4(ip: Ipv4Addr) -> Ipv4Addr {
    let octets = ip.octets();
    Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3].wrapping_add(1))
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

    let server = Arc::new(DhcpServer {
        config,
        leases: Arc::new(RwLock::new(HashMap::new())),
        pool: Arc::new(RwLock::new(IpPool::new(pool_start, pool_end))),
    });

    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, SERVER_PORT);
    let std_addr = std::net::SocketAddr::V4(bind_addr);
    let socket = match socket2::Socket::new(
        socket2::Domain::for_address(std_addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    ) {
        Ok(s2) => {
            let _ = s2.set_reuse_address(true);
            let _ = s2.set_broadcast(true);
            let _ = s2.bind(&socket2::SockAddr::from(std_addr));
            let _ = s2.set_nonblocking(true);
            info!("DHCP server listening on {} (SO_REUSEADDR)", bind_addr);
            Arc::new(tokio::net::UdpSocket::from_std(s2.into()).unwrap())
        }
        Err(e) => { warn!("Cannot bind DHCP port {}: {}", SERVER_PORT, e); return None; }
    };

    let mut buf = vec![0u8; 1024];
    let mut shutdown = shutdown_rx;
    let svr = server.clone();
    let cfg_check = server.config.clone();

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
                            handle_dhcp_packet(s, sock, data, src).await;
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
) {
    let mut decoder = dhcproto::Decoder::new(&data);
    let msg = match Message::decode(&mut decoder) {
        Ok(m) => m,
        Err(_) => return,
    };

    let msg_type = match msg.opts().get(dhcproto::v4::OptionCode::MessageType) {
        Some(dhcproto::v4::DhcpOption::MessageType(mt)) => *mt,
        _ => return,
    };

    let chaddr = msg.chaddr();
    if chaddr.len() < 6 { return; }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&chaddr[..6]);

    match msg_type {
        MessageType::Discover => {
            let offered_ip = { server.pool.write().next_available() }; // drop guard before await
            if let Some(ip) = offered_ip {
                let response = build_offer(&msg, ip, &server);
                if let Ok(bytes) = encode_message(&response) {
                    let dest = std::net::SocketAddr::V4(
                        SocketAddrV4::new(Ipv4Addr::BROADCAST, CLIENT_PORT)
                    );
                    let _ = socket.send_to(&bytes, dest).await;
                    debug!("DHCP OFFER {} to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                }
            }
        }
        MessageType::Request => {
            let requested_ip = msg.opts().get(dhcproto::v4::OptionCode::RequestedIpAddress)
                .and_then(|o| match o {
                    dhcproto::v4::DhcpOption::RequestedIpAddress(ip) => Some(*ip),
                    _ => None,
                });

            if let Some(ip) = requested_ip {
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

                let lease = Lease { ip, mac, hostname, expires_at: expires };
                server.leases.write().insert(mac, lease);

                let response = build_ack(&msg, ip, &server);
                if let Ok(bytes) = encode_message(&response) {
                    let dest = std::net::SocketAddr::V4(
                        SocketAddrV4::new(Ipv4Addr::BROADCAST, CLIENT_PORT)
                    );
                    let _ = socket.send_to(&bytes, dest).await;
                    debug!("DHCP ACK {} to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
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

fn make_msg(xid: u32, yiaddr: Ipv4Addr, chaddr: &[u8]) -> Message {
    Message::new_with_id(
        xid,
        Ipv4Addr::UNSPECIFIED, // ciaddr
        yiaddr,
        Ipv4Addr::UNSPECIFIED, // siaddr
        Ipv4Addr::UNSPECIFIED, // giaddr
        chaddr,
    )
}

fn build_offer(discover: &Message, offered_ip: Ipv4Addr, server: &DhcpServer) -> Message {
    let cfg = server.config.read();
    let mut msg = make_msg(discover.xid(), offered_ip, &discover.chaddr()[..6]);
    msg.set_opcode(Opcode::BootReply);
    msg.set_flags(Flags::default().set_broadcast());

    let mut opts = DhcpOptions::new();
    opts.insert(dhcproto::v4::DhcpOption::MessageType(MessageType::Offer));
    let sid = cfg.router.unwrap_or(Ipv4Addr::new(192, 168, 1, 1));
    opts.insert(dhcproto::v4::DhcpOption::ServerIdentifier(sid));
    opts.insert(dhcproto::v4::DhcpOption::SubnetMask(cfg.netmask));
    // DNS server: if configured, use it; otherwise use ourselves (the router/gateway)
    if let Some(dns) = cfg.dns_server {
        opts.insert(dhcproto::v4::DhcpOption::DomainNameServer(vec![dns]));
    } else {
        opts.insert(dhcproto::v4::DhcpOption::DomainNameServer(vec![sid]));
    }
    if let Some(router) = cfg.router {
        opts.insert(dhcproto::v4::DhcpOption::Router(vec![router]));
    }
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
    let mut msg = make_msg(request.xid(), offered_ip, &request.chaddr()[..6]);
    msg.set_opcode(Opcode::BootReply);
    msg.set_flags(Flags::default().set_broadcast());

    let mut opts = DhcpOptions::new();
    opts.insert(dhcproto::v4::DhcpOption::MessageType(MessageType::Ack));
    let sid = cfg.router.unwrap_or(Ipv4Addr::new(192, 168, 1, 1));
    opts.insert(dhcproto::v4::DhcpOption::ServerIdentifier(sid));
    opts.insert(dhcproto::v4::DhcpOption::SubnetMask(cfg.netmask));
    // DNS server: use ourselves (the router) if not explicitly configured
    if let Some(dns) = cfg.dns_server {
        opts.insert(dhcproto::v4::DhcpOption::DomainNameServer(vec![dns]));
    } else {
        opts.insert(dhcproto::v4::DhcpOption::DomainNameServer(vec![sid]));
    }
    if let Some(router) = cfg.router {
        opts.insert(dhcproto::v4::DhcpOption::Router(vec![router]));
    }
    opts.insert(dhcproto::v4::DhcpOption::AddressLeaseTime(cfg.lease_time));
    if let Some(ref domain) = cfg.domain {
        opts.insert(dhcproto::v4::DhcpOption::DomainName(domain.clone()));
    }
    msg.set_opts(opts);
    drop(cfg);
    msg
}

/// Get current leases (for API)
pub fn get_leases(server: &DhcpServer) -> Vec<Lease> {
    server.leases.read().values().cloned().collect()
}

pub fn get_lease_count(server: &DhcpServer) -> usize {
    server.leases.read().len()
}

// Use dhcproto's Flags directly
use dhcproto::v4::Flags;
