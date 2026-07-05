// =============================================================================
// DNS Listener
// =============================================================================

use std::net::SocketAddr;
use std::sync::Arc;

use hickory_proto::op::{Message, OpCode, ResponseCode};
use tokio::net::{UdpSocket, TcpListener};
use tracing::{info, error, debug};

use crate::dns::router::{QueryRouter, QueryResult, truncate_if_needed};

const MAX_DNS_SIZE: usize = 4096;

/// Start the DNS listener on the given address
pub async fn start(
    bind_addr: SocketAddr,
    router: Arc<QueryRouter>,
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

    // Run UDP and TCP concurrently
    let udp_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        handle_udp(sock_udp, rtr_udp, udp_shutdown).await;
    });
    tokio::spawn(async move {
        handle_tcp(tcp_listener, rtr_tcp, shutdown_rx).await;
    });

    Ok(())
}

async fn handle_udp(socket: Arc<UdpSocket>, router: Arc<QueryRouter>, mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
    let mut buf = vec![0u8; MAX_DNS_SIZE];

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, src)) => {
                        let data = buf[..len].to_vec();
                        let sock = socket.clone();
                        let rtr = router.clone();
                        tokio::spawn(async move {
                            process_udp_query(sock, data, src, rtr).await.ok();
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

    let result = router.route(query, src).await;

    match result {
        QueryResult::Response(mut bytes) => {
            // Truncate if response exceeds UDP max payload (only for UDP)
            let msg = Message::from_vec(&bytes).ok();
            if let Some(ref msg) = msg {
                if let Some(truncated) = truncate_if_needed(msg) {
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

async fn handle_tcp(listener: TcpListener, router: Arc<QueryRouter>, mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((mut stream, src)) => {
                        let rtr = router.clone();
                        tokio::spawn(async move {
                            let mut len_buf = [0u8; 2];
                            if let Err(e) = stream.read_exact(&mut len_buf).await {
                                debug!("TCP read length failed from {}: {}", src, e);
                                return;
                            }

                            let query_len = u16::from_be_bytes(len_buf) as usize;
                            if query_len == 0 || query_len > MAX_DNS_SIZE {
                                return;
                            }

                            let mut query_buf = vec![0u8; query_len];
                            if let Err(_e) = stream.read_exact(&mut query_buf).await {
                                return;
                            }

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
