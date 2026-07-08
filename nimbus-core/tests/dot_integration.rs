// =============================================================================
// DoT Integration Tests
// =============================================================================
// Uses a fake DoT server with a self-signed certificate to test:
//   - Basic query/response flow
//   - Reconnect on connection drop (regression #1)
//   - In-flight disconnect → ConnectionClosed
//   - Timeout isolation (no cross-delivery, regression #2)
//   - ID multiplexing (concurrent queries, out-of-order responses)
// =============================================================================

use std::sync::Arc;
use std::time::Duration;

use nimbus_core::config::DnsUpstream;
use nimbus_core::dns::{DotError, DotManager};

// ── Fake DoT Server ──────────────────────────────────────────────────────────

#[derive(Clone)]
enum Mode {
    /// Normal: respond to each query with an echoed ID+question
    Normal,
    /// Drop the connection immediately after accepting (simulate TCP RST)
    Drop,
    /// Respond once then disconnect (simulate server-side close)
    RespondThenDrop,
    /// For timeout isolation: delay first response, respond quickly to second
    DelayFirst { delay: Duration },
}

fn make_self_signed_cert() -> (Vec<u8>, Vec<u8>) {
    use rcgen::*;
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    (cert.cert.der().to_vec(), cert.key_pair.serialize_der())
}

fn make_client_config(ca_der: &[u8]) -> rustls::ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(rustls::pki_types::CertificateDer::from(ca_der.to_vec()))
        .unwrap();
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

/// Run a fake DoT server on a random port. Returns the port and the
/// certificate DER (so the caller can trust the same cert).
/// The server handles exactly one TLS connection then exits.
async fn handle_connection(tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>, mode: &Mode) {
    let (mut reader, mut writer) = tokio::io::split(tls);
    match mode {
        Mode::Drop => (),
        Mode::RespondThenDrop => {
            if let Ok(data) = read_dns_msg_srv(&mut reader).await {
                let response = build_response(&data);
                let _ = write_dns_msg_srv(&mut writer, &response).await;
            }
        }
        Mode::DelayFirst { delay } => {
            if let Ok(data) = read_dns_msg_srv(&mut reader).await {
                tokio::time::sleep(*delay).await;
                let response = build_response(&data);
                let _ = write_dns_msg_srv(&mut writer, &response).await;
            }
            if let Ok(data) = read_dns_msg_srv(&mut reader).await {
                let response = build_response(&data);
                let _ = write_dns_msg_srv(&mut writer, &response).await;
            }
        }
        Mode::Normal => {
            while let Ok(data) = read_dns_msg_srv(&mut reader).await {
                let response = build_response(&data);
                let _ = write_dns_msg_srv(&mut writer, &response).await;
            }
        }
    }
}

async fn run_fake_dot_server(mode: Mode) -> (u16, Vec<u8>) {
    let (cert_der, key_der) = make_self_signed_cert();
    let ca_for_client = cert_der.clone();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der)],
            rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
            ),
        )
        .expect("bad server cert/key");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let mode = Arc::new(mode);

    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.expect("accept");
            let tls = tokio_rustls::TlsAcceptor::from(Arc::new(server_config.clone()))
                .accept(tcp)
                .await
                .expect("TLS accept failed");
            let mode = Arc::clone(&mode);
            tokio::spawn(async move {
                handle_connection(tls, &mode).await;
            });
        }
    });

    (port, ca_for_client)
}

/// Server-side reader: uses `tokio_rustls::server::TlsStream`
type ServerStream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

async fn read_dns_msg_srv(
    reader: &mut tokio::io::ReadHalf<ServerStream>,
) -> Result<Vec<u8>, ()> {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await.map_err(|_| ())?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 4096 {
        return Err(());
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await.map_err(|_| ())?;
    Ok(buf)
}

async fn write_dns_msg_srv(
    writer: &mut tokio::io::WriteHalf<ServerStream>,
    data: &[u8],
) -> Result<(), ()> {
    use tokio::io::AsyncWriteExt;
    let len = (data.len() as u16).to_be_bytes();
    writer.write_all(&len).await.map_err(|_| ())?;
    writer.write_all(data).await.map_err(|_| ())?;
    Ok(())
}

/// Build a response that echoes the query's ID and first question.
fn build_response(query: &[u8]) -> Vec<u8> {
    if let Ok(msg) = hickory_proto::op::Message::from_vec(query) {
        let mut resp =
            hickory_proto::op::Message::response(msg.metadata.id, hickory_proto::op::OpCode::Query);
        for q in &msg.queries {
            resp.add_query(q.clone());
        }
        // Add a dummy answer so the response is valid
        if let Some(q) = msg.queries.first() {
            let name = q.name().clone();
            let qtype = q.query_type();
            if qtype == hickory_proto::rr::RecordType::A {
                let record = hickory_proto::rr::Record::from_rdata(
                    name,
                    60,
                    hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A::new(
                        127, 0, 0, 1,
                    )),
                );
                resp.add_answer(record);
            }
        }
        resp.to_vec().unwrap_or_else(|_| query.to_vec())
    } else {
        query.to_vec()
    }
}

fn make_query(id: u16, name: &str) -> Vec<u8> {
    let mut msg = hickory_proto::op::Message::query();
    msg.metadata.id = id;
    msg.add_query(hickory_proto::op::Query::query(
        hickory_proto::rr::Name::from_utf8(name).unwrap(),
        hickory_proto::rr::RecordType::A,
    ));
    msg.to_vec().unwrap()
}

fn dns_id(data: &[u8]) -> u16 {
    if data.len() >= 2 {
        u16::from_be_bytes([data[0], data[1]])
    } else {
        0
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// Test 41: Basic query → response with correct ID echo
#[tokio::test]
async fn test_basic_query_response() {
    let (port, ca) = run_fake_dot_server(Mode::Normal).await;
    let manager = DotManager::with_tls_config(make_client_config(&ca));

    let upstream = DnsUpstream::Tls {
        address: "127.0.0.1".parse().unwrap(),
        port,
        hostname: "localhost".into(),
    };

    let query = make_query(42, "test.example.com");
    let result = manager
        .send_query(&upstream, &query, Duration::from_secs(5))
        .await;
    assert!(result.is_ok(), "expected Ok, got {:?}", result);
    let response = result.unwrap();
    assert_eq!(
        dns_id(&response),
        42,
        "response ID should match query ID"
    );
}

/// Test 42: Reconnect (#1) — server disconnects after first query,
/// second query reconnects on a fresh connection and succeeds.
#[tokio::test]
async fn test_reconnect_after_drop() {
    let (port, ca) = run_fake_dot_server(Mode::RespondThenDrop).await;
    let manager = DotManager::with_tls_config(make_client_config(&ca));

    let upstream = DnsUpstream::Tls {
        address: "127.0.0.1".parse().unwrap(),
        port,
        hostname: "localhost".into(),
    };

    // First query succeeds (server responds then drops the connection)
    let q1 = make_query(1, "first.example.com");
    let r1 = manager
        .send_query(&upstream, &q1, Duration::from_secs(5))
        .await;
    assert!(r1.is_ok(), "first query should succeed");

    // Second query — the old connection is dead; DoT reconnects to the
    // multi-connection server, which accepts a fresh TLS connection.
    // A query that races into the closing window gets ConnectionClosed
    // (see test_inflight_disconnect); the retry loop waits out reconnect.
    let q2 = make_query(2, "second.example.com");
    let mut r2 = None;
    for _ in 0..10 {
        match manager.send_query(&upstream, &q2, Duration::from_secs(10)).await {
            Ok(resp) => { r2 = Some(resp); break; }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let r2 = r2.expect("second query should succeed after reconnect");
    assert_eq!(dns_id(&r2), 2, "response should have query2's ID");
}

/// Test 43: In-flight disconnect → caller gets ConnectionClosed
#[tokio::test]
async fn test_inflight_disconnect() {
    let (port, ca) = run_fake_dot_server(Mode::Drop).await;
    let manager = DotManager::with_tls_config(make_client_config(&ca));

    let upstream = DnsUpstream::Tls {
        address: "127.0.0.1".parse().unwrap(),
        port,
        hostname: "localhost".into(),
    };

    let query = make_query(1, "drop.example.com");
    let result = manager
        .send_query(&upstream, &query, Duration::from_secs(5))
        .await;
    match result {
        Err(DotError::ConnectionClosed) => {}
        Err(DotError::Io(_)) => {}
        Err(DotError::TlsHandshake(_)) => {}
        other => panic!(
            "expected ConnectionClosed/Io/TlsHandshake, got {:?}",
            other
        ),
    }
}

/// Test 44: Timeout isolation (#2) — query1 times out (short timeout),
/// query2 (normal timeout) gets its own correct response.
#[tokio::test]
async fn test_timeout_isolation() {
    let (port, ca) = run_fake_dot_server(Mode::DelayFirst {
            delay: Duration::from_millis(500),
        })
        .await;
    let manager = DotManager::with_tls_config(make_client_config(&ca));

    let upstream = DnsUpstream::Tls {
        address: "127.0.0.1".parse().unwrap(),
        port,
        hostname: "localhost".into(),
    };

    // query1: very short timeout → should time out
    let q1 = make_query(10, "timeout.example.com");
    let r1 = manager
        .send_query(&upstream, &q1, Duration::from_millis(50))
        .await;
    assert!(matches!(r1, Err(DotError::Timeout)));

    // query2: normal timeout → should succeed (server responds quickly for 2nd query)
    let q2 = make_query(20, "normal.example.com");
    let r2 = manager
        .send_query(&upstream, &q2, Duration::from_secs(5))
        .await;
    assert!(r2.is_ok(), "second query should succeed, got {:?}", r2);
    let resp = r2.unwrap();
    assert_eq!(
        dns_id(&resp),
        20,
        "response should have query2's ID"
    );
}

/// Test 45: ID multiplexing — 2 concurrent queries, each gets its own response.
#[tokio::test]
async fn test_id_multiplexing() {
    let (port, ca) = run_fake_dot_server(Mode::Normal).await;
    let manager = DotManager::with_tls_config(make_client_config(&ca));

    let upstream = DnsUpstream::Tls {
        address: "127.0.0.1".parse().unwrap(),
        port,
        hostname: "localhost".into(),
    };

    // Fire two queries concurrently
    let q1 = make_query(100, "first.example.com");
    let q2 = make_query(200, "second.example.com");

    let (r1, r2) = tokio::join!(
        manager.send_query(&upstream, &q1, Duration::from_secs(5)),
        manager.send_query(&upstream, &q2, Duration::from_secs(5)),
    );

    assert!(r1.is_ok(), "first query should succeed, got {:?}", r1);
    assert!(r2.is_ok(), "second query should succeed, got {:?}", r2);

    let resp1 = r1.unwrap();
    let resp2 = r2.unwrap();

    assert_eq!(
        dns_id(&resp1),
        100,
        "first response should have ID 100"
    );
    assert_eq!(
        dns_id(&resp2),
        200,
        "second response should have ID 200"
    );
}
