//! Establishing a direct peer-to-peer QUIC connection.
//!
//! 1. Bind one UDP socket and learn its public mapping via STUN.
//! 2. Exchange candidate addresses through the mailbox (internet) and/or discover the peer via
//!    LAN broadcast/multicast (no internet needed).
//! 3. Hole-punch: both sides fire small probe packets at every candidate of the other side until
//!    one gets through in each direction.
//! 4. Hand the very same socket (and therefore the same NAT mappings) to QUIC.

use crate::code::Code;
use crate::events::{emit, status, warn, Event, Tx};
use crate::mailbox::{Claim, Mailbox, PeerInfo};
use crate::stun;
use anyhow::{anyhow, bail, Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::watch;

pub const ALPN: &[u8] = b"wormhole/1";
pub const LAN_PORT: u16 = 47807;
pub const MCAST_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 78, 87);

const PROBE: &[u8; 4] = b"WHP1";
const ACK: &[u8; 4] = b"WHK1";
const LAN_Q: &[u8; 4] = b"WHQ1";
const LAN_A: &[u8; 4] = b"WHA1";

/// How long a receiver waits for a sender before giving up.
pub const RECEIVER_WAIT: Duration = Duration::from_secs(30 * 60);
/// How long a sender tries to punch through once it knows the receiver's addresses.
const PUNCH_TIMEOUT: Duration = Duration::from_secs(25);

pub struct Prepared {
    sock: UdpSocket,
    pub candidates: Vec<SocketAddr>,
}

fn bind_socket() -> Result<std::net::UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_broadcast(true)?;
    s.set_nonblocking(true)?;
    let _ = s.set_recv_buffer_size(4 << 20);
    let _ = s.set_send_buffer_size(4 << 20);
    s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())?;
    Ok(s.into())
}

struct Iface {
    ip: Ipv4Addr,
    broadcast: Option<Ipv4Addr>,
}

fn interfaces() -> Vec<Iface> {
    let mut out = Vec::new();
    if let Ok(list) = if_addrs::get_if_addrs() {
        for i in list {
            if let if_addrs::IfAddr::V4(v4) = i.addr {
                if v4.ip.is_loopback() || v4.ip.is_link_local() {
                    continue;
                }
                out.push(Iface { ip: v4.ip, broadcast: v4.broadcast });
            }
        }
    }
    out
}

/// Bind the socket, discover local and public (STUN) addresses.
pub async fn prepare(tx: &Tx, use_stun: bool) -> Result<Prepared> {
    let std_sock = bind_socket().context("binding UDP socket")?;
    let port = std_sock.local_addr()?.port();
    let sock = UdpSocket::from_std(std_sock)?;
    let mut candidates: Vec<SocketAddr> = interfaces()
        .iter()
        .map(|i| SocketAddr::new(IpAddr::V4(i.ip), port))
        .collect();
    if use_stun {
        status(tx, "Discovering public address…");
        let servers = stun::resolve(&stun::servers()).await;
        let mapped = stun::query(&sock, &servers, Duration::from_millis(1500)).await;
        if mapped.is_empty() {
            warn(tx, "Could not reach a STUN server; only local-network connections will work.");
        } else {
            let ports: HashSet<u16> = mapped.iter().map(|a| a.port()).collect();
            if ports.len() > 1 {
                warn(
                    tx,
                    "Your NAT assigns a different port per destination (symmetric NAT); a direct \
                     connection only works if the other side has an easy NAT or a public IP.",
                );
            }
            for m in mapped {
                if !candidates.contains(&m) {
                    candidates.push(m);
                }
            }
        }
    }
    Ok(Prepared { sock, candidates })
}

fn info(candidates: &[SocketAddr]) -> PeerInfo {
    PeerInfo { v: 1, addrs: candidates.iter().map(|a| a.to_string()).collect() }
}

fn parse_addrs(info: &PeerInfo) -> Vec<SocketAddr> {
    info.addrs.iter().filter_map(|a| a.parse().ok()).filter(SocketAddr::is_ipv4).collect()
}

fn packet(kind: &[u8; 4], tag: &[u8; 16]) -> [u8; 20] {
    let mut p = [0u8; 20];
    p[..4].copy_from_slice(kind);
    p[4..].copy_from_slice(tag);
    p
}

/// True if `a` is on the same subnet as one of our interfaces (i.e. no router in between).
fn is_lan_addr(a: &SocketAddr) -> bool {
    let IpAddr::V4(ip) = a.ip() else { return false };
    if ip.is_loopback() {
        return true;
    }
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .any(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) => {
                let m = u32::from(v4.netmask);
                u32::from(v4.ip) & m == u32::from(ip) & m
            }
            _ => false,
        })
}

/// Receiver side: claim a nameplate and return the code to show the user.
pub async fn claim_code(prep: &Prepared, mailbox: Option<&Mailbox>, tx: &Tx) -> Result<(Code, bool)> {
    let pi = info(&prep.candidates);
    if let Some(mb) = mailbox {
        status(tx, "Registering with the rendezvous mailbox…");
        let mut digits = 999u32;
        for attempt in 0..12 {
            if attempt == 6 {
                digits = 9999;
            }
            let np = rand::Rng::gen_range(&mut rand::thread_rng(), 1..=digits);
            match mb.claim(np, &pi).await {
                Ok(Claim::Claimed) => return Ok((Code::generate(np), true)),
                Ok(Claim::Taken) => continue,
                Err(e) => {
                    warn(tx, format!("{e:#}. Falling back to local-network only."));
                    break;
                }
            }
        }
    }
    let np = rand::Rng::gen_range(&mut rand::thread_rng(), 1..=999);
    Ok((Code::generate(np), false))
}

/// Joins the LAN multicast group and answers discovery queries for our nameplate.
fn lan_listener() -> Result<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    #[cfg(unix)]
    s.set_reuse_port(true)?;
    s.set_nonblocking(true)?;
    s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, LAN_PORT)).into())?;
    let mut joined = false;
    for i in interfaces() {
        if s.join_multicast_v4(&MCAST_GROUP, &i.ip).is_ok() {
            joined = true;
        }
    }
    if !joined {
        let _ = s.join_multicast_v4(&MCAST_GROUP, &Ipv4Addr::UNSPECIFIED);
    }
    Ok(UdpSocket::from_std(s.into())?)
}

async fn lan_responder(listener: UdpSocket, main: Arc<UdpSocket>, lan_id: [u8; 16]) {
    let mut buf = [0u8; 64];
    let answer = packet(LAN_A, &lan_id);
    loop {
        if let Ok((n, src)) = listener.recv_from(&mut buf).await {
            if n == 20 && &buf[..4] == LAN_Q && buf[4..20] == lan_id {
                // Answer from the main socket so the sender learns the exact address to punch.
                let _ = main.send_to(&answer, src).await;
            }
        }
    }
}

/// Receiver: wait until a sender reaches us, then return a QUIC endpoint + connection.
pub async fn receiver_connect(
    prep: Prepared,
    code: &Code,
    mailbox: Option<Mailbox>,
    tx: &Tx,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let sock = Arc::new(prep.sock);
    let token = code.probe_token();
    let probe = packet(PROBE, &token);
    let ack = packet(ACK, &token);

    let lan_task = match lan_listener() {
        Ok(l) => Some(tokio::spawn(lan_responder(l, sock.clone(), code.lan_id()))),
        Err(e) => {
            warn(tx, format!("Local-network discovery unavailable ({e})."));
            None
        }
    };

    let (cand_tx, cand_rx) = watch::channel(Vec::<SocketAddr>::new());
    let np = code.nameplate;
    let poll_task = mailbox.map(|mb| {
        tokio::spawn(async move {
            let mut last: Option<Vec<String>> = None;
            let started = Instant::now();
            loop {
                if let Ok(Some((_, Some(s)))) = mb.get(np).await {
                    if last.as_ref() != Some(&s.addrs) {
                        last = Some(s.addrs.clone());
                        let _ = cand_tx.send(parse_addrs(&s));
                    }
                }
                // Poll quickly at first, then back off to keep the mailbox cheap.
                let secs = if started.elapsed() < Duration::from_secs(120) { 1 } else { 3 };
                tokio::time::sleep(Duration::from_secs(secs)).await;
            }
        })
    });

    let result = async {
        let deadline = tokio::time::sleep(RECEIVER_WAIT);
        tokio::pin!(deadline);
        let mut tick = tokio::time::interval(Duration::from_millis(150));
        let mut buf = [0u8; 1500];
        let mut announced = false;
        loop {
            tokio::select! {
                _ = &mut deadline => bail!("timed out waiting for a sender (code expired)"),
                _ = tick.tick() => {
                    let c = cand_rx.borrow().clone();
                    if !c.is_empty() && !announced {
                        announced = true;
                        status(tx, "Sender found, establishing a direct connection…");
                    }
                    for a in c {
                        let _ = sock.send_to(&probe, a).await;
                    }
                }
                r = sock.recv_from(&mut buf) => {
                    let Ok((n, src)) = r else { continue };
                    if n == 20 && buf[4..20] == token {
                        if &buf[..4] == PROBE {
                            for _ in 0..3 {
                                let _ = sock.send_to(&ack, src).await;
                            }
                            return Ok(src);
                        } else if &buf[..4] == ACK {
                            return Ok(src);
                        }
                    }
                }
            }
        }
    }
    .await;

    if let Some(t) = lan_task {
        t.abort();
        let _ = t.await;
    }
    if let Some(t) = poll_task {
        t.abort();
        let _ = t.await;
    }
    let peer = result?;

    let sock = Arc::try_unwrap(sock).map_err(|_| anyhow!("socket still in use"))?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config()?),
        sock.into_std()?,
        Arc::new(quinn::TokioRuntime),
    )?;
    status(tx, "Securing the connection…");
    let conn = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let incoming = endpoint.accept().await.ok_or_else(|| anyhow!("endpoint closed"))?;
            match incoming.await {
                Ok(c) => return Ok::<_, anyhow::Error>(c),
                Err(_) => continue,
            }
        }
    })
    .await
    .map_err(|_| anyhow!("peer did not complete the QUIC handshake"))??;
    let remote = conn.remote_address();
    let _ = peer;
    emit(tx, Event::Connected { peer: remote, lan: is_lan_addr(&remote) });
    Ok((endpoint, conn))
}

enum Lookup {
    Pending,
    Found(Vec<SocketAddr>),
    NotFound,
    Unavailable,
}

/// Sender: find the receiver for `code`, punch through, connect.
pub async fn sender_connect(
    prep: Prepared,
    code: &Code,
    mailbox: Option<Mailbox>,
    tx: &Tx,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let sock = Arc::new(prep.sock);
    let token = code.probe_token();
    let probe = packet(PROBE, &token);
    let ack = packet(ACK, &token);
    let lan_q = packet(LAN_Q, &code.lan_id());
    let lan_id = code.lan_id();

    let (look_tx, look_rx) = watch::channel(Lookup::Pending);
    let np = code.nameplate;
    let my_info = info(&prep.candidates);
    let lookup_task = match mailbox {
        None => {
            let _ = look_tx.send(Lookup::Unavailable);
            None
        }
        Some(mb) => Some(tokio::spawn(async move {
            let res = async {
                match mb.get(np).await? {
                    Some((Some(r), _)) => {
                        mb.put_sender(np, &my_info).await?;
                        Ok::<_, anyhow::Error>(Lookup::Found(parse_addrs(&r)))
                    }
                    _ => Ok(Lookup::NotFound),
                }
            }
            .await;
            let _ = look_tx.send(res.unwrap_or(Lookup::Unavailable));
        })),
    };

    let mut targets: Vec<SocketAddr> = Vec::new();
    for i in interfaces() {
        if let Some(b) = i.broadcast {
            targets.push(SocketAddr::V4(SocketAddrV4::new(b, LAN_PORT)));
        }
    }
    targets.push(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, LAN_PORT)));
    targets.push(SocketAddr::V4(SocketAddrV4::new(MCAST_GROUP, LAN_PORT)));

    status(tx, "Looking for the receiver…");
    let started = Instant::now();
    let result = async {
        let mut tick = tokio::time::interval(Duration::from_millis(150));
        let mut lan_tick = tokio::time::interval(Duration::from_millis(700));
        let mut buf = [0u8; 1500];
        let mut lan_peers: Vec<SocketAddr> = Vec::new();
        let mut found_at: Option<Instant> = None;
        loop {
            tokio::select! {
                _ = lan_tick.tick() => {
                    for t in &targets {
                        let _ = sock.send_to(&lan_q, t).await;
                    }
                }
                _ = tick.tick() => {
                    let mut c = lan_peers.clone();
                    match &*look_rx.borrow() {
                        Lookup::Found(r) => c.extend(r.iter().copied()),
                        Lookup::NotFound | Lookup::Unavailable if lan_peers.is_empty()
                            && started.elapsed() > Duration::from_secs(6) => {
                            bail!("no receiver is waiting for code {code} (check the code; it may have expired)");
                        }
                        _ => {}
                    }
                    if !c.is_empty() && found_at.is_none() {
                        found_at = Some(Instant::now());
                        status(tx, "Receiver found, establishing a direct connection…");
                    }
                    if let Some(f) = found_at {
                        if f.elapsed() > PUNCH_TIMEOUT {
                            bail!("could not establish a direct connection: both sides are probably \
                                   behind strict (symmetric/carrier-grade) NATs or a firewall blocks UDP");
                        }
                    }
                    for a in c {
                        let _ = sock.send_to(&probe, a).await;
                    }
                }
                r = sock.recv_from(&mut buf) => {
                    let Ok((n, src)) = r else { continue };
                    if n != 20 { continue }
                    let kind = &buf[..4];
                    if kind == LAN_A && buf[4..20] == lan_id {
                        if !lan_peers.contains(&src) {
                            lan_peers.push(src);
                            let _ = sock.send_to(&probe, src).await;
                        }
                    } else if buf[4..20] == token {
                        if kind == PROBE {
                            let _ = sock.send_to(&ack, src).await;
                            return Ok(src);
                        } else if kind == ACK {
                            return Ok(src);
                        }
                    }
                }
            }
        }
    }
    .await;
    if let Some(t) = lookup_task {
        t.abort();
        let _ = t.await;
    }
    let peer = result?;

    let sock = Arc::try_unwrap(sock).map_err(|_| anyhow!("socket still in use"))?;
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        sock.into_std()?,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config()?);
    status(tx, "Securing the connection…");
    let conn = tokio::time::timeout(Duration::from_secs(15), endpoint.connect(peer, "wormhole")?)
        .await
        .map_err(|_| anyhow!("QUIC handshake with {peer} timed out"))?
        .context("QUIC handshake")?;
    emit(tx, Event::Connected { peer, lan: is_lan_addr(&peer) });
    Ok((endpoint, conn))
}

fn transport() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    t.keep_alive_interval(Some(Duration::from_secs(4)));
    t.stream_receive_window(quinn::VarInt::from_u32(32 << 20));
    t.receive_window(quinn::VarInt::from_u32(64 << 20));
    t.send_window(64 << 20);
    Arc::new(t)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn server_config() -> Result<quinn::ServerConfig> {
    let ck = rcgen::generate_simple_self_signed(vec!["wormhole".to_string()])?;
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    sc.transport_config(transport());
    Ok(sc)
}

fn client_config() -> Result<quinn::ClientConfig> {
    let p = provider();
    let mut tls = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PakeBound(p)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut cc = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    cc.transport_config(transport());
    Ok(cc)
}

/// Certificates are throw-away; the peer is authenticated afterwards by the SPAKE2 handshake,
/// which is bound to this TLS session's exporter secret (see `auth.rs`).
#[derive(Debug)]
struct PakeBound(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for PakeBound {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
