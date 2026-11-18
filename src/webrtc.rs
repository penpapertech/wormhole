//! WebRTC transport, so browsers can send to and receive from the CLI.
//!
//! The receiver side (CLI or browser) creates a WebRTC *offer* up front (one data channel, ICE
//! candidates from its own UDP socket + STUN) and publishes it in the mailbox. The sender answers
//! through the mailbox; ICE does the hole punching and DTLS encrypts the channel. The CLI is the
//! offerer when receiving (`prepare` + `accept`) and the answerer when sending to a browser
//! (`answer` + `connect`).
//! Authentication is the same SPAKE2 handshake as for QUIC, bound to both DTLS fingerprints so a
//! tampered offer/answer can't be used to sit in the middle.
//!
//! str0m is sans-IO: a driver task owns the socket and the `Rtc` state machine, and talks to the
//! rest of the program through channels.

use crate::connect::{self, AbortOnDrop};
use crate::events::{status, Tx};
use crate::mailbox::PeerInfo;
use crate::stun;
use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};
use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::ChannelId;
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch};

/// Stop queueing into SCTP above this many buffered bytes.
/// The send cap scales with the round-trip time (measured by ICE): enough data in flight for
/// `TARGET_RATE`, within [MIN_IN_FLIGHT, HIGH_WATER]. str0m's SCTP has no pacing and recovers
/// from losses slowly, so on a fast LAN a small window is much faster than a large one; a long
/// path needs a large one (4 MiB at 50 ms ≈ 80 MB/s).
const HIGH_WATER: usize = 4 << 20;
const MIN_IN_FLIGHT: usize = 256 << 10;
const TARGET_RATE: f64 = 160e6;

fn in_flight_cap(rtt: Duration) -> usize {
    ((rtt.as_secs_f64() * TARGET_RATE) as usize).clamp(MIN_IN_FLIGHT, HIGH_WATER)
}
/// How long ICE + DTLS + SCTP may take once the answer has arrived.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Prepared {
    sock: UdpSocket,
    rtc: Rtc,
    pending: SdpPendingOffer,
    cid: ChannelId,
    pub offer_sdp: String,
    default_ip: Option<IpAddr>,
}

/// The IP the OS would use to reach the internet (no packet is sent).
fn default_ip() -> Option<IpAddr> {
    let s = StdUdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:53").ok()?;
    Some(s.local_addr().ok()?.ip())
}

/// Bind a socket and gather local candidates (host + STUN server-reflexive).
async fn gather(use_stun: bool) -> Result<(UdpSocket, Rtc, Option<IpAddr>)> {
    let std_sock = connect::bind_socket()?;
    let port = std_sock.local_addr()?.port();
    let sock = UdpSocket::from_std(std_sock)?;
    let mut rtc = Rtc::builder()
        .set_crypto_provider(Arc::new(str0m::crypto::from_feature_flags()))
        .set_sctp_max_buffered_amount(2 * HIGH_WATER)
        .set_stats_interval(Some(Duration::from_millis(500)))
        .build(Instant::now());

    let mut hosts = Vec::new();
    for i in connect::interfaces() {
        let a = SocketAddr::new(IpAddr::V4(i.ip), port);
        if let Ok(c) = Candidate::host(a, "udp") {
            rtc.add_local_candidate(c);
            hosts.push(a);
        }
    }
    let default_ip = default_ip().or_else(|| hosts.first().map(|a| a.ip()));
    if use_stun {
        let servers = stun::resolve(&stun::servers()).await;
        for mapped in stun::query(&sock, &servers, Duration::from_millis(1500)).await {
            if hosts.contains(&mapped) {
                continue; // public IP, no NAT
            }
            if let Some(ip) = default_ip {
                if let Ok(c) = Candidate::server_reflexive(mapped, SocketAddr::new(ip, port), "udp") {
                    rtc.add_local_candidate(c);
                }
            }
        }
    }
    if hosts.is_empty() {
        bail!("no usable network interface");
    }
    Ok((sock, rtc, default_ip))
}

/// Bind a socket, gather candidates (host + STUN) and create the offer.
pub async fn prepare(use_stun: bool) -> Result<Prepared> {
    let (sock, mut rtc, default_ip) = gather(use_stun).await?;
    let mut api = rtc.sdp_api();
    let cid = api.add_channel("wormhole".to_string());
    let (offer, pending) = api.apply().ok_or_else(|| anyhow!("could not create WebRTC offer"))?;
    Ok(Prepared { sock, rtc, pending, cid, offer_sdp: offer.to_sdp_string(), default_ip })
}

/// Browsers hide their LAN addresses behind mDNS names (`xxxx.local`) that str0m can't parse or
/// resolve. Drop those candidates: the browser's connectivity checks still reach our own host
/// candidates, which gives str0m the browser's address as a peer-reflexive candidate.
fn strip_mdns(sdp: &str) -> String {
    sdp.split_inclusive('\n')
        .filter(|l| !(l.starts_with("a=candidate:") && l.split_whitespace().nth(4).is_some_and(|a| a.ends_with(".local"))))
        .collect()
}

/// The answering side (CLI sending to a browser receiver), ready to connect.
pub struct Answering {
    sock: UdpSocket,
    rtc: Rtc,
    default_ip: Option<IpAddr>,
    pub answer_sdp: String,
}

/// Answer a browser receiver's offer (from the mailbox).
pub async fn answer(offer_sdp: &str, use_stun: bool) -> Result<Answering> {
    let (sock, mut rtc, default_ip) = gather(use_stun).await?;
    let offer = SdpOffer::from_sdp_string(&strip_mdns(offer_sdp)).map_err(|e| anyhow!("bad WebRTC offer: {e}"))?;
    let answer = rtc.sdp_api().accept_offer(offer).map_err(|e| anyhow!("WebRTC offer rejected: {e}"))?;
    Ok(Answering { sock, rtc, default_ip, answer_sdp: answer.to_sdp_string() })
}

/// Wait for the browser's data channel to open (after our answer was posted).
pub async fn connect(a: Answering) -> Result<DcConn> {
    start(a.sock, a.rtc, None, false, a.default_ip).await
}

pub struct Msg {
    pub binary: bool,
    pub data: Vec<u8>,
}

/// An open, not yet authenticated data channel to a browser.
pub struct DcConn {
    out: Option<mpsc::Sender<(bool, Vec<u8>)>>,
    inbox: mpsc::UnboundedReceiver<Msg>,
    pub peer: SocketAddr,
    /// SHA-256 over both DTLS fingerprints (offer's, then answer's), for SPAKE2 binding.
    pub binding: [u8; 32],
    done: Option<oneshot::Receiver<()>>,
    _driver: AbortOnDrop,
}

impl DcConn {
    pub async fn send(&self, binary: bool, data: Vec<u8>) -> Result<()> {
        let out = self.out.as_ref().ok_or_else(|| anyhow!("channel closed"))?;
        out.send((binary, data)).await.map_err(|_| anyhow!("connection lost"))
    }

    pub async fn send_text(&self, s: &str) -> Result<()> {
        self.send(false, s.as_bytes().to_vec()).await
    }

    /// A message that has already arrived, if any.
    pub fn try_recv(&mut self) -> Option<Msg> {
        self.inbox.try_recv().ok()
    }

    pub async fn recv(&mut self) -> Result<Msg> {
        self.inbox.recv().await.ok_or_else(|| anyhow!("connection lost"))
    }

    /// Flush everything we queued, then close.
    pub async fn close(mut self) {
        self.out.take();
        if let Some(d) = self.done.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), d).await;
        }
    }
}

struct Opened {
    peer: SocketAddr,
    binding: [u8; 32],
}

/// Wait for a browser's answer (via the mailbox) and for the data channel to open.
pub async fn accept(
    prep: Prepared,
    mut sender_info: watch::Receiver<Option<PeerInfo>>,
    tx: &Tx,
) -> Result<DcConn> {
    // Wait for an answer to show up in the mailbox.
    let answer_sdp = loop {
        if let Some(sdp) = sender_info.borrow().as_ref().and_then(|i| i.webrtc.clone()) {
            break sdp;
        }
        sender_info.changed().await.map_err(|_| anyhow!("mailbox poller stopped"))?;
    };
    status(tx, "Browser sender found, establishing a WebRTC connection…");
    let answer = SdpAnswer::from_sdp_string(&strip_mdns(&answer_sdp)).map_err(|e| anyhow!("bad WebRTC answer: {e}"))?;
    let Prepared { sock, mut rtc, pending, cid, default_ip, .. } = prep;
    rtc.sdp_api().accept_answer(pending, answer).map_err(|e| anyhow!("WebRTC answer rejected: {e}"))?;
    start(sock, rtc, Some(cid), true, default_ip).await
}

/// Spawn the driver and wait for the data channel to open.
async fn start(sock: UdpSocket, rtc: Rtc, cid: Option<ChannelId>, offerer: bool, default_ip: Option<IpAddr>) -> Result<DcConn> {
    let (out_tx, out_rx) = mpsc::channel::<(bool, Vec<u8>)>(64);
    // Unbounded: the driver must never block (it also answers ICE consent checks); the inflow is
    // limited by the network and the consumer (decompress + write) is normally much faster.
    let (in_tx, in_rx) = mpsc::unbounded_channel::<Msg>();
    let (open_tx, open_rx) = oneshot::channel::<Result<Opened, String>>();
    let (done_tx, done_rx) = oneshot::channel::<()>();
    let driver = tokio::spawn(async move {
        let r = drive(sock, rtc, cid, offerer, default_ip, out_rx, in_tx, open_tx).await;
        if std::env::var_os("WORMHOLE_DEBUG").is_some() {
            if let Err(e) = &r { eprintln!("[webrtc] driver stopped: {e:#}"); }
        }
        let _ = done_tx.send(());
    });
    let driver = AbortOnDrop(driver);

    let opened = tokio::time::timeout(CONNECT_TIMEOUT, open_rx)
        .await
        .map_err(|_| anyhow!("WebRTC connection timed out (strict NAT or UDP blocked?)"))?
        .map_err(|_| anyhow!("WebRTC connection failed"))?
        .map_err(|e| anyhow!(e))?;
    Ok(DcConn {
        out: Some(out_tx),
        inbox: in_rx,
        peer: opened.peer,
        binding: opened.binding,
        done: Some(done_rx),
        _driver: driver,
    })
}

/// The local address a datagram from `src` most likely arrived on (our socket is bound to
/// 0.0.0.0, but ICE needs the concrete address of the local candidate). `ifaces` is a cached
/// list of (ip, netmask): looking interfaces up per packet is far too slow.
fn local_dest(src: &SocketAddr, port: u16, ifaces: &[(u32, u32, Ipv4Addr)], default_ip: Option<IpAddr>) -> SocketAddr {
    if let IpAddr::V4(sip) = src.ip() {
        let sip = u32::from(sip);
        for &(ip, mask, addr) in ifaces {
            if ip & mask == sip & mask {
                return SocketAddr::new(IpAddr::V4(addr), port);
            }
        }
    }
    SocketAddr::new(default_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), port)
}

fn binding(rtc: &mut Rtc, offerer: bool) -> Result<[u8; 32], String> {
    let api = rtc.direct_api();
    let local = api.local_dtls_fingerprint().clone();
    let remote = api.remote_dtls_fingerprint().cloned().ok_or("no remote DTLS fingerprint")?;
    if !local.hash_func.eq_ignore_ascii_case("sha-256") || !remote.hash_func.eq_ignore_ascii_case("sha-256") {
        return Err("unsupported DTLS fingerprint hash".into());
    }
    let (offer_fp, answer_fp) = if offerer { (&local, &remote) } else { (&remote, &local) };
    let mut h = Sha256::new();
    h.update(b"wormhole-webrtc-v1");
    h.update(&offer_fp.bytes);
    h.update(&answer_fp.bytes);
    Ok(h.finalize().into())
}

/// Token-bucket pacer for outgoing datagrams. str0m's SCTP sends a whole congestion window back
/// to back as soon as an ack arrives; bursts like that overflow the peer's (or a router's) UDP
/// buffer, and SCTP then stalls for its 1 s minimum retransmission timeout. Spreading packets
/// out avoids that.
struct Pacer {
    queue: std::collections::VecDeque<(Vec<u8>, SocketAddr)>,
    tokens: f64,
    last: Instant,
    rate: f64,  // bytes per second
    burst: f64, // bytes
}

impl Pacer {
    fn new() -> Pacer {
        // Fast enough not to limit gigabit links; measured best for stability on a LAN.
        let (rate, burst) = (400e6, 256.0 * 1024.0);
        Pacer { queue: Default::default(), tokens: burst, last: Instant::now(), rate, burst }
    }

    /// Send what the bucket allows. Returns true if packets are still waiting.
    fn flush(&mut self, sock: &UdpSocket) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate).min(self.burst);
        self.last = now;
        while let Some((data, dest)) = self.queue.front() {
            if self.tokens < data.len() as f64 {
                break;
            }
            match sock.try_send_to(data, *dest) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                _ => {}
            }
            self.tokens -= data.len() as f64;
            self.queue.pop_front();
        }
        !self.queue.is_empty()
    }
}

/// Driver state that the output pump needs.
struct Pump {
    pacer: Pacer,
    /// Current send cap (see `in_flight_cap`); the minimum until the first RTT measurement.
    cap: usize,
    min_rtt: Option<Duration>,
    /// Our channel; for the answerer, the first one the browser opens.
    cid: Option<ChannelId>,
    offerer: bool,
    open: bool,
    open_tx: Option<oneshot::Sender<Result<Opened, String>>>,
    last_src: Option<SocketAddr>,
    in_tx: mpsc::UnboundedSender<Msg>,
    disconnected_since: Option<Instant>,
}

impl Pump {
    /// Drain everything str0m wants to do right now (send packets, emit events). Must run after
    /// every input: str0m only processes queued DTLS records while being polled. Returns the next
    /// timeout, or None when the channel is finished.
    fn run(&mut self, rtc: &mut Rtc, sock: &UdpSocket) -> Result<Option<Instant>> {
        loop {
            match rtc.poll_output().context("webrtc")? {
                Output::Timeout(t) => return Ok(Some(t)),
                Output::Transmit(t) => {
                    self.pacer.queue.push_back((t.contents.into(), t.destination));
                    self.pacer.flush(sock);
                }
                Output::Event(ev) => match ev {
                    Event::ChannelOpen(id, _) if self.cid.is_none_or(|c| c == id) => {
                        self.cid = Some(id);
                        self.open = true;
                        if let Some(o) = self.open_tx.take() {
                            let peer = self.last_src.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
                            let _ = o.send(binding(rtc, self.offerer).map(|b| Opened { peer, binding: b }));
                        }
                        if let Some(mut ch) = rtc.channel(id) {
                            ch.set_buffered_amount_low_threshold(MIN_IN_FLIGHT / 2);
                        }
                    }
                    Event::ChannelData(d) if Some(d.id) == self.cid => {
                        if self.in_tx.send(Msg { binary: d.binary, data: d.data }).is_err() {
                            return Ok(None);
                        }
                    }
                    Event::ChannelClose(id) if Some(id) == self.cid => return Ok(None),
                    Event::IceConnectionStateChange(IceConnectionState::Disconnected) => {
                        self.disconnected_since.get_or_insert_with(Instant::now);
                    }
                    Event::IceConnectionStateChange(_) => self.disconnected_since = None,
                    Event::PeerStats(st) => {
                        let pair = st.selected_candidate_pair.as_ref().and_then(|p| p.current_round_trip_time);
                        // Use the minimum: RTT measured under load includes our own queueing delay,
                        // which would otherwise feed back into an ever larger window.
                        if let Some(rtt) = pair.or(st.rtt) {
                            let min = self.min_rtt.map_or(rtt, |m| m.min(rtt));
                            self.min_rtt = Some(min);
                            self.cap = in_flight_cap(min);
                        }
                    }
                    _ => {}
                },
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn drive(
    sock: UdpSocket,
    mut rtc: Rtc,
    cid: Option<ChannelId>,
    offerer: bool,
    default_ip: Option<IpAddr>,
    mut out_rx: mpsc::Receiver<(bool, Vec<u8>)>,
    in_tx: mpsc::UnboundedSender<Msg>,
    open_tx: oneshot::Sender<Result<Opened, String>>,
) -> Result<()> {
    // ICE "disconnected" is often transient (e.g. a few consent checks lost); only give up if it
    // lasts this long.
    const DISCONNECT_GRACE: Duration = Duration::from_secs(20);
    let port = sock.local_addr()?.port();
    let ifaces: Vec<(u32, u32, Ipv4Addr)> = connect::interfaces()
        .into_iter()
        .map(|i| (u32::from(i.ip), u32::from(i.netmask), i.ip))
        .collect();
    let mut pump = Pump { pacer: Pacer::new(), cap: MIN_IN_FLIGHT, min_rtt: None, cid, offerer, open: false, open_tx: Some(open_tx), last_src: None, in_tx, disconnected_since: None };
    let mut closing = false;
    let mut queued: Option<(bool, Vec<u8>)> = None;
    let mut buf = vec![0u8; 2048];
    let mut drained_at: Option<Instant> = None;

    loop {
        let Some(mut deadline) = pump.run(&mut rtc, &sock)? else { return Ok(()) };
        let mut wrote = false;

        // Feed outgoing data while there is room in the SCTP buffer.
        if pump.open {
            while let Some(mut ch) = pump.cid.and_then(|c| rtc.channel(c)) {
                if ch.buffered_amount() >= pump.cap || pump.pacer.queue.len() > 256 {
                    break;
                }
                let item = match queued.take() {
                    Some(q) => q,
                    None => match out_rx.try_recv() {
                        Ok(m) => m,
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            closing = true;
                            break;
                        }
                    },
                };
                if !ch.write(item.0, &item.1).context("webrtc write")? {
                    queued = Some(item);
                    break;
                }
                wrote = true;
            }
            // New data must be packetized and sent now, not at the previously computed timeout.
            if wrote {
                let Some(d) = pump.run(&mut rtc, &sock)? else { return Ok(()) };
                deadline = d;
            }
            if closing && queued.is_none() {
                let empty = pump.cid.and_then(|c| rtc.channel(c)).map(|mut c| c.buffered_amount() == 0).unwrap_or(true);
                if empty {
                    // Give the last packets / acks a moment, then stop.
                    let t = *drained_at.get_or_insert_with(Instant::now);
                    if t.elapsed() > Duration::from_millis(500) {
                        rtc.disconnect();
                        let _ = pump.run(&mut rtc, &sock);
                        return Ok(());
                    }
                }
            }
        }

        if pump.disconnected_since.is_some_and(|t| t.elapsed() > DISCONNECT_GRACE) {
            bail!("peer disconnected");
        }
        if !rtc.is_alive() {
            bail!("connection closed");
        }

        let now = Instant::now();
        let mut wait = deadline.saturating_duration_since(now).min(Duration::from_millis(50));
        if pump.pacer.flush(&sock) {
            wait = wait.min(Duration::from_millis(1));
        }
        let can_take = pump.open && !closing && queued.is_none();
        tokio::select! {
            _ = tokio::time::sleep(wait) => {
                rtc.handle_input(Input::Timeout(Instant::now())).context("webrtc")?;
            }
            r = sock.recv_from(&mut buf) => {
                // Handle this datagram and then everything else already queued in the socket, so
                // a burst doesn't overflow the (often small) kernel receive buffer. str0m's output
                // is drained after every datagram.
                let mut next = r.ok();
                let mut handled = 0;
                while let Some((n, src)) = next.take() {
                    if let Ok(contents) = buf[..n].try_into() {
                        let input = Input::Receive(
                            Instant::now(),
                            Receive { proto: Protocol::Udp, source: src, destination: local_dest(&src, port, &ifaces, default_ip), contents },
                        );
                        if rtc.accepts(&input) {
                            pump.last_src = Some(src);
                            rtc.handle_input(input).context("webrtc")?;
                            if pump.run(&mut rtc, &sock)?.is_none() {
                                return Ok(());
                            }
                        }
                    }
                    handled += 1;
                    if handled >= 256 {
                        break;
                    }
                    next = sock.try_recv_from(&mut buf).ok();
                }
            }
            m = out_rx.recv(), if can_take => {
                match m {
                    Some(item) => queued = Some(item),
                    None => closing = true,
                }
            }
        }
    }
}
