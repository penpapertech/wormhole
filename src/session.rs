//! Top-level send/receive flows shared by the CLI and the TUI.

use crate::auth::{self, WRONG_CODE};
use crate::code::Code;
use crate::connect;
use crate::events::{emit, status, Event, Summary, Tx};
use crate::mailbox::{Claim, Mailbox, PeerInfo};
use crate::transfer;
use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Mailbox URL override (`off` = LAN only).
    pub mailbox: Option<String>,
    /// Don't offer the WebRTC transport (browser senders).
    pub no_webrtc: bool,
}

/// An authenticated connection to a sender, over whichever transport won.
enum Link {
    Quic {
        endpoint: quinn::Endpoint,
        conn: quinn::Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    },
    Web(crate::webrtc::DcConn),
}

fn is_auth_failure(e: &anyhow::Error) -> bool {
    e.to_string().contains(WRONG_CODE)
}

impl Options {
    fn mailbox(&self) -> Option<Mailbox> {
        Mailbox::new(self.mailbox.as_deref())
    }
}

/// While waiting, the mailbox entry is renewed this often (it expires after 30 minutes).
/// WORMHOLE_TEST_RENEW_SECS shortens it for tests.
fn renew_every() -> Duration {
    let secs = std::env::var("WORMHOLE_TEST_RENEW_SECS").ok().and_then(|v| v.parse().ok());
    Duration::from_secs(secs.unwrap_or(10 * 60))
}
/// Longest pause after repeated wrong-code attempts on a receiver that stays open.
const MAX_LOCKOUT: Duration = Duration::from_secs(10 * 60);

/// The receiver's nameplate in the mailbox. Freed on drop, so Ctrl+C doesn't leave it taken.
struct Slot {
    mb: Mailbox,
    np: u32,
    held: AtomicBool,
}

impl Slot {
    /// Free the nameplate without waiting (one-shot receivers do this once authenticated).
    fn release_soon(&self) {
        if self.held.swap(false, Ordering::SeqCst) {
            let (mb, np) = (self.mb.clone(), self.np);
            tokio::spawn(async move { mb.release(np).await });
        }
    }

    /// Point the nameplate at `info` (a new round's addresses), clearing any old sender entry.
    /// Mailbox outages are retried; only losing the nameplate to someone else is an error.
    async fn register(&self, info: &PeerInfo, tx: &Tx) -> Result<()> {
        let mut delay = 2;
        loop {
            let res = async {
                self.mb.release(self.np).await?;
                self.mb.claim(self.np, info).await
            }
            .await;
            match res {
                Ok(Claim::Claimed) => {
                    self.held.store(true, Ordering::SeqCst);
                    return Ok(());
                }
                Ok(Claim::Taken) => bail!(
                    "another receiver took this code's number while it was being renewed; \
                     restart to get a new code"
                ),
                Err(e) => {
                    crate::events::warn(tx, format!("{e:#}; retrying in {delay}s"));
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                    delay = (delay * 2).min(60);
                }
            }
        }
    }

    /// Keep the entry from expiring. Returns only if the nameplate is lost.
    async fn keep_alive(&self, info: &PeerInfo, connected: &AtomicBool, tx: &Tx) -> anyhow::Error {
        let mut skipped = false;
        loop {
            tokio::time::sleep(renew_every()).await;
            // Renewing clears the sender's entry, so don't do it while a sender is still connecting
            // (but only skip once: an entry that is still there next time is stale).
            if !connected.load(Ordering::SeqCst) && !skipped {
                if let Ok(Some((_, Some(_)))) = self.mb.get(self.np).await {
                    skipped = true;
                    continue;
                }
            }
            skipped = false;
            if let Err(e) = self.register(info, tx).await {
                return e;
            }
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if self.held.load(Ordering::SeqCst) {
            self.mb.release_blocking(self.np);
        }
    }
}

/// Receive files into `dest`. With `once`, return after one transfer; otherwise keep accepting
/// transfers with the same code until cancelled, emitting `Event::Done` after each.
pub async fn receive(opts: Options, dest: PathBuf, once: bool, tx: Tx) -> Result<Summary> {
    let mailbox = opts.mailbox();
    // Browsers can only reach us through the mailbox, so WebRTC needs it.
    let want_web = mailbox.is_some() && !opts.no_webrtc;
    let mut code: Option<Code> = None;
    let mut slot: Option<Slot> = None; // None: local network only
    let mut wrong = 0u32;
    let mut first = true;
    loop {
        // Each round gets fresh sockets and a fresh WebRTC offer; both gather (STUN) in parallel.
        let (prep, web) = tokio::join!(connect::prepare(&tx, mailbox.is_some()), async {
            if want_web { Some(crate::webrtc::prepare(true).await) } else { None }
        });
        let prep = prep?;
        let web = match web {
            Some(Ok(w)) => Some(w),
            Some(Err(e)) => {
                crate::events::warn(&tx, format!("Browser senders unavailable: {e:#}"));
                None
            }
            None => None,
        };
        let info = connect::receiver_info(&prep, web.as_ref().map(|w| w.offer_sdp.clone()));
        let code = match (&code, &slot) {
            (Some(c), Some(sl)) => {
                sl.register(&info, &tx).await?;
                c.clone()
            }
            (Some(c), None) => c.clone(),
            (None, _) => {
                let (c, online) = connect::claim_code(&info, mailbox.as_ref(), &tx).await?;
                emit(&tx, Event::Code { code: c.to_string(), browser: online && web.is_some() });
                if online {
                    let mb = mailbox.clone().expect("online implies a mailbox");
                    slot = Some(Slot { mb, np: c.nameplate, held: AtomicBool::new(true) });
                } else {
                    status(&tx, "Mailbox unavailable: the sender must be on the same local network.");
                }
                code.insert(c).clone()
            }
        };
        status(&tx, if first { "Waiting for the sender…" } else { "Waiting for the next sender…" });
        first = false;

        let poller = slot.as_ref().map(|s| connect::spawn_sender_poller(s.mb.clone(), s.np));
        let sender_info = poller.as_ref().map(|(rx, _)| rx.clone());
        let connected = AtomicBool::new(false);
        let round = async {
            let wait = once.then_some(connect::RECEIVER_WAIT);
            let link = race(prep, web, &code, sender_info, wait, &tx).await?;
            drop(poller);
            connected.store(true, Ordering::SeqCst);
            if once {
                if let Some(sl) = &slot {
                    sl.release_soon();
                }
            }
            status(&tx, "Authenticated.");
            match link {
                Link::Quic { endpoint, conn, mut send, mut recv } => {
                    let summary = transfer::receive(&conn, &mut send, &mut recv, &dest, &tx).await?;
                    let _ = send.finish();
                    // Let the sender read our confirmation and close the connection.
                    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
                    endpoint.close(0u32.into(), b"done");
                    Ok(summary)
                }
                Link::Web(mut dc) => {
                    let summary = transfer::receive_dc(&mut dc, &dest, &tx).await;
                    dc.close().await;
                    summary
                }
            }
        };
        let renew = async {
            match &slot {
                Some(sl) if !once => sl.keep_alive(&info, &connected, &tx).await,
                _ => std::future::pending().await,
            }
        };
        let res = tokio::select! {
            r = round => r,
            e = renew => return Err(e),
        };
        if once {
            return res; // dropping `slot` frees the nameplate if it is still held
        }
        match res {
            Ok(summary) => {
                wrong = 0;
                emit(&tx, Event::Done(summary));
            }
            Err(e) if is_auth_failure(&e) => {
                // The code never changes, so each wrong guess costs the guesser more time.
                wrong += 1;
                let pause = Duration::from_secs(1u64 << (wrong - 1).min(10)).min(MAX_LOCKOUT);
                crate::events::warn(
                    &tx,
                    format!(
                        "A sender used the wrong code ({wrong} in a row); not accepting connections for {}s.",
                        pause.as_secs()
                    ),
                );
                tokio::time::sleep(pause).await;
            }
            Err(e) => {
                crate::events::warn(&tx, format!("Transfer failed: {e:#}"));
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

/// Wait on both transports; the first sender to authenticate wins. A wrong code on either one
/// aborts (a guessing attacker gets exactly one try); other failures just disable that path.
async fn race(
    prep: connect::Prepared,
    web: Option<crate::webrtc::Prepared>,
    code: &Code,
    sender_info: Option<tokio::sync::watch::Receiver<Option<PeerInfo>>>,
    wait: Option<Duration>,
    tx: &Tx,
) -> Result<Link> {
    let quic = async {
        let (endpoint, conn) = connect::receiver_connect(prep, code, sender_info.clone(), wait, tx).await?;
        let (mut send, mut recv) = conn.accept_bi().await.context("waiting for the sender")?;
        if let Err(e) = auth::authenticate(&conn, &mut send, &mut recv, code, false).await {
            conn.close(1u32.into(), b"bad code");
            return Err(e);
        }
        Ok(Link::Quic { endpoint, conn, send, recv })
    };
    let webrtc = async {
        let (Some(w), Some(info)) = (web, sender_info.clone()) else {
            return std::future::pending().await;
        };
        let mut dc = crate::webrtc::accept(w, info, tx).await?;
        emit(tx, Event::Connected { peer: dc.peer, lan: connect::is_lan_addr(&dc.peer) });
        if let Err(e) = auth::authenticate_dc(&mut dc, code, false).await {
            // Tell the browser explicitly, then close the channel cleanly.
            let _ = dc.send_text(r#"{"ok":false,"error":"wrong code"}"#).await;
            dc.close().await;
            return Err(e);
        }
        Ok::<_, anyhow::Error>(Link::Web(dc))
    };
    tokio::pin!(quic, webrtc);
    let (mut quic_done, mut web_done) = (false, false);
    loop {
        let (r, which) = tokio::select! {
            r = &mut quic, if !quic_done => (r, "direct"),
            r = &mut webrtc, if !web_done => (r, "WebRTC"),
        };
        match r {
            Ok(link) => return Ok(link),
            Err(e) if is_auth_failure(&e) => return Err(e),
            Err(e) => {
                if which == "direct" { quic_done = true } else { web_done = true }
                if quic_done && web_done {
                    return Err(e);
                }
                crate::events::warn(tx, format!("{which} connection failed: {e:#}; still waiting…"));
            }
        }
    }
}

pub async fn send(opts: Options, code: String, paths: Vec<PathBuf>, recursive: bool, tx: Tx) -> Result<Summary> {
    let code = Code::parse(&code)?;
    let plan = transfer::plan(&paths, recursive)?;
    for s in &plan.skipped {
        crate::events::warn(&tx, format!("skipping {s}"));
    }
    let mailbox = opts.mailbox();
    // A browser receiver posts only a WebRTC offer (no QUIC addresses): answer it instead.
    if let Some(mb) = &mailbox {
        status(&tx, "Looking up the receiver…");
        if let Ok(Some((Some(r), _))) = mb.get(code.nameplate).await {
            if r.addrs.is_empty() {
                if let Some(offer) = r.webrtc {
                    return send_webrtc(mb, &code, &offer, plan, &tx).await;
                }
            }
        }
    }
    let prep = connect::prepare(&tx, mailbox.is_some()).await?;
    let (endpoint, conn) = connect::sender_connect(prep, &code, mailbox, &tx).await?;
    let (mut s, mut r) = conn.open_bi().await?;
    auth::authenticate(&conn, &mut s, &mut r, &code, true)
        .await
        .map_err(|e| if e.to_string().contains("closed") { anyhow::anyhow!(WRONG_CODE) } else { e })?;
    status(&tx, "Authenticated.");
    let summary = transfer::send(&conn, &mut s, &mut r, plan, &tx).await?;
    conn.close(0u32.into(), b"done");
    let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
    Ok(summary)
}

/// Send to a receiver running in a browser (WebRTC; we are the answerer).
async fn send_webrtc(mb: &Mailbox, code: &Code, offer: &str, plan: transfer::Plan, tx: &Tx) -> Result<Summary> {
    status(tx, "The receiver is a web browser; connecting over WebRTC…");
    let a = crate::webrtc::answer(offer, true).await?;
    let info = PeerInfo { v: 1, addrs: vec![], webrtc: Some(a.answer_sdp.clone()) };
    if !mb.put_sender(code.nameplate, &info).await? {
        anyhow::bail!("no receiver is waiting for code {code} (it may have expired)");
    }
    let mut dc = crate::webrtc::connect(a).await?;
    emit(tx, Event::Connected { peer: dc.peer, lan: connect::is_lan_addr(&dc.peer) });
    auth::authenticate_dc(&mut dc, code, true).await?;
    status(tx, "Authenticated.");
    let summary = transfer::send_dc(&mut dc, plan, tx).await;
    dc.close().await;
    summary
}
