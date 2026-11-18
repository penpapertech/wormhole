//! Top-level send/receive flows shared by the CLI and the TUI.

use crate::auth::{self, WRONG_CODE};
use crate::code::Code;
use crate::connect;
use crate::events::{emit, status, Event, Summary, Tx};
use crate::mailbox::Mailbox;
use crate::transfer;
use anyhow::{Context, Result};
use std::path::PathBuf;
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

pub async fn receive(opts: Options, dest: PathBuf, tx: Tx) -> Result<Summary> {
    let mailbox = opts.mailbox();
    // Browsers can only reach us through the mailbox, so WebRTC needs it. Both transports gather
    // their addresses (STUN) in parallel.
    let want_web = mailbox.is_some() && !opts.no_webrtc;
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
    let offer_sdp = web.as_ref().map(|w| w.offer_sdp.clone());
    let (code, online) = connect::claim_code(&prep, offer_sdp, mailbox.as_ref(), &tx).await?;
    emit(&tx, Event::Code { code: code.to_string(), browser: online && web.is_some() });
    if !online {
        status(&tx, "Mailbox unavailable: the sender must be on the same local network.");
    }
    status(&tx, "Waiting for the sender…");

    let poller = match (&mailbox, online) {
        (Some(mb), true) => Some(connect::spawn_sender_poller(mb.clone(), code.nameplate)),
        _ => None,
    };
    let sender_info = poller.as_ref().map(|(rx, _)| rx.clone());

    let res = async {
        let link = race(prep, web, &code, sender_info, &tx).await?;
        drop(poller);
        if let (true, Some(mb)) = (online, mailbox.clone()) {
            let np = code.nameplate;
            tokio::spawn(async move { mb.release(np).await });
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
    }
    .await;
    if res.is_err() && online {
        if let Some(mb) = &mailbox {
            mb.release(code.nameplate).await;
        }
    }
    res
}

/// Wait on both transports; the first sender to authenticate wins. A wrong code on either one
/// aborts (a guessing attacker gets exactly one try); other failures just disable that path.
async fn race(
    prep: connect::Prepared,
    web: Option<crate::webrtc::Prepared>,
    code: &Code,
    sender_info: Option<tokio::sync::watch::Receiver<Option<crate::mailbox::PeerInfo>>>,
    tx: &Tx,
) -> Result<Link> {
    let quic = async {
        let (endpoint, conn) = connect::receiver_connect(prep, code, sender_info.clone(), tx).await?;
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
        if let Err(e) = auth::authenticate_dc(&mut dc, code).await {
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
