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
}

impl Options {
    fn mailbox(&self) -> Option<Mailbox> {
        Mailbox::new(self.mailbox.as_deref())
    }
}

pub async fn receive(opts: Options, dest: PathBuf, tx: Tx) -> Result<Summary> {
    let mailbox = opts.mailbox();
    let prep = connect::prepare(&tx, mailbox.is_some()).await?;
    let (code, online) = connect::claim_code(&prep, mailbox.as_ref(), &tx).await?;
    emit(&tx, Event::Code(code.to_string()));
    if !online {
        status(&tx, "Mailbox unavailable: the sender must be on the same local network.");
    }
    status(&tx, "Waiting for the sender…");

    let res = async {
        let (endpoint, conn) =
            connect::receiver_connect(prep, &code, if online { mailbox.clone() } else { None }, &tx).await?;
        if let (true, Some(mb)) = (online, mailbox.clone()) {
            let np = code.nameplate;
            tokio::spawn(async move { mb.release(np).await });
        }
        let (mut s, mut r) = conn.accept_bi().await.context("waiting for the sender")?;
        if let Err(e) = auth::authenticate(&conn, &mut s, &mut r, &code, false).await {
            conn.close(1u32.into(), b"bad code");
            return Err(e);
        }
        status(&tx, "Authenticated.");
        let summary = transfer::receive(&conn, &mut s, &mut r, &dest, &tx).await?;
        let _ = s.finish();
        // Let the sender read our confirmation and close the connection.
        let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
        endpoint.close(0u32.into(), b"done");
        Ok(summary)
    }
    .await;
    if res.is_err() && online {
        if let Some(mb) = &mailbox {
            mb.release(code.nameplate).await;
        }
    }
    res
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
