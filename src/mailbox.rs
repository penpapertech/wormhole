//! Client for the rendezvous mailbox (an AWS Lambda function URL backed by DynamoDB).
//! The mailbox only ever sees nameplates, candidate IP:port addresses and WebRTC SDP — never the
//! code words and never file data.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

/// Default public mailbox. Override at build time with WORMHOLE_MAILBOX_URL, or at run time
/// with `--mailbox <url>` / the WORMHOLE_MAILBOX env var (`off` disables it: LAN only).
pub const DEFAULT_URL: &str = match option_env!("WORMHOLE_MAILBOX_URL") {
    Some(u) => u,
    None => "https://n7pfkdycg2ts6xcat7ltivpvva0zhndg.lambda-url.eu-west-2.on.aws/",
};

/// The web sender. The receiver prints `<WEB_URL>#<code>`; the fragment never leaves the browser.
pub const WEB_URL: &str = match option_env!("WORMHOLE_WEB_URL") {
    Some(u) => u,
    None => "https://penpapertech.github.io/wormhole/",
};

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PeerInfo {
    pub v: u32,
    /// Candidate IP:port addresses for the native QUIC transport.
    #[serde(default)]
    pub addrs: Vec<String>,
    /// WebRTC SDP: the receiver's offer, or a browser sender's answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webrtc: Option<String>,
}

#[derive(Clone)]
pub struct Mailbox {
    url: String,
    agent: ureq::Agent,
}

pub enum Claim {
    Claimed,
    Taken,
}

impl Mailbox {
    pub fn new(setting: Option<&str>) -> Option<Mailbox> {
        let url = setting.unwrap_or(DEFAULT_URL).trim();
        if url.is_empty() || url.eq_ignore_ascii_case("off") || url.starts_with("__") {
            return None;
        }
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(8))
            .user_agent(concat!("wormhole/", env!("CARGO_PKG_VERSION")))
            .build();
        Some(Mailbox { url: url.to_string(), agent })
    }

    async fn call(&self, body: Value) -> Result<(u16, Value)> {
        let agent = self.agent.clone();
        let url = self.url.clone();
        tokio::task::spawn_blocking(move || {
            let res = agent.post(&url).send_json(body);
            let resp = match res {
                Ok(r) => r,
                Err(ureq::Error::Status(_, r)) => r,
                Err(e) => return Err(anyhow!("mailbox unreachable: {e}")),
            };
            let status = resp.status();
            let v: Value = resp.into_json().unwrap_or(Value::Null);
            Ok((status, v))
        })
        .await
        .context("mailbox task")?
    }

    pub async fn claim(&self, nameplate: u32, info: &PeerInfo) -> Result<Claim> {
        let data = serde_json::to_string(info)?;
        let (st, v) = self
            .call(json!({"op": "claim", "np": nameplate.to_string(), "data": data}))
            .await?;
        match st {
            200 => Ok(Claim::Claimed),
            409 => Ok(Claim::Taken),
            _ => Err(anyhow!("mailbox error {st}: {v}")),
        }
    }

    /// Returns false if no receiver is waiting on this nameplate.
    pub async fn put_sender(&self, nameplate: u32, info: &PeerInfo) -> Result<bool> {
        let data = serde_json::to_string(info)?;
        let (st, v) = self
            .call(json!({"op": "put", "np": nameplate.to_string(), "side": "s", "data": data}))
            .await?;
        match st {
            200 => Ok(true),
            404 => Ok(false),
            _ => Err(anyhow!("mailbox error {st}: {v}")),
        }
    }

    /// Returns None if the nameplate is not open, else (receiver info, sender info).
    pub async fn get(&self, nameplate: u32) -> Result<Option<(Option<PeerInfo>, Option<PeerInfo>)>> {
        let (st, v) = self.call(json!({"op": "get", "np": nameplate.to_string()})).await?;
        match st {
            200 => {
                let parse = |k: &str| {
                    v.get(k)
                        .and_then(Value::as_str)
                        .and_then(|s| serde_json::from_str::<PeerInfo>(s).ok())
                };
                Ok(Some((parse("r"), parse("s"))))
            }
            404 => Ok(None),
            _ => Err(anyhow!("mailbox error {st}: {v}")),
        }
    }

    pub async fn release(&self, nameplate: u32) -> Result<()> {
        let (st, v) = self.call(json!({"op": "release", "np": nameplate.to_string()})).await?;
        if st != 200 {
            return Err(anyhow!("mailbox error {st}: {v}"));
        }
        Ok(())
    }

    /// For use in `Drop`, where we can't await: frees the nameplate, blocking briefly.
    pub fn release_blocking(&self, nameplate: u32) {
        let _ = self.agent.post(&self.url).send_json(json!({"op": "release", "np": nameplate.to_string()}));
    }
}
