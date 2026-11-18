//! Mutual authentication with the wormhole code.
//!
//! SPAKE2 turns the short, low-entropy code into a strong shared key without revealing anything
//! an eavesdropper could brute-force offline; an active attacker gets exactly one guess. Each side
//! then proves knowledge of that key with an HMAC over the QUIC/TLS exporter secret, which binds
//! the PAKE to *this* TLS session and defeats man-in-the-middle relaying.

use crate::code::Code;
use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use quinn::{Connection, RecvStream, SendStream};
use serde::{de::DeserializeOwned, Serialize};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};

pub async fn write_frame(s: &mut SendStream, data: &[u8]) -> Result<()> {
    s.write_all(&(data.len() as u32).to_be_bytes()).await?;
    s.write_all(data).await?;
    Ok(())
}

pub async fn read_frame(r: &mut RecvStream, max: usize) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await.context("peer closed the connection")?;
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        bail!("protocol error: frame too large ({len} bytes)");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.context("peer closed the connection")?;
    Ok(buf)
}

pub async fn write_json<T: Serialize>(s: &mut SendStream, v: &T) -> Result<()> {
    write_frame(s, &serde_json::to_vec(v)?).await
}

pub async fn read_json<T: DeserializeOwned>(r: &mut RecvStream) -> Result<T> {
    let b = read_frame(r, 16 << 20).await?;
    serde_json::from_slice(&b).context("protocol error: bad message")
}

fn mac(key: &[u8], label: &[u8], exporter: &[u8]) -> Hmac<Sha256> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(label);
    m.update(exporter);
    m
}

pub const WRONG_CODE: &str = "authentication failed: wrong code (or someone tried to guess it)";

pub async fn authenticate(
    conn: &Connection,
    send: &mut SendStream,
    recv: &mut RecvStream,
    code: &Code,
    is_sender: bool,
) -> Result<()> {
    let (state, msg) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(code.password()),
        &Identity::new(b"wormhole-v1"),
    );
    write_frame(send, &msg).await?;
    let peer_msg = read_frame(recv, 1024).await?;
    let key = state.finish(&peer_msg).map_err(|_| anyhow!(WRONG_CODE))?;

    let mut exporter = [0u8; 32];
    conn.export_keying_material(&mut exporter, b"EXPORTER-wormhole-v1", b"")
        .map_err(|_| anyhow!("TLS exporter unavailable"))?;

    let (mine, theirs): (&[u8], &[u8]) =
        if is_sender { (b"sender", b"receiver") } else { (b"receiver", b"sender") };
    let my_tag = mac(&key, mine, &exporter).finalize().into_bytes();

    if is_sender {
        write_frame(send, &my_tag).await?;
        let t = read_frame(recv, 64).await.map_err(|_| anyhow!(WRONG_CODE))?;
        mac(&key, theirs, &exporter).verify_slice(&t).map_err(|_| anyhow!(WRONG_CODE))?;
    } else {
        let t = read_frame(recv, 64).await?;
        mac(&key, theirs, &exporter).verify_slice(&t).map_err(|_| anyhow!(WRONG_CODE))?;
        write_frame(send, &my_tag).await?;
    }
    Ok(())
}
