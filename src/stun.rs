//! Minimal STUN (RFC 5389) binding client, used to learn our public (NAT-mapped) address.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const MAGIC: u32 = 0x2112_A442;
pub const DEFAULT_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun1.l.google.com:19302",
];

pub fn servers() -> Vec<String> {
    match std::env::var("WORMHOLE_STUN") {
        Ok(s) => s.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        Err(_) => DEFAULT_SERVERS.iter().map(|s| s.to_string()).collect(),
    }
}

pub async fn resolve(names: &[String]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for n in names {
        if let Ok(Ok(addrs)) =
            tokio::time::timeout(Duration::from_secs(2), tokio::net::lookup_host(n.as_str())).await
        {
            if let Some(a) = addrs.into_iter().find(|a| a.is_ipv4()) {
                if !out.contains(&a) {
                    out.push(a);
                }
            }
        }
    }
    out
}

pub fn request(txid: &[u8; 12]) -> [u8; 20] {
    let mut b = [0u8; 20];
    b[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
    b[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    b[8..20].copy_from_slice(txid);
    b
}

/// Parse a binding success response; returns (txid, mapped address).
pub fn parse_response(buf: &[u8]) -> Option<([u8; 12], SocketAddr)> {
    if buf.len() < 20 || u16::from_be_bytes([buf[0], buf[1]]) != 0x0101 {
        return None;
    }
    if u32::from_be_bytes(buf[4..8].try_into().ok()?) != MAGIC {
        return None;
    }
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let txid: [u8; 12] = buf[8..20].try_into().ok()?;
    let body = buf.get(20..20 + len)?;
    let mut i = 0;
    let mut mapped = None;
    while i + 4 <= body.len() {
        let t = u16::from_be_bytes([body[i], body[i + 1]]);
        let l = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        let v = body.get(i + 4..i + 4 + l)?;
        if (t == 0x0020 || t == 0x0001) && l >= 8 && v[1] == 0x01 {
            let mut port = u16::from_be_bytes([v[2], v[3]]);
            let mut ip = u32::from_be_bytes([v[4], v[5], v[6], v[7]]);
            if t == 0x0020 {
                port ^= (MAGIC >> 16) as u16;
                ip ^= MAGIC;
            }
            let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port);
            if t == 0x0020 || mapped.is_none() {
                mapped = Some(a);
            }
        }
        i += 4 + ((l + 3) & !3);
    }
    mapped.map(|m| (txid, m))
}

/// Ask every server for our mapped address; returns the distinct mapped addresses seen.
pub async fn query(sock: &UdpSocket, servers: &[SocketAddr], timeout: Duration) -> Vec<SocketAddr> {
    if servers.is_empty() {
        return vec![];
    }
    let txids: Vec<[u8; 12]> = servers.iter().map(|_| rand::random()).collect();
    let mut got: Vec<Option<SocketAddr>> = vec![None; servers.len()];
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 1500];
    let mut next_send = Instant::now();
    loop {
        let now = Instant::now();
        if now >= deadline || got.iter().all(Option::is_some) {
            break;
        }
        if now >= next_send {
            for (i, s) in servers.iter().enumerate() {
                if got[i].is_none() {
                    let _ = sock.send_to(&request(&txids[i]), s).await;
                }
            }
            next_send = now + Duration::from_millis(350);
        }
        let wait = next_send.min(deadline).saturating_duration_since(Instant::now());
        if let Ok(Ok((n, _))) = tokio::time::timeout(wait, sock.recv_from(&mut buf)).await {
            if let Some((txid, m)) = parse_response(&buf[..n]) {
                if let Some(i) = txids.iter().position(|t| *t == txid) {
                    got[i] = Some(m);
                }
            }
        }
        // Once one answer is in, give the others only a short grace period.
        if got.iter().any(Option::is_some) && deadline > Instant::now() + Duration::from_millis(400) {
            let d = Instant::now() + Duration::from_millis(400);
            if d < deadline {
                return finish(sock, servers, &txids, got, d).await;
            }
        }
    }
    dedup(got)
}

async fn finish(
    sock: &UdpSocket,
    _servers: &[SocketAddr],
    txids: &[[u8; 12]],
    mut got: Vec<Option<SocketAddr>>,
    deadline: Instant,
) -> Vec<SocketAddr> {
    let mut buf = [0u8; 1500];
    while Instant::now() < deadline && !got.iter().all(Option::is_some) {
        let wait = deadline.saturating_duration_since(Instant::now());
        if let Ok(Ok((n, _))) = tokio::time::timeout(wait, sock.recv_from(&mut buf)).await {
            if let Some((txid, m)) = parse_response(&buf[..n]) {
                if let Some(i) = txids.iter().position(|t| *t == txid) {
                    got[i] = Some(m);
                }
            }
        }
    }
    dedup(got)
}

fn dedup(got: Vec<Option<SocketAddr>>) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for a in got.into_iter().flatten() {
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_xor_mapped() {
        let txid = [7u8; 12];
        let mut b = Vec::new();
        b.extend_from_slice(&0x0101u16.to_be_bytes());
        b.extend_from_slice(&12u16.to_be_bytes());
        b.extend_from_slice(&MAGIC.to_be_bytes());
        b.extend_from_slice(&txid);
        b.extend_from_slice(&0x0020u16.to_be_bytes());
        b.extend_from_slice(&8u16.to_be_bytes());
        b.extend_from_slice(&[0, 1]);
        b.extend_from_slice(&(5000u16 ^ 0x2112).to_be_bytes());
        b.extend_from_slice(&(u32::from(Ipv4Addr::new(1, 2, 3, 4)) ^ MAGIC).to_be_bytes());
        let (t, a) = parse_response(&b).unwrap();
        assert_eq!(t, txid);
        assert_eq!(a, "1.2.3.4:5000".parse().unwrap());
    }
}
