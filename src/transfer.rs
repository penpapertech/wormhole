//! File transfer: the sender streams `tar | zstd` over a QUIC stream; the receiver decompresses
//! and extracts on the fly. Nothing touches any server — data flows peer to peer only.

use crate::auth::{read_json, write_json};
use crate::events::{emit, warn, Event, Summary, Tx};
use anyhow::{bail, Context, Result};
use quinn::{Connection, RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Offer {
    /// Top-level names (files or directories).
    pub names: Vec<String>,
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    /// Expected size of the uncompressed tar stream (for progress).
    pub tar_bytes: u64,
    /// Compression of the data stream: "zstd" (default, CLI), "gzip" (browsers) or "none".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Answer {
    ok: bool,
    error: Option<String>,
    #[serde(default)]
    saved: Vec<String>,
}

#[derive(Debug, Clone)]
enum Kind {
    Dir,
    File(u64),
}

#[derive(Debug, Clone)]
pub struct Entry {
    src: PathBuf,
    name: String,
    kind: Kind,
}

pub struct Plan {
    entries: Vec<Entry>,
    pub offer: Offer,
    pub skipped: Vec<String>,
}

fn pad512(n: u64) -> u64 {
    n.div_ceil(512) * 512
}

fn walk(dir: &Path, name: &str, out: &mut Vec<Entry>, skipped: &mut Vec<String>) -> Result<()> {
    out.push(Entry { src: dir.to_path_buf(), name: name.to_string(), kind: Kind::Dir });
    let mut children: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok())
        .collect();
    children.sort_by_key(|e| e.file_name());
    for child in children {
        let path = child.path();
        let cname = format!("{}/{}", name, child.file_name().to_string_lossy());
        let is_link = child.file_type().map(|t| t.is_symlink()).unwrap_or(false);
        match fs::metadata(&path) {
            Ok(m) if m.is_dir() && is_link => skipped.push(format!("{cname} (symlink to directory)")),
            Ok(m) if m.is_dir() => walk(&path, &cname, out, skipped)?,
            Ok(m) if m.is_file() => out.push(Entry { src: path, name: cname, kind: Kind::File(m.len()) }),
            Ok(_) => skipped.push(format!("{cname} (not a regular file)")),
            Err(_) => skipped.push(format!("{cname} (unreadable or broken link)")),
        }
    }
    Ok(())
}

/// Work out what to send. Directories require `recursive`.
pub fn plan(paths: &[PathBuf], recursive: bool) -> Result<Plan> {
    if paths.is_empty() {
        bail!("nothing to send");
    }
    let mut entries = Vec::new();
    let mut names = Vec::new();
    let mut skipped = Vec::new();
    for p in paths {
        let meta = fs::metadata(p).with_context(|| format!("cannot access '{}'", p.display()))?;
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .or_else(|| fs::canonicalize(p).ok()?.file_name().map(|n| n.to_string_lossy().to_string()))
            .filter(|n| n != "." && n != "..")
            .with_context(|| format!("cannot determine a name for '{}'", p.display()))?;
        if names.contains(&name) {
            bail!("two items are both named '{name}'; send them separately");
        }
        if meta.is_dir() {
            if !recursive {
                bail!("'{}' is a directory (use -R to send directories)", p.display());
            }
            walk(p, &name, &mut entries, &mut skipped)?;
        } else if meta.is_file() {
            entries.push(Entry { src: p.clone(), name: name.clone(), kind: Kind::File(meta.len()) });
        } else {
            bail!("'{}' is not a regular file or directory", p.display());
        }
        names.push(name);
    }
    let mut files = 0;
    let mut dirs = 0;
    let mut bytes = 0;
    let mut tar_bytes = 1024;
    for e in &entries {
        let path_len = e.name.len() as u64 + matches!(e.kind, Kind::Dir) as u64;
        tar_bytes += 512;
        if path_len > 100 {
            tar_bytes += 512 + pad512(path_len + 1);
        }
        match e.kind {
            Kind::Dir => dirs += 1,
            Kind::File(n) => {
                files += 1;
                bytes += n;
                tar_bytes += pad512(n);
            }
        }
    }
    Ok(Plan { entries, offer: Offer { names, files, dirs, bytes, tar_bytes, encoding: None }, skipped })
}

/// `Write` adapter that ships chunks to an async task.
struct ChanWriter {
    tx: mpsc::Sender<Vec<u8>>,
    buf: Vec<u8>,
}

const CHUNK: usize = 256 * 1024;

impl Write for ChanWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= CHUNK {
            self.flush()?;
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let chunk = std::mem::replace(&mut self.buf, Vec::with_capacity(CHUNK));
            self.tx
                .blocking_send(chunk)
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))?;
        }
        Ok(())
    }
}

struct Counting<T> {
    inner: T,
    n: Arc<AtomicU64>,
}

impl<W: Write> Write for Counting<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let k = self.inner.write(data)?;
        self.n.fetch_add(k as u64, Ordering::Relaxed);
        Ok(k)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let k = self.inner.read(buf)?;
        self.n.fetch_add(k as u64, Ordering::Relaxed);
        Ok(k)
    }
}

/// `Read` adapter that pulls chunks from an async task.
struct ChanReader {
    rx: mpsc::Receiver<bytes::Bytes>,
    cur: bytes::Bytes,
}

impl Read for ChanReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.cur.is_empty() {
            match self.rx.blocking_recv() {
                Some(b) => self.cur = b,
                None => return Ok(0),
            }
        }
        let n = buf.len().min(self.cur.len());
        buf[..n].copy_from_slice(&self.cur[..n]);
        self.cur = self.cur.slice(n..);
        Ok(n)
    }
}

type Archiver = tokio::task::JoinHandle<Result<()>>;

enum Enc {
    Gzip(flate2::write::GzEncoder<ChanWriter>),
    Zstd(zstd::Encoder<'static, ChanWriter>),
}

impl Enc {
    fn finish(self) -> io::Result<ChanWriter> {
        match self {
            Enc::Gzip(g) => g.finish(),
            Enc::Zstd(z) => z.finish(),
        }
    }
}

impl Write for Enc {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        match self {
            Enc::Gzip(g) => g.write(data),
            Enc::Zstd(z) => z.write(data),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Enc::Gzip(g) => g.flush(),
            Enc::Zstd(z) => z.flush(),
        }
    }
}

/// Build `tar | <encoding>` in a blocking thread; compressed chunks come out of the receiver.
/// `progress` counts uncompressed tar bytes.
fn spawn_archiver(entries: Vec<Entry>, encoding: &'static str, progress: Arc<AtomicU64>) -> (mpsc::Receiver<Vec<u8>>, Archiver) {
    let (chunk_tx, chunk_rx) = mpsc::channel::<Vec<u8>>(16);
    let handle = tokio::task::spawn_blocking(move || -> Result<()> {
        let w = ChanWriter { tx: chunk_tx, buf: Vec::with_capacity(CHUNK) };
        let enc = if encoding == "gzip" {
            // Level 1: browsers decompress gzip natively but nothing better; speed matters more.
            Enc::Gzip(flate2::write::GzEncoder::new(w, flate2::Compression::fast()))
        } else {
            let mut z = zstd::Encoder::new(w, level())?;
            z.include_checksum(true)?;
            let _ = z.multithread(std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1).min(8));
            Enc::Zstd(z)
        };
        let mut b = tar::Builder::new(Counting { inner: enc, n: progress });
        for e in &entries {
            match e.kind {
                Kind::Dir => b.append_dir(&e.name, &e.src),
                Kind::File(_) => {
                    let mut f = fs::File::open(&e.src)
                        .with_context(|| format!("opening {}", e.src.display()))?;
                    b.append_file(&e.name, &mut f)
                }
            }
            .with_context(|| format!("reading {}", e.src.display()))?;
        }
        let mut w = b.into_inner()?.inner.finish()?;
        w.flush()?;
        Ok(())
    });
    (chunk_rx, handle)
}

fn level() -> i32 {
    std::env::var("WORMHOLE_ZSTD_LEVEL").ok().and_then(|s| s.parse().ok()).unwrap_or(3)
}

pub async fn send(
    conn: &Connection,
    ctrl_send: &mut SendStream,
    ctrl_recv: &mut RecvStream,
    plan: Plan,
    tx: &Tx,
) -> Result<Summary> {
    let offer = plan.offer.clone();
    write_json(ctrl_send, &offer).await?;
    let answer: Answer = read_json(ctrl_recv).await?;
    if !answer.ok {
        bail!("receiver declined: {}", answer.error.unwrap_or_default());
    }

    let start = Instant::now();
    let progress = Arc::new(AtomicU64::new(0));
    let (mut chunk_rx, builder) = spawn_archiver(plan.entries, "zstd", progress.clone());

    let mut data = conn.open_uni().await?;
    let mut wire = 0u64;
    let mut last = Instant::now();
    while let Some(chunk) = chunk_rx.recv().await {
        wire += chunk.len() as u64;
        data.write_all(&chunk).await.context("sending data")?;
        if last.elapsed() > Duration::from_millis(100) {
            last = Instant::now();
            emit(tx, Event::Progress { done: progress.load(Ordering::Relaxed), total: offer.tar_bytes });
        }
    }
    builder.await.context("archiver task")??;
    data.finish()?;
    emit(tx, Event::Progress { done: offer.tar_bytes, total: offer.tar_bytes });

    let answer: Answer = read_json(ctrl_recv).await.context("waiting for the receiver to confirm")?;
    if !answer.ok {
        bail!("receiver failed: {}", answer.error.unwrap_or_default());
    }
    Ok(Summary {
        files: offer.files,
        bytes: offer.bytes,
        wire_bytes: wire,
        secs: start.elapsed().as_secs_f64(),
        names: offer.names,
    })
}

/// Pick a name that doesn't clash with existing files: `name (1).ext`, `name (2).ext`, …
pub fn unique_name(dest: &Path, name: &str) -> String {
    if !dest.join(name).exists() {
        return name.to_string();
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    (1..)
        .map(|i| format!("{stem} ({i}){ext}"))
        .find(|n| !dest.join(n).exists())
        .unwrap()
}

fn valid_top_name(n: &str) -> bool {
    let p = Path::new(n);
    !n.is_empty()
        && p.components().count() == 1
        && matches!(p.components().next(), Some(Component::Normal(_)))
}

fn decoder<'a, R: Read + 'a>(encoding: &str, r: R) -> Result<Box<dyn Read + 'a>> {
    Ok(match encoding {
        "zstd" => Box::new(zstd::Decoder::new(r)?),
        "gzip" => Box::new(flate2::read::MultiGzDecoder::new(io::BufReader::new(r))),
        "none" => Box::new(r),
        other => bail!("unsupported encoding '{other}'"),
    })
}

pub fn extract<R: Read>(
    r: R,
    encoding: &str,
    dest: &Path,
    renames: &HashMap<String, String>,
    progress: Arc<AtomicU64>,
) -> Result<(u64, u64, u64)> {
    let dec = decoder(encoding, r)?;
    let mut ar = tar::Archive::new(Counting { inner: dec, n: progress });
    let (mut files, mut bytes, mut skipped) = (0u64, 0u64, 0u64);
    for entry in ar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let mut comps = Vec::new();
        for c in path.components() {
            match c {
                Component::Normal(s) => comps.push(s.to_owned()),
                Component::CurDir => {}
                _ => bail!("refusing unsafe path in archive: {}", path.display()),
            }
        }
        let Some(top) = comps.first() else { continue };
        let Some(mapped) = renames.get(&*top.to_string_lossy()) else {
            bail!("archive contains an unexpected entry: {}", path.display());
        };
        let mut out = dest.join(mapped);
        for c in &comps[1..] {
            out.push(c);
        }
        match entry.header().entry_type() {
            tar::EntryType::Directory => fs::create_dir_all(&out)
                .with_context(|| format!("creating {}", out.display()))?,
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                if let Some(parent) = out.parent() {
                    fs::create_dir_all(parent)?;
                }
                entry.unpack(&out).with_context(|| format!("writing {}", out.display()))?;
                files += 1;
                bytes += entry.size();
            }
            _ => skipped += 1,
        }
    }
    // Drain the remainder (tar padding, zstd checksum) so integrity is verified.
    io::copy(&mut ar.into_inner(), &mut io::sink())?;
    Ok((files, bytes, skipped))
}

/// Validate an incoming offer and decide the final top-level names (never overwrite).
pub(crate) fn plan_receive(offer: &Offer, dest: &Path, tx: &Tx) -> Result<(HashMap<String, String>, Vec<String>)> {
    if let Some(bad) = offer.names.iter().find(|n| !valid_top_name(n)) {
        bail!("unsafe name in offer: {bad:?}");
    }
    match offer.encoding.as_deref().unwrap_or("zstd") {
        "zstd" | "gzip" | "none" => {}
        other => bail!("unsupported encoding '{other}'"),
    }
    fs::create_dir_all(dest).with_context(|| format!("creating {}", dest.display()))?;
    let mut renames = HashMap::new();
    let mut saved = Vec::new();
    for n in &offer.names {
        let u = unique_name(dest, n);
        if &u != n {
            warn(tx, format!("'{n}' already exists, saving as '{u}'"));
        }
        saved.push(u.clone());
        renames.insert(n.clone(), u);
    }
    Ok((renames, saved))
}

type Extractor = tokio::task::JoinHandle<Result<(u64, u64, u64)>>;

/// Start extracting in a blocking thread; feed it chunks through the returned sender.
pub(crate) fn spawn_extractor(
    offer: &Offer,
    dest: &Path,
    renames: HashMap<String, String>,
    progress: Arc<AtomicU64>,
) -> (mpsc::Sender<bytes::Bytes>, Extractor) {
    let (chunk_tx, chunk_rx) = mpsc::channel::<bytes::Bytes>(16);
    let dest = dest.to_path_buf();
    let encoding = offer.encoding.clone().unwrap_or_else(|| "zstd".into());
    let handle = tokio::task::spawn_blocking(move || {
        extract(ChanReader { rx: chunk_rx, cur: bytes::Bytes::new() }, &encoding, &dest, &renames, progress)
    });
    (chunk_tx, handle)
}

fn finish_summary(
    tx: &Tx,
    offer: &Offer,
    r: (u64, u64, u64),
    wire: u64,
    start: Instant,
    saved: Vec<String>,
) -> Summary {
    let (files, bytes, skipped) = r;
    if skipped > 0 {
        warn(tx, format!("skipped {skipped} special entries (links/devices)"));
    }
    emit(tx, Event::Progress { done: offer.tar_bytes, total: offer.tar_bytes });
    Summary { files, bytes, wire_bytes: wire, secs: start.elapsed().as_secs_f64(), names: saved }
}

pub async fn receive(
    conn: &Connection,
    ctrl_send: &mut SendStream,
    ctrl_recv: &mut RecvStream,
    dest: &Path,
    tx: &Tx,
) -> Result<Summary> {
    let offer: Offer = read_json(ctrl_recv).await?;
    let (renames, saved) = match plan_receive(&offer, dest, tx) {
        Ok(x) => x,
        Err(e) => {
            write_json(ctrl_send, &Answer { ok: false, error: Some(e.to_string()), saved: vec![] }).await?;
            return Err(e);
        }
    };
    emit(tx, Event::Offer(offer.clone()));
    write_json(ctrl_send, &Answer { ok: true, error: None, saved: vec![] }).await?;

    let start = Instant::now();
    let mut data = conn.accept_uni().await.context("waiting for data stream")?;
    let progress = Arc::new(AtomicU64::new(0));
    let (chunk_tx, extractor) = spawn_extractor(&offer, dest, renames, progress.clone());

    let mut wire = 0u64;
    let mut last = Instant::now();
    let mut read_err = None;
    loop {
        match data.read_chunk(CHUNK, true).await {
            Ok(Some(c)) => {
                wire += c.bytes.len() as u64;
                if chunk_tx.send(c.bytes).await.is_err() {
                    break; // extractor failed; its error is reported below
                }
            }
            Ok(None) => break,
            Err(e) => {
                read_err = Some(e);
                break;
            }
        }
        if last.elapsed() > Duration::from_millis(100) {
            last = Instant::now();
            emit(tx, Event::Progress { done: progress.load(Ordering::Relaxed), total: offer.tar_bytes });
        }
    }
    drop(chunk_tx);
    let result = extractor.await.context("extractor task")?;
    let result = match (result, read_err) {
        (Ok(r), None) => Ok(r),
        (Err(e), _) => Err(e),
        (Ok(_), Some(e)) => Err(anyhow::Error::from(e).context("connection lost")),
    };
    match result {
        Ok(r) => {
            write_json(ctrl_send, &Answer { ok: true, error: None, saved: saved.clone() }).await?;
            Ok(finish_summary(tx, &offer, r, wire, start, saved))
        }
        Err(e) => {
            let _ = write_json(ctrl_send, &Answer { ok: false, error: Some(format!("{e:#}")), saved: vec![] }).await;
            Err(e)
        }
    }
}

/// Largest data-channel message we send (browsers accept 256 KiB; stay well below).
const DC_CHUNK: usize = 64 * 1024;

fn dc_error(m: &crate::webrtc::Msg) -> String {
    let v: serde_json::Value = serde_json::from_slice(&m.data).unwrap_or_default();
    v.get("error").and_then(|e| e.as_str()).unwrap_or("unexpected message").to_string()
}

/// Send to a browser receiver over a WebRTC data channel. Same message flow as `receive_dc`;
/// the stream is gzip because that is what browsers can decompress natively.
pub async fn send_dc(conn: &mut crate::webrtc::DcConn, plan: Plan, tx: &Tx) -> Result<Summary> {
    let mut offer = plan.offer.clone();
    offer.encoding = Some("gzip".into());
    conn.send_text(&serde_json::to_string(&offer)?).await?;
    let m = conn.recv().await.context("waiting for the receiver")?;
    let answer: Answer = serde_json::from_slice(&m.data).context("protocol error: bad answer")?;
    if !answer.ok {
        bail!("receiver declined: {}", answer.error.unwrap_or_default());
    }

    let start = Instant::now();
    let progress = Arc::new(AtomicU64::new(0));
    let (mut chunk_rx, builder) = spawn_archiver(plan.entries, "gzip", progress.clone());
    let mut wire = 0u64;
    let mut last = Instant::now();
    while let Some(chunk) = chunk_rx.recv().await {
        // The receiver only talks during the stream if something went wrong.
        if let Some(m) = conn.try_recv() {
            bail!("receiver failed: {}", dc_error(&m));
        }
        for part in chunk.chunks(DC_CHUNK) {
            wire += part.len() as u64;
            conn.send(true, part.to_vec()).await.context("sending data")?;
        }
        if last.elapsed() > Duration::from_millis(100) {
            last = Instant::now();
            emit(tx, Event::Progress { done: progress.load(Ordering::Relaxed), total: offer.tar_bytes });
        }
    }
    builder.await.context("archiver task")??;
    conn.send_text(r#"{"done":true}"#).await?;
    emit(tx, Event::Progress { done: offer.tar_bytes, total: offer.tar_bytes });

    let m = conn.recv().await.context("waiting for the receiver to confirm")?;
    let answer: Answer = serde_json::from_slice(&m.data).context("protocol error: bad answer")?;
    if !answer.ok {
        bail!("receiver failed: {}", answer.error.unwrap_or_default());
    }
    Ok(Summary {
        files: offer.files,
        bytes: offer.bytes,
        wire_bytes: wire,
        secs: start.elapsed().as_secs_f64(),
        names: if answer.saved.is_empty() { offer.names } else { answer.saved },
    })
}

/// Receive over a WebRTC data channel from a browser. Messages: text JSON offer → text JSON
/// answer → binary data chunks → text `{"done":true}` → text JSON answer.
pub async fn receive_dc(conn: &mut crate::webrtc::DcConn, dest: &Path, tx: &Tx) -> Result<Summary> {
    let m = conn.recv().await?;
    if m.binary {
        bail!("protocol error: expected the file offer");
    }
    let offer: Offer = serde_json::from_slice(&m.data).context("protocol error: bad offer")?;
    let (renames, saved) = match plan_receive(&offer, dest, tx) {
        Ok(x) => x,
        Err(e) => {
            let a = Answer { ok: false, error: Some(e.to_string()), saved: vec![] };
            conn.send_text(&serde_json::to_string(&a)?).await?;
            return Err(e);
        }
    };
    emit(tx, Event::Offer(offer.clone()));
    conn.send_text(&serde_json::to_string(&Answer { ok: true, error: None, saved: vec![] })?).await?;

    let start = Instant::now();
    let progress = Arc::new(AtomicU64::new(0));
    let (chunk_tx, extractor) = spawn_extractor(&offer, dest, renames, progress.clone());
    let mut wire = 0u64;
    let mut last = Instant::now();
    let mut net_err = None;
    loop {
        match conn.recv().await {
            Ok(m) if m.binary => {
                wire += m.data.len() as u64;
                if chunk_tx.send(bytes::Bytes::from(m.data)).await.is_err() {
                    break;
                }
            }
            Ok(m) => {
                let v: serde_json::Value = serde_json::from_slice(&m.data).unwrap_or_default();
                if v.get("done").and_then(|d| d.as_bool()) == Some(true) {
                    break;
                }
                net_err = Some(anyhow::anyhow!("sender aborted: {}", String::from_utf8_lossy(&m.data)));
                break;
            }
            Err(e) => {
                net_err = Some(e);
                break;
            }
        }
        if last.elapsed() > Duration::from_millis(100) {
            last = Instant::now();
            emit(tx, Event::Progress { done: progress.load(Ordering::Relaxed), total: offer.tar_bytes });
        }
    }
    drop(chunk_tx);
    let result = extractor.await.context("extractor task")?;
    let result = match (result, net_err) {
        (Ok(r), None) => Ok(r),
        (Err(e), _) => Err(e),
        (Ok(_), Some(e)) => Err(e),
    };
    match result {
        Ok(r) => {
            let a = Answer { ok: true, error: None, saved: saved.clone() };
            conn.send_text(&serde_json::to_string(&a)?).await?;
            Ok(finish_summary(tx, &offer, r, wire, start, saved))
        }
        Err(e) => {
            let a = Answer { ok: false, error: Some(format!("{e:#}")), saved: vec![] };
            let _ = conn.send_text(&serde_json::to_string(&a)?).await;
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wh-test-{tag}-{}", rand::random::<u64>()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn plan_and_extract_roundtrip() {
        let src = tmpdir("src");
        fs::create_dir_all(src.join("dir/sub")).unwrap();
        fs::write(src.join("dir/a.txt"), "hello").unwrap();
        fs::write(src.join("dir/sub/b.bin"), vec![7u8; 100_000]).unwrap();
        fs::write(src.join("top.txt"), "top").unwrap();
        let p = plan(&[src.join("dir"), src.join("top.txt")], true).unwrap();
        assert_eq!(p.offer.files, 3);
        assert_eq!(p.offer.names, vec!["dir", "top.txt"]);

        // Build the archive like `send` does, but into memory.
        let mut enc = zstd::Encoder::new(Vec::new(), 3).unwrap();
        {
            let mut b = tar::Builder::new(&mut enc);
            for e in &p.entries {
                match e.kind {
                    Kind::Dir => b.append_dir(&e.name, &e.src).unwrap(),
                    Kind::File(_) => b.append_file(&e.name, &mut fs::File::open(&e.src).unwrap()).unwrap(),
                }
            }
            b.finish().unwrap();
        }
        let compressed = enc.finish().unwrap();

        let dst = tmpdir("dst");
        fs::write(dst.join("top.txt"), "existing").unwrap();
        let mut renames = HashMap::new();
        for n in &p.offer.names {
            renames.insert(n.clone(), unique_name(&dst, n));
        }
        let prog = Arc::new(AtomicU64::new(0));
        let (files, bytes, _) = extract(&compressed[..], "zstd", &dst, &renames, prog.clone()).unwrap();
        assert_eq!(files, 3);
        assert_eq!(bytes, 100_008);
        assert_eq!(fs::read_to_string(dst.join("dir/a.txt")).unwrap(), "hello");
        assert_eq!(fs::read(dst.join("dir/sub/b.bin")).unwrap().len(), 100_000);
        assert_eq!(fs::read_to_string(dst.join("top.txt")).unwrap(), "existing");
        assert_eq!(fs::read_to_string(dst.join("top (1).txt")).unwrap(), "top");
        let est = p.offer.tar_bytes;
        let real = prog.load(Ordering::Relaxed);
        assert!(real <= est + 10240 && real + 10240 >= est, "estimate {est} vs real {real}");
        fs::remove_dir_all(src).unwrap();
        fs::remove_dir_all(dst).unwrap();
    }

    #[test]
    fn directory_needs_recursive() {
        let src = tmpdir("norec");
        assert!(plan(&[src.clone()], false).is_err());
        fs::remove_dir_all(src).unwrap();
    }

    #[test]
    fn rejects_traversal() {
        let mut data = Vec::new();
        {
            let mut b = tar::Builder::new(&mut data);
            let mut h = tar::Header::new_gnu();
            h.set_size(1);
            h.set_entry_type(tar::EntryType::Regular);
            h.as_gnu_mut().unwrap().name[..9].copy_from_slice(b"../evil.x");
            h.set_cksum();
            b.append(&h, &b"x"[..]).unwrap();
            b.finish().unwrap();
        }
        let compressed = zstd::encode_all(&data[..], 1).unwrap();
        let dst = tmpdir("trav");
        let mut renames = HashMap::new();
        renames.insert("..".to_string(), "x".to_string());
        assert!(extract(&compressed[..], "zstd", &dst, &renames, Arc::new(AtomicU64::new(0))).is_err());
        assert!(!dst.parent().unwrap().join("evil.x").exists());
        fs::remove_dir_all(dst).unwrap();
    }
}
