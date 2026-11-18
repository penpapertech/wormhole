// wormhole in the browser: send files/folders to, and receive them from, `wormhole` (CLI) or
// another browser.
//
// The receiving side posts a WebRTC offer in the mailbox under a nameplate and shows the code; the
// sender looks it up and posts its answer → ICE/DTLS data channel (peer to peer) → SPAKE2 with
// the code, bound to both DTLS fingerprints → tar | gzip stream → the receiver extracts it on the
// fly.

import { WORDS } from "./words.js";
import { extractTar } from "./save.js";

export const DEFAULT_MAILBOX = "https://n7pfkdycg2ts6xcat7ltivpvva0zhndg.lambda-url.eu-west-2.on.aws/";
const ICE_SERVERS = [{ urls: ["stun:stun.l.google.com:19302", "stun:stun.cloudflare.com:3478"] }];
const CHUNK = 64 * 1024;
const HIGH_WATER = 4 * 1024 * 1024;
const enc = new TextEncoder();

// ---------------------------------------------------------------- codes

export function parseCode(input) {
  const parts = input.trim().toLowerCase().replace(/[ _]/g, "-").split("-").filter(Boolean);
  const np = parts[0] || "";
  const words = parts.slice(1);
  if (!/^[0-9]{1,6}$/.test(np) || Number(np) === 0 || words.length === 0 || words.some((w) => !/^[a-z0-9]+$/.test(w))) {
    throw new Error(`Invalid code "${input.trim()}" — expected something like 7-purple-sausage`);
  }
  const nameplate = Number(np);
  return { nameplate, canonical: [String(nameplate), ...words].join("-") };
}

/** A fresh code for `nameplate`: two random words, like the CLI. */
export function generateCode(nameplate) {
  const r = crypto.getRandomValues(new Uint32Array(2));
  return `${nameplate}-${WORDS[r[0] % WORDS.length]}-${WORDS[r[1] % WORDS.length]}`;
}

// ---------------------------------------------------------------- small helpers

const concat = (...arrs) => {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
};
const sha256 = async (data) => new Uint8Array(await crypto.subtle.digest("SHA-256", data));
async function hmac(key, ...parts) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, concat(...parts)));
}
function equalCT(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
function sdpFingerprint(sdp) {
  const m = /a=fingerprint:sha-256 ([0-9a-f:]+)/i.exec(sdp);
  if (!m) throw new Error("no sha-256 DTLS fingerprint in SDP");
  return new Uint8Array(m[1].split(":").map((h) => parseInt(h, 16)));
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function withTimeout(p, ms, msg) {
  let t;
  return Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(new Error(msg)), ms); })]).finally(() => clearTimeout(t));
}

// ---------------------------------------------------------------- SPAKE2 (Rust crate → wasm)

let wasmPromise;
function wasm() {
  wasmPromise ??= fetch(new URL("spake2.wasm", import.meta.url))
    .then((r) => { if (!r.ok) throw new Error("could not load spake2.wasm"); return r.arrayBuffer(); })
    .then((b) => WebAssembly.instantiate(b, {}))
    .then((r) => r.instance.exports);
  return wasmPromise;
}
function wasmCall(w, inputs, fn) {
  const ptrs = inputs.map((b) => { const p = w.wh_alloc(b.length); new Uint8Array(w.memory.buffer, p, b.length).set(b); return p; });
  try {
    const n = fn(...ptrs);
    if (n < 0) return null;
    return new Uint8Array(w.memory.buffer, w.wh_out(), n).slice();
  } finally {
    ptrs.forEach((p, i) => w.wh_free(p, inputs[i].length));
  }
}
async function spakeStart(password) {
  const w = await wasm();
  const pw = enc.encode(password);
  return wasmCall(w, [pw, crypto.getRandomValues(new Uint8Array(32))], (p, s) => w.wh_start(p, pw.length, s));
}
async function spakeFinish(msg) {
  const w = await wasm();
  return wasmCall(w, [msg], (p) => w.wh_finish(p, msg.length));
}

// ---------------------------------------------------------------- mailbox

async function mailbox(url, body) {
  let r;
  try {
    r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  } catch (e) {
    throw new Error("Cannot reach the rendezvous mailbox (" + e.message + ")");
  }
  return { status: r.status, body: await r.json().catch(() => ({})) };
}

// ---------------------------------------------------------------- tar writer (ustar + PAX)

const utf8len = (s) => enc.encode(s).length;
const pad512 = (n) => Math.ceil(n / 512) * 512;
const MAX_OCTAL_SIZE = 8 ** 11 - 1;

function paxRecords(path, size) {
  const recs = [];
  if (utf8len(path) > 100) recs.push(["path", path]);
  if (size > MAX_OCTAL_SIZE) recs.push(["size", String(size)]);
  if (!recs.length) return null;
  let out = "";
  for (const [k, v] of recs) {
    const body = ` ${k}=${v}\n`;
    let len = utf8len(body) + 1;
    while (String(len).length + utf8len(body) !== len) len++;
    out += len + body;
  }
  return enc.encode(out);
}

function header(name, size, type, mtime, mode) {
  const h = new Uint8Array(512);
  const put = (off, len, str) => { const b = enc.encode(str).slice(0, len); h.set(b, off); };
  const oct = (off, len, n) => put(off, len, n.toString(8).padStart(len - 1, "0") + "\0");
  put(0, 100, name);
  oct(100, 8, mode);
  oct(108, 8, 0);
  oct(116, 8, 0);
  oct(124, 12, Math.min(size, MAX_OCTAL_SIZE));
  oct(136, 12, Math.max(0, Math.floor(mtime / 1000)));
  put(148, 8, "        ");
  put(156, 1, type);
  put(257, 6, "ustar\0");
  put(263, 2, "00");
  let sum = 0;
  for (const b of h) sum += b;
  put(148, 8, sum.toString(8).padStart(6, "0") + "\0 ");
  return h;
}

function entryHeaders(e) {
  const path = e.file ? e.path : e.path + "/";
  const size = e.file ? e.file.size : 0;
  const pax = paxRecords(path, size);
  const parts = [];
  if (pax) {
    parts.push(header("PaxHeaders/" + path.slice(-80), pax.length, "x", Date.now(), 0o644), pax);
    const padding = pad512(pax.length) - pax.length;
    if (padding) parts.push(new Uint8Array(padding));
  }
  parts.push(header(path, size, e.file ? "0" : "5", e.file ? e.file.lastModified : Date.now(), e.file ? 0o644 : 0o755));
  return parts;
}

export function tarSize(entries) {
  let n = 1024;
  for (const e of entries) {
    for (const p of entryHeaders(e)) n += p.length;
    if (e.file) n += pad512(e.file.size);
  }
  return n;
}

function tarStream(entries, onBytes) {
  let i = 0;
  let reader = null;
  let filePad = 0;
  return new ReadableStream({
    async pull(ctl) {
      const push = (chunk) => { onBytes(chunk.length); ctl.enqueue(chunk); };
      if (reader) {
        const { done, value } = await reader.read();
        if (!done) return push(value);
        reader = null;
        if (filePad) push(new Uint8Array(filePad));
        return;
      }
      if (i >= entries.length) {
        push(new Uint8Array(1024));
        return ctl.close();
      }
      const e = entries[i++];
      for (const p of entryHeaders(e)) push(p);
      if (e.file && e.file.size > 0) {
        reader = e.file.stream().getReader();
        filePad = pad512(e.file.size) - e.file.size;
      }
    },
  });
}

// ---------------------------------------------------------------- selection model

/** Build the sorted entry list (dirs before their contents) from {path, file|null} items. */
export function buildEntries(items) {
  const map = new Map();
  for (const it of items) {
    const segs = it.path.split("/").filter(Boolean);
    if (!segs.length || segs.some((s) => s === "." || s === "..")) continue;
    for (let k = 1; k < segs.length; k++) {
      const d = segs.slice(0, k).join("/");
      if (!map.has(d)) map.set(d, { path: d, file: null });
    }
    const p = segs.join("/");
    if (it.file || !map.has(p)) map.set(p, { path: p, file: it.file || null });
  }
  return [...map.values()].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

export function summarize(entries) {
  const names = [...new Set(entries.map((e) => e.path.split("/")[0]))];
  const files = entries.filter((e) => e.file);
  return {
    names,
    files: files.length,
    dirs: entries.length - files.length,
    bytes: files.reduce((n, e) => n + e.file.size, 0),
  };
}

/** Walk a drop's DataTransfer (must be called synchronously inside the drop handler). */
export function itemsFromDrop(dataTransfer) {
  const roots = [...dataTransfer.items].map((i) => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
  const plain = roots.length ? [] : [...dataTransfer.files].map((f) => ({ path: f.name, file: f }));
  return (async () => {
    const out = [...plain];
    const walk = async (entry) => {
      const path = entry.fullPath.replace(/^\/+/, "");
      if (entry.isFile) {
        out.push({ path, file: await new Promise((res, rej) => entry.file(res, rej)) });
      } else if (entry.isDirectory) {
        out.push({ path, file: null });
        const r = entry.createReader();
        for (;;) {
          const batch = await new Promise((res, rej) => r.readEntries(res, rej));
          if (!batch.length) break;
          for (const c of batch) await walk(c);
        }
      }
    };
    for (const e of roots) await walk(e);
    return out;
  })();
}

// ---------------------------------------------------------------- data channel wrapper

class Channel {
  constructor(dc) {
    this.dc = dc;
    this.queue = [];
    this.waiters = [];
    this.error = null;
    dc.binaryType = "arraybuffer";
    dc.bufferedAmountLowThreshold = HIGH_WATER / 4;
    dc.onmessage = (e) => this.push(typeof e.data === "string" ? { text: e.data } : { bin: new Uint8Array(e.data) });
    dc.onclose = () => this.fail(new Error("connection closed by the receiver"));
    dc.onerror = (e) => this.fail(new Error("data channel error: " + (e.error?.message || "unknown")));
  }
  push(m) { const w = this.waiters.shift(); w ? w.res(m) : this.queue.push(m); }
  fail(err) { this.error ??= err; for (const w of this.waiters.splice(0)) w.rej(this.error); }
  recv(ms = 60000) {
    if (this.queue.length) return Promise.resolve(this.queue.shift());
    if (this.error) return Promise.reject(this.error);
    const p = new Promise((res, rej) => this.waiters.push({ res, rej }));
    return withTimeout(p, ms, "The receiver stopped responding");
  }
  async recvBin(ms) {
    const m = await this.recv(ms);
    if (!m.bin) {
      let err = "protocol error: expected binary";
      try { err = JSON.parse(m.text).error || err; } catch {}
      throw new Error(err);
    }
    return m.bin;
  }
  async recvJson(ms) { const m = await this.recv(ms); if (m.text === undefined) throw new Error("protocol error: expected text"); return JSON.parse(m.text); }
  async send(data) {
    if (this.error) throw this.error;
    while (this.dc.bufferedAmount > HIGH_WATER) {
      await new Promise((res) => { this.dc.onbufferedamountlow = res; setTimeout(res, 200); });
      if (this.error) throw this.error;
    }
    this.dc.send(data);
  }
  async drain() { while (this.dc.bufferedAmount > 0 && !this.error) await sleep(20); }
}

// ---------------------------------------------------------------- send

/**
 * Send `entries` ([{path, file|null}]) to the receiver holding `codeText`.
 * `on(event, data)` gets: status(text), connected({type}), progress({done,total,wire}), done(summary).
 */
export async function send(codeText, entries, on = () => {}, { mailboxUrl = DEFAULT_MAILBOX, iceServers = ICE_SERVERS } = {}) {
  const code = parseCode(codeText);
  if (!entries.length) throw new Error("Nothing to send");
  const sum = summarize(entries);
  if (new Set(sum.names).size !== sum.names.length) throw new Error("Duplicate names");

  on("status", "Looking up the receiver…");
  const got = await mailbox(mailboxUrl, { op: "get", np: String(code.nameplate) });
  if (got.status === 404) throw new Error(`No receiver is waiting for code ${code.canonical} (check the code; it may have expired)`);
  if (got.status !== 200) throw new Error(`Mailbox error ${got.status}`);
  const rinfo = JSON.parse(got.body.r || "{}");
  if (!rinfo.webrtc) throw new Error("This receiver can't accept browser senders (it needs a newer wormhole, or was started with --no-webrtc)");

  const pc = new RTCPeerConnection({ iceServers });
  try {
    const channelP = new Promise((res) => { pc.ondatachannel = (e) => res(e.channel); });
    await pc.setRemoteDescription({ type: "offer", sdp: rinfo.webrtc });
    await pc.setLocalDescription(await pc.createAnswer());
    on("status", "Gathering network candidates…");
    await withTimeout(new Promise((res) => {
      if (pc.iceGatheringState === "complete") return res();
      pc.addEventListener("icegatheringstatechange", () => pc.iceGatheringState === "complete" && res());
    }), 4000, "gather").catch(() => {}); // send whatever we have after 4s
    const answer = pc.localDescription.sdp;
    const put = await mailbox(mailboxUrl, {
      op: "put", np: String(code.nameplate), side: "s", data: JSON.stringify({ v: 1, addrs: [], webrtc: answer }),
    });
    if (put.status !== 200) throw new Error(put.status === 404 ? "The receiver is gone (code expired?)" : `Mailbox error ${put.status}`);

    on("status", "Connecting peer-to-peer…");
    const dc = await withTimeout(channelP, 30000, "Could not connect to the receiver (strict NAT or UDP blocked on one side)");
    if (dc.readyState !== "open") await withTimeout(new Promise((res) => (dc.onopen = res)), 15000, "Data channel did not open");
    const ch = new Channel(dc);
    pc.addEventListener("connectionstatechange", () => {
      if (pc.connectionState === "failed") ch.fail(new Error("Connection to the receiver was lost"));
    });
    on("connected", { type: await selectedPairType(pc) });

    // --- authenticate (SPAKE2 bound to both DTLS fingerprints)
    on("status", "Authenticating…");
    const binding = await sha256(concat(enc.encode("wormhole-webrtc-v1"), sdpFingerprint(rinfo.webrtc), sdpFingerprint(answer)));
    const mine = await spakeStart(code.canonical);
    await ch.send(mine);
    const theirs = await ch.recvBin();
    const key = await spakeFinish(theirs);
    if (!key) throw new Error("Authentication failed: wrong code");
    await ch.send(await hmac(key, enc.encode("sender"), binding));
    let tag;
    try { tag = await ch.recvBin(20000); } catch { throw new Error("Authentication failed: wrong code (or someone tried to guess it)"); }
    if (!equalCT(tag, await hmac(key, enc.encode("receiver"), binding))) throw new Error("Authentication failed: wrong code");

    // --- offer
    const total = tarSize(entries);
    await ch.send(JSON.stringify({ ...sum, tar_bytes: total, encoding: "gzip" }));
    const ans = await ch.recvJson();
    if (!ans.ok) throw new Error("Receiver declined: " + (ans.error || ""));

    // --- stream tar | gzip
    on("status", "Sending…");
    const t0 = performance.now();
    let done = 0;
    let wire = 0;
    let lastTick = 0;
    const tick = (force) => {
      const now = performance.now();
      if (force || now - lastTick > 100) { lastTick = now; on("progress", { done, total, wire, secs: (now - t0) / 1000 }); }
    };
    const gz = tarStream(entries, (n) => { done += n; }).pipeThrough(new CompressionStream("gzip"));
    const reader = gz.getReader();
    for (;;) {
      const { done: end, value } = await reader.read();
      if (end) break;
      for (let o = 0; o < value.length; o += CHUNK) {
        const part = value.subarray(o, Math.min(o + CHUNK, value.length));
        await ch.send(part);
        wire += part.length;
      }
      tick(false);
    }
    await ch.send(JSON.stringify({ done: true }));
    tick(true);
    on("status", "Waiting for the receiver to confirm…");
    const fin = await ch.recvJson(120000);
    if (!fin.ok) throw new Error("Receiver failed: " + (fin.error || ""));
    const summary = { ...sum, wire, secs: (performance.now() - t0) / 1000, saved: fin.saved || [] };
    on("done", summary);
    await ch.drain();
    return summary;
  } finally {
    setTimeout(() => pc.close(), 500);
  }
}

// ---------------------------------------------------------------- receive

function abortable(signal, ms) {
  return new Promise((res, rej) => {
    if (signal?.aborted) return rej(new Error("Cancelled"));
    const t = setTimeout(res, ms);
    signal?.addEventListener("abort", () => { clearTimeout(t); rej(new Error("Cancelled")); }, { once: true });
  });
}

function checkOffer(offer) {
  const bad = (offer.names || []).find((n) => !n || n === "." || n === ".." || /[/\\\0]/.test(n));
  if (bad !== undefined || !Array.isArray(offer.names) || !offer.names.length) throw new Error(`unsafe name in offer: ${JSON.stringify(bad)}`);
  const encoding = offer.encoding || "zstd";
  if (encoding !== "gzip" && encoding !== "none") {
    throw new Error(`the sender uses '${encoding}' compression, which browsers can't decode (update wormhole on the sending side)`);
  }
  return encoding;
}

/**
 * Receive files into `sink` (see save.js). `on(event, data)` gets: status(text), code(code),
 * connected({type}), offer(offer), progress({done,total,wire,secs}), done(summary).
 * Resolves with {files, bytes, wire, secs, saved, download}. `signal` cancels while waiting.
 */
export async function receive(sink, on = () => {}, { mailboxUrl = DEFAULT_MAILBOX, iceServers = ICE_SERVERS, signal } = {}) {
  const pc = new RTCPeerConnection({ iceServers });
  let np = null;
  const release = () => {
    if (np === null) return;
    mailbox(mailboxUrl, { op: "release", np: String(np) }).catch(() => {});
    np = null;
  };
  try {
    const dc = pc.createDataChannel("wormhole");
    const opened = new Promise((res) => { dc.onopen = res; });
    await pc.setLocalDescription(await pc.createOffer());
    on("status", "Gathering network candidates…");
    await withTimeout(new Promise((res) => {
      if (pc.iceGatheringState === "complete") return res();
      pc.addEventListener("icegatheringstatechange", () => pc.iceGatheringState === "complete" && res());
    }), 4000, "gather").catch(() => {});
    const offer = pc.localDescription.sdp;

    // --- claim a nameplate (like the CLI: small numbers first)
    on("status", "Registering with the rendezvous mailbox…");
    const data = JSON.stringify({ v: 1, addrs: [], webrtc: offer });
    for (let attempt = 0; attempt < 12 && np === null; attempt++) {
      const cand = 1 + (crypto.getRandomValues(new Uint32Array(1))[0] % (attempt < 6 ? 999 : 9999));
      const r = await mailbox(mailboxUrl, { op: "claim", np: String(cand), data });
      if (r.status === 200) np = cand;
      else if (r.status !== 409) throw new Error(`Mailbox error ${r.status}`);
    }
    if (np === null) throw new Error("Could not get a code from the mailbox; try again");
    const codeText = generateCode(np);
    on("code", codeText);

    // --- wait for a sender's answer
    on("status", "Waiting for the sender…");
    const t0 = Date.now();
    let answer = null;
    let warnedOld = false;
    while (!answer) {
      await abortable(signal, Date.now() - t0 < 120000 ? 1000 : 3000);
      let g;
      try { g = await mailbox(mailboxUrl, { op: "get", np: String(np) }); } catch { continue; }
      if (g.status === 404) { np = null; throw new Error("The code expired; get a new one"); }
      if (g.status !== 200 || !g.body.s) continue;
      const sinfo = JSON.parse(g.body.s);
      if (sinfo.webrtc) answer = sinfo.webrtc;
      else if (!warnedOld) {
        warnedOld = true;
        on("status", "A sender tried to connect with an older wormhole that can't send to browsers — it needs updating.");
      }
    }
    on("status", "Sender found, connecting peer-to-peer…");
    await pc.setRemoteDescription({ type: "answer", sdp: answer });
    await withTimeout(opened, 30000, "Could not connect to the sender (strict NAT or UDP blocked on one side)");
    release();
    const ch = new Channel(dc);
    pc.addEventListener("connectionstatechange", () => {
      if (pc.connectionState === "failed") ch.fail(new Error("Connection to the sender was lost"));
    });
    on("connected", { type: await selectedPairType(pc) });

    // --- authenticate (receiver role: answer the sender's messages)
    on("status", "Authenticating…");
    const binding = await sha256(concat(enc.encode("wormhole-webrtc-v1"), sdpFingerprint(offer), sdpFingerprint(answer)));
    const parsed = parseCode(codeText);
    const theirs = await ch.recvBin(30000);
    const mine = await spakeStart(parsed.canonical);
    await ch.send(mine);
    const key = await spakeFinish(theirs);
    const tag = await ch.recvBin(30000);
    if (!key || !equalCT(tag, await hmac(key, enc.encode("sender"), binding))) {
      await ch.send(JSON.stringify({ ok: false, error: "wrong code" })).catch(() => {});
      await ch.drain();
      throw new Error("Authentication failed: wrong code (or someone tried to guess it)");
    }
    await ch.send(await hmac(key, enc.encode("receiver"), binding));

    // --- offer
    const fileOffer = await ch.recvJson(60000);
    let encoding, renames;
    try {
      encoding = checkOffer(fileOffer);
      renames = await sink.begin(fileOffer);
    } catch (e) {
      await ch.send(JSON.stringify({ ok: false, error: e.message })).catch(() => {});
      await ch.drain();
      throw e;
    }
    on("offer", fileOffer);
    await ch.send(JSON.stringify({ ok: true, error: null, saved: [] }));

    // --- data: binary chunks until {"done":true}, extracted as they arrive
    on("status", "Receiving…");
    const start = performance.now();
    let wire = 0, done = 0, lastTick = 0;
    const total = fileOffer.tar_bytes || 0;
    const tick = (force) => {
      const now = performance.now();
      if (force || now - lastTick > 100) { lastTick = now; on("progress", { done, total, wire, secs: (now - start) / 1000 }); }
    };
    let ctl;
    const input = new ReadableStream({ start(c) { ctl = c; } }, { highWaterMark: Infinity });
    const plain = encoding === "gzip" ? input.pipeThrough(new DecompressionStream("gzip")) : input;
    let failed = null;
    const extracting = extractTar(plain.getReader(), renames, sink, (n) => { done += n; tick(false); })
      .catch((e) => { failed = e; throw e; });
    extracting.catch(() => {});
    try {
      for (;;) {
        const m = await Promise.race([ch.recv(120000), extracting.then(() => new Promise(() => {}))]);
        if (m.bin) {
          wire += m.bin.length;
          if (!failed) ctl.enqueue(m.bin);
          continue;
        }
        let v = {};
        try { v = JSON.parse(m.text); } catch {}
        if (v.done) break;
        throw new Error("The sender stopped: " + (v.error || "unknown error"));
      }
      ctl.close();
      const r = await extracting;
      const download = await sink.finish();
      tick(true);
      const saved = fileOffer.names.map((n) => renames[n]);
      await ch.send(JSON.stringify({ ok: true, error: null, saved }));
      await ch.drain();
      const summary = { files: r.files, bytes: r.bytes, wire, secs: (performance.now() - start) / 1000, saved, download, sink: sink.kind };
      on("done", summary);
      await sleep(300);
      return summary;
    } catch (e) {
      const err = failed || e;
      try { ctl.error(err); } catch {}
      if (!ch.error) {
        await ch.send(JSON.stringify({ ok: false, error: err.message })).catch(() => {});
        await ch.drain();
      }
      throw err;
    }
  } finally {
    release();
    setTimeout(() => pc.close(), 500);
  }
}

async function selectedPairType(pc) {
  try {
    const stats = await pc.getStats();
    let pair;
    stats.forEach((s) => { if (s.type === "candidate-pair" && s.state === "succeeded" && (s.nominated || s.selected)) pair ??= s; });
    const local = pair && stats.get(pair.localCandidateId);
    const remote = pair && stats.get(pair.remoteCandidateId);
    if (!local || !remote) return "direct";
    return local.candidateType === "host" && (remote.candidateType === "host" || remote.candidateType === "prflx") ? "local network" : "direct over the internet";
  } catch { return "direct"; }
}
