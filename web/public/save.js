// Receiving side of the web page: a streaming tar reader and two ways to save what it yields.
//
// - folderSink(handle): writes straight into a folder (File System Access API: a folder the user
//   picked in Chrome/Edge, or the origin-private file system). Never overwrites: clashing
//   top-level names become "name (1).ext", like the CLI.
// - downloadSink(): keeps files in memory (as Blobs) and offers one download at the end — the
//   file itself, or a .zip when there are several. Works in every browser; limited by memory.

const dec = new TextDecoder();
const enc = new TextEncoder();
const pad512 = (n) => Math.ceil(n / 512) * 512;

// ---------------------------------------------------------------- byte source over a stream reader

class Source {
  constructor(reader, onBytes) {
    this.r = reader;
    this.cur = new Uint8Array(0);
    this.off = 0;
    this.onBytes = onBytes;
  }
  async next() {
    while (this.off >= this.cur.length) {
      const { done, value } = await this.r.read();
      if (done) return false;
      this.onBytes(value.length);
      this.cur = value;
      this.off = 0;
    }
    return true;
  }
  async exact(n) {
    const out = new Uint8Array(n);
    let o = 0;
    while (o < n) {
      if (!(await this.next())) throw new Error("the archive ended early (connection lost?)");
      const k = Math.min(n - o, this.cur.length - this.off);
      out.set(this.cur.subarray(this.off, this.off + k), o);
      o += k;
      this.off += k;
    }
    return out;
  }
  /** Yield the next n bytes as zero-copy pieces. */
  async *pieces(n) {
    while (n > 0) {
      if (!(await this.next())) throw new Error("the archive ended early (connection lost?)");
      const k = Math.min(n, this.cur.length - this.off);
      const piece = this.cur.subarray(this.off, this.off + k);
      this.off += k;
      n -= k;
      yield piece;
    }
  }
  async skip(n) { for await (const _ of this.pieces(n)); } // eslint-disable-line no-unused-vars
  async drain() { while (await this.next()) this.off = this.cur.length; }
}

// ---------------------------------------------------------------- tar reader (ustar, GNU, PAX)

const str = (h, off, len) => {
  let e = off;
  while (e < off + len && h[e]) e++;
  return dec.decode(h.subarray(off, e));
};

function num(h, off, len) {
  if (h[off] & 0x80) { // GNU base-256 (sizes ≥ 8 GiB)
    let n = h[off] & 0x7f;
    for (let i = off + 1; i < off + len; i++) n = n * 256 + h[i];
    return n;
  }
  const s = str(h, off, len).trim();
  return s ? parseInt(s, 8) : 0;
}

function checksumOk(h) {
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : h[i];
  return sum === num(h, 148, 8);
}

function parsePax(b) {
  const out = {};
  let i = 0;
  while (i < b.length) {
    let sp = i;
    while (sp < b.length && b[sp] !== 0x20) sp++;
    const len = parseInt(dec.decode(b.subarray(i, sp)), 10);
    if (!len || len < 0 || i + len > b.length) break;
    const rec = dec.decode(b.subarray(sp + 1, i + len - 1)); // drop the trailing \n
    const eq = rec.indexOf("=");
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    i += len;
  }
  return out;
}

/** Split an archive path into safe segments, or throw. */
export function safeSegments(path) {
  if (path.startsWith("/") || /^[a-zA-Z]:/.test(path)) throw new Error(`refusing unsafe path in archive: ${path}`);
  const segs = path.split("/").filter((s) => s && s !== ".");
  if (segs.some((s) => s === ".." || s.includes("\\") || s.includes("\0"))) throw new Error(`refusing unsafe path in archive: ${path}`);
  return segs;
}

/**
 * Read a tar stream and hand entries to `sink`. `renames` maps each top-level name in the offer
 * to the name it is saved under; anything outside those names is refused.
 */
export async function extractTar(reader, renames, sink, onBytes = () => {}) {
  const src = new Source(reader, onBytes);
  let longName = null;
  let pax = {};
  let files = 0, bytes = 0, skipped = 0;
  for (;;) {
    if (!(await src.next())) throw new Error("the archive ended early (connection lost?)");
    const h = await src.exact(512);
    if (h.every((b) => b === 0)) break; // end-of-archive marker
    if (!checksumOk(h)) throw new Error("corrupt archive (bad header checksum)");
    const type = h[156] ? String.fromCharCode(h[156]) : "0";
    let size = num(h, 124, 12);
    if (pax.size !== undefined) size = Number(pax.size);
    if (type === "L" || type === "x" || type === "g") {
      const body = (await src.exact(pad512(size))).subarray(0, size);
      if (type === "L") longName = str(body, 0, size);
      if (type === "x") pax = parsePax(body);
      continue;
    }
    let name = str(h, 0, 100);
    if (str(h, 257, 6) === "ustar") { // POSIX ustar: optional prefix field
      const prefix = str(h, 345, 155);
      if (prefix) name = prefix + "/" + name;
    }
    if (pax.path !== undefined) name = pax.path;
    else if (longName !== null) name = longName;
    longName = null;
    pax = {};

    const segs = safeSegments(name);
    if (!segs.length) { await src.skip(pad512(size)); continue; }
    if (!Object.hasOwn(renames, segs[0])) throw new Error(`archive contains an unexpected entry: ${name}`);
    segs[0] = renames[segs[0]];
    if (type === "5") {
      await sink.dir(segs);
      await src.skip(pad512(size));
    } else if (type === "0" || type === "7") {
      await sink.file(segs, size, src.pieces(size));
      await src.skip(pad512(size) - size);
      files++;
      bytes += size;
    } else {
      skipped++; // links, devices, …
      await src.skip(pad512(size));
    }
  }
  await src.drain(); // trailing zero block + gzip trailer: lets the decompressor verify the CRC
  return { files, bytes, skipped };
}

// ---------------------------------------------------------------- sinks

/** Name for `name` that doesn't clash in `dir`: name, "name (1).ext", "name (2).ext", … */
async function uniqueName(dir, name) {
  const exists = async (n) => {
    for (const get of ["getFileHandle", "getDirectoryHandle"]) {
      try { await dir[get](n); return true; } catch (e) { if (e.name === "TypeMismatchError") return true; }
    }
    return false;
  };
  if (!(await exists(name))) return name;
  const i = name.lastIndexOf(".");
  const [stem, ext] = i > 0 ? [name.slice(0, i), name.slice(i)] : [name, ""];
  for (let k = 1; ; k++) {
    const n = `${stem} (${k})${ext}`;
    if (!(await exists(n))) return n;
  }
}

async function subdir(root, segs) {
  let d = root;
  for (const s of segs) d = await d.getDirectoryHandle(s, { create: true });
  return d;
}

const WRITE_BATCH = 4 << 20;

/** Save into a FileSystemDirectoryHandle (picked folder or navigator.storage.getDirectory()). */
export function folderSink(root) {
  return {
    kind: "folder",
    name: root.name,
    async begin(offer) {
      const renames = {};
      for (const n of offer.names) renames[n] = await uniqueName(root, n);
      return renames;
    },
    async dir(segs) { await subdir(root, segs); },
    async file(segs, size, pieces) {
      const d = await subdir(root, segs.slice(0, -1));
      const w = await (await d.getFileHandle(segs.at(-1), { create: true })).createWritable();
      try {
        let batch = [], n = 0;
        for await (const p of pieces) {
          batch.push(p);
          n += p.length;
          if (n >= WRITE_BATCH) { await w.write(new Blob(batch)); batch = []; n = 0; }
        }
        if (n) await w.write(new Blob(batch));
        await w.close();
      } catch (e) {
        await w.abort().catch(() => {});
        throw e;
      }
    },
    async finish() { return null; },
  };
}

// CRC-32 (for zip)
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(crc, buf) {
  crc = ~crc;
  for (let i = 0; i < buf.length; i++) crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return ~crc >>> 0;
}

const ZIP_LIMIT = 0xffffffff;

/** Build a zip (stored, no compression: the data was compressed in transit) from entries. */
export function buildZip(entries) {
  const d = new Date();
  const time = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
  const date = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  const parts = [], central = [];
  let offset = 0;
  for (const e of entries) {
    const name = enc.encode(e.path);
    const size = e.blob ? e.blob.size : 0;
    const local = new Uint8Array(30 + name.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(6, 0x0800, true); // UTF-8 names
    lv.setUint16(8, 0, true); // stored
    lv.setUint16(10, time, true);
    lv.setUint16(12, date, true);
    lv.setUint32(14, e.crc || 0, true);
    lv.setUint32(18, size, true);
    lv.setUint32(22, size, true);
    lv.setUint16(26, name.length, true);
    local.set(name, 30);
    const c = new Uint8Array(46 + name.length);
    const cv = new DataView(c.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 0x0314, true); // made by: unix, 2.0
    cv.setUint16(6, 20, true);
    cv.setUint16(8, 0x0800, true);
    cv.setUint16(12, time, true);
    cv.setUint16(14, date, true);
    cv.setUint32(16, e.crc || 0, true);
    cv.setUint32(20, size, true);
    cv.setUint32(24, size, true);
    cv.setUint16(28, name.length, true);
    cv.setUint32(38, (e.blob ? 0o100644 : 0o040755) * 65536, true); // unix mode
    cv.setUint32(42, offset, true);
    c.set(name, 46);
    parts.push(local);
    if (e.blob) parts.push(e.blob);
    central.push(c);
    offset += local.length + size;
    if (offset > ZIP_LIMIT) throw new Error("too large for a zip download (4 GB)");
  }
  const cdSize = central.reduce((n, c) => n + c.length, 0);
  const end = new Uint8Array(22);
  const ev = new DataView(end.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, entries.length, true);
  ev.setUint16(10, entries.length, true);
  ev.setUint32(12, cdSize, true);
  ev.setUint32(16, offset, true);
  return new Blob([...parts, ...central, end], { type: "application/zip" });
}

export function saveBlob(name, blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

/**
 * Keep everything in memory and offer one download at the end: the file itself, or a .zip.
 * `save(name, blob)` does the download (default: an <a download> click).
 */
export function downloadSink(save = saveBlob) {
  const entries = [];
  let names = [];
  return {
    kind: "download",
    async begin(offer) {
      if (offer.bytes >= ZIP_LIMIT || offer.files + offer.dirs > 65000) {
        throw new Error("too large to receive as a download in this browser — use Chrome or Edge and save into a folder");
      }
      names = offer.names;
      return Object.fromEntries(offer.names.map((n) => [n, n]));
    },
    async dir(segs) { entries.push({ path: segs.join("/") + "/", blob: null }); },
    async file(segs, size, pieces) {
      const blobs = [];
      let batch = [], n = 0, crc = 0;
      for await (const p of pieces) {
        crc = crc32(crc, p);
        batch.push(p);
        n += p.length;
        if (n >= 8 << 20) { blobs.push(new Blob(batch)); batch = []; n = 0; }
      }
      blobs.push(new Blob(batch));
      entries.push({ path: segs.join("/"), blob: new Blob(blobs), crc });
    },
    async finish() {
      const files = entries.filter((e) => e.blob);
      let name, blob;
      if (entries.length === 1 && files.length === 1) {
        name = files[0].path;
        blob = files[0].blob;
      } else {
        name = (names.length === 1 ? names[0] : "wormhole") + ".zip";
        blob = buildZip(entries);
      }
      save(name, blob);
      return { name, size: blob.size };
    },
  };
}
