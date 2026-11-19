// Browser end-to-end tests over WebRTC: headless Chromium sends to `wormhole receive`, receives
// from `wormhole send`, and talks to another browser page.
// Usage: (cd tests/browser && npm install && node browser_e2e.mjs [path/to/wormhole])
// Browser: CHROME=/path/to/chrome to launch a local one; otherwise Chromium runs in Docker
// (tests/browser/Dockerfile, host network) — snap-packaged Chromium can't reach local servers.
import puppeteer from "puppeteer-core";
import { spawn, execSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, statSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const BIN = resolve(process.argv[2] || join(root, "target/release/wormhole"));
const TLS_PORT = 18384, PLAIN_PORT = 18383;
// Same in-memory mailbox: CLI over plain HTTP, browser over HTTPS (Chromium refuses plain HTTP).
// MAILBOX_URL=<real mailbox> runs both sides against a deployed mailbox instead.
const MAILBOX = process.env.MAILBOX_URL || `http://127.0.0.1:${PLAIN_PORT}/`;
const PAGE_ORIGIN = `https://127.0.0.1:${TLS_PORT}`;
const PAGE_MAILBOX = process.env.MAILBOX_URL || `${PAGE_ORIGIN}/mailbox`;

const DEBUG_PORT = 9333;

async function startBrowser() {
  const args = ["--ignore-certificate-errors", "--disable-features=WebRtcHideLocalIpsWithMdns"];
  if (process.env.CHROME) {
    return puppeteer.launch({ executablePath: process.env.CHROME, headless: true, pipe: true, args: ["--no-sandbox", ...args], acceptInsecureCerts: true });
  }
  execSync("docker rm -f wh-chrome-test >/dev/null 2>&1 || true");
  execSync(`docker build -q -t wormhole-chrome-test ${here} >/dev/null`);
  // Mount this directory at the same path so file-input uploads can see test files.
  execSync(`docker run -d --rm --name wh-chrome-test --network host -v ${here}:${here}:ro wormhole-chrome-test ` +
    `--remote-debugging-port=${DEBUG_PORT} ${args.join(" ")} about:blank`);
  for (let i = 0; i < 50; i++) {
    try { return await puppeteer.connect({ browserURL: `http://127.0.0.1:${DEBUG_PORT}`, acceptInsecureCerts: true }); }
    catch { await sleep(200); }
  }
  throw new Error("could not connect to Chromium in Docker");
}

const procs = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function bg(cmd, args, opts = {}) {
  const p = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"], ...opts });
  p.out = "";
  p.stdout.on("data", (d) => (p.out += d));
  p.stderr.on("data", (d) => (p.out += d));
  p.done = new Promise((res) => p.on("exit", (code) => res(code)));
  procs.push(p);
  return p;
}
const strip = (s) => s.replace(/\x1b\[[0-9;]*m/g, "");

async function startReceiver(dir) {
  const p = bg(BIN, ["receive", "--once"], { cwd: dir, env: { ...process.env, WORMHOLE_MAILBOX: MAILBOX } });
  for (let i = 0; i < 100; i++) {
    const m = /(\d+-[a-z]+-[a-z]+)/.exec(strip(p.out));
    if (m) return { p, code: m[1] };
    await sleep(100);
  }
  throw new Error("receiver printed no code:\n" + p.out);
}

// Deterministic content shared by page and node.
const genSrc = `(n, seed) => { const a = new Uint8Array(n); let x = seed >>> 0 || 1;
  for (let i = 0; i < n; i++) { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; a[i] = x & 255; } return a; }`;
const gen = eval(genSrc);
const sha = (b) => createHash("sha256").update(b).digest("hex");

const LONG = "folder/" + "a-rather-long-directory-name-for-testing/".repeat(3) + "file-with-a-long-name.txt";
const SPEC = [
  { path: "hello.txt", text: "hello from the browser\n" },
  { path: "folder/sub/data.bin", rand: 3_000_000, seed: 7 },
  { path: "folder/notes.txt", text: "line\n".repeat(20000) },
  { path: "folder/empty.txt", text: "" },
  { path: "folder/emptydir", dir: true },
  { path: LONG, text: "long path ok\n" },
  { path: "ünïcødé ✓.txt", text: "unicode ok\n" },
];
const expected = (s) => (s.text !== undefined ? Buffer.from(s.text) : Buffer.from(gen(s.rand, s.seed)));

let failures = 0;
const only = (n) => !process.env.ONLY || process.env.ONLY.split(",").includes(String(n));
const ok = (msg) => console.log("  OK   " + msg);
const fail = (msg) => { console.log("  FAIL " + msg); failures++; };

async function main() {
  const certDir = mkdtempSync(join(tmpdir(), "wh-cert-"));
  execSync(`openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=127.0.0.1 -keyout ${certDir}/k.pem -out ${certDir}/c.pem 2>/dev/null`);
  bg("python3", [join(here, "serve.py"), String(TLS_PORT), String(PLAIN_PORT), join(root, "web/public"), `${certDir}/c.pem`, `${certDir}/k.pem`]);
  await sleep(800);
  const browser = await startBrowser();
  const page = await browser.newPage();
  page.on("console", (m) => process.env.DEBUG && console.log("  [page]", m.text()));
  await page.goto(`${PAGE_ORIGIN}/?mailbox=${encodeURIComponent(PAGE_MAILBOX)}`);

  const pageSend = (code, spec) =>
    page.evaluate(async (code, spec, genSrc, mailboxUrl) => {
      const gen = eval(genSrc);
      const items = spec.map((s) => s.dir ? { path: s.path, file: null }
        : { path: s.path, file: new File([s.text !== undefined ? s.text : gen(s.rand, s.seed)], s.path.split("/").pop()) });
      const entries = window.wormhole.buildEntries(items);
      const events = [];
      try {
        const summary = await window.wormhole.send(code, entries, (e, d) => { events.push([e, e === "progress" ? null : d]); if (e !== "progress") console.log("event", e, JSON.stringify(d)); }, { mailboxUrl });
        return { ok: true, summary, events };
      } catch (e) {
        return { ok: false, error: e.message, events };
      }
    }, code, spec, genSrc, PAGE_MAILBOX);

  // ---------------------------------------------------------------- 1. API-level send
  if (only(1)) console.log("== 1. browser → CLI: nested folders, long path, unicode, empty file & dir, name collision");
  if (only(1)) {
    const dst = mkdtempSync(join(tmpdir(), "wh-br-"));
    writeFileSync(join(dst, "hello.txt"), "pre-existing\n");
    const { p, code } = await startReceiver(dst);
    const r = await Promise.race([pageSend(code, SPEC), sleep(60000).then(() => ({ ok: false, error: "browser timed out" }))]);
    const rc = await Promise.race([p.done, sleep(20000).then(() => "timeout")]);
    if (!r.ok) console.log("    receiver exit:", rc, "output:\n" + strip(p.out).split("\n").map((l) => "      " + l).join("\n"));
    if (!r.ok) fail("send failed: " + r.error + "\n" + strip(p.out));
    else if (rc !== 0) fail("receiver exit " + rc + "\n" + strip(p.out));
    else {
      let bad = 0;
      for (const s of SPEC) {
        const target = join(dst, s.path === "hello.txt" ? "hello (1).txt" : s.path);
        if (s.dir) { if (!existsSync(target) || !statSync(target).isDirectory()) { bad++; console.log("    missing dir", s.path); } continue; }
        if (!existsSync(target) || sha(readFileSync(target)) !== sha(expected(s))) { bad++; console.log("    mismatch", s.path); }
      }
      if (readFileSync(join(dst, "hello.txt"), "utf8") !== "pre-existing\n") bad++;
      const conn = r.events.find((e) => e[0] === "connected");
      bad ? fail(`${bad} files wrong`) : ok(`all files identical (${r.summary.files} files, ${r.summary.wire} bytes on the wire, ${conn?.[1]?.type})`);
      console.log("    receiver: " + strip(p.out).split("\n").filter((l) => /Connected|Received|Saved/.test(l)).map((l) => l.trim()).join(" | "));
    }
    rmSync(dst, { recursive: true, force: true });
  }

  // ---------------------------------------------------------------- 2. through the real UI
  if (only(2)) console.log("== 2. browser UI: file input + Send button");
  if (only(2)) {
    const dst = mkdtempSync(join(tmpdir(), "wh-br-"));
    // Inside this directory so the (dockerized) browser can read them.
    const srcDir = mkdtempSync(join(here, ".ui-tmp-"));
    const f1 = join(srcDir, "photo.jpg"), f2 = join(srcDir, "report.pdf");
    writeFileSync(f1, gen(500_000, 3)); writeFileSync(f2, "%PDF-fake\n".repeat(1000));
    const { p, code } = await startReceiver(dst);
    await page.reload();
    await page.type("#code", code);
    const input = await page.$("#files");
    await input.uploadFile(f1, f2);
    await page.waitForFunction(() => document.querySelectorAll("#list li").length === 2);
    await page.click("#send");
    await page.waitForFunction(() => /✔|✘/.test(document.querySelector("#status").textContent), { timeout: 40000 });
    const status = await page.$eval("#status", (e) => e.textContent);
    await Promise.race([p.done, sleep(10000)]);
    const same = existsSync(join(dst, "photo.jpg")) && sha(readFileSync(join(dst, "photo.jpg"))) === sha(readFileSync(f1))
      && sha(readFileSync(join(dst, "report.pdf"))) === sha(readFileSync(f2));
    status.startsWith("✔") && same ? ok(status.slice(0, 110)) : fail(status + "\n" + strip(p.out));
    rmSync(dst, { recursive: true, force: true });
    rmSync(srcDir, { recursive: true, force: true });
  }

  // ---------------------------------------------------------------- 3. wrong code
  if (only(3)) console.log("== 3. wrong code is rejected on both sides");
  if (only(3)) {
    const dst = mkdtempSync(join(tmpdir(), "wh-br-"));
    const { p, code } = await startReceiver(dst);
    const wrong = code.split("-")[0] + "-wrong-guess";
    await page.reload();
    const r = await pageSend(wrong, [{ path: "x.txt", text: "x" }]);
    const rc = await Promise.race([p.done, sleep(15000).then(() => "timeout")]);
    !r.ok && /wrong code/i.test(r.error) && rc === 1 && /wrong code/.test(p.out) && readdirSync(dst).length === 0
      ? ok(`browser: "${r.error}"; receiver exited 1`)
      : fail(`browser: ${JSON.stringify(r.error)} receiver rc=${rc}\n${strip(p.out)}`);
    rmSync(dst, { recursive: true, force: true });
  }

  // ---------------------------------------------------------------- 4. throughput
  if (only(4)) console.log("== 4. throughput: 50 MB incompressible");
  if (only(4)) {
    const dst = mkdtempSync(join(tmpdir(), "wh-br-"));
    const { p, code } = await startReceiver(dst);
    await page.reload();
    const spec = [{ path: "big.bin", rand: 50_000_000, seed: 11 }];
    const r = await pageSend(code, spec);
    await Promise.race([p.done, sleep(30000)]);
    const good = r.ok && sha(readFileSync(join(dst, "big.bin"))) === sha(expected(spec[0]));
    good ? ok(`${(50 / r.summary.secs).toFixed(1)} MB/s browser → CLI (same machine)`) : fail(r.error || "content mismatch");
    rmSync(dst, { recursive: true, force: true });
  }

  // ---------------------------------------------------------------- browser receiving
  const SRC_SPEC = SPEC; // same tree, now sent by the CLI
  const makeSrc = () => {
    const d = mkdtempSync(join(tmpdir(), "wh-src-"));
    for (const s of SRC_SPEC) {
      const p = join(d, s.path);
      if (s.dir) { mkdirSync(p, { recursive: true }); continue; }
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, expected(s));
    }
    return d;
  };
  const tops = [...new Set(SRC_SPEC.map((s) => s.path.split("/")[0]))];

  // Start receiving in `pg` (sink: "folder" = origin-private file system, or "download");
  // resolves with the code once it is shown.
  const pageReceive = (pg, mode, preexisting) =>
    pg.evaluate(async (mode, mailboxUrl, preexisting) => {
      const root = await navigator.storage.getDirectory();
      for await (const [name] of root.entries()) await root.removeEntry(name, { recursive: true });
      for (const [name, text] of Object.entries(preexisting || {})) {
        const w = await (await root.getFileHandle(name, { create: true })).createWritable();
        await w.write(text); await w.close();
      }
      let dl = null;
      const nullSink = { kind: "null", begin: async (o) => Object.fromEntries(o.names.map((n) => [n, n])), dir: async () => {},
        file: async (s, n, pieces) => { for await (const _ of pieces); }, finish: async () => null }; // eslint-disable-line no-unused-vars
      const sink = mode === "folder" ? window.wormhole.folderSink(root) : mode === "null" ? nullSink
        : window.wormhole.downloadSink((name, blob) => { dl = { name, blob }; });
      let gotCode;
      const codeP = new Promise((r) => (gotCode = r));
      const b64 = async (blob) => { const u = new Uint8Array(await blob.arrayBuffer()); let s = ""; for (let i = 0; i < u.length; i += 32768) s += String.fromCharCode(...u.subarray(i, i + 32768)); return btoa(s); };
      window.__rx = window.wormhole.receive(sink, (e, d) => { if (e === "code") gotCode(d); if (e !== "progress") console.log("rx", e, JSON.stringify(d)); }, { mailboxUrl })
        .then(async (s) => ({ ok: true, s, dl: dl && { name: dl.name, b64: await b64(dl.blob) } }), (e) => ({ ok: false, error: e.message }));
      return Promise.race([codeP, window.__rx.then((r) => { throw new Error("receive ended early: " + r.error); })]);
    }, mode, PAGE_MAILBOX, preexisting);
  const pageResult = (pg, ms = 60000) =>
    Promise.race([pg.evaluate(() => window.__rx), sleep(ms).then(() => ({ ok: false, error: "browser receive timed out" }))]);
  const opfsHashes = (pg) =>
    pg.evaluate(async () => {
      const out = {};
      const walk = async (d, pre) => {
        for await (const [n, h] of d.entries()) {
          const p = pre ? pre + "/" + n : n;
          if (h.kind === "directory") { out[p + "/"] = "dir"; await walk(h, p); continue; }
          const dg = new Uint8Array(await crypto.subtle.digest("SHA-256", await (await h.getFile()).arrayBuffer()));
          out[p] = [...dg].map((x) => x.toString(16).padStart(2, "0")).join("");
        }
      };
      await walk(await navigator.storage.getDirectory(), "");
      return out;
    });
  const cliSend = (code, args, cwd) => bg(BIN, ["send", code, ...args], { cwd, env: { ...process.env, WORMHOLE_MAILBOX: MAILBOX } });
  const checkTree = (have, rename = {}) => {
    let bad = 0;
    for (const s of SRC_SPEC) {
      const top = s.path.split("/")[0];
      const p = (rename[top] ? s.path.replace(top, rename[top]) : s.path) + (s.dir ? "/" : "");
      const want = s.dir ? "dir" : sha(expected(s));
      if (have[p] !== want) { bad++; console.log("    mismatch", p); }
    }
    return bad;
  };

  if (only(5)) console.log("== 5. CLI → browser (save into a folder): nested folders, long path, unicode, empty file & dir, name collision");
  if (only(5)) {
    const src = makeSrc();
    await page.reload();
    const code = await pageReceive(page, "folder", { "hello.txt": "pre-existing\n" });
    const p = cliSend(code, ["-R", ...tops], src);
    const r = await pageResult(page);
    const rc = await Promise.race([p.done, sleep(20000).then(() => "timeout")]);
    if (!r.ok || rc !== 0) fail(`browser: ${r.error || "ok"}; sender rc=${rc}\n${strip(p.out)}`);
    else {
      const have = await opfsHashes(page);
      let bad = checkTree(have, { "hello.txt": "hello (1).txt" });
      if (have["hello.txt"] !== sha(Buffer.from("pre-existing\n"))) { bad++; console.log("    pre-existing file changed"); }
      bad ? fail(`${bad} entries wrong`) : ok(`all files identical (${r.s.files} files, ${r.s.wire} bytes on the wire); saved as ${r.s.saved.join(", ")}`);
      console.log("    sender: " + strip(p.out).split("\n").filter((l) => /Connected|Sent|receiver is/.test(l)).map((l) => l.trim()).join(" | "));
    }
    rmSync(src, { recursive: true, force: true });
  }

  if (only(6)) console.log("== 6. CLI → browser (download as .zip)");
  if (only(6)) {
    const src = makeSrc();
    await page.reload();
    const code = await pageReceive(page, "download");
    const p = cliSend(code, ["-R", ...tops], src);
    const r = await pageResult(page);
    await Promise.race([p.done, sleep(20000)]);
    if (!r.ok || !r.dl) fail(`browser: ${r.error || "no download"}\n${strip(p.out)}`);
    else {
      const zdir = mkdtempSync(join(tmpdir(), "wh-zip-"));
      writeFileSync(join(zdir, "x.zip"), Buffer.from(r.dl.b64, "base64"));
      // Python's zipfile checks every CRC, then we compare contents.
      const listing = execSync(`python3 -I -c "import zipfile,sys,hashlib,json; z=zipfile.ZipFile(sys.argv[1]); assert z.testzip() is None; print(json.dumps({i.filename: ('dir' if i.is_dir() else hashlib.sha256(z.read(i)).hexdigest()) for i in z.infolist()}))" ${join(zdir, "x.zip")}`).toString();
      const bad = checkTree(JSON.parse(listing));
      bad ? fail(`${bad} entries wrong in ${r.dl.name}`) : ok(`${r.dl.name}: ${Buffer.from(r.dl.b64, "base64").length} bytes, all CRCs and contents correct`);
      rmSync(zdir, { recursive: true, force: true });
    }
    rmSync(src, { recursive: true, force: true });
  }

  if (only(7)) console.log("== 7. browser → browser");
  if (only(7)) {
    const page2 = await browser.newPage();
    page2.on("console", (m) => process.env.DEBUG && console.log("  [page2]", m.text()));
    await page2.goto(`${PAGE_ORIGIN}/?mailbox=${encodeURIComponent(PAGE_MAILBOX)}`);
    await page.reload();
    const code = await pageReceive(page2, "folder");
    const sent = await pageSend(code, SPEC);
    const r = await pageResult(page2);
    if (!sent.ok || !r.ok) fail(`sender: ${sent.error || "ok"}; receiver: ${r.error || "ok"}`);
    else {
      const bad = checkTree(await opfsHashes(page2));
      const conn = sent.events.find((e) => e[0] === "connected");
      bad ? fail(`${bad} entries wrong`) : ok(`all files identical (${r.s.files} files, ${conn?.[1]?.type})`);
    }
    await page2.close();
  }

  if (only(8)) console.log("== 8. CLI → browser with a wrong code is rejected on both sides");
  if (only(8)) {
    const src = makeSrc();
    await page.reload();
    const code = await pageReceive(page, "folder");
    const p = cliSend(code.split("-")[0] + "-wrong-guess", ["hello.txt"], src);
    const r = await pageResult(page, 30000);
    const rc = await Promise.race([p.done, sleep(20000).then(() => "timeout")]);
    const files = Object.keys(await opfsHashes(page));
    !r.ok && /wrong code/i.test(r.error) && rc !== 0 && /wrong code/.test(strip(p.out)) && files.length === 0
      ? ok(`browser: "${r.error}"; sender exited ${rc}`)
      : fail(`browser: ${JSON.stringify(r)} sender rc=${rc} files=${files}\n${strip(p.out)}`);
    rmSync(src, { recursive: true, force: true });
  }

  if (only(9)) console.log("== 9. throughput: CLI → browser, 50 MB incompressible");
  if (only(9)) {
    const src = mkdtempSync(join(tmpdir(), "wh-src-"));
    const spec = { path: "big.bin", rand: 50_000_000, seed: 11 };
    writeFileSync(join(src, "big.bin"), expected(spec));
    await page.reload();
    const sinkMode = process.env.THRU_SINK || "folder";
    const code = await pageReceive(page, sinkMode);
    const p = cliSend(code, ["big.bin"], src);
    const r = await pageResult(page, 120000);
    await Promise.race([p.done, sleep(20000)]);
    const have = r.ok ? await opfsHashes(page) : {};
    r.ok && (sinkMode === "null" || have["big.bin"] === sha(expected(spec)))
      ? ok(`${(50 / r.s.secs).toFixed(1)} MB/s CLI → browser (same machine)`)
      : fail((r.error || "content mismatch") + "\n" + strip(p.out));
    rmSync(src, { recursive: true, force: true });
  }

  if (only(10)) console.log("== 10. browser UI: Receive tab → download");
  if (only(10)) {
    const src = makeSrc();
    const cdp = await browser.target().createCDPSession();
    const downloads = [];
    cdp.on("Browser.downloadProgress", (e) => { if (e.state === "completed") downloads.push(e); });
    await cdp.send("Browser.setDownloadBehavior", { behavior: "allowAndName", downloadPath: "/tmp/wh-downloads", eventsEnabled: true });
    await page.goto(`${PAGE_ORIGIN}/?mailbox=${encodeURIComponent(PAGE_MAILBOX)}#receive`);
    await page.click('input[value="download"]');
    await page.click("#recvStart");
    await page.waitForFunction(() => document.querySelector("#codeOut").textContent, { timeout: 20000 });
    const code = await page.$eval("#codeOut", (e) => e.textContent);
    const link = await page.$eval("#linkOut", (e) => e.href);
    const p = cliSend(code, ["hello.txt", "ünïcødé ✓.txt"], src);
    await page.waitForFunction(() => /✔|✘/.test(document.querySelector("#recvStatus").textContent), { timeout: 40000 });
    const status = await page.$eval("#recvStatus", (e) => e.textContent);
    for (let i = 0; i < 50 && !downloads.length; i++) await sleep(100);
    await Promise.race([p.done, sleep(10000)]);
    status.startsWith("✔") && downloads.length === 1 && downloads[0].totalBytes > 0 && link.endsWith("#" + code)
      ? ok(`${status.slice(0, 120)} (download ${downloads[0].totalBytes} bytes)`)
      : fail(`${status} downloads=${JSON.stringify(downloads)}\n${strip(p.out)}`);
    await cdp.detach();
    rmSync(src, { recursive: true, force: true });
  }

  if (process.env.CHROME) await browser.close(); else execSync("docker rm -f wh-chrome-test >/dev/null 2>&1 || true");
  console.log(failures ? `${failures} BROWSER TEST(S) FAILED` : "ALL BROWSER TESTS PASSED");
}

main()
  .catch((e) => { console.error(e); failures++; })
  .finally(() => {
    for (const p of procs) try { p.kill(); } catch {}
    if (!process.env.CHROME) try { execSync("docker rm -f wh-chrome-test >/dev/null 2>&1"); } catch {}
    process.exit(failures ? 1 : 0);
  });
