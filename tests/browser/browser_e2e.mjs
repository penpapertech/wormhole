// Browser → CLI end-to-end tests: headless Chromium sends to `wormhole receive` over WebRTC.
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
  const p = bg(BIN, ["receive"], { cwd: dir, env: { ...process.env, WORMHOLE_MAILBOX: MAILBOX } });
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
