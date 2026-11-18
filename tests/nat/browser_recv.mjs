// Runs inside the NAT test container (network namespace of peer b): headless Chromium receives
// files from a CLI sender behind another NAT into its origin-private file system. Prints
// "CODE <code>" as soon as the code is known, then a JSON result with the received files' hashes.
// Usage: node browser_recv.mjs <page-url> <stun host:port> <debug-port>
import puppeteer from "/tb/node_modules/puppeteer-core/lib/esm/puppeteer/puppeteer-core.js";

const [url, stun, port] = process.argv.slice(2);
let browser;
for (let i = 0; i < 100 && !browser; i++) {
  try { browser = await puppeteer.connect({ browserURL: `http://127.0.0.1:${port}`, acceptInsecureCerts: true }); }
  catch { await new Promise((r) => setTimeout(r, 200)); }
}
const page = await browser.newPage();
await page.goto(url);
const mailboxUrl = new URL("/mailbox", url).href;
const code = await page.evaluate(async (stun, mailboxUrl) => {
  const root = await navigator.storage.getDirectory();
  for await (const [name] of root.entries()) await root.removeEntry(name, { recursive: true });
  let gotCode;
  const codeP = new Promise((r) => (gotCode = r));
  window.__rx = window.wormhole.receive(window.wormhole.folderSink(root), (e, d) => { if (e === "code") gotCode(d); },
    { mailboxUrl, iceServers: [{ urls: "stun:" + stun }] })
    .then((s) => ({ ok: true, files: s.files }), (e) => ({ ok: false, error: e.message }));
  return Promise.race([codeP, window.__rx.then((r) => r.error)]);
}, stun, mailboxUrl);
console.log("CODE " + code);
const res = await page.evaluate(async () => {
  const r = await window.__rx;
  if (!r.ok) return r;
  const hashes = {};
  const walk = async (d, pre) => {
    for await (const [n, h] of d.entries()) {
      const p = pre ? pre + "/" + n : n;
      if (h.kind === "directory") { await walk(h, p); continue; }
      const dg = new Uint8Array(await crypto.subtle.digest("SHA-256", await (await h.getFile()).arrayBuffer()));
      hashes[p] = [...dg].map((x) => x.toString(16).padStart(2, "0")).join("");
    }
  };
  await walk(await navigator.storage.getDirectory(), "");
  return { ...r, hashes };
});
console.log(JSON.stringify(res));
await browser.disconnect();
process.exit(0);
