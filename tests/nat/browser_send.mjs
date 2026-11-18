// Runs inside the NAT test container (network namespace of peer b): drives headless Chromium to
// send files to a CLI receiver behind another NAT. Prints a JSON result.
// Usage: node browser_send.mjs <page-url> <code> <stun host:port> <debug-port>
import puppeteer from "/tb/node_modules/puppeteer-core/lib/esm/puppeteer/puppeteer-core.js";

const [url, code, stun, port] = process.argv.slice(2);
let browser;
for (let i = 0; i < 100 && !browser; i++) {
  try { browser = await puppeteer.connect({ browserURL: `http://127.0.0.1:${port}`, acceptInsecureCerts: true }); }
  catch { await new Promise((r) => setTimeout(r, 200)); }
}
const page = await browser.newPage();
await page.goto(url);
const res = await page.evaluate(async (code, stun, mailboxUrl) => {
  const rnd = new Uint8Array(4_000_000);
  for (let o = 0; o < rnd.length; o += 65536) crypto.getRandomValues(rnd.subarray(o, Math.min(o + 65536, rnd.length)));
  const files = { "a.txt": new TextEncoder().encode("hi\n"), "dir/sub/rand.bin": rnd, "dir/nums.txt": new TextEncoder().encode("1\n2\n3\n".repeat(50000)) };
  const hashes = {};
  for (const [p, b] of Object.entries(files)) {
    hashes[p] = [...new Uint8Array(await crypto.subtle.digest("SHA-256", b))].map((x) => x.toString(16).padStart(2, "0")).join("");
  }
  const items = Object.entries(files).map(([p, b]) => ({ path: p, file: new File([b], p.split("/").pop()) }));
  let connected = null;
  try {
    const s = await window.wormhole.send(code, window.wormhole.buildEntries(items), (e, d) => { if (e === "connected") connected = d.type; },
      { mailboxUrl, iceServers: [{ urls: "stun:" + stun }] });
    return { ok: true, hashes, connected, secs: s.secs };
  } catch (e) {
    return { ok: false, error: e.message, connected };
  }
}, code, stun, new URL("/mailbox", url).href);
console.log(JSON.stringify(res));
await browser.disconnect();
process.exit(0);
