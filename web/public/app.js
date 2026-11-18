import { send, buildEntries, summarize, itemsFromDrop, parseCode, DEFAULT_MAILBOX } from "./wormhole.js";

const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
const mailboxUrl = params.get("mailbox") || DEFAULT_MAILBOX;
// ?stun=host:port[,host:port] overrides the STUN servers (self-hosting / tests).
const iceServers = params.get("stun") ? [{ urls: params.get("stun").split(",").map((h) => "stun:" + h) }] : undefined;
// The receiver prints <page>#<code>; the fragment is never sent to the server.
const fromHash = decodeURIComponent(location.hash.slice(1));
if (fromHash) { $("code").value = fromHash; history.replaceState(null, "", location.pathname + location.search); }

let items = []; // [{path, file|null}]
let busy = false;

const human = (n) => {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + " " + u[i];
};

function addItems(newItems) {
  const existing = new Set(items.map((i) => i.path.split("/")[0]));
  const incomingTops = new Set(newItems.map((i) => i.path.split("/")[0]));
  for (const t of incomingTops) {
    if (existing.has(t)) items = items.filter((i) => i.path.split("/")[0] !== t); // replace same-named
  }
  items.push(...newItems);
  render();
}

function render() {
  const groups = new Map();
  for (const it of items) {
    const top = it.path.split("/")[0];
    const g = groups.get(top) || { dir: false, files: 0, bytes: 0 };
    if (it.path.includes("/") || !it.file) g.dir = true;
    if (it.file) { g.files++; g.bytes += it.file.size; }
    groups.set(top, g);
  }
  const ul = $("list");
  ul.replaceChildren();
  for (const [name, g] of groups) {
    const li = document.createElement("li");
    const n = document.createElement("span");
    n.className = "name";
    n.textContent = (g.dir ? "📁 " : "📄 ") + name;
    const m = document.createElement("span");
    m.className = "meta";
    m.textContent = g.dir ? `${g.files} files · ${human(g.bytes)}` : human(g.bytes);
    const rm = document.createElement("button");
    rm.textContent = "✕";
    rm.title = "Remove";
    rm.disabled = busy;
    rm.onclick = () => { items = items.filter((i) => i.path.split("/")[0] !== name); render(); };
    li.append(n, m, rm);
    ul.append(li);
  }
  const s = summarize(buildEntries(items));
  $("totals").textContent = items.length ? `${s.files} file${s.files === 1 ? "" : "s"}, ${human(s.bytes)}` : "";
  let codeOk = true;
  try { parseCode($("code").value); } catch { codeOk = false; }
  $("send").disabled = busy || !items.length || !codeOk;
}

function setStatus(text, cls = "muted") {
  $("status").className = cls;
  $("status").textContent = text;
}

// --- inputs
$("code").addEventListener("input", render);
$("pickFiles").onclick = () => $("files").click();
$("pickDir").onclick = () => $("dir").click();
$("files").onchange = (e) => { addItems([...e.target.files].map((f) => ({ path: f.name, file: f }))); e.target.value = ""; };
$("dir").onchange = (e) => { addItems([...e.target.files].map((f) => ({ path: f.webkitRelativePath || f.name, file: f }))); e.target.value = ""; };

const drop = $("drop");
for (const ev of ["dragenter", "dragover"]) {
  window.addEventListener(ev, (e) => { e.preventDefault(); if (!busy) drop.classList.add("over"); });
}
window.addEventListener("dragleave", (e) => { if (!e.relatedTarget) drop.classList.remove("over"); });
window.addEventListener("drop", async (e) => {
  e.preventDefault();
  drop.classList.remove("over");
  if (busy) return;
  const p = itemsFromDrop(e.dataTransfer); // must start synchronously
  try { addItems(await p); } catch (err) { setStatus("Could not read the dropped items: " + err.message, "err"); }
});

// --- send
$("send").onclick = async () => {
  busy = true;
  render();
  $("progress").hidden = false;
  $("fill").style.width = "0";
  $("pmeta").textContent = "";
  try {
    const entries = buildEntries(items);
    const summary = await send($("code").value, entries, (ev, d) => {
      if (ev === "status") setStatus(d);
      if (ev === "connected") setStatus(`Connected (${d.type})`);
      if (ev === "progress") {
        $("fill").style.width = Math.min(100, (100 * d.done) / d.total).toFixed(1) + "%";
        const rate = d.secs > 0.2 ? ` · ${human(d.done / d.secs)}/s` : "";
        $("pmeta").textContent = `${human(Math.min(d.done, d.total))} / ${human(d.total)}${rate}`;
      }
    }, { mailboxUrl, ...(iceServers && { iceServers }) });
    $("fill").style.width = "100%";
    const ratio = summary.bytes ? Math.round((100 * summary.wire) / summary.bytes) : 100;
    setStatus(`✔ Sent ${summary.files} file${summary.files === 1 ? "" : "s"} (${human(summary.bytes)}) in ${summary.secs.toFixed(1)}s — ` +
      `${human(summary.wire)} on the wire (compressed to ${ratio}%). Saved as: ${summary.saved.join(", ")}`, "ok");
    items = [];
    $("code").value = "";
  } catch (err) {
    setStatus("✘ " + err.message, "err");
  } finally {
    busy = false;
    render();
  }
};

render();
// Hook for automated tests.
window.wormhole = { send, buildEntries, iceServers };
