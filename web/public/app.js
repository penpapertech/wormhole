import { send, receive, buildEntries, summarize, itemsFromDrop, parseCode, DEFAULT_MAILBOX } from "./wormhole.js";
import { folderSink, downloadSink, buildZip } from "./save.js";

const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
const mailboxUrl = params.get("mailbox") || DEFAULT_MAILBOX;
// ?stun=host:port[,host:port] overrides the STUN servers (self-hosting / tests).
const iceServers = params.get("stun") ? [{ urls: params.get("stun").split(",").map((h) => "stun:" + h) }] : undefined;
// The receiver prints <page>#<code>; the fragment is never sent to the server. #receive opens the
// Receive tab.
const fromHash = decodeURIComponent(location.hash.slice(1));
if (fromHash && fromHash !== "receive") { $("code").value = fromHash; history.replaceState(null, "", location.pathname + location.search); }

let items = []; // [{path, file|null}]
let busy = false;
let receiving = null; // AbortController while a receive is running

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
    const pct = summary.bytes ? (100 * summary.wire) / summary.bytes : 100;
    const ratio = pct > 0 && pct < 1 ? "<1" : Math.round(pct);
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

// --- tabs
function showTab(recv) {
  $("tabSend").setAttribute("aria-selected", String(!recv));
  $("tabRecv").setAttribute("aria-selected", String(recv));
  $("sendPanel").hidden = recv;
  $("recvPanel").hidden = !recv;
  history.replaceState(null, "", location.pathname + location.search + (recv ? "#receive" : ""));
}
$("tabSend").onclick = () => showTab(false);
$("tabRecv").onclick = () => showTab(true);
if (fromHash === "receive") showTab(true);
window.addEventListener("hashchange", () => {
  const h = decodeURIComponent(location.hash.slice(1));
  if (h === "receive") { if (!receiving && !busy) showTab(true); }
  else if (h && !busy) { $("code").value = h; showTab(false); render(); }
});

// --- receive
const canPickFolder = typeof window.showDirectoryPicker === "function";
if (!canPickFolder) {
  const o = $("optFolder");
  o.classList.add("disabled");
  o.querySelector("input").disabled = true;
  o.querySelector("small").textContent = "Not available in this browser (needs Chrome, Edge or another Chromium browser).";
  document.querySelector('input[value="download"]').checked = true;
}

function recvStatus(text, cls = "muted") {
  $("recvStatus").className = cls;
  $("recvStatus").textContent = text;
}

const senderLink = (code) => location.origin + location.pathname + location.search + "#" + code;

for (const b of document.querySelectorAll("[data-copy]")) {
  b.onclick = async () => {
    try { await navigator.clipboard.writeText($(b.dataset.copy).textContent); b.textContent = "Copied"; }
    catch { b.textContent = "Copy failed"; }
    setTimeout(() => (b.textContent = "Copy"), 1500);
  };
}

function resetReceive() {
  $("recvSetup").hidden = false;
  $("recvCodeCard").hidden = true;
  $("recvProgressCard").hidden = true;
  $("tabSend").disabled = false;
}

$("recvStart").onclick = async () => {
  const mode = document.querySelector('input[name="dest"]:checked').value;
  let sink;
  if (mode === "folder") {
    try {
      sink = folderSink(await window.showDirectoryPicker({ id: "wormhole-receive", mode: "readwrite" }));
    } catch (e) {
      if (e.name !== "AbortError") recvStatus("Could not open that folder: " + e.message, "err");
      return;
    }
  } else {
    sink = downloadSink();
  }
  receiving = new AbortController();
  $("recvSetup").hidden = true;
  $("recvProgressCard").hidden = false;
  $("recvProgress").hidden = true;
  $("recvCancel").hidden = false;
  $("recvAgain").hidden = true;
  $("tabSend").disabled = true;
  recvStatus("Starting…");
  try {
    const s = await receive(sink, (ev, d) => {
      if (ev === "status") recvStatus(d);
      if (ev === "code") {
        $("codeOut").textContent = d;
        $("cmdOut").textContent = `wormhole send ${d} <files…>`;
        $("linkOut").textContent = $("linkOut").href = senderLink(d);
        $("recvCodeCard").hidden = false;
      }
      if (ev === "connected") { $("recvCodeCard").hidden = true; recvStatus(`Connected (${d.type})`); }
      if (ev === "offer") {
        $("recvCancel").hidden = true; // can't cancel mid-stream cleanly yet; closing the tab works
        $("recvProgress").hidden = false;
        $("recvFill").style.width = "0";
        recvStatus(`Receiving ${d.files} file${d.files === 1 ? "" : "s"} (${human(d.bytes)})…`);
      }
      if (ev === "progress") {
        $("recvFill").style.width = Math.min(100, (100 * d.done) / Math.max(1, d.total)).toFixed(1) + "%";
        const rate = d.secs > 0.2 ? ` · ${human(d.done / d.secs)}/s` : "";
        $("recvMeta").textContent = `${human(Math.min(d.done, d.total))} / ${human(d.total)}${rate}`;
      }
    }, { mailboxUrl, ...(iceServers && { iceServers }), signal: receiving.signal });
    $("recvFill").style.width = "100%";
    const where = s.sink === "folder" ? ` into “${sink.name}”` : s.download ? ` — downloaded as ${s.download.name}` : "";
    recvStatus(`✔ Received ${s.files} file${s.files === 1 ? "" : "s"} (${human(s.bytes)}) in ${s.secs.toFixed(1)}s${where}. Saved as: ${s.saved.join(", ")}`, "ok");
  } catch (err) {
    $("recvCodeCard").hidden = true;
    recvStatus(err.message === "Cancelled" ? "Cancelled." : "✘ " + err.message, err.message === "Cancelled" ? "muted" : "err");
  } finally {
    receiving = null;
    $("recvCancel").hidden = true;
    $("recvAgain").hidden = false;
    $("tabSend").disabled = false;
  }
};
$("recvCancel").onclick = () => receiving?.abort();
$("recvAgain").onclick = resetReceive;
window.addEventListener("beforeunload", (e) => { if (receiving || busy) e.preventDefault(); });

render();
// Hook for automated tests.
window.wormhole = { send, receive, buildEntries, folderSink, downloadSink, buildZip, iceServers };
