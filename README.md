# wormhole

Send files and folders between two computers using a short one-time code. It works even when both
computers are behind NAT. Everything ships as **one self-contained binary** for macOS and Linux.

```
computer A $ wormhole receive
  Wormhole code:  42-maple-sunset
  On the other computer run:
      wormhole send 42-maple-sunset <files…>
  or send from a browser:
      https://penpapertech.github.io/wormhole/#42-maple-sunset

computer B $ wormhole send 42-maple-sunset -R *
  Connected to 81.2.69.160:52811 (direct over the internet)
  ████████████████████████████████ 1.2 GiB/1.2 GiB 48 MiB/s
  ✔ Sent 1342 files (1.2 GiB) in 26.0s — 47 MiB/s, 610 MiB on the wire (compressed to 51%)
```

- **Peer to peer.** File data goes straight from one machine to the other over an encrypted QUIC
  connection, and no server ever stores or relays it.
- **NAT traversal.** UDP hole punching (STUN + simultaneous probes) works through typical home and
  office routers.
- **LAN discovery.** On the same network the peers find each other by broadcast or multicast,
  even with no internet connection.
- **Compressed and auto-extracted.** Files and folders are streamed as `tar | zstd` and unpacked on
  the fly into the receiver's current folder. Existing files are never overwritten (`a.txt`
  becomes `a (1).txt`).
- **Secure with a short code.** SPAKE2 (a password-authenticated key exchange) turns the
  `42-maple-sunset` code into a strong key, bound to the TLS session. An attacker gets one guess,
  and a failed guess aborts the transfer.
- **TUI or CLI.** Run `wormhole` with no arguments for an interactive UI where you can drag and
  drop files onto the terminal window, or script it with `receive` and `send`.
- **Works in a browser too.** The [web page](https://penpapertech.github.io/wormhole/) can send to
  and receive from the CLI or another browser, with nothing to install. Drag files or folders in to
  send. To receive, the page shows a code and either writes straight into a folder you pick
  (Chrome, Edge) or offers a download (a single file, or a .zip). Data goes peer to peer over
  WebRTC.

## Install

### Homebrew (macOS and Linux)

```sh
brew install penpapertech/tap/wormhole
```

Update with `brew upgrade`. Use the full name: a plain `brew install wormhole` installs an
unrelated app with the same name. Homebrew installs skip the macOS "unidentified developer" warning.

### Manual download

Prebuilt binaries are on the [Releases](https://github.com/penpapertech/wormhole/releases) page.
Each is a single file with no dependencies. Pick your platform:

| Platform | Download |
|---|---|
| macOS, Apple Silicon (M1 and later) | `wormhole-macos-arm64.tar.gz` |
| macOS, Intel | `wormhole-macos-x86_64.tar.gz` |
| Linux, x86_64 (most PCs and servers) | `wormhole-linux-x86_64.tar.gz` |
| Linux, ARM64 (Raspberry Pi 4/5 with a 64-bit OS, Graviton, Ampere) | `wormhole-linux-aarch64.tar.gz` |

Not sure which one? Run `uname -sm`: `Darwin arm64` is Apple Silicon, `Darwin x86_64` is an
Intel Mac, `Linux x86_64` is Linux x86_64, `Linux aarch64` is Linux ARM64.

#### macOS

```sh
# Apple Silicon (use wormhole-macos-x86_64 on an Intel Mac)
curl -fsSL https://github.com/penpapertech/wormhole/releases/latest/download/wormhole-macos-arm64.tar.gz | tar xz
sudo mv wormhole /usr/local/bin/
wormhole --help
```

The binary isn't signed by Apple. If you downloaded it with a browser instead of `curl`, macOS
blocks it on first run ("cannot be opened because the developer cannot be verified"). Clear the
quarantine flag once:

```sh
xattr -d com.apple.quarantine /usr/local/bin/wormhole
```

The first time it runs, macOS may ask to let your terminal access the local network. Allow it;
it's needed to find the other computer when both are on the same Wi-Fi.

#### Linux

```sh
# x86_64 (use wormhole-linux-aarch64 on ARM64)
curl -fsSL https://github.com/penpapertech/wormhole/releases/latest/download/wormhole-linux-x86_64.tar.gz | tar xz
mkdir -p ~/.local/bin && mv wormhole ~/.local/bin/
wormhole --help
```

The Linux builds are statically linked (musl), so they run on any distribution, including Alpine
and old glibc systems. If `wormhole` isn't found, add `~/.local/bin` to your `PATH`, or move the
binary to `/usr/local/bin` with `sudo` instead.

#### Verify the download (optional)

Each archive has a `.sha256` file next to it:

```sh
curl -fsSLO https://github.com/penpapertech/wormhole/releases/latest/download/wormhole-linux-x86_64.tar.gz
curl -fsSLO https://github.com/penpapertech/wormhole/releases/latest/download/wormhole-linux-x86_64.tar.gz.sha256
shasum -a 256 -c wormhole-linux-x86_64.tar.gz.sha256    # or: sha256sum -c …
```

### Windows

There's no native Windows build. Use the [web page](https://penpapertech.github.io/wormhole/) in
Chrome or Edge, which can send to and receive from the CLI, or run the Linux x86_64 build under
WSL.

### From source

With a [Rust toolchain](https://rustup.rs) (stable):

```sh
cargo install --git https://github.com/penpapertech/wormhole
```

This puts `wormhole` in `~/.cargo/bin`.

### Updating and uninstalling

With Homebrew, `brew upgrade` and `brew uninstall wormhole`. Otherwise, to update, repeat the
install commands (`latest` always points at the newest release), and to uninstall, delete the binary (`/usr/local/bin/wormhole`, `~/.local/bin/wormhole` or
`~/.cargo/bin/wormhole`). wormhole keeps no config files or caches.

## Usage

| Command | What it does |
|---|---|
| `wormhole` | Interactive TUI: *Receive* shows a code; *Send* lets you type the code and drag files in |
| `wormhole receive` (`r`) | Print a code, wait, save into the current folder (`-o DIR` to choose) |
| `wormhole send CODE FILE…` (`s`) | Send files; add `-R` for folders, e.g. `wormhole send CODE -R *` |
| `wormhole send CODE` | Open the TUI send screen with the code filled in, then drop files |
| [web page](https://penpapertech.github.io/wormhole/) | Send from a browser, or open *Receive* to get a code there (`wormhole send CODE …` works with it) |

Options and environment variables:

- `--mailbox URL` / `WORMHOLE_MAILBOX` sets a different rendezvous mailbox. Use `off` for LAN only.
- `WORMHOLE_STUN=host:port,…` sets the STUN servers (default: Google and Cloudflare).
- `WORMHOLE_ZSTD_LEVEL` sets the compression level (default 3, range 1–19).
- `wormhole receive --no-webrtc` doesn't offer the browser transport.
- The web page accepts `?mailbox=URL` and `?stun=host:port` for self-hosting.

## How it works

```
 receiver                          mailbox (AWS Lambda+DynamoDB)                    sender
    │ STUN → learn public ip:port            │                                        │
    │ claim nameplate 42, post addrs ───────►│                                        │
    │ show code 42-maple-sunset              │◄──────── get 42, post own addrs        │
    │◄───────── poll: sender addrs           │                                        │
    │◄═════════════ UDP probes both ways (hole punching) / LAN broadcast ════════════►│
    │◄═════════════ QUIC (TLS 1.3) on the same UDP socket ═══════════════════════════►│
    │◄═════════════ SPAKE2(code) + HMAC over TLS exporter → mutual authentication ═══►│
    │◄═════════════ tar | zstd stream, extracted on the fly ═════════════════════════│
```

1. Each side binds a single UDP socket and asks STUN servers for its public address.
2. The receiver claims a random **nameplate** (the number in the code) in the mailbox and posts
   its candidate addresses, both LAN and public. The sender looks the nameplate up and posts its
   own. The mailbox entry expires after 30 minutes and is deleted once the peers connect.
3. Both sides send small probe packets to each other's candidates. The outgoing packets open the
   NAT mappings, and the first probe that gets through settles the address. On a LAN, a
   broadcast/multicast query on UDP port 47807 finds the receiver directly.
4. The same socket is handed to QUIC, so the NAT mappings stay valid.
5. Inside QUIC, both sides run **SPAKE2** with the full code as the password. Each side proves it
   holds the resulting key with an HMAC over the TLS exporter secret, which defeats a
   man-in-the-middle.
6. The sender streams `tar | zstd` over a QUIC stream. The receiver decompresses and extracts as
   data arrives, rejects unsafe paths (`..`, absolute paths, links), and confirms.

**What the mailbox sees:** the nameplate number, the IP:port candidates and the WebRTC offer and
answer (which contain the same addresses), for a few minutes. It never sees the code words, the
key or any file data.

### Browsers (WebRTC)

A browser can't open raw UDP sockets, so `wormhole receive` listens on **two transports at once**
and uses whichever sender authenticates first:

```
 wormhole receive                                mailbox                     sender
   ├─ QUIC socket: STUN + addresses ─────┐
   ├─ WebRTC: offer (SDP + ICE cands) ───┴──► claim 42 ──► wormhole CLI: addrs → QUIC (above)
   │                                                   └─► browser: reads offer → posts answer
   │◄════════ ICE (STUN, hole punching) + DTLS + SCTP data channel ═══════════════════►│
   │◄════════ SPAKE2(code) + HMAC over both DTLS fingerprints ════════════════════════►│
   │◄════════ tar | gzip (the browser's built-in CompressionStream), extracted on the fly ══│
```

- The receiver creates its WebRTC offer up front and posts it next to its QUIC addresses, so a
  browser needs only one round trip: it reads the offer and posts an answer.
- **Browser as receiver:** the page posts only a WebRTC offer. `wormhole send` sees that, answers
  it, and streams `tar | gzip` (browsers can't decode zstd). The page extracts on the fly with
  the same path safety rules as the CLI, and never overwrites (`name (1).ext`). A browser sender
  doesn't care whether the receiver is a CLI or another browser.
- The CLI side uses [str0m](https://github.com/algesten/str0m) with pure-Rust crypto, so the
  binary stays self-contained.
- The page runs the **same SPAKE2 crate** compiled to WebAssembly (`web/spake2-wasm`, 48 KB). The
  HMAC confirmation covers both DTLS certificate fingerprints, so swapping the offer or answer in
  the mailbox can't be used to sit in the middle.
- The page is static (`web/public`), hosted on GitHub Pages, and never touches file data.
- **Speed:** WebRTC data channels are slower than QUIC. On one machine, browser → CLI and
  CLI → browser both reach about 50–70 MB/s, versus several hundred MB/s for CLI ↔ CLI. Over the
  internet, both are usually limited by the connection itself. The CLI paces its packets and
  sizes its send window from the measured round-trip time, because the SCTP library it uses
  stalls for a second after burst losses.
- **Browsers:** tested with Chromium. Firefox (113+) and Safari (16.4+) have every API used, but
  haven't been tested yet. Saving into a folder needs the File System Access API (Chrome, Edge);
  other browsers receive into memory and download at the end (a .zip up to 4 GB).

### Limitations

- **No relay.** If both peers are behind *symmetric* NATs (some corporate networks, carrier-grade
  NAT on mobile), or one is symmetric and the other is a strict cone NAT, a direct path cannot be
  punched. The sender then gets a clear error after about 25 seconds. A relay fallback would fix
  this and could be added later.
- IPv4 only for now.

## Running your own mailbox

The mailbox is a ~200-line Python Lambda (`aws/mailbox.py`) with a public function URL (CORS
enabled for the web sender) and a DynamoDB table with TTL. To deploy it to your AWS account
(idempotent):

```sh
aws/deploy.sh                       # prints the mailbox URL
WORMHOLE_MAILBOX_URL=<url> cargo build --release   # bake it in as the default
```

**Cost:** it stays within the AWS always-free tier for normal use. Each transfer makes a handful
of Lambda calls, and the receiver polls about once a second while waiting. The table uses small
*provisioned* capacity (10 RCU / 5 WCU, inside the free 25/25), so if someone hammers the public
endpoint, DynamoDB throttles instead of billing more. Logs are kept for 3 days.

For testing you can run the same code locally with an in-memory store:
`python3 aws/mailbox.py --serve 8080`, then `wormhole --mailbox http://127.0.0.1:8080/ …`.

## Testing

```sh
cargo test                               # unit tests (codes, STUN parsing, tar/zstd roundtrip, path safety, drag & drop parsing)
tests/local_e2e.sh                       # two processes on one machine, local mailbox, 300+ files
MAILBOX=off tests/local_e2e.sh           # LAN discovery only
python3 tests/tui_smoke.py target/release/wormhole   # drives the TUI through a pty (paste/drop, send & receive)

web/build.sh && (cd tests/browser && npm install)    # once, for the browser tests
node tests/browser/browser_e2e.mjs       # headless Chromium (in docker) ↔ CLI and browser ↔ browser: folders, long/unicode names, zip, UI, wrong code, throughput
MAILBOX_URL=<deployed url> node tests/browser/browser_e2e.mjs   # same, against a real mailbox
tests/nat/run.sh                         # Docker: peers behind simulated home-router NATs (needs docker)
```

The NAT test builds this topology inside one privileged container using network namespaces. The
routers use Linux `MASQUERADE` and drop unsolicited inbound packets, like a typical home router.
It checks: cone↔cone in both directions (hole punching), same LAN, LAN-only without a mailbox,
**a browser behind one NAT sending to a CLI behind another, and the reverse** (WebRTC), and that symmetric-NAT
cases fail cleanly.

## License

MIT
