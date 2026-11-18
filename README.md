# wormhole

Send files and folders between two computers using a short one-time code. It works even when both
computers are behind NAT. Everything ships as **one self-contained binary** for macOS and Linux.

```
computer A $ wormhole receive
  Wormhole code:  42-maple-sunset
  On the other computer run:
      wormhole send 42-maple-sunset <files…>

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

## Install

Download a binary from [Releases](https://github.com/andykcheng/wormhole/releases) (Linux
x86_64/aarch64 static musl builds, macOS arm64/x86_64), or build from source:

```sh
cargo install --git https://github.com/andykcheng/wormhole
```

On macOS, a downloaded binary may be quarantined. Run `xattr -d com.apple.quarantine wormhole`.
The first time it runs, macOS may also ask to allow your terminal to access the local network
(needed for LAN discovery).

## Usage

| Command | What it does |
|---|---|
| `wormhole` | Interactive TUI: *Receive* shows a code; *Send* lets you type the code and drag files in |
| `wormhole receive` (`r`) | Print a code, wait, save into the current folder (`-o DIR` to choose) |
| `wormhole send CODE FILE…` (`s`) | Send files; add `-R` for folders, e.g. `wormhole send CODE -R *` |
| `wormhole send CODE` | Open the TUI send screen with the code filled in, then drop files |

Options and environment variables:

- `--mailbox URL` / `WORMHOLE_MAILBOX` sets a different rendezvous mailbox. Use `off` for LAN only.
- `WORMHOLE_STUN=host:port,…` sets the STUN servers (default: Google and Cloudflare).
- `WORMHOLE_ZSTD_LEVEL` sets the compression level (default 3, range 1–19).

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

**What the mailbox sees:** the nameplate number and the IP:port candidates, for a few minutes. It
never sees the code words, the key or any file data.

### Limitations

- **No relay.** If both peers are behind *symmetric* NATs (some corporate networks, carrier-grade
  NAT on mobile), or one is symmetric and the other is a strict cone NAT, a direct path cannot be
  punched. The sender then gets a clear error after about 25 seconds. A relay fallback would fix
  this and could be added later.
- IPv4 only for now.

## Running your own mailbox

The mailbox is a ~150-line Python Lambda (`aws/mailbox.py`) with a public function URL and a
DynamoDB table with TTL. To deploy it to your AWS account (idempotent):

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
tests/nat/run.sh                         # Docker: peers behind simulated home-router NATs (needs docker)
```

The NAT test builds this topology inside one privileged container using network namespaces. The
routers use Linux `MASQUERADE` and drop unsolicited inbound packets, like a typical home router.
It checks: cone↔cone in both directions (hole punching), same LAN, LAN-only without a mailbox, and
that symmetric-NAT cases fail cleanly.

## License

MIT
