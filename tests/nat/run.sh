#!/usr/bin/env bash
# NAT traversal test. Runs one privileged Docker container that builds, with network namespaces:
#
#     peer a, a2 ── lan 10.10.1.0/24 ── nat_a ─┐
#                                              ├── "internet" 10.99.0.0/24 (STUN + mailbox)
#     peer b     ── lan 10.10.2.0/24 ── nat_b ─┘
#
# Routers masquerade (like home routers) and drop unsolicited inbound packets.
# Usage: tests/nat/run.sh [binary]   (binary must run in an ubuntu:24.04 container on this arch)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
BIN=$(realpath "${1:-$ROOT/target/release/wormhole}")
docker build -q -t wormhole-nat-test "$HERE" >/dev/null
exec docker run --rm --privileged \
  -v "$HERE:/t:ro" -v "$ROOT/aws:/aws:ro" -v "$BIN:/usr/local/bin/wormhole:ro" \
  wormhole-nat-test bash /t/inside.sh
