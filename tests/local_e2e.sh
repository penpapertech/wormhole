#!/usr/bin/env bash
# End-to-end test on one machine: receiver + sender processes, local mailbox (or MAILBOX=off for
# LAN-discovery only). Usage: tests/local_e2e.sh [path-to-binary]
set -euo pipefail
BIN=$(realpath "${1:-target/release/wormhole}")
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT

PORT=${MAILBOX_PORT:-18181}
if [ "${MAILBOX:-local}" = "local" ]; then
  python3 "$ROOT/aws/mailbox.py" --serve "$PORT" & sleep 0.5
  export WORMHOLE_MAILBOX="http://127.0.0.1:$PORT/"
else
  export WORMHOLE_MAILBOX="$MAILBOX"
fi

mkdir -p "$W/src/tree/deep/er" "$W/dst"
echo hello > "$W/src/hello.txt"
echo "spaces" > "$W/src/name with spaces.txt"
seq 1 200000 > "$W/src/tree/numbers.txt"
head -c 30000000 /dev/urandom > "$W/src/tree/deep/er/random.bin"
for i in $(seq 1 300); do echo "file $i" > "$W/src/tree/deep/small_$i.txt"; done
echo "pre-existing" > "$W/dst/hello.txt"

(cd "$W/dst" && "$BIN" receive > "$W/recv.log" 2>&1) &
RPID=$!
for _ in $(seq 1 50); do
  CODE=$(grep -oE '[0-9]+-[a-z]+-[a-z]+' "$W/recv.log" | head -1 || true)
  [ -n "$CODE" ] && break; sleep 0.2
done
[ -n "$CODE" ] || { cat "$W/recv.log"; echo "no code"; exit 1; }
echo "code: $CODE"
(cd "$W/src" && "$BIN" send "$CODE" -R hello.txt "name with spaces.txt" tree) 2>&1 | tail -3
wait $RPID
tail -3 "$W/recv.log"

diff -r "$W/src/tree" "$W/dst/tree"
diff "$W/src/hello.txt" "$W/dst/hello (1).txt"
grep -q pre-existing "$W/dst/hello.txt"
diff "$W/src/name with spaces.txt" "$W/dst/name with spaces.txt"
echo "PASS"
