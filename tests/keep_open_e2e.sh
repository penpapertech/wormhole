#!/usr/bin/env bash
# A receiver that stays open: several transfers with one code, a wrong-code attempt in between,
# the code outliving the mailbox's expiry (renewal), and Ctrl+C freeing the code.
# Usage: tests/keep_open_e2e.sh [path-to-binary]
set -euo pipefail
BIN=$(realpath "${1:-target/release/wormhole}")
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT

PORT=${MAILBOX_PORT:-18182}
# Entries expire after 6s here, and the receiver renews every 2s.
TTL_SECONDS=6 python3 "$ROOT/aws/mailbox.py" --serve "$PORT" & sleep 0.5
MB="http://127.0.0.1:$PORT/"
export WORMHOLE_MAILBOX=$MB WORMHOLE_TEST_RENEW_SECS=2

mkdir -p "$W/src/dir/sub" "$W/dst"
echo one > "$W/src/one.txt"
echo two > "$W/src/two.txt"
head -c 2000000 /dev/urandom > "$W/src/dir/sub/blob.bin"

(cd "$W/dst" && exec "$BIN" receive > "$W/recv.log" 2>&1) &
RPID=$!
for _ in $(seq 1 50); do
  CODE=$(grep -oE '[0-9]+-[a-z]+-[a-z]+' "$W/recv.log" | head -1 || true)
  [ -n "$CODE" ] && break; sleep 0.2
done
[ -n "$CODE" ] || { cat "$W/recv.log"; echo "no code"; exit 1; }
NP=${CODE%%-*}
echo "code: $CODE"
send() { (cd "$W/src" && "$BIN" send "$@") > "$W/send.log" 2>&1; }
fail() { echo "FAIL: $*"; echo "--- receiver"; sed 's/\x1b\[[0-9;]*m//g' "$W/recv.log" | tail -15; echo "--- sender"; tail -5 "$W/send.log"; exit 1; }

send "$CODE" one.txt || fail "first send"
diff "$W/src/one.txt" "$W/dst/one.txt" || fail "first file"
echo "  1st transfer OK"

send "$CODE" -R two.txt dir || fail "second send"
diff -r "$W/src/dir" "$W/dst/dir" && diff "$W/src/two.txt" "$W/dst/two.txt" || fail "second files"
echo "  2nd transfer (same code) OK"

WRONG="$NP-${CODE#*-}"; WRONG="${WRONG%-*}-zzz"
if send "$WRONG" one.txt; then fail "wrong code was accepted"; fi
grep -q "wrong code" "$W/send.log" || fail "sender did not report a wrong code"
grep -q "wrong code (1 in a row)" "$W/recv.log" || fail "receiver did not report the wrong code"
echo "  wrong code rejected, receiver still running"
kill -0 $RPID || fail "receiver exited"

sleep 10  # longer than the mailbox's 6s expiry: only renewal keeps the code alive
send "$CODE" one.txt || fail "send after the expiry window"
diff "$W/src/one.txt" "$W/dst/one (1).txt" || fail "renamed duplicate"
echo "  code still valid after the expiry window (renewed); duplicate saved as 'one (1).txt'"

kill -INT $RPID
wait $RPID && rc=0 || rc=$?
[ $rc -eq 0 ] || fail "receiver exit code $rc after Ctrl+C"
grep -q "Stopped after 3 transfers" "$W/recv.log" || fail "no stop summary"
st=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' \
       -d "{\"op\":\"get\",\"np\":\"$NP\"}" "$MB")
[ "$st" = 404 ] || fail "code still registered after Ctrl+C (HTTP $st)"
echo "  Ctrl+C: exit 0, code freed in the mailbox"

# Local network only (no mailbox): the same code keeps working too.
mkdir -p "$W/dst/lan"
(cd "$W/dst" && WORMHOLE_MAILBOX=off exec "$BIN" receive -o "$W/dst/lan" > "$W/recv.log" 2>&1) &
RPID=$!
CODE=""
for _ in $(seq 1 50); do
  CODE=$(grep -oE '[0-9]+-[a-z]+-[a-z]+' "$W/recv.log" | head -1 || true)
  [ -n "$CODE" ] && break; sleep 0.2
done
WORMHOLE_MAILBOX=off send "$CODE" one.txt || fail "LAN send 1"
WORMHOLE_MAILBOX=off send "$CODE" two.txt || fail "LAN send 2"
diff "$W/src/two.txt" "$W/dst/lan/two.txt" || fail "LAN files"
kill -INT $RPID; wait $RPID || fail "LAN receiver exit"
echo "  LAN only: two transfers with one code OK"
echo "PASS"
