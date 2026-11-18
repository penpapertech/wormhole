#!/usr/bin/env bash
# Executed inside the privileged test container (see run.sh).
set -uo pipefail
NS() { ip netns exec "$@"; }

ip netns add wan
for n in nat_a nat_b a a2 b; do ip netns add $n; done
for n in wan nat_a nat_b a a2 b; do NS $n ip link set lo up; done

# internet: bridge in "wan" ns, which also hosts STUN + mailbox at 10.99.0.5
NS wan ip link add br0 type bridge
NS wan ip addr add 10.99.0.5/24 dev br0
NS wan ip link set br0 up

i=0
for r in a b; do
  i=$((i + 1))
  ip link add w_$r netns wan type veth peer name wan netns nat_$r
  NS wan ip link set w_$r master br0 up
  NS nat_$r ip addr add 10.99.0.1$i/24 dev wan
  NS nat_$r ip link set wan up
  NS nat_$r ip link add lan0 type bridge
  NS nat_$r ip addr add 10.10.$i.2/24 dev lan0
  NS nat_$r ip link set lan0 up
  NS nat_$r sysctl -qw net.ipv4.ip_forward=1
done

add_peer() { # peer router ip gw
  ip link add l_$1 netns $2 type veth peer name eth0 netns $1
  NS $2 ip link set l_$1 master lan0 up
  NS $1 ip addr add $3/24 dev eth0
  NS $1 ip link set eth0 up
  NS $1 ip route add default via $4
  mkdir -p /work/$1/src/dir/sub /work/$1/dst
  python3 -c "import random,sys; sys.stdout.buffer.write(random.Random(7).randbytes(5000000))" > /work/$1/src/dir/sub/rand.bin
  seq 1 100000 > /work/$1/src/dir/nums.txt
  echo hi > /work/$1/src/a.txt
}
add_peer a nat_a 10.10.1.10 10.10.1.2
add_peer a2 nat_a 10.10.1.11 10.10.1.2
add_peer b nat_b 10.10.2.10 10.10.2.2

nat_mode() { # router mode(cone|symmetric) subnet
  NS $1 iptables -t nat -F
  NS $1 iptables -F
  local extra=""
  [ "$2" = symmetric ] && extra="--random-fully"
  NS $1 iptables -t nat -A POSTROUTING -s $3 -o wan -j MASQUERADE $extra
  NS $1 iptables -A INPUT -i wan -m conntrack --ctstate NEW -j DROP
  NS $1 iptables -A FORWARD -i wan -m conntrack --ctstate NEW -j DROP
  NS $1 conntrack -F 2>/dev/null || true
}
routers() { nat_mode nat_a $1 10.10.1.0/24; nat_mode nat_b $2 10.10.2.0/24; }

NS wan python3 /t/stun_server.py 3478 3479 &
NS wan python3 /aws/mailbox.py --serve 8080 &
sleep 0.5

ENVS="WORMHOLE_MAILBOX=http://10.99.0.5:8080/ WORMHOLE_STUN=10.99.0.5:3478,10.99.0.5:3479"

transfer() { # receiver sender expect
  rm -rf /work/$1/dst/* /work/$1/recv.log
  (cd /work/$1/dst && NS $1 env $ENVS wormhole receive > /work/$1/recv.log 2>&1) &
  local rpid=$! code=""
  for _ in $(seq 1 50); do
    code=$(grep -oE '[0-9]+-[a-z]+-[a-z]+' /work/$1/recv.log 2>/dev/null | head -1)
    [ -n "$code" ] && break; sleep 0.2
  done
  local start=$(date +%s.%N)
  local out rc
  out=$(cd /work/$2/src && NS $2 env $ENVS timeout 60 wormhole send "$code" -R a.txt dir 2>&1); rc=$?
  local took=$(python3 -c "print(round($(date +%s.%N) - $start, 1))")
  echo "$out" | sed 's/\x1b\[[0-9;]*m//g' | grep -vE '^\s*$' | sed 's/^/    sender: /' | tail -3
  sleep 0.3
  kill $rpid 2>/dev/null; pkill -f "wormhole receive" 2>/dev/null; wait $rpid 2>/dev/null
  local result=fail
  if [ $rc -eq 0 ] && diff -r /work/$2/src/dir /work/$1/dst/dir >/dev/null && [ "$(cat /work/$1/dst/a.txt)" = hi ]; then
    result=pass
  fi
  if [ $result = $3 ]; then echo "  OK   (expected $3, ${took}s)"; else echo "  FAIL (expected $3, got $result)"; sed 's/^/    recv: /' /work/$1/recv.log | tail -5; FAILED=1; fi
}

FAILED=0
echo "== 1. both behind port-restricted cone NATs (typical home routers)"
routers cone cone; transfer a b pass
echo "== 2. reverse direction"
routers cone cone; transfer b a pass
echo "== 3. same LAN, behind the same NAT"
routers cone cone; transfer a a2 pass
echo "== 4. same LAN, no mailbox (LAN discovery only)"
SAVE=$ENVS; ENVS="WORMHOLE_MAILBOX=off"; transfer a a2 pass; ENVS=$SAVE
echo "== 5. one side symmetric NAT, other cone (hard case: expected to fail cleanly without a relay)"
routers symmetric cone; transfer a b fail
echo "== 6. both symmetric NATs (expected to fail cleanly without a relay)"
routers symmetric symmetric; transfer a b fail

[ $FAILED = 0 ] && echo "ALL NAT TESTS PASSED" || { echo "SOME NAT TESTS FAILED"; exit 1; }
