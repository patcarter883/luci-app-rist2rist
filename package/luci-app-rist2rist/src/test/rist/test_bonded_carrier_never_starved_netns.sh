#!/bin/bash
# librist. Copyright © 2026 SipRadius LLC.
# SPDX-License-Identifier: BSD-2-Clause
#
# Regression for the RTT-mute / stall "no carrier" starvation. The sender pulls
# a leg from the payload rotation for two independent reasons: RTT-mute (leg RTT
# over the ceiling) and stall (leg gone silent on its return path). Each check
# keeps at least one leg out of its OWN mechanism, but they run independently:
# one leg muted for high RTT PLUS its only sibling stalled for silence leaves
# the balancer with zero carriers, and it then drops the payload. The receiver
# starves on both legs at once even though one leg is still perfectly able to
# deliver (just late).
#
# This drives exactly that split on a two-leg bonded caller, in sequence so the
# mute genuinely fires before the stall:
#   1. leg A (ca): +300 ms each way -> smoothed RTT ~600 ms > rtt-drop=400, and
#      with leg B still healthy it is actually MUTED (its share moves to B).
#   2. leg B (cb): 100% loss both ways -> silent on its return path -> STALLED.
#      Now A is muted and B is stalled: the balancer has no carrier.
# The buffer is large (6 s) so the liveness timeout (~12 s) does not tear leg B
# down during the window: it stays authenticated-but-stalled, holding the split.
#
# Before the fix both legs were skipped and the receiver's per-interval
# "received" collapsed to ~0 (only the muted leg's 1-in-100 trickle). After it,
# the muted leg is kept as the sole carrier and data keeps flowing, late but
# continuous.
#
# Needs real interfaces + tc, so it runs only on Linux as root with netns/tc and
# SKIPs (77) otherwise.
#
# Usage:   test_bonded_carrier_never_starved_netns.sh <ristsender> <ristreceiver>
# Exit:    0 = a carrier survived the muted+stalled split (fixed)
#          1 = receiver starved on both legs at once (regression)
#          77 = SKIP (needs Linux root + netns + tc)
#          99 = setup error / INDETERMINATE (the split did not form)
set -u

TX="${1:-}"
RX="${2:-}"
USER=carrieruser; PASS=carrierpass; CN=testcn
RXIP=10.0.2.61
NS=rist_carrier_snd
RXLOG="$(mktemp)"; TXLOG="$(mktemp)"

skip()  { echo "SKIP: $*"; cleanup 2>/dev/null; exit 77; }
setup_err() { echo "SETUP ERROR: $*"; cleanup 2>/dev/null; exit 99; }

cleanup() {
  ip netns del "$NS" 2>/dev/null
  ip link del veth-ca 2>/dev/null
  ip link del veth-cb 2>/dev/null
  ip link del cbr0   2>/dev/null
  [ -n "${TXPID:-}" ] && kill "$TXPID" 2>/dev/null
  [ -n "${RXPID:-}" ] && kill "$RXPID" 2>/dev/null
  [ -n "${FEEDPID:-}" ] && kill "$FEEDPID" 2>/dev/null
  rm -f "$RXLOG" "$TXLOG" 2>/dev/null
}
trap cleanup EXIT

# ---- environment gate: skip cleanly where we cannot reproduce ----------
[ "$(uname -s)" = "Linux" ] || skip "not Linux"
[ "$(id -u)" = "0" ] || skip "needs root (CAP_NET_ADMIN) for netns/veth/tc"
[ -n "$TX" ] && [ -x "$TX" ] || setup_err "ristsender not found ($TX)"
[ -n "$RX" ] && [ -x "$RX" ] || setup_err "ristreceiver not found ($RX)"
command -v ip >/dev/null 2>&1 || skip "iproute2 'ip' missing"
command -v tc >/dev/null 2>&1 || skip "iproute2 'tc' missing"
ip netns add "$NS" 2>/dev/null || skip "cannot create netns (no CAP_NET_ADMIN?)"

# ---- topology: bridge in root ns, two veth legs into a sender netns -----
ip link add cbr0 type bridge                        || setup_err "bridge add"
ip addr add ${RXIP}/24 dev cbr0                      || setup_err "bridge addr"
ip link set cbr0 up                                  || setup_err "bridge up"

ip link add veth-ca type veth peer name ca           || setup_err "veth-ca"
ip link add veth-cb type veth peer name cb           || setup_err "veth-cb"
ip link set veth-ca master cbr0; ip link set veth-ca up
ip link set veth-cb master cbr0; ip link set veth-cb up
ip link set ca netns "$NS"; ip link set cb netns "$NS"
ip netns exec "$NS" ip addr add 10.0.2.30/24 dev ca
ip netns exec "$NS" ip addr add 10.0.2.131/24 dev cb
ip netns exec "$NS" ip link set ca up
ip netns exec "$NS" ip link set cb up
ip netns exec "$NS" ip link set lo up
# same-subnet multi-homing: disable rp_filter so miface egress is kept
ip netns exec "$NS" sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec "$NS" sysctl -qw net.ipv4.conf.ca.rp_filter=0
ip netns exec "$NS" sysctl -qw net.ipv4.conf.cb.rp_filter=0
sysctl -qw net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1

ip netns exec "$NS" ping -c1 -W2 -I ca ${RXIP} >/dev/null 2>&1 || skip "leg A no connectivity"
ip netns exec "$NS" ping -c1 -W2 -I cb ${RXIP} >/dev/null 2>&1 || skip "leg B no connectivity"

# ---- receiver: listener, advanced profile, SRP authenticator -----------
# 6 s buffer keeps the liveness timeout (~2x buffer) well above the ~8 s
# impairment, so leg B stays authenticated-but-stalled. -S 500 gives fine
# stats sampling for the received-per-interval measurement below.
$RX -p 2 -v 6 -S 500 \
  -i "rist://@${RXIP}:2041?username=${USER}&password=${PASS}&buffer=6000" \
  -o "udp://127.0.0.1:12356" >"$RXLOG" 2>&1 &
RXPID=$!
sleep 1

# udp feeder inside the sender netns -> ristsender input (~50 pkt/s)
ip netns exec "$NS" bash -c 'while :; do printf "RISTTESTPACKET%08d" $RANDOM > /dev/udp/127.0.0.1/5567; sleep 0.02; done' &
FEEDPID=$!
sleep 0.5

# ---- sender: bonded caller, two SRP legs with RTT auto-mute configured --
RTTQS="rtt-drop=400&rtt-restore=200&rtt-drop-settle=1000&rtt-drop-trickle=100"
ip netns exec "$NS" $TX -p 2 -v 6 \
  -i "udp://@127.0.0.1:5567" \
  -o "rist://${RXIP}:2041?miface=ca&weight=5&username=${USER}&password=${PASS}&cname=${CN}&buffer=6000&${RTTQS},rist://${RXIP}:2041?miface=cb&weight=5&username=${USER}&password=${PASS}&cname=${CN}&buffer=6000&${RTTQS}" \
  >"$TXLOG" 2>&1 &
TXPID=$!

echo "== warmup 12s (both legs authenticate + stream) =="
sleep 12
auths_setup=$(grep -c "Successfully authenticated" "$RXLOG")
echo "after warmup: successful auths=${auths_setup}"
if [ "$auths_setup" -lt 2 ]; then
  echo "INDETERMINATE: both legs did not authenticate before the impairment."
  exit 99
fi

echo "== step 1: leg A (ca) +300ms each way -> RTT over ceiling, mutes (B healthy) =="
ip netns exec "$NS" tc qdisc add dev ca root netem delay 300ms || setup_err "tc add ca"
tc qdisc add dev veth-ca root netem delay 300ms               || setup_err "tc add veth-ca"
sleep 4   # RTT ramp + drop-settle: leg A actually mutes while B still carries

echo "== step 2: leg B (cb) 100% loss both ways -> stalls; A must be kept carrier =="
ip netns exec "$NS" tc qdisc add dev cb root netem loss 100%  || setup_err "tc add cb"
tc qdisc add dev veth-cb root netem loss 100%                 || setup_err "tc add veth-cb"

echo "== let the split form (3s) =="
sleep 3
rx_off=$(wc -l < "$RXLOG")

echo "== measure received-per-interval for 6s while muted+stalled =="
sleep 6

# ---- teardown impairment; observe recovery briefly ----------------------
ip netns exec "$NS" tc qdisc del dev ca root 2>/dev/null
tc qdisc del dev veth-ca root 2>/dev/null
ip netns exec "$NS" tc qdisc del dev cb root 2>/dev/null
tc qdisc del dev veth-cb root 2>/dev/null

# ---- INDETERMINATE guard: the muted+stalled split must actually form -----
muted=$(grep -c "over .*ceiling" "$TXLOG")
stalled=$(grep -c "stalled: silent" "$TXLOG")
echo "== split check: mute events=${muted}, stall events=${stalled} =="
if [ "$muted" -eq 0 ] || [ "$stalled" -eq 0 ]; then
  echo "INDETERMINATE: impairment did not produce a muted+stalled split"\
       "(mute=${muted}, stall=${stalled}); cannot judge the carrier guard."
  exit 99
fi

# ---- verdict: with both legs pulled, did the receiver keep getting data? -
# Per-interval flow "received" over the measurement window. Streaming ~50 pkt/s
# at -S 500 is ~25/interval when a carrier survives; starvation leaves only the
# muted leg's 1-in-100 trickle, i.e. ~0.
window=$(tail -n +"$((rx_off + 1))" "$RXLOG" | grep '"receiver-stats"')
intervals=$(printf '%s\n' "$window" | grep -c '"received"')
ok=$(printf '%s\n' "$window" | grep -o '"received":[0-9]*' \
       | grep -o '[0-9]*' | awk '$1 >= 10 {c++} END {print c+0}')
maxrx=$(printf '%s\n' "$window" | grep -o '"received":[0-9]*' \
       | grep -o '[0-9]*' | sort -n | tail -1)
echo "== during split: ${intervals} stats intervals, ${ok} with received>=10,"\
     "peak received/interval=${maxrx:-0} =="

if [ "${intervals:-0}" -lt 3 ]; then
  echo "INDETERMINATE: too few receiver-stats samples in the window"\
       "(${intervals}); cannot judge starvation."
  exit 99
fi
if [ "${ok:-0}" -lt 3 ]; then
  echo "FAIL: receiver starved during the muted+stalled split"\
       "(${ok}/${intervals} intervals carried data, peak ${maxrx:-0}/interval);"\
       "both legs were pulled and the payload was dropped."
  exit 1
fi

echo "PASS: a carrier survived the muted+stalled split"\
     "(${ok}/${intervals} intervals carried data, peak ${maxrx}/interval);"\
     "data kept flowing on the reinstated leg instead of starving."
exit 0
