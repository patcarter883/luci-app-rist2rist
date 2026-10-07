#!/bin/bash
# librist. Copyright © 2026 SipRadius LLC.
# SPDX-License-Identifier: BSD-2-Clause
#
# Companion to test_bonded_leg_flap_netns.sh (issue #224). That test silences a
# bonded leg long enough to exceed the liveness timeout and asserts the leg tears
# down and re-handshakes. This one asserts the opposite for a SHORT stall: a leg
# that goes silent for less than the liveness timeout must be fast-muted but kept
# authenticated and resume on the SAME session, with no re-auth churn.
#
# Setup mirrors the #224 test: a bonded EAP-SRP caller with two legs to one
# listening receiver, one leg silenced (100% loss both ways, interface UP so the
# source tuple persists) while the other keeps the bond alive. The difference is
# the buffer: large, so the liveness timeout (max of session_timeout and twice
# the buffer) is ~12 s, well above the 6 s silence.
#
# Before routing and session lifetime were split, any silence past the (then
# 250 ms) liveness timeout tore the leg down and forced a cold re-handshake. Now:
#   1. No sender EAP reset  ("reset EAP and re-initiated the SRP" must stay 0).
#   2. No new receiver auth  (successful-auth count must not move: the leg keeps
#      its original session across the stall).
#   3. The leg is back in the weighted bond after recovery (two mifaces in the
#      final sender-stats line), proving the mute self-cleared on resume.
#
# Needs real interfaces + tc loss, so it runs only on Linux as root with
# netns/tc and SKIPs (77) otherwise.
#
# Usage:   test_bonded_leg_stall_grace_netns.sh <ristsender> <ristreceiver>
# Exit:    0 = short stall rode through on the same session (fixed)
#          1 = leg re-authenticated on a sub-grace stall (regression)
#          77 = SKIP (needs Linux root + netns + tc)   99 = setup error
set -u

TX="${1:-}"
RX="${2:-}"
USER=graceuser; PASS=gracepass; CN=testcn
RXIP=10.0.2.51
NS=rist_grace_snd
RXLOG="$(mktemp)"; TXLOG="$(mktemp)"

skip()  { echo "SKIP: $*"; cleanup 2>/dev/null; exit 77; }
setup_err() { echo "SETUP ERROR: $*"; cleanup 2>/dev/null; exit 99; }

cleanup() {
  ip netns del "$NS" 2>/dev/null
  ip link del veth-ga 2>/dev/null
  ip link del veth-gb 2>/dev/null
  ip link del gbr0   2>/dev/null
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
ip link add gbr0 type bridge                        || setup_err "bridge add"
ip addr add ${RXIP}/24 dev gbr0                      || setup_err "bridge addr"
ip link set gbr0 up                                  || setup_err "bridge up"

ip link add veth-ga type veth peer name ga           || setup_err "veth-ga"
ip link add veth-gb type veth peer name gb           || setup_err "veth-gb"
ip link set veth-ga master gbr0; ip link set veth-ga up
ip link set veth-gb master gbr0; ip link set veth-gb up
ip link set ga netns "$NS"; ip link set gb netns "$NS"
ip netns exec "$NS" ip addr add 10.0.2.20/24 dev ga
ip netns exec "$NS" ip addr add 10.0.2.122/24 dev gb
ip netns exec "$NS" ip link set ga up
ip netns exec "$NS" ip link set gb up
ip netns exec "$NS" ip link set lo up
# same-subnet multi-homing: disable rp_filter so miface egress is kept
ip netns exec "$NS" sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec "$NS" sysctl -qw net.ipv4.conf.ga.rp_filter=0
ip netns exec "$NS" sysctl -qw net.ipv4.conf.gb.rp_filter=0
sysctl -qw net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1

ip netns exec "$NS" ping -c1 -W2 -I ga ${RXIP} >/dev/null 2>&1 || skip "leg A no connectivity"
ip netns exec "$NS" ping -c1 -W2 -I gb ${RXIP} >/dev/null 2>&1 || skip "leg B no connectivity"

# ---- receiver: listener, advanced profile, SRP authenticator -----------
# Large buffer so the re-auth grace (~2x buffer) is ~12 s, comfortably above
# the 6 s stall below.
$RX -p 2 -v 6 \
  -i "rist://@${RXIP}:2031?username=${USER}&password=${PASS}&buffer=6000" \
  -o "udp://127.0.0.1:12346" >"$RXLOG" 2>&1 &
RXPID=$!
sleep 1

# udp feeder inside the sender netns -> ristsender input
ip netns exec "$NS" bash -c 'while :; do printf "RISTTESTPACKET%08d" $RANDOM > /dev/udp/127.0.0.1/5557; sleep 0.02; done' &
FEEDPID=$!
sleep 0.5

# ---- sender: bonded caller, two SRP legs (same cname + creds) ----------
ip netns exec "$NS" $TX -p 2 -v 6 \
  -i "udp://@127.0.0.1:5557" \
  -o "rist://${RXIP}:2031?miface=ga&weight=10&username=${USER}&password=${PASS}&cname=${CN}&buffer=6000,rist://${RXIP}:2031?miface=gb&weight=5&username=${USER}&password=${PASS}&cname=${CN}&buffer=6000" \
  >"$TXLOG" 2>&1 &
TXPID=$!

echo "== warmup 12s (both legs authenticate + stream) =="
sleep 12
auths_setup=$(grep -c "Successfully authenticated" "$RXLOG")
echo "after warmup: successful auths=${auths_setup}"
if [ "$auths_setup" -lt 2 ]; then
  echo "INDETERMINATE: both legs did not authenticate before the stall."
  exit 99
fi

echo "== stall leg B (gb): 100% loss both ways, interface UP, 6s (< grace) =="
ip netns exec "$NS" tc qdisc add dev gb root netem loss 100% || setup_err "tc add gb"
tc qdisc add dev veth-gb root netem loss 100%                || setup_err "tc add veth-gb"
sleep 6
echo "== leg B restored (same socket / same source tuple) =="
ip netns exec "$NS" tc qdisc del dev gb root 2>/dev/null
tc qdisc del dev veth-gb root 2>/dev/null
echo "== observe 15s (leg B must resume on the SAME session, no re-auth) =="
sleep 15

auths_final=$(grep -c "Successfully authenticated" "$RXLOG")
resets=$(grep -c "reset EAP and re-initiated the SRP" "$TXLOG")
last_sstats=$(grep '"sender-stats"' "$TXLOG" | tail -1)
legs_balancing=$(printf '%s' "$last_sstats" | grep -o '"miface":"[^"]*"' | sort -u | wc -l)
legs_balancing=$(printf '%s' "$legs_balancing" | tr -d ' ')
echo "== after stall: successful auths ${auths_setup} -> ${auths_final}, "\
     "sender EAP resets=${resets}, legs balancing after recovery=${legs_balancing} =="

# 1 + 2: a sub-grace stall must not tear the session down. Any sender EAP reset
# or a rise in the receiver's successful-auth count means the leg re-handshook
# instead of riding through on its existing session.
if [ "$resets" -ne 0 ] || [ "$auths_final" -ne "$auths_setup" ]; then
  echo "FAIL: a 6s stall (under the ~12s grace) forced a re-auth"\
       "(sender EAP resets=${resets}, successful auths ${auths_setup} ->"\
       "${auths_final}); the leg should have resumed on the same session."
  exit 1
fi

# 3: the muted leg self-cleared on resume and is back in the weighted bond.
if [ "${legs_balancing:-0}" -lt 2 ]; then
  echo "FAIL: leg B did not rejoin the weighted bond after the stall"\
       "(sender balances over only ${legs_balancing} leg)."
  exit 1
fi

echo "PASS: the 6s stall rode through on the same session (no EAP reset,"\
     "successful auths stayed ${auths_setup}) and leg B rejoined the bond"\
     "(${legs_balancing} legs balancing)."
exit 0
