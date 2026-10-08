#!/bin/bash
# librist. Copyright © 2026 SipRadius LLC.
# SPDX-License-Identifier: BSD-2-Clause
#
# Regression for the bonded EAP-SRP sender-leg re-authentication bug
# (upstream issue #224).
#
# A bonded caller (sender) with EAP-SRP has two legs to one listening
# receiver.  One leg is silenced (100% packet loss BOTH ways) long enough
# for the listener to time out and purge that leg's peer, while the other
# leg keeps the bond -- and the caller process -- alive.  Crucially the
# silenced leg's interface stays UP, so its miface-bound UDP socket is
# never torn down: when the loss clears the leg resumes from the EXACT
# same source tuple, with the caller still in EAP SUCCESS.  The listener
# purged the session and now silently drops the caller's data while it
# waits for an EAPOL START the caller never sends (EAP is authenticator-
# driven and the caller believes it is still authenticated).  The leg is
# wedged forever.
#
# This is why the reproduction needs real interfaces + tc packet loss and
# cannot be an in-process loopback test: a loopback leg has no miface
# binding, so it is recreated on timeout with a fresh ephemeral port and
# self-heals with a cold handshake -- hiding the bug.  Likewise an
# "ip link set ... down" makes the sends fail and forces the same
# new-port reconnect.  Only same-tuple silence reproduces the wedge.
#
# The fix drives the caller to reset EAP and re-run the SRP handshake on
# that leg once it has been silent past session_timeout, so the leg
# re-authenticates AND rejoins the weighted bond on its own.
#
# Two discriminators (the receiver is a stable listener the whole time, so
# the flow never resets):
#   1. Successful EAP authentications.  Two legs authenticate at startup; a
#      third is only possible if the flapped leg re-authenticated on its own.
#      Before any fix it stays wedged at two and the receiver floods
#      "handshake is still pending".
#   2. Legs the sender is balancing over after recovery, counted as the
#      distinct mifaces in the final sender-stats line.  A leg only appears
#      there while it is authenticated and in the balancing rotation, so this
#      catches the reintegration defect where a leg re-authenticates but is
#      left out of balancing and streams only NACK retransmits (returns 1
#      instead of 2).
#
# Usage:   test_bonded_leg_flap_netns.sh <ristsender> <ristreceiver>
# Exit:    0 = leg re-authenticated and rejoined the bond (fixed)
#          1 = leg wedged or did not rejoin balancing (bug)
#          77 = SKIP (needs Linux root + netns + tc)   99 = setup error
set -u

TX="${1:-}"
RX="${2:-}"
USER=flapuser; PASS=flappass; CN=testcn
RXIP=10.0.1.51
NS=rist224_snd
RXLOG="$(mktemp)"; TXLOG="$(mktemp)"

skip()  { echo "SKIP: $*"; cleanup 2>/dev/null; exit 77; }
setup_err() { echo "SETUP ERROR: $*"; cleanup 2>/dev/null; exit 99; }

cleanup() {
  ip netns del "$NS" 2>/dev/null
  ip link del veth-a 2>/dev/null
  ip link del veth-b 2>/dev/null
  ip link del rbr0   2>/dev/null
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
ip link add rbr0 type bridge                        || setup_err "bridge add"
ip addr add ${RXIP}/24 dev rbr0                      || setup_err "bridge addr"
ip link set rbr0 up                                  || setup_err "bridge up"

ip link add veth-a type veth peer name sa            || setup_err "veth-a"
ip link add veth-b type veth peer name sb            || setup_err "veth-b"
ip link set veth-a master rbr0; ip link set veth-a up
ip link set veth-b master rbr0; ip link set veth-b up
ip link set sa netns "$NS"; ip link set sb netns "$NS"
ip netns exec "$NS" ip addr add 10.0.1.20/24 dev sa
ip netns exec "$NS" ip addr add 10.0.1.122/24 dev sb
ip netns exec "$NS" ip link set sa up
ip netns exec "$NS" ip link set sb up
ip netns exec "$NS" ip link set lo up
# same-subnet multi-homing: disable rp_filter so miface egress is kept
ip netns exec "$NS" sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec "$NS" sysctl -qw net.ipv4.conf.sa.rp_filter=0
ip netns exec "$NS" sysctl -qw net.ipv4.conf.sb.rp_filter=0
sysctl -qw net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1

ip netns exec "$NS" ping -c1 -W2 -I sa ${RXIP} >/dev/null 2>&1 || skip "leg A no connectivity"
ip netns exec "$NS" ping -c1 -W2 -I sb ${RXIP} >/dev/null 2>&1 || skip "leg B no connectivity"

# ---- receiver: listener, advanced profile, SRP authenticator -----------
$RX -p 2 -v 6 \
  -i "rist://@${RXIP}:2030?username=${USER}&password=${PASS}" \
  -o "udp://127.0.0.1:12345" >"$RXLOG" 2>&1 &
RXPID=$!
sleep 1

# udp feeder inside the sender netns -> ristsender input
ip netns exec "$NS" bash -c 'while :; do printf "RISTTESTPACKET%08d" $RANDOM > /dev/udp/127.0.0.1/5556; sleep 0.02; done' &
FEEDPID=$!
sleep 0.5

# ---- sender: bonded caller, two SRP legs (same cname + creds) ----------
ip netns exec "$NS" $TX -p 2 -v 6 \
  -i "udp://@127.0.0.1:5556" \
  -o "rist://${RXIP}:2030?miface=sa&weight=10&username=${USER}&password=${PASS}&cname=${CN},rist://${RXIP}:2030?miface=sb&weight=5&username=${USER}&password=${PASS}&cname=${CN}" \
  >"$TXLOG" 2>&1 &
TXPID=$!

echo "== warmup 12s (both legs authenticate + stream) =="
sleep 12
auths_setup=$(grep -c "Successfully authenticated" "$RXLOG")
echo "after warmup: successful auths=${auths_setup}"
if [ "$auths_setup" -lt 2 ]; then
  echo "INDETERMINATE: both legs did not authenticate before the flap."
  exit 99
fi

echo "== silence leg B (sb): 100% loss both ways, interface stays UP, 10s =="
ip netns exec "$NS" tc qdisc add dev sb root netem loss 100% || setup_err "tc add sb"
tc qdisc add dev veth-b root netem loss 100%                 || setup_err "tc add veth-b"
sleep 10
echo "== leg B restored (same socket / same source tuple) =="
ip netns exec "$NS" tc qdisc del dev sb root 2>/dev/null
tc qdisc del dev veth-b root 2>/dev/null
echo "== observe 28s (leg B must re-authenticate AND rejoin balancing) =="
sleep 28

auths_final=$(grep -c "Successfully authenticated" "$RXLOG")
flood=$(grep -c "handshake is still pending" "$RXLOG")
resets=$(grep -c "reset EAP and re-initiated the SRP" "$TXLOG")

# Reintegration check: the sender only lists a leg in its per-peer stats
# while that leg is authenticated and in the weighted balancing rotation, so
# the number of distinct mifaces in the final sender-stats line is the number
# of legs actually carrying balanced data.  Re-authenticating alone is not
# enough -- a leg that re-auths but is left out of balancing streams only NACK
# retransmits and never returns to its share (that was the original defect).
last_sstats=$(grep '"sender-stats"' "$TXLOG" | tail -1)
legs_balancing=$(printf '%s' "$last_sstats" | grep -o '"miface":"[^"]*"' | sort -u | wc -l)
legs_balancing=$(printf '%s' "$legs_balancing" | tr -d ' ')
echo "== after flap: successful auths ${auths_setup} -> ${auths_final}, "\
     "handshake-pending flood=${flood}, sender EAP resets=${resets}, "\
     "legs balancing after recovery=${legs_balancing} =="

# A fresh EAP authentication after the flap proves the wedged leg
# re-handshook on its own.  Without the fix the count never moves and the
# receiver floods "handshake is still pending".
if [ "$auths_final" -le "$auths_setup" ]; then
  echo "FAIL (issue #224): the flapped SRP leg never re-authenticated; it"\
       "stayed wedged in EAP SUCCESS while the listener waited for an"\
       "EAPOL START it never sent (successful auths stuck at ${auths_final},"\
       "handshake-pending flood=${flood})."
  exit 1
fi

if [ "${legs_balancing:-0}" -lt 2 ]; then
  echo "FAIL (issue #224 reintegration): the flapped leg re-authenticated"\
       "(successful auths ${auths_setup} -> ${auths_final}) but did not rejoin"\
       "the weighted bond; the sender balances over only ${legs_balancing} leg"\
       "so the returning leg carries no share."
  exit 1
fi

echo "PASS: the flapped SRP leg reset EAP, re-authenticated (successful auths"\
     "${auths_setup} -> ${auths_final}) and rejoined the weighted bond"\
     "(${legs_balancing} legs balancing) on its own."
exit 0
