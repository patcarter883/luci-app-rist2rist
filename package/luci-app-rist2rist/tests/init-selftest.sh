#!/bin/sh
# Off-device test for rist2rist.init's output-leg construction.
#
#   sh tests/init-selftest.sh
#
# What this locks in:
#
#   1. A destination is fanned out across every uplink whose interface is
#      PRESENT, one -o URL per leg. The destination itself carries only an
#      address -- the cloud POP the encoder selected -- so the encoder never has
#      to know this router's modem names.
#   2. A leg whose interface is absent must NOT reach -o. Feeding
#      miface=<absent-iface> to the binary makes librist fail the bind and the
#      peer resolve, and rist2rist.c calls exit(1), which procd turns into an
#      endless crash loop. An unplugged modem is the ordinary bench state, so it
#      has to be a non-event.
#   3. Uplinks declared but none present -> no output URLs at all -> the service
#      is NOT started, rather than started and crash-looping.
#   4. No uplinks declared at all -> send over the default route (a single-WAN box
#      needs no uplink list).
#
# No stubbing of the interface test is needed: /sys/class/net is real, so `lo`
# (present) and `wwan0` (absent on any normal machine) are the fixtures.
#
# The init is `#!/bin/sh /etc/rc.common` and defines its helpers at the top level,
# so sourcing it defines them without running procd. config_* and logger are
# stubbed; procd_* is stubbed to capture what WOULD have been started.

set -u

here=$(cd "$(dirname "$0")" && pwd)
init="$here/../files/rist2rist.init"
fails=0

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; fails=$((fails + 1)); }

# ---------------------------------------------------------------- harness -----
# config_get/config_get_bool/config_foreach read flat STUB_ keys, mirroring how
# stub-functions.sh models files/rist2rist.config for the rpcd plugin test.
config_load() { :; }
config_get() { eval "$1=\"\${STUB_${2}_${3}:-${4:-}}\""; }
config_get_bool() { eval "$1=\"\${STUB_${2}_${3}:-${4:-0}}\""; }

config_foreach() {
    local cb="$1" type="$2" n i
    case "$type" in
        destination)
            n="${STUB_DEST_COUNT:-0}"
            i=0
            while [ "$i" -lt "$n" ]; do
                eval "STUB_destination_${i}_address=\${STUB_DEST_${i}_ADDR:-}"
                # config_foreach passes the section NAME, which config_get keys on.
                "$cb" "destination_${i}"
                i=$((i + 1))
            done
            ;;
        uplink)
            n="${STUB_UPLINK_COUNT:-0}"
            i=0
            while [ "$i" -lt "$n" ]; do
                eval "STUB_uplink_${i}_interface=\${STUB_UP_${i}_IFACE:-}"
                eval "STUB_uplink_${i}_weight=\${STUB_UP_${i}_WEIGHT:-}"
                "$cb" "uplink_${i}"
                i=$((i + 1))
            done
            ;;
    esac
}

# Capture procd's intent instead of starting anything.
STARTED_CHILD=""
procd_open_instance() { STARTED_CHILD=""; }
procd_set_param() { :; }
procd_append_param() {
    # Only the -o argument (the assembled output leg list) matters here.
    [ "$1" = "command" ] && [ "$2" = "-o" ] && STARTED_CHILD="$3"
    return 0
}
procd_close_instance() { :; }

# Capture the notices, so "why nothing was sent" can be asserted rather than
# assumed.
LOG=""
logger() {
    case "$*" in
        *rist2rist*) LOG="${LOG}$*
" ;;
    esac
}
uci() { echo "80"; }

# shellcheck disable=SC1090
. "$init"

# ------------------------------------------------------------- the tests ------
echo "rist2rist.init: destination fan-out across local uplinks"

STUB_main_listen_url="rist://@0.0.0.0:5000"
STUB_main_enabled="1"

run_case() {
    OUTPUT_URLS=""
    OUTPUT_RECOVERY=""
    STARTED_CHILD=""
    LOG=""
    start_service >/dev/null 2>&1 || true
}

# how many occurrences of a needle are in the assembled -o list
count_in_child() { printf '%s' "$STARTED_CHILD" | grep -o "$1" | wc -l | tr -d ' '; }

# --- 1. one leg present, one absent -----------------------------------------
STUB_DEST_COUNT=1
STUB_DEST_0_ADDR="syd1-a.relay.example.net:5000"
STUB_UPLINK_COUNT=2
STUB_UP_0_IFACE="wwan0"    # absent
STUB_UP_0_WEIGHT="0"
STUB_UP_1_IFACE="lo"       # present everywhere
STUB_UP_1_WEIGHT="0"
run_case
if [ -z "$STARTED_CHILD" ]; then
    fail "no leg reached -o although one uplink is present"
else
    case "$STARTED_CHILD" in
        *"miface=wwan0"*) fail "absent uplink reached the binary: -o='$STARTED_CHILD'" ;;
        *"miface=lo"*)    pass "present uplink used, absent uplink dropped" ;;
        *)                fail "present uplink missing from -o: -o='$STARTED_CHILD'" ;;
    esac
    case "$STARTED_CHILD" in
        *"weight=0"*) pass "weight carried onto the leg (0 = full duplicate)" ;;
        *)            fail "weight lost: -o='$STARTED_CHILD'" ;;
    esac
    case "$STARTED_CHILD" in
        *"syd1-a.relay.example.net:5000"*) pass "destination address carried" ;;
        *)                                 fail "address lost: -o='$STARTED_CHILD'" ;;
    esac
fi

# --- 2. uplinks declared, none present -> nothing started --------------------
STUB_DEST_COUNT=1
STUB_DEST_0_ADDR="syd1-a.relay.example.net:5000"
STUB_UPLINK_COUNT=2
STUB_UP_0_IFACE="wwan0"
STUB_UP_0_WEIGHT="0"
STUB_UP_1_IFACE="wwan1"
STUB_UP_1_WEIGHT="0"
run_case
if [ -z "$STARTED_CHILD" ]; then
    pass "all uplinks absent -> service is NOT started (no crash loop)"
else
    fail "service started with every uplink absent: -o='$STARTED_CHILD'"
fi
case "$LOG" in
    *"no uplink is present"*) pass "the reason is logged, not silent" ;;
    *)                        fail "no explanation logged for an all-absent uplink set" ;;
esac

# --- 3. no uplinks declared -> default route, unbound ------------------------
STUB_UPLINK_COUNT=0
STUB_DEST_COUNT=1
STUB_DEST_0_ADDR="syd1-a.relay.example.net:5000"
run_case
case "$STARTED_CHILD" in
    *"miface="*) fail "an unbound send should carry no miface: -o='$STARTED_CHILD'" ;;
    *"syd1-a.relay.example.net:5000"*) pass "no uplinks: sent over the default route, unbound" ;;
    *)                                 fail "no uplinks: the destination was dropped" ;;
esac
case "$LOG" in
    *"no uplinks configured"*) pass "the default-route fallback is logged" ;;
    *)                         fail "default-route fallback not logged" ;;
esac

# --- 4. fan-out: 2 destinations x 2 present uplinks = 4 legs -----------------
STUB_UPLINK_COUNT=2
STUB_UP_0_IFACE="lo"
STUB_UP_0_WEIGHT="0"
STUB_UP_1_IFACE="lo"
STUB_UP_1_WEIGHT="3"
STUB_DEST_COUNT=2
STUB_DEST_0_ADDR="syd1-a.relay.example.net:5000"
STUB_DEST_1_ADDR="hvl1-a.relay.example.net:5000"
run_case
legs=$(count_in_child 'miface=')
if [ "$legs" = "4" ]; then
    pass "2 destinations x 2 present uplinks = 4 legs"
else
    fail "expected 4 legs, got $legs: -o='$STARTED_CHILD'"
fi
for a in syd1-a hvl1-a; do
    n=$(printf '%s' "$STARTED_CHILD" | grep -o "$a" | wc -l | tr -d ' ')
    if [ "$n" = "2" ]; then
        pass "$a emitted once per uplink"
    else
        fail "$a emitted $n times, expected 2"
    fi
done
case "$STARTED_CHILD" in
    *"weight=3"*) pass "per-leg weight carried (load-balance)" ;;
    *)            fail "per-leg weight lost in fan-out" ;;
esac

# --- 5. an empty address is skipped ------------------------------------------
STUB_UPLINK_COUNT=1
STUB_UP_0_IFACE="lo"
STUB_UP_0_WEIGHT="0"
STUB_DEST_COUNT=1
STUB_DEST_0_ADDR=""
run_case
if [ -z "$STARTED_CHILD" ]; then
    pass "a destination with no address is skipped"
else
    fail "an address-less destination produced a leg: -o='$STARTED_CHILD'"
fi

echo
if [ "$fails" -eq 0 ]; then
    echo "  all assertions passed"
else
    echo "  $fails assertion(s) failed"
fi
exit "$fails"
