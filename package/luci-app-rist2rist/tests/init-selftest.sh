#!/bin/sh
# Off-device test for rist2rist.init's output-leg construction.
#
#   sh tests/init-selftest.sh
#
# What this locks in (DT-27 -- the operator's model):
#
#   1. The leg set for every destination is THIS BOX's PRESENT WAN LINKS, resolved
#      by the shared resolver (files/rist2rist-wan.sh), NOT the `config uplink`
#      set. Each present link gets one -o URL bound with `miface=<iface>`, so CAKE
#      (which runs through an IFB) actually shapes the stream.
#   2. `config uplink` is only an OPTIONAL per-interface weight override: a section
#      for a resolved interface supplies its `weight=`; it can NEVER add a leg, and
#      a section for an absent interface contributes nothing.
#   3. A WAN link that is ABSENT must NOT reach -o: feeding `miface=<absent>` to the
#      binary makes librist fail the bind and the peer resolve, and rist2rist.c
#      calls exit(1), which procd turns into an endless crash loop.
#   4. No PRESENT WAN link (a bench box, or the resolver not installed) -> the URL
#      is still emitted UNBOUND over the default route, plus a log line, so the
#      stream is never lost.
#
# No stubbing of the interface test is needed: the resolver honours WAN_LIB_SYSFS
# and WAN_LIB_NETWORK_FIXTURE, so a fake netdev root models "wwan1 present, wwan0
# absent" exactly as production does (lo is real but is not a WAN here).
#
# The init is `#!/bin/sh /etc/rc.common` and defines its helpers at the top level,
# so sourcing it defines them without running procd. config_* and logger are
# stubbed; procd_* is stubbed to capture what WOULD have been started.

set -u

here=$(cd "$(dirname "$0")" && pwd)
init="$here/../files/rist2rist.init"
wanlib="$here/../files/rist2rist-wan.sh"
fails=0

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

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

# ------------------------------------------------------------- fixtures -------
# The leg set is the box's present WAN links (DT-27), so every case drives the
# shared resolver through its documented test hooks.
netfix="$tmp/network.show"
cat > "$netfix" <<'EOF'
network.loopback.proto='static'
network.lan.proto='static'
network.wwan0.proto='modemmanager'
network.wwan1.device='/sys/devices/pci0000:00/0000:00:15.0/usb1/1-2'
network.wwan1.proto='modemmanager'
network.wwan2.proto='modemmanager'
EOF
one="$tmp/net-one";   mkdir -p "$one/wwan1"
two="$tmp/net-two";   mkdir -p "$two/wwan1" "$two/wwan2"
none="$tmp/net-none"; mkdir -p "$none"

# use_wan <resolver-path> <netdev-root> -- point the resolver at its hooks.
use_wan() {
    RIST2RIST_WAN_LIB="$1"
    WAN_LIB_NETWORK_FIXTURE="$netfix"
    WAN_LIB_SYSFS="$2"
    export RIST2RIST_WAN_LIB WAN_LIB_NETWORK_FIXTURE WAN_LIB_SYSFS
}

# ------------------------------------------------------------- the tests ------
echo "rist2rist.init: the output leg set is the box's present WAN links (DT-27)"

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

# --- 1. primary path: one present WAN link, no config uplink -> one bound leg --
# The production case: no `config uplink` (not bonding), but the router HAS a WAN
# link. Exactly one URL, bound with miface=<the present link>, no weight.
use_wan "$wanlib" "$one"
STUB_UPLINK_COUNT=0
STUB_DEST_COUNT=1
STUB_DEST_0_ADDR="syd1-a.relay.example.net:5000"
run_case
if [ -z "$STARTED_CHILD" ]; then
    fail "no leg reached -o although a WAN link is present"
else
    case "$STARTED_CHILD" in
        *"miface=wwan1"*) pass "a present WAN link is bound with miface=" ;;
        *)                fail "present WAN link missing from -o: -o='$STARTED_CHILD'" ;;
    esac
    case "$STARTED_CHILD" in
        *"miface=wwan0"*) fail "an ABSENT WAN link reached the binary" ;;
        *)                pass "the absent WAN link is dropped" ;;
    esac
    if [ "$(count_in_child 'miface=')" = "1" ]; then
        pass "exactly ONE output URL for one present WAN link"
    else
        fail "expected 1 leg, got $(count_in_child 'miface='): -o='$STARTED_CHILD'"
    fi
    case "$STARTED_CHILD" in
        *"weight="*) fail "no config uplink -> the leg must carry no weight" ;;
        *)           pass "no config uplink -> the leg carries no weight" ;;
    esac
    case "$STARTED_CHILD" in
        *"syd1-a.relay.example.net:5000"*) pass "destination address carried" ;;
        *)                                 fail "address lost: -o='$STARTED_CHILD'" ;;
    esac
fi

# --- 2. config uplink supplies a weight, but never adds a leg ------------------
# A section for the PRESENT interface supplies its weight; a section for the
# ABSENT interface must contribute nothing at all.
use_wan "$wanlib" "$one"
STUB_UPLINK_COUNT=2
STUB_UP_0_IFACE="wwan1"; STUB_UP_0_WEIGHT="3"   # present -> weight applies
STUB_UP_1_IFACE="wwan0"; STUB_UP_1_WEIGHT="0"   # absent  -> ignored
STUB_DEST_COUNT=1
STUB_DEST_0_ADDR="syd1-a.relay.example.net:5000"
run_case
if [ "$(count_in_child 'miface=')" = "1" ]; then
    pass "a config uplink for an ABSENT interface adds no leg"
else
    fail "config uplink added a leg: -o='$STARTED_CHILD'"
fi
case "$STARTED_CHILD" in
    *"miface=wwan1"*"weight=3"*) pass "a matching config uplink supplies the leg's weight" ;;
    *)                           fail "weight override not applied: -o='$STARTED_CHILD'" ;;
esac
case "$STARTED_CHILD" in
    *"miface=wwan0"*) fail "an absent interface's uplink reached the binary" ;;
    *)                pass "an absent interface's uplink was not emitted" ;;
esac

# --- 2b. weight '0' must be emitted, not dropped -------------------------------
# SMPTE 2022-7 redundancy: weight=0 means "duplicate the full stream down this
# link". `[ -n "0" ]` is TRUE, so a present interface declared with weight '0'
# must carry `weight=0` on its leg. This is the case the config comment calls out,
# and it was untested.
use_wan "$wanlib" "$one"
STUB_UPLINK_COUNT=1
STUB_UP_0_IFACE="wwan1"; STUB_UP_0_WEIGHT="0"
STUB_DEST_COUNT=1
STUB_DEST_0_ADDR="syd1-a.relay.example.net:5000"
run_case
if [ "$(count_in_child 'weight=0')" = "1" ]; then
    pass "weight '0' (SMPTE 2022-7 redundancy) is emitted as weight=0"
else
    fail "weight '0' was dropped: -o='$STARTED_CHILD'"
fi
case "$STARTED_CHILD" in
    *"miface=wwan1"*"weight=0"*) pass "the weight=0 leg is bound to the present interface" ;;
    *)                           fail "weight=0 leg malformed: -o='$STARTED_CHILD'" ;;
esac

# --- 3. two present WAN links -> two bound legs --------------------------------
use_wan "$wanlib" "$two"
STUB_UPLINK_COUNT=0
STUB_DEST_COUNT=1
STUB_DEST_0_ADDR="syd1-a.relay.example.net:5000"
run_case
if [ "$(count_in_child 'miface=')" = "2" ]; then
    pass "two present WAN links -> two bound output URLs"
else
    fail "expected 2 legs, got $(count_in_child 'miface='): -o='$STARTED_CHILD'"
fi

# --- 4. no PRESENT WAN link -> unbound default-route fallback ------------------
use_wan "$wanlib" "$none"
STUB_UPLINK_COUNT=0
STUB_DEST_COUNT=1
STUB_DEST_0_ADDR="syd1-a.relay.example.net:5000"
run_case
case "$STARTED_CHILD" in
    *"miface="*) fail "no present WAN link must stay unbound: -o='$STARTED_CHILD'" ;;
    *"syd1-a.relay.example.net:5000"*) pass "no present WAN link -> unbound default-route send" ;;
    *)                                 fail "the destination was dropped with no present WAN link" ;;
esac
case "$LOG" in
    *"no WAN link is present"*) pass "the unbound fallback is logged" ;;
    *)                          fail "unbound fallback not logged" ;;
esac

# --- 5. resolver not installed (older install) -> unbound fallback, no crash ---
use_wan "$tmp/absent-resolver.sh" "$one"
STUB_UPLINK_COUNT=0
STUB_DEST_COUNT=1
STUB_DEST_0_ADDR="syd1-a.relay.example.net:5000"
run_case
case "$STARTED_CHILD" in
    *"miface="*) fail "a missing resolver must keep the unbound behaviour" ;;
    *"syd1-a.relay.example.net:5000"*) pass "missing resolver -> unbound fallback, no crash" ;;
    *)                                 fail "destination dropped when the resolver is missing" ;;
esac

# --- 6. fan-out: 2 destinations x 2 present WAN links = 4 legs -----------------
use_wan "$wanlib" "$two"
STUB_UPLINK_COUNT=0
STUB_DEST_COUNT=2
STUB_DEST_0_ADDR="syd1-a.relay.example.net:5000"
STUB_DEST_1_ADDR="hvl1-a.relay.example.net:5000"
run_case
if [ "$(count_in_child 'miface=')" = "4" ]; then
    pass "2 destinations x 2 present WAN links = 4 legs"
else
    fail "expected 4 legs, got $(count_in_child 'miface='): -o='$STARTED_CHILD'"
fi
for a in syd1-a hvl1-a; do
    n=$(printf '%s' "$STARTED_CHILD" | grep -o "$a" | wc -l | tr -d ' ')
    if [ "$n" = "2" ]; then
        pass "$a emitted once per present WAN link"
    else
        fail "$a emitted $n times, expected 2"
    fi
done

# --- 7. an empty address is skipped -------------------------------------------
use_wan "$wanlib" "$one"
STUB_UPLINK_COUNT=0
STUB_DEST_COUNT=1
STUB_DEST_0_ADDR=""
run_case
if [ -z "$STARTED_CHILD" ]; then
    pass "a destination with no address is skipped"
else
    fail "an address-less destination produced a leg: -o='$STARTED_CHILD'"
fi

# --- 8. recovery / query construction is untouched -----------------------------
# The leg rewrite must not disturb the query the leg is built from.
use_wan "$wanlib" "$one"
STUB_UPLINK_COUNT=0
STUB_DEST_COUNT=1
STUB_DEST_0_ADDR="syd1-a.relay.example.net:5000"
run_case
case "$STARTED_CHILD" in
    *"timing-mode=0"*"bandwidth="*) pass "the bound leg keeps timing-mode + bandwidth" ;;
    *)                              fail "query construction disturbed: -o='$STARTED_CHILD'" ;;
esac

unset RIST2RIST_WAN_LIB WAN_LIB_NETWORK_FIXTURE WAN_LIB_SYSFS

echo
if [ "$fails" -eq 0 ]; then
    echo "  all assertions passed"
else
    echo "  $fails assertion(s) failed"
fi
exit "$fails"
