#!/bin/sh
# Off-device test for rist2rist-measure.
#
#   sh tests/measure-selftest.sh
#
# What this locks in:
#
#   1. The JSON contract: one object, a `legs` array with exactly the agreed
#      field set, and an `aggregate` shaped only by the PRESENT legs.
#   2. "Unknown" is a first-class state. A value that could not be read is null,
#      NEVER 0 -- a fabricated 0 is indistinguishable from a real reading and is
#      worse than an honest null.
#   3. An ABSENT interface (the ordinary bench state -- no modem attached) is
#      reported present:false / state "absent" and does NOT abort the run.
#
# Two layers are exercised separately:
#   * the PURE core, emit_measurement, is called directly with crafted records --
#     no files, no commands -- so the JSON decision is tested in isolation;
#   * the I/O shell is run as a subprocess against the real /sys/class/net (lo is
#     present, wwan1 is absent on a normal machine) with tc/mmcli stubbed through
#     tests/bin.
#
# Needs python3 for the JSON assertions. The helper itself is POSIX sh.
set -u

here=$(cd "$(dirname "$0")" && pwd)
measure="$here/../files/rist2rist-measure"
stub="$here/stub-functions.sh"
fails=0

chmod +x "$here"/bin/* 2>/dev/null || true
PATH="$here/bin:$PATH"
export PATH

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; fails=$((fails + 1)); }

# py <json> <boolean-expression over d> -> 0 if the assertion holds.
py() {
    printf '%s' "$1" | python3 -c "
import json,sys
d = json.load(sys.stdin)
assert $2
" 2>/dev/null
}

check() { # check <label> <json> <expression>
    if py "$2" "$3"; then
        pass "$1"
    else
        fail "$1"
        printf '       got: %s\n' "$2"
    fi
}

# The config_* stub, so sourcing the helper off-device succeeds. The PURE core
# never calls it; the I/O shell does, in the subprocess.
FUNCTIONS_SH="$stub"
export FUNCTIONS_SH
# shellcheck source=/dev/null
. "$measure"

# ======================================================================
# the pure core
# ======================================================================

echo "rist2rist-measure: pure core (emit_measurement)"

rec=$(printf 'wwan1|true|8000|100|200|0|1|0|-70\nwwan0|false|||||||\n')
out=$(emit_measurement '2026-01-01T00:00:00Z' "$rec")
check "core: generated_at echoed" "$out" "d['generated_at'] == '2026-01-01T00:00:00Z'"
check "core: one leg per record" "$out" "len(d['legs']) == 2"
check "core: a present shaped leg is state ok" "$out" \
    "d['legs'][0]['interface']=='wwan1' and d['legs'][0]['present'] is True and d['legs'][0]['state']=='ok'"
check "core: the counters are carried through" "$out" \
    "d['legs'][0]['shaped_kbps']==8000 and d['legs'][0]['tx_bytes']==100 and d['legs'][0]['rx_bytes']==200"
check "core: dropped/overlimits/backlog carried" "$out" \
    "d['legs'][0]['tx_dropped']==0 and d['legs'][0]['tx_overlimits']==1 and d['legs'][0]['backlog_bytes']==0"
check "core: signal carried as an integer" "$out" "d['legs'][0]['signal_dbm'] == -70"
check "core: the not-yet-measurable fields are null" "$out" \
    "d['legs'][0]['rtt_ms'] is None and d['legs'][0]['jitter_ms'] is None and d['legs'][0]['quality'] is None and d['legs'][0]['measured_kbps'] is None and d['legs'][0]['measured_at'] is None"
check "core: an absent leg is present:false / state absent" "$out" \
    "d['legs'][1]['present'] is False and d['legs'][1]['state']=='absent'"
check "core: an absent leg reports null, not 0" "$out" \
    "d['legs'][1]['shaped_kbps'] is None and d['legs'][1]['tx_bytes'] is None"
check "core: aggregate shapes only the present legs" "$out" \
    "d['aggregate']['shaped_kbps'] == 8000"
check "core: aggregate measured is null (nothing measured yet)" "$out" \
    "d['aggregate']['measured_kbps'] is None"

echo
echo "-- the unknown rule --"

rec=$(printf 'wwan1|true||5|6||||\n')
out=$(emit_measurement '2026-01-01T00:00:00Z' "$rec")
check "core: a present leg with no shaper is state unknown" "$out" \
    "d['legs'][0]['state']=='unknown'"
check "core: no shaper -> shaped_kbps null, NOT 0" "$out" \
    "d['legs'][0]['shaped_kbps'] is None"
check "core: an unshaped present leg leaves the aggregate null" "$out" \
    "d['aggregate']['shaped_kbps'] is None"

rec=$(printf 'wwan0|false|0|0|0|0|0|0|0\n')
out=$(emit_measurement '2026-01-01T00:00:00Z' "$rec")
check "core: an absent leg cannot smuggle a 0 through" "$out" \
    "d['legs'][0]['shaped_kbps'] is None and d['legs'][0]['tx_bytes'] is None and d['legs'][0]['signal_dbm'] is None"
check "core: no present leg -> aggregate shaped null" "$out" \
    "d['aggregate']['shaped_kbps'] is None"

rec=$(printf 'wwan1|true|8000|||||||\nwwan2|true|2000|||||||\n')
out=$(emit_measurement '2026-01-01T00:00:00Z' "$rec")
check "core: aggregate sums the present shaped legs" "$out" \
    "d['aggregate']['shaped_kbps'] == 10000"

out=$(emit_measurement '2026-01-01T00:00:00Z' "")
check "core: no legs -> empty array and null aggregate" "$out" \
    "d['legs'] == [] and d['aggregate']['shaped_kbps'] is None"

# ======================================================================
# the I/O shell
# ======================================================================

echo
echo "rist2rist-measure: I/O shell (real /sys/class/net, stubbed tc/mmcli)"

# The stub uplinks are lo (present) and wwan1 (absent) -- the same fixtures the
# other suites use.
run_measure() { # run_measure <TC_STUB_MODE>
    env FUNCTIONS_SH="$stub" TC_STUB_MODE="$1" sh "$measure"
}

out=$(run_measure cake); rc=$?
if [ "$rc" -eq 0 ]; then pass "e2e: exits 0"; else fail "e2e: exit $rc"; fi
check "e2e: emits a JSON object" "$out" "isinstance(d, dict)"
check "e2e: one leg per configured uplink" "$out" "len(d['legs']) == 2"
check "e2e: lo is present and shaped (state ok)" "$out" \
    "d['legs'][0]['interface']=='lo' and d['legs'][0]['present'] is True and d['legs'][0]['state']=='ok' and d['legs'][0]['shaped_kbps']==8000"
check "e2e: lo's CAKE counters are reported" "$out" \
    "d['legs'][0]['tx_dropped']==3 and d['legs'][0]['tx_overlimits']==7 and d['legs'][0]['backlog_bytes']==1337"
check "e2e: wwan1 is absent, and the run still emitted" "$out" \
    "d['legs'][1]['interface']=='wwan1' and d['legs'][1]['present'] is False and d['legs'][1]['state']=='absent' and d['legs'][1]['shaped_kbps'] is None"
check "e2e: aggregate shaped is the present leg's rate" "$out" \
    "d['aggregate']['shaped_kbps'] == 8000"

out=$(run_measure noqueue); rc=$?
if [ "$rc" -eq 0 ]; then pass "e2e noqueue: exits 0"; else fail "e2e noqueue: exit $rc"; fi
check "e2e noqueue: a present leg with no shaper is state unknown" "$out" \
    "d['legs'][0]['state']=='unknown'"
check "e2e noqueue: shaped_kbps is null, NOT 0" "$out" \
    "d['legs'][0]['shaped_kbps'] is None"
check "e2e noqueue: aggregate shaped is null" "$out" \
    "d['aggregate']['shaped_kbps'] is None"

echo
echo "-- modem signal (mmcli) --"

MMCLI_STUB_RSSI=-71
export MMCLI_STUB_RSSI
sig=$(modem_signal wwan1)
if [ "$sig" = "-71" ]; then
    pass "modem: RSSI is read for a modem-backed leg"
else
    fail "modem: got '$sig', expected -71"
fi
unset MMCLI_STUB_RSSI
sig=$(modem_signal wwan1)
if [ -z "$sig" ]; then
    pass "modem: no modem -> empty (unknown), not 0"
else
    fail "modem: got '$sig', expected empty"
fi

echo
if [ "$fails" -eq 0 ]; then
    echo "  all assertions passed"
else
    echo "  $fails assertion(s) failed"
fi
exit "$fails"
