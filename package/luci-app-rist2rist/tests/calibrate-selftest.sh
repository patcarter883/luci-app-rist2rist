#!/bin/sh
# Off-device test for the calibration run's WEIGHT DERIVATION (DT-29).
#
#   sh tests/calibrate-selftest.sh
#
# DT-29: every available WAN link is bonded, and a leg's weight is its measured
# contribution to the aggregate -- DERIVED, never configured. This drives the
# plugin's `calibrate` method against stubbed legs and a stubbed probe, and asserts
# the weights it writes, the aggregate it reports (which must NOT be a partial sum),
# the provenance it records, and the refusals. Needs python3.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
fails=0

chmod +x "$here"/bin/* 2>/dev/null || true
PATH="$here/bin:$PATH"
export PATH

plugin="$here/../root/usr/libexec/rpcd/rist2rist"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

TOKEN='test-token-abcdefghijklmnop'
TOKEN_HASH=$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)

# The two present legs this box has, in the resolver's order.
cat > "$tmp/wan.sh" <<'WAN'
wan_links() { echo lo; echo wwan1; }
WAN

# The probe double. PROBE_<iface>_KBPS is that leg's carried rate and
# PROBE_<iface>_RC its exit code (3 = a deliberate refusal, the tool's own
# contract; anything non-zero = a failed measurement). A leg that "carried nothing"
# is modelled as the tool really reports it: exit 1 with measured_kbps 0.
cat > "$tmp/probe" <<'PROBE'
#!/bin/sh
iface="$1"
eval "kbps=\${PROBE_${iface}_KBPS:-0}"
eval "rc=\${PROBE_${iface}_RC:-0}"
[ "$rc" -ne 0 ] && exit "$rc"
printf '%s\n' "$*" >> "${PROBE_ARGV_LOG:-/dev/null}"
printf '{"interface":"%s","measured_kbps":%s,"measured_at":"2026-10-09T00:00:00Z","quality":90}\n' \
	"$iface" "$kbps"
PROBE
chmod +x "$tmp/probe"

UCI_STUB_LOG="$tmp/uci.log"
PROBE_ARGV_LOG="$tmp/probe.argv"
STUB_main_probe_psk_file="$tmp/psk"
export UCI_STUB_LOG PROBE_ARGV_LOG STUB_main_probe_psk_file

# Drive the plugin's calibrate method. The uci double logs every command, so the
# writes can be asserted; PROC_ROOT is deliberately UNSET so the ubus double
# reports no running instance and the pre-start guard lets the run through.
run_cal() {
	: > "$UCI_STUB_LOG"
	: > "$PROBE_ARGV_LOG"
	rm -f "$UCI_STUB_LOG.add" "$UCI_STUB_LOG.del"
	printf '{"token":"%s"}' "$TOKEN" | env \
		FUNCTIONS_SH="$here/stub-functions.sh" \
		STUB_MAIN_TOKEN_HASH="$TOKEN_HASH" \
		STUB_MAIN_MANAGED=1 \
		STUB_main_probe_endpoint='rist://198.51.100.9:20001' \
		PROBE_CMD="$tmp/probe" \
		RIST2RIST_WAN_LIB="$tmp/wan.sh" \
		PROBE_STATE_DIR="$tmp/state" \
		sh "$plugin" call calibrate
}

field() { # field <json> <python expression over d>
	printf '%s' "$1" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print($2)"
}

assert() { # assert <name> <shell condition, using $out / $log>
	if eval "$2"; then
		printf '  OK   %s\n' "$1"
	else
		printf '  FAIL %s\n' "$1"
		fails=$((fails + 1))
	fi
}

# ---------------------------------------------------------------------------
echo "-- two measured legs: the fastest sets the scale, the other is proportional --"
PROBE_lo_KBPS=2000
PROBE_wwan1_KBPS=500
export PROBE_lo_KBPS PROBE_wwan1_KBPS
out=$(run_cal)
log=$(cat "$UCI_STUB_LOG")

assert "both legs are reported ok" \
	"[ \"\$(field \"\$out\" '[L[\"state\"] for L in d[\"legs\"]]')\" = \"['ok', 'ok']\" ]"
assert "the fastest leg takes the full scale (100)" \
	"[ \"\$(field \"\$out\" 'd[\"legs\"][0][\"weight\"]')\" = 100 ]"
assert "the slower leg is proportionally weighted (500 of 2000 -> 25)" \
	"[ \"\$(field \"\$out\" 'd[\"legs\"][1][\"weight\"]')\" = 25 ]"
assert "the aggregate is the sum, and says so" \
	"[ \"\$(field \"\$out\" 'd[\"aggregate_kbps\"]')\" = 2500 ]"
assert "the aggregate state is ok" \
	"[ \"\$(field \"\$out\" 'd[\"aggregate_state\"]')\" = ok ]"
assert "the weights are written where the init reads a per-leg weight" \
	"printf '%s' \"\$log\" | grep -q 'set rist2rist.up_a.weight=100'"
assert "the other leg's weight is written too" \
	"printf '%s' \"\$log\" | grep -q 'set rist2rist.up_b.weight=25'"
assert "a hand-declared weight does not survive a calibration" \
	"! printf '%s' \"\$log\" | grep -q 'set rist2rist.up_b.weight=3'"
assert "the weight lands on the EXISTING section naming that leg, so nothing is declared twice" \
	"printf '%s' \"\$log\" | grep -q 'set rist2rist.up_a.interface=lo'"
assert "the figure the weight came from is recorded, so it traces back" \
	"printf '%s' \"\$log\" | grep -q 'set rist2rist.up_a.measured_kbps=2000'"
assert "and when it was measured" \
	"printf '%s' \"\$log\" | grep -q 'set rist2rist.up_a.measured_at=2026-10-09T00:00:00Z'"
assert "the change is committed" "printf '%s' \"\$log\" | grep -q 'commit rist2rist'"

# ---------------------------------------------------------------------------
echo
echo "-- one leg refuses: a refusal is not a measurement, and the sum must not pretend --"
PROBE_lo_KBPS=2000
PROBE_wwan1_KBPS=0
PROBE_wwan1_RC=3
export PROBE_wwan1_RC
out=$(run_cal)
log=$(cat "$UCI_STUB_LOG")

assert "the refusing leg is reported as refused, not as a failure" \
	"[ \"\$(field \"\$out\" 'd[\"legs\"][1][\"state\"]')\" = refused ]"
assert "a refusing leg is handed NO weight to shape from" \
	"[ \"\$(field \"\$out\" 'd[\"legs\"][1][\"weight\"]')\" = None ]"
assert "the measured leg still takes the full scale" \
	"[ \"\$(field \"\$out\" 'd[\"legs\"][0][\"weight\"]')\" = 100 ]"
assert "the aggregate is null, NOT a sum of the legs that answered" \
	"[ \"\$(field \"\$out\" 'd[\"aggregate_kbps\"]')\" = None ]"
assert "and it says which kind of incomplete it is" \
	"[ \"\$(field \"\$out\" 'd[\"aggregate_state\"]')\" = partial ]"
assert "no weight is written for the leg that refused" \
	"! printf '%s' \"\$log\" | grep -q 'set rist2rist.up_b.weight='"
assert "and a STALE weight from an earlier run is cleared, not left mixing into this ratio" \
	"printf '%s' \"\$log\" | grep -q 'delete rist2rist.up_b.weight'"

# ---------------------------------------------------------------------------
echo
echo "-- a leg that carried nothing (exit 1, measured_kbps 0) is NOT a measurement of 0 --"
unset PROBE_wwan1_RC
PROBE_lo_KBPS=2000
PROBE_wwan1_KBPS=0
out=$(run_cal)

assert "a zero rate is treated as no measurement, not as a floor of zero" \
	"[ \"\$(field \"\$out\" 'd[\"legs\"][1][\"weight\"]')\" = None ]"
assert "it fails the leg rather than reporting a figure" \
	"[ \"\$(field \"\$out\" 'd[\"legs\"][1][\"state\"]')\" != ok ]"

# ---------------------------------------------------------------------------
echo
echo "-- the floor: a leg a thousand times slower still gets a share, never 0 --"
PROBE_lo_KBPS=2000
PROBE_wwan1_KBPS=1
out=$(run_cal)

assert "the slow leg is floored at 1, not rounded to 0" \
	"[ \"\$(field \"\$out\" 'd[\"legs\"][1][\"weight\"]')\" = 1 ]"
assert "NO leg is ever weighted 0 (weight 0 means DUPLICATE, not unused)" \
	"! printf '%s' \"\$(cat \"\$UCI_STUB_LOG\")\" | grep -qE 'weight=0( |$)'"

# ---------------------------------------------------------------------------
echo
echo "-- the credential path: an upgraded bridge may have no such option at all --"
# A package upgrade does NOT overwrite an existing /etc/config, so probe_psk_file
# can be ABSENT on a real bridge. config_get would then return "" and the probe
# would be handed `--psk-file ""`, which is not a path.
STUB_main_probe_psk_file=""
export STUB_main_probe_psk_file
PROBE_lo_KBPS=2000
PROBE_wwan1_KBPS=500
out=$(run_cal)
argv=$(cat "$PROBE_ARGV_LOG")

assert "an absent probe_psk_file falls back to the built-in path" \
	"printf '%s' \"\$argv\" | grep -q -- '--psk-file /etc/rist2rist-probe/psk'"
assert "the credential path is never the empty string" \
	"! printf '%s' \"\$argv\" | grep -q -- '--psk-file  '"

# ---------------------------------------------------------------------------
echo
echo "-- nothing measured: derive NOTHING rather than inventing a share --"
PROBE_lo_KBPS=0
PROBE_wwan1_KBPS=0
PROBE_lo_RC=3
PROBE_wwan1_RC=3
export PROBE_lo_RC PROBE_wwan1_RC
out=$(run_cal)
log=$(cat "$UCI_STUB_LOG")

assert "the run says no weight was derived" \
	"printf '%s' \"\$out\" | grep -q calibration_measured_nothing"
assert "and writes nothing at all -- no weight, no section, no commit" \
	"[ -z \"\$log\" ]"

unset PROBE_lo_RC PROBE_wwan1_RC

# ---------------------------------------------------------------------------
echo
if [ "$fails" -eq 0 ]; then
	echo "ALL PASS"
else
	echo "$fails FAILED"
	exit 1
fi
