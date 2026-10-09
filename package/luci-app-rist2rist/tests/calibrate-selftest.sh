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

# A shaper-aware tc double for THIS suite, put AHEAD of tests/bin. The shared
# tests/bin/tc answers per-MODE (TC_STUB_MODE) for the measure helper; this suite
# needs per-DEVICE, because the case that matters is one leg shaped and another
# not -- and a fixture that answers by name would hide exactly that bug.
mkdir -p "$tmp/tcbin"
cat > "$tmp/tcbin/tc" <<'TC'
#!/bin/sh
[ "$1" = "-s" ] && [ "$2 $3" = "qdisc show" ] && [ "$4" = "dev" ] || exit 0
if [ -e "${STUB_SHAPED_DIR:-/nonexistent}/$5" ]; then
	printf 'qdisc cake 8012: root refcnt 2 bandwidth 8Mbit besteffort triple-isolate\n Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)\n'
fi
exit 0
TC
chmod +x "$tmp/tcbin/tc"
PATH="$tmp/tcbin:$PATH"
export PATH

TOKEN='test-token-abcdefghijklmnop'
TOKEN_HASH=$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)

# The resolver exposes TWO answers, as the real one does: `wan_links` is every
# CONFIGURED WAN and `wan_links_present` the ones actually there. wwan0 is the box's
# configured-but-absent leg (`NO_DEVICE`), so it must be in the first and NOT the
# second -- the exact shape that made calibrate probe a modem that was not attached.
cat > "$tmp/wan.sh" <<'WAN'
wan_links() { echo wwan0; echo lo; echo wwan1; }
wan_links_present() { echo lo; echo wwan1; }
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
# The DIAGNOSTIC fields: why the ramp stopped and what the leg was doing.
# MODELLED on the real tool's output, because a stub that emits only a rate cannot
# catch a plugin that drops the reasons.
eval "fr=\${PROBE_${iface}_FAILED_ON_RTT:-false}"
eval "q=\${PROBE_${iface}_QUALITY:-90}"
eval "lr=\${PROBE_${iface}_LOADED_RTT:-null}"
eval "fak=\${PROBE_${iface}_FAILED_AT:-null}"
printf '{"interface":"%s","measured_kbps":%s,"measured_at":"2026-10-09T00:00:00Z","quality":%s,"loaded_rtt_ms":%s,"failed_at_kbps":%s,"failed_on_rtt":%s}\n' \
	"$iface" "$kbps" "$q" "$lr" "$fak" "$fr"
PROBE
chmod +x "$tmp/probe"

# The shaper's service, as the plugin uses it: `stop` clears the qdiscs, `start`
# installs them. Both are logged into the PROBE log, so the ORDER is assertable --
# the whole point is that no probe byte is sent while the shaper is up. A fixture
# with a shaped leg is a file in STUB_SHAPED_DIR; tc reports cake for it.
mkdir -p "$tmp/shaped"
STUB_SHAPED_DIR="$tmp/shaped"
STUB_SHAPED_SAVE="$tmp/shaped.save"
cat > "$tmp/sqm" <<'SQM'
#!/bin/sh
case "$1" in
	stop)
		ls "$STUB_SHAPED_DIR" > "$STUB_SHAPED_SAVE" 2>/dev/null || true
		rm -f "$STUB_SHAPED_DIR"/*
		printf 'sqm stop\n' >> "$PROBE_ARGV_LOG" ;;
	start)
		while read -r d; do [ -n "$d" ] && touch "$STUB_SHAPED_DIR/$d"; done < "$STUB_SHAPED_SAVE" 2>/dev/null
		# A restore that does not come back, for the case that must be REPORTED
		# rather than assumed.
		[ "${STUB_SQM_START_BROKEN:-0}" = 1 ] && rm -f "$STUB_SHAPED_DIR"/*
		printf 'sqm start\n' >> "$PROBE_ARGV_LOG" ;;
	esac
exit 0
SQM
chmod +x "$tmp/sqm"

UCI_STUB_LOG="$tmp/uci.log"
PROBE_ARGV_LOG="$tmp/probe.argv"
STUB_main_probe_psk_file="$tmp/psk"
export UCI_STUB_LOG PROBE_ARGV_LOG STUB_main_probe_psk_file
export SQM_INIT="$tmp/sqm" STUB_SHAPED_DIR STUB_SHAPED_SAVE

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
echo "-- an ABSENT leg (configured, no device) is not measured and not weighted --"
PROBE_lo_KBPS=2000
PROBE_wwan1_KBPS=500
out=$(run_cal)
log=$(cat "$UCI_STUB_LOG")

assert "only the PRESENT legs are reported -- the absent one is not in the array" \
	"[ \"\$(field \"\$out\" 'sorted(L[\"interface\"] for L in d[\"legs\"])')\" = \"['lo', 'wwan1']\" ]"
assert "the absent leg is never probed" \
	"! printf '%s' \"\$(cat \"\$PROBE_ARGV_LOG\")\" | grep -q wwan0"
assert "and no weight is written for a leg that will never be bonded" \
	"! printf '%s' \"\$log\" | grep -q wwan0"
assert "an absent leg cannot poison the aggregate (it is not in it to fail)" \
	"[ \"\$(field \"\$out\" 'd[\"aggregate_state\"]')\" = ok ]"

# ---------------------------------------------------------------------------
echo
echo "-- a RUNNING bridge daemon must not block calibration --"
# The daemon runs whenever the service is enabled, idle or not, so using its pid as
# "a session is running" refuses every calibration on a healthy box. This is the
# shape the off-device suite originally missed: PROC_ROOT unset meant no pid, so the
# bug could not show. The honest signal is traffic on the leg, and that is the
# tool's own guard.
mkdir -p "$tmp/proc/4242"
printf '/usr/bin/rist2rist\0' > "$tmp/proc/4242/cmdline"
PROC_ROOT="$tmp/proc"
export PROC_ROOT
PROBE_lo_KBPS=2000
PROBE_wwan1_KBPS=500
out=$(run_cal)
log=$(cat "$UCI_STUB_LOG")

assert "a running service does NOT refuse the calibration" \
	"printf '%s' \"\$out\" | grep -q '\"ok\":true'"
assert "and the legs are still measured through it" \
	"[ \"\$(field \"\$out\" 'd[\"legs\"][0][\"state\"]')\" = ok ]"
assert "so the weights are still derived" \
	"printf '%s' \"\$log\" | grep -q 'set rist2rist.up_a.weight=100'"
unset PROC_ROOT

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
echo "-- a leg that carried its rate but could not hold its LATENCY still says why --"
# The shape this bridge actually produced: the tool exits 0, reports
# measured_kbps 0, quality 100.00, a loaded RTT far above idle, and
# failed_on_rtt true. Reporting only "measured nothing" makes a leg that carried
# every byte and merely bloated read as a leg that carried nothing -- the reading
# that produced a wrong conclusion about this modem.
PROBE_lo_KBPS=0
PROBE_lo_FAILED_ON_RTT=true
PROBE_lo_QUALITY=100.00
PROBE_lo_LOADED_RTT=1114.0
PROBE_lo_FAILED_AT=500
PROBE_wwan1_RC=3
export PROBE_lo_FAILED_ON_RTT PROBE_lo_QUALITY PROBE_lo_LOADED_RTT PROBE_lo_FAILED_AT
out=$(run_cal)

assert "the failed run still names every leg" \
	"[ \"\$(field \"\$out\" '[L[\"interface\"] for L in d[\"legs\"]]')\" = \"['lo', 'wwan1']\" ]"
assert "and says the leg stopped on LATENCY, not on quality" \
	"[ \"\$(field \"\$out\" 'd[\"legs\"][0][\"failed_on_rtt\"]')\" = True ]"
assert "the failing step's quality is reported, never left at the initialiser" \
	"[ \"\$(field \"\$out\" 'd[\"legs\"][0][\"quality\"]')\" = 100.0 ]"
assert "the loaded RTT is reported, not null" \
	"[ \"\$(field \"\$out\" 'd[\"legs\"][0][\"loaded_rtt_ms\"]')\" = 1114.0 ]"
assert "and which rate broke it" \
	"[ \"\$(field \"\$out\" 'd[\"legs\"][0][\"failed_at_kbps\"]')\" = 500 ]"
assert "no weight is derived from a leg that held no rate" \
	"[ \"\$(field \"\$out\" 'd[\"legs\"][0][\"weight\"]')\" = None ]"
assert "and still nothing is written" \
	"[ -z \"\$(cat \"\$UCI_STUB_LOG\")\" ]"

unset PROBE_lo_FAILED_ON_RTT PROBE_lo_QUALITY PROBE_lo_LOADED_RTT PROBE_lo_FAILED_AT

# ---------------------------------------------------------------------------
echo
echo "-- the shaper is CLEARED for the measurement, and put back afterwards --"
# A leg measured THROUGH its own shaper is not measured: CAKE caps the rate and
# flattens the queue, so the ramp reads the qdisc instead of the link and calls
# its own ceiling clean. Ordering -- calibrate before shaping -- only works the
# first time; a bridge arriving at a second event still shaped from the last one
# would derive every weight from the shaper.
touch "$tmp/shaped/ifb4wwan1"
PROBE_lo_KBPS=2000
PROBE_wwan1_KBPS=500
out=$(run_cal)

first=$(head -1 "$PROBE_ARGV_LOG")
last=$(tail -1 "$PROBE_ARGV_LOG")
assert "the shaper is stopped BEFORE the first probe byte" \
	"[ \"\$first\" = 'sqm stop' ]"
assert "and it is not started again until the probing is done" \
	"[ \"\$last\" = 'sqm start' ]"
between=$(sed -n '/sqm stop/,/sqm start/p' "$PROBE_ARGV_LOG")
assert "both probes ran INSIDE the cleared window" \
	"[ \"\$(printf '%s' \"\$between\" | grep -c -- '--psk-file')\" = 2 ]"
assert "the run reports how the shaper was left" \
	"[ \"\$(field \"\$out\" 'd[\"shaper\"]')\" = restored ]"

echo
echo "-- a run that derives NOTHING still puts the shaper back --"
PROBE_lo_KBPS=0
PROBE_wwan1_KBPS=0
PROBE_lo_RC=3
PROBE_wwan1_RC=3
export PROBE_lo_RC PROBE_wwan1_RC
touch "$tmp/shaped/ifb4wwan1"
out=$(run_cal)

assert "the shaper is restored even when no weight was derived" \
	"printf '%s' \"\$(cat \"\$PROBE_ARGV_LOG\")\" | grep -q 'sqm start'"
assert "and the error says so rather than leaving it unsaid" \
	"[ \"\$(field \"\$out\" 'd[\"shaper\"]')\" = restored ]"
unset PROBE_lo_RC PROBE_wwan1_RC

echo
echo "-- an UNSHAPED bridge: starting the service would install a shaper it never had --"
rm -f "$tmp/shaped"/*
PROBE_lo_KBPS=2000
PROBE_wwan1_KBPS=500
out=$(run_cal)

assert "nothing is stopped, and nothing is started, when no leg is shaped" \
	"! printf '%s' \"\$(cat \"\$PROBE_ARGV_LOG\")\" | grep -q 'sqm '"
assert "and the run says the shaper was not involved" \
	"[ \"\$(field \"\$out\" 'd[\"shaper\"]')\" = none ]"

echo
echo "-- a restore that does not come back must be REPORTED, never assumed --"
touch "$tmp/shaped/ifb4wwan1"
STUB_SQM_START_BROKEN=1
export STUB_SQM_START_BROKEN
out=$(run_cal)

assert "a failed restore is reported as failed" \
	"[ \"\$(field \"\$out\" 'd[\"shaper\"]')\" = restore_failed ]"
unset STUB_SQM_START_BROKEN
rm -f "$tmp/shaped"/*

# ---------------------------------------------------------------------------
echo
echo "-- the shaper is SET from the measurement, and the setting is confirmed --"
# Measure -> configure -> VERIFY. A shaper set from nothing is a guess, and a
# setting that was never tested is an assumption: the legs are measured raw, the
# shaper is written from those measurements, and then each shaped leg is held at
# the rate it was just set to, with the shaper up, to see whether the link does
# what the numbers say.
touch "$tmp/shaped/ifb4wwan1"
STUB_SQM_QUEUES="lo wwan1"
export STUB_SQM_QUEUES
PROBE_lo_KBPS=2000
PROBE_wwan1_KBPS=500
out=$(run_cal)
log=$(cat "$UCI_STUB_LOG")
argvlog=$(cat "$PROBE_ARGV_LOG")

assert "each measured leg's own queue is set, at the measured capacity less the margin" \
	"printf '%s' \"\$log\" | grep -q 'set sqm.@queue\[0\].upload=1800' && printf '%s' \"\$log\" | grep -q 'set sqm.@queue\[1\].upload=450'"
assert "the queue is found by INTERFACE, so a leg is never shaped on another leg's queue" \
	"printf '%s' \"\$log\" | grep -q 'set sqm.@queue\[1\].upload=450'"
assert "the shaper change is committed, separately from the bridge's own config" \
	"printf '%s' \"\$log\" | grep -q 'commit sqm'"
assert "the report says what each leg was shaped to" \
	"[ \"\$(field \"\$out\" 'd[\"legs\"][0][\"shaper_kbps\"]')\" = 1800 ]"
assert "and the other leg's, from its own measurement" \
	"[ \"\$(field \"\$out\" 'd[\"legs\"][1][\"shaper_kbps\"]')\" = 450 ]"
assert "the confirmation re-runs the test WITH the shaper up" \
	"printf '%s' \"\$argvlog\" | grep -q 'shaped-lo.json'"
assert "and it runs after the shaper is put back, never before" \
	"[ \"\$(printf '%s' \"\$argvlog\" | grep -n 'shaped-lo.json' | cut -d: -f1)\" -gt \"\$(printf '%s' \"\$argvlog\" | grep -n 'sqm start' | cut -d: -f1)\" ]"
assert "it is the STANDARD test -- a ramp, not a held rate" \
	"[ \"\$(printf '%s' \"\$argvlog\" | grep 'shaped-' | grep -c -- '-r ')\" = 0 ]"
assert "and the report says what the shaped leg then measured" \
	"[ \"\$(field \"\$out\" 'd[\"legs\"][0][\"shaped_measured_kbps\"]')\" = 2000 ]"
assert "the budget the bridge will SEND with is the sum of the shapers" \
	"printf '%s' \"\$log\" | grep -q 'set rist2rist.main.measured_budget_kbps=2250'"

echo
echo "-- a leg that did NOT measure is never shaped from a guess --"
rm -f "$tmp/shaped"/*
PROBE_lo_KBPS=2000
PROBE_wwan1_KBPS=0
PROBE_wwan1_RC=3
export PROBE_wwan1_RC
out=$(run_cal)
log=$(cat "$UCI_STUB_LOG")
assert "the measured leg is shaped" \
	"printf '%s' \"\$log\" | grep -q 'set sqm.@queue\[0\].upload=1800'"
assert "the leg that carried nothing gets NO shaper value" \
	"! printf '%s' \"\$log\" | grep -q 'set sqm.@queue\[1\].upload'"
assert "and the report says so rather than inventing one" \
	"[ \"\$(field \"\$out\" 'd[\"legs\"][1][\"shaper_kbps\"]')\" = None ]"
unset PROBE_wwan1_RC

# ---------------------------------------------------------------------------
echo
if [ "$fails" -eq 0 ]; then
	echo "ALL PASS"
else
	echo "$fails FAILED"
	exit 1
fi
