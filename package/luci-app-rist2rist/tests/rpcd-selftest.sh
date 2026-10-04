#!/bin/sh
# Off-device test for the rist2rist rpcd plugin.
#
#   sh tests/rpcd-selftest.sh
#
# Stubs /lib/functions.sh, and puts tests/bin (jsonfilter, uci, reload-stub) ahead
# on PATH so the WRITE path can be exercised without a router. Exits non-zero on
# the first failure. Needs python3 -- the jsonfilter double is Python, and the
# assertions are made with it. The plugin itself is POSIX sh.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
plugin="$here/../root/usr/libexec/rpcd/rist2rist"
stub="$here/stub-functions.sh"
fails=0

chmod +x "$here"/bin/* 2>/dev/null || true
PATH="$here/bin:$PATH"
export PATH

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

check() {
	# check <label> <json> <python-expression-over-d>
	if printf '%s' "$2" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert $3
" 2>/dev/null; then
		echo "  OK   $1"
	else
		echo "  FAIL $1"
		printf '       got: %s\n' "$2"
		fails=$((fails + 1))
	fi
}

check_log() { # check_log <label> <logfile> <grep-pattern>
	if grep -q -- "$3" "$2" 2>/dev/null; then
		echo "  OK   $1"
	else
		echo "  FAIL $1"
		printf '       log: %s\n' "$(cat "$2" 2>/dev/null)"
		fails=$((fails + 1))
	fi
}

check_no_log() { # check_no_log <label> <logfile> <grep-pattern>
	if grep -q -- "$3" "$2" 2>/dev/null; then
		echo "  FAIL $1 (unexpected match)"
		fails=$((fails + 1))
	else
		echo "  OK   $1"
	fi
}

run() { # run <managed 0|1> <method> [body]
	if [ -n "${3:-}" ]; then
		printf '%s' "$3" | env UCI_STUB_LOG="$tmp/uci" STUB_MAIN_MANAGED="$1" \
			FUNCTIONS_SH="$stub" RELOAD_CMD="$here/bin/reload-stub" \
			RELOAD_STUB_LOG="$tmp/reload" sh "$plugin" call "$2" || true
	else
		env UCI_STUB_LOG="$tmp/uci" STUB_MAIN_MANAGED="$1" \
			FUNCTIONS_SH="$stub" RELOAD_CMD="$here/bin/reload-stub" \
			RELOAD_STUB_LOG="$tmp/reload" sh "$plugin" call "$2" </dev/null || true
	fi
}

echo "== rist2rist rpcd plugin self-test =="

# --- list ---
out=$(FUNCTIONS_SH="$stub" sh "$plugin" list)
check "list enumerates the read methods" "$out" \
	"'status' in d and 'get_config' in d"
check "list enumerates the write methods" "$out" \
	"'set_config' in d and 'reconcile' in d and 'reload' in d"

# --- get_config ---
out=$(FUNCTIONS_SH="$stub" sh "$plugin" call get_config)
check "get_config: enabled is a JSON bool" "$out" "d['enabled'] is True"
check "get_config: listen_url carried" "$out" "d['listen_url'] == 'rist://0.0.0.0:5000'"
check "get_config: recovery block present" "$out" "d['recovery']['reorder_buffer'] == '20'"
check "get_config: telemetry target carried" "$out" "d['telemetry']['target'] == '192.0.2.10:9999'"
check "get_config: reports the managed flag" "$out" "d['managed'] is False"
check "get_config: both destinations emitted" "$out" "len(d['outputs']) == 2"
check "get_config: destination fields correct" "$out" \
	"d['outputs'][1]['address'] == '198.51.100.7:5000' and d['outputs'][1]['weight'] == '2'"

# --- status (no ubus/jsonfilter off-device -> must still be valid JSON) ---
out=$(FUNCTIONS_SH="$stub" sh "$plugin" call status)
check "status: valid JSON with running=false when not running" "$out" \
	"d['running'] is False and d['pid'] == ''"

# --- unknown method must not crash ---
out=$(FUNCTIONS_SH="$stub" sh "$plugin" call nope)
check "unknown method returns {}" "$out" "d == {}"

# ======================================================================
# write path
# ======================================================================

echo
echo "-- managed gate --"

rm -f "$tmp"/uci*
out=$(run 0 reconcile '{"listen_url":"rist://0.0.0.0:6000"}')
check "unmanaged reconcile is refused" "$out" \
	"d['ok'] is False and d['error'] == 'unmanaged'"
if [ -f "$tmp/uci" ]; then
	echo "  FAIL unmanaged reconcile changed no config"
	fails=$((fails + 1))
else
	echo "  OK   unmanaged reconcile changed no config"
fi

echo
echo "-- reconcile --"

rm -f "$tmp"/uci*
out=$(run 1 reconcile '{"listen_url":"rist://0.0.0.0:6000"}')
check "managed reconcile succeeds" "$out" "d['ok'] is True"
check_log "reconcile sets listen_url" "$tmp/uci" "set rist2rist.main.listen_url=rist://0.0.0.0:6000"

rm -f "$tmp"/uci*
out=$(run 1 reconcile '{"outputs":[{"address":"203.0.113.9:5000","interface":"wan","weight":"1"}]}')
check "reconcile with outputs succeeds" "$out" "d['ok'] is True"
check_log "reconcile adds a destination section" "$tmp/uci" "add rist2rist destination"
check_log "reconcile sets the output address" "$tmp/uci" "set rist2rist.cfg1.address=203.0.113.9:5000"
check_log "reconcile commits" "$tmp/uci" "commit rist2rist"

echo
echo "-- set_config --"

rm -f "$tmp"/uci*
out=$(run 1 set_config '{"recovery":{"buffer_max":"9000"},"enabled":true}')
check "set_config applies recovery + enabled" "$out" "d['ok'] is True"
check_log "set_config sets buffer_max" "$tmp/uci" "set rist2rist.main.buffer_max=9000"
check_log "set_config sets enabled=1" "$tmp/uci" "set rist2rist.main.enabled=1"

echo
echo "-- the two rules the bridge enforces itself --"

rm -f "$tmp"/uci*
out=$(run 1 reconcile '{"listen_url":"rist://203.0.113.5:5000?secret=abc123"}')
check "a URL carrying a secret is rejected" "$out" \
	"d['ok'] is False and d['error'] == 'secret_in_url'"
check_no_log "rejected URL is never committed" "$tmp/uci" "commit"

rm -f "$tmp"/uci*
out=$(run 1 reconcile '{"secret":"abc123"}')
check "a secret-bearing field is rejected" "$out" \
	"d['ok'] is False and d['error'] == 'secret_field'"

rm -f "$tmp"/uci*
out=$(run 1 reconcile '{"listen_url":"rist://0.0.0.0:6000","evil":"x"}')
check "an unknown field is rejected, not ignored" "$out" \
	"d['ok'] is False and d['error'] == 'unknown_field'"

rm -f "$tmp"/uci*
out=$(run 1 reconcile '{"profile":"2"}')
check "reconcile may not set profile (narrower than set_config)" "$out" \
	"d['ok'] is False and d['error'] == 'unknown_field'"

echo
echo "-- reload --"

rm -f "$tmp/reload"
out=$(run 1 reload '')
check "managed reload succeeds" "$out" "d['ok'] is True and d['reloaded'] is True"
check_log "reload invoked the service entry point" "$tmp/reload" "reload"

rm -f "$tmp/reload"
out=$(run 0 reload '')
check "unmanaged reload is refused" "$out" "d['ok'] is False"

echo
if [ "$fails" -eq 0 ]; then
	echo "ALL PASS"
else
	echo "$fails FAILED"
	exit 1
fi
