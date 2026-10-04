#!/bin/sh
# Off-device test for the rist2rist rpcd plugin. It stubs /lib/functions.sh and
# checks that the plugin emits valid JSON with the fields the encoder consumes.
#
#   sh tests/rpcd-selftest.sh
#
# Exits non-zero on the first failure. Needs python3 (JSON validation only; the
# plugin itself does not).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
plugin="$here/../root/usr/libexec/rpcd/rist2rist"
stub="$here/stub-functions.sh"
fails=0

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

echo "== rist2rist rpcd plugin self-test =="

# --- list ---
out=$(FUNCTIONS_SH="$stub" sh "$plugin" list)
check "list enumerates both methods" "$out" \
	"'status' in d and 'get_config' in d"

# --- get_config ---
out=$(FUNCTIONS_SH="$stub" sh "$plugin" call get_config)
check "get_config: enabled is a JSON bool" "$out" "d['enabled'] is True"
check "get_config: listen_url carried" "$out" "d['listen_url'] == 'rist://0.0.0.0:5000'"
check "get_config: recovery block present" "$out" "d['recovery']['reorder_buffer'] == '20'"
check "get_config: telemetry target carried" "$out" "d['telemetry']['target'] == '192.0.2.10:9999'"
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

echo
if [ "$fails" -eq 0 ]; then
	echo "ALL PASS"
else
	echo "$fails FAILED"
	exit 1
fi
