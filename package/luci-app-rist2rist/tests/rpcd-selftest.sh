#!/bin/sh
# Off-device test for the rist2rist rpcd plugin.
#
#   sh tests/rpcd-selftest.sh
#
# Stubs /lib/functions.sh, and puts tests/bin (jsonfilter, uci, reload-stub) ahead
# on PATH so the claim and write paths can be exercised without a router. Needs
# python3 -- the jsonfilter double is Python and the assertions use it. The plugin
# itself is POSIX sh.
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

# The token a CLAIMED bridge accepts. The stub reports its sha256 as the stored
# hash, exactly as the plugin does, so the comparison path is the real one.
TOKEN='test-token-abcdefghijklmnop'
TOKEN_HASH=$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)

py() { # py <json> <expression-over-d> -> 0 if the assertion holds
	printf '%s' "$1" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert $2
" 2>/dev/null
}

jget_field() { # jget_field <json> <key>
	printf '%s' "$1" | python3 -c "import json,sys;print(json.load(sys.stdin).get('$2',''))" 2>/dev/null || echo ""
}

check() { # check <label> <json> <expression>
	if py "$2" "$3"; then
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

# --- bridge states -------------------------------------------------------
claimed()    { export STUB_MAIN_TOKEN_HASH="$TOKEN_HASH"; }
unclaimed()  { unset STUB_MAIN_TOKEN_HASH 2>/dev/null || true; }
virgin()     { export STUB_DESTINATIONS=0; }
configured() { unset STUB_DESTINATIONS 2>/dev/null || true; }

# run <managed 0|1> <method> [body] -- the exported state above is inherited.
# LINK_SECRET_FILE is redirected into the sandbox: the real path is /etc, and a
# test must never write there.
run() {
	if [ -n "${3:-}" ]; then
		printf '%s' "$3" | env UCI_STUB_LOG="$tmp/uci" STUB_MAIN_MANAGED="$1" \
			FUNCTIONS_SH="$stub" RELOAD_CMD="$here/bin/reload-stub" \
			RELOAD_STUB_LOG="$tmp/reload" LINK_SECRET_FILE="$tmp/link_secret" \
			PROC_ROOT="$tmp/proc" \
			sh "$plugin" call "$2" || true
	else
		env UCI_STUB_LOG="$tmp/uci" STUB_MAIN_MANAGED="$1" \
			FUNCTIONS_SH="$stub" RELOAD_CMD="$here/bin/reload-stub" \
			RELOAD_STUB_LOG="$tmp/reload" LINK_SECRET_FILE="$tmp/link_secret" \
			PROC_ROOT="$tmp/proc" \
			sh "$plugin" call "$2" </dev/null || true
	fi
}

# tb '<json>' -- the same object with the valid token added, so that a test body
# only has to express the field under test.
tb() {
	case "${1:-}" in
		''|'{}') printf '{"token":"%s"}' "$TOKEN" ;;
		*)       printf '{"token":"%s",%s' "$TOKEN" "${1#\{}" ;;
	esac
}

echo "== rist2rist rpcd plugin self-test =="

# --- list ---
out=$(FUNCTIONS_SH="$stub" sh "$plugin" list)
check "list enumerates the read methods" "$out" "'status' in d and 'get_config' in d"
check "list enumerates the write methods" "$out" \
	"'set_config' in d and 'reconcile' in d and 'reload' in d"
check "list enumerates the claim and release" "$out" "'claim' in d and 'release' in d"

# --- unknown method must not crash (and is refused before auth, like any method) ---
out=$(FUNCTIONS_SH="$stub" sh "$plugin" call nope)
check "an unknown method is refused without a token" "$out" "d['ok'] is False"
configured; claimed
out=$(run 1 nope "$(tb '{}')")
check "an unknown method returns {} once authenticated" "$out" "d == {}"

# ======================================================================
# claim
# ======================================================================

echo
echo "-- claim --"

virgin; unclaimed
rm -f "$tmp"/uci*
out=$(run 0 claim '{"device_uid":"enc-0001"}')
check "a virgin, unclaimed bridge can be claimed" "$out" \
	"d['ok'] is True and d['managed'] is True"
check "the claim returns a 32-character token" "$out" "len(d['token']) == 32"
claimed_token=$(jget_field "$out" token)
check_log "claim stores the managed flag" "$tmp/uci" "set rist2rist.main.managed=1"
check_log "claim records who claimed it" "$tmp/uci" "set rist2rist.main.claimed_by=enc-0001"
check_log "claim commits" "$tmp/uci" "commit rist2rist"
# Only the HASH may be stored: the bridge must never be able to re-reveal a token.
check_log "claim stores the token hash" "$tmp/uci" "set rist2rist.main.pair_token_hash="
check_no_log "claim never stores the plaintext token" "$tmp/uci" "$claimed_token"

configured
rm -f "$tmp"/uci*
out=$(run 0 claim '{"device_uid":"enc-0002"}')
check "a configured bridge cannot be claimed" "$out" \
	"d['ok'] is False and d['error'] == 'not_virgin'"

virgin; claimed
rm -f "$tmp"/uci*
out=$(run 0 claim '{"device_uid":"enc-0003"}')
check "claiming is refused when a token already exists" "$out" \
	"d['ok'] is False and d['error'] == 'already_claimed'"

# ======================================================================
# the token gate
# ======================================================================

echo
echo "-- the token gate --"

configured; unclaimed
rm -f "$tmp"/uci*
out=$(run 1 get_config '{}')
check "an unclaimed bridge refuses everything" "$out" \
	"d['ok'] is False and d['error'] == 'unclaimed'"

configured; claimed
out=$(run 1 get_config '{}')
check "a claimed bridge refuses a call with no token" "$out" \
	"d['ok'] is False and d['error'] == 'token_required'"

out=$(run 1 get_config '{"token":"not-the-token"}')
check "a wrong token is refused" "$out" \
	"d['ok'] is False and d['error'] == 'bad_token'"

out=$(run 1 get_config "$(tb '{}')")
check "the right token is accepted" "$out" "d['claimed'] is True"
# strip_token must have removed it, and nothing may echo it back.
check "get_config never echoes the token back" "$out" "'token' not in d"

# ======================================================================
# read, with a token
# ======================================================================

echo
echo "-- read --"

configured; claimed
out=$(run 1 get_config "$(tb '{}')")
check "get_config: enabled is a JSON bool" "$out" "d['enabled'] is True"
check "get_config: listen_url carried" "$out" "d['listen_url'] == 'rist://0.0.0.0:5000'"
check "get_config: recovery block present" "$out" "d['recovery']['reorder_buffer'] == '20'"
check "get_config: both destinations emitted" "$out" "len(d['outputs']) == 2"
check "get_config: a destination is ADDRESS ONLY" "$out" \
	"d['outputs'][1]['address'] == '198.51.100.7:5000' and 'interface' not in d['outputs'][1] and 'weight' not in d['outputs'][1]"
check "get_config: uplinks reported" "$out" "len(d['uplinks']) == 2"
check "get_config: uplink interface + weight carried" "$out" \
	"d['uplinks'][0]['interface'] == 'lo' and d['uplinks'][1]['weight'] == '3'"
check "get_config: uplink presence is reported" "$out" \
	"d['uplinks'][0]['present'] is True and d['uplinks'][1]['present'] is False"

# status needs no ubus/jsonfilter off-device, so it must still emit valid JSON.
out=$(run 1 status "$(tb '{}')")
check "status: valid JSON with running=false when not running" "$out" \
	"d['running'] is False and d['pid'] == ''"

# ======================================================================
# write, with a token
# ======================================================================

echo
echo "-- the managed kill-switch --"

configured; claimed
rm -f "$tmp"/uci*
out=$(run 0 reconcile "$(tb '{"listen_url":"rist://0.0.0.0:6000"}')")
check "managed=0 still refuses a token-holding caller" "$out" \
	"d['ok'] is False and d['error'] == 'unmanaged'"
if [ -f "$tmp/uci" ]; then
	echo "  FAIL the kill-switch changed no config"
	fails=$((fails + 1))
else
	echo "  OK   the kill-switch changed no config"
fi

echo
echo "-- reconcile --"

configured; claimed
rm -f "$tmp"/uci*
out=$(run 1 reconcile "$(tb '{"listen_url":"rist://0.0.0.0:6000"}')")
check "reconcile succeeds with a token" "$out" "d['ok'] is True"
check_log "reconcile sets listen_url" "$tmp/uci" "set rist2rist.main.listen_url=rist://0.0.0.0:6000"

rm -f "$tmp"/uci*
out=$(run 1 reconcile "$(tb '{"outputs":[{"address":"203.0.113.9:5000"}]}')")
check "reconcile with an address-only output succeeds" "$out" "d['ok'] is True"
check_log "reconcile adds a destination section" "$tmp/uci" "add rist2rist destination"
check_log "reconcile sets the output address" "$tmp/uci" "set rist2rist.cfg1.address=203.0.113.9:5000"
check_log "reconcile commits" "$tmp/uci" "commit rist2rist"
# The token must never land in a config field.
check_no_log "the token is stripped before the applier" "$tmp/uci" "$TOKEN"

# The uplink list is LOCAL configuration. A caller naming an interface, or a
# weight, must be REJECTED rather than silently ignored -- otherwise an encoder
# could believe it had pinned a leg the bridge dropped.
rm -f "$tmp"/uci*
out=$(run 1 reconcile "$(tb '{"outputs":[{"address":"203.0.113.9:5000","interface":"wwan0"}]}')")
check "reconcile rejects an interface on a destination" "$out" \
	"d['ok'] is False and d['error'] == 'unknown_field'"

out=$(run 1 reconcile "$(tb '{"listen_url":"rist://0.0.0.0:6000","weight":"5"}')")
check "reconcile rejects a weight" "$out" \
	"d['ok'] is False and d['error'] == 'unknown_field'"

out=$(run 1 set_config "$(tb '{"outputs":[{"address":"203.0.113.9:5000","weight":"5"}]}')")
check "set_config rejects a weight on a destination" "$out" \
	"d['ok'] is False and d['error'] == 'unknown_field'"

# rpcd PREPENDS `ubus_rpc_session` to every exec call's arguments. Left in the
# body, the field whitelist rejects EVERY write with `unknown_field` -- and no
# off-device test caught it, because there is no rpcd in this path to inject the
# key. Found by a real ubus call against a real rpcd on an OpenWrt VM.
rm -f "$tmp"/uci*
out=$(run 1 reconcile "$(tb '{"ubus_rpc_session":"00000000000000000000000000000000","listen_url":"rist://0.0.0.0:7000"}')")
check "reconcile tolerates rpcd's injected ubus_rpc_session" "$out" "d['ok'] is True"
check_log "and still applies listen_url" "$tmp/uci" "set rist2rist.main.listen_url=rist://0.0.0.0:7000"
check_no_log "the injected key never reaches a config field" "$tmp/uci" "ubus_rpc_session"

# The same key FIRST, with the token second -- rpcd's real ordering, which the
# tb() helper cannot produce because it always puts the token first.
rm -f "$tmp"/uci*
out=$(run 1 reconcile "{\"ubus_rpc_session\":\"00000000000000000000000000000000\",\"token\":\"$TOKEN\",\"listen_url\":\"rist://0.0.0.0:7001\"}")
check "reconcile tolerates a leading ubus_rpc_session" "$out" "d['ok'] is True"
check_log "and applies listen_url in that ordering too" "$tmp/uci" "set rist2rist.main.listen_url=rist://0.0.0.0:7001"

echo
echo "-- set_config --"

rm -f "$tmp"/uci*
out=$(run 1 set_config "$(tb '{"recovery":{"buffer_max":"9000"},"enabled":true}')")
check "set_config applies recovery + enabled" "$out" "d['ok'] is True"
check_log "set_config sets buffer_max" "$tmp/uci" "set rist2rist.main.buffer_max=9000"
check_log "set_config sets enabled=1" "$tmp/uci" "set rist2rist.main.enabled=1"

echo
echo "-- the rules the bridge enforces itself --"

rm -f "$tmp"/uci*
out=$(run 1 reconcile "$(tb '{"listen_url":"rist://203.0.113.5:5000?secret=abc123"}')")
check "a URL carrying a secret is rejected" "$out" \
	"d['ok'] is False and d['error'] == 'secret_in_url'"
check_no_log "a rejected URL is never committed" "$tmp/uci" "commit"

rm -f "$tmp"/uci*
out=$(run 1 reconcile "$(tb '{"secret":"abc123"}')")
check "a secret-bearing field is rejected" "$out" \
	"d['ok'] is False and d['error'] == 'secret_field'"

rm -f "$tmp"/uci*
out=$(run 1 reconcile "$(tb '{"listen_url":"rist://0.0.0.0:6000","evil":"x"}')")
check "an unknown field is rejected, not ignored" "$out" \
	"d['ok'] is False and d['error'] == 'unknown_field'"

rm -f "$tmp"/uci*
out=$(run 1 reconcile "$(tb '{"profile":"2"}')")
check "reconcile may not set profile (narrower than set_config)" "$out" \
	"d['ok'] is False and d['error'] == 'unknown_field'"

echo
echo "-- reload --"

rm -f "$tmp/reload"
out=$(run 1 reload "$(tb '{}')")
check "reload succeeds with a token" "$out" "d['ok'] is True and d['reloaded'] is True"
check_log "reload invoked the service entry point" "$tmp/reload" "reload"

echo
echo "-- release (portal-side recovery, without router access) --"

configured; claimed
rm -f "$tmp"/uci*
out=$(run 1 release "$(tb '{}')")
check "release succeeds with a token" "$out" "d['ok'] is True and d['released'] is True"
check_log "release clears the token" "$tmp/uci" "set rist2rist.main.pair_token_hash="
check_log "release clears managed" "$tmp/uci" "set rist2rist.main.managed=0"
check_log "release commits" "$tmp/uci" "commit rist2rist"

out=$(run 1 release '{"token":"not-the-token"}')
check "release without a valid token is refused" "$out" \
	"d['ok'] is False and d['error'] == 'bad_token'"

echo
echo "-- link secret (write-only) --"

configured; claimed
rm -f "$tmp"/uci* "$tmp/link_secret"

out=$(run 1 set_link_secret "$(tb '{"link_secret":"s3cret-abcdefghij"}')")
check "a valid link secret is accepted" "$out" \
	"d['ok'] is True and d['link_secret_set'] is True"
check "the acknowledgement never echoes the secret" "$out" "'s3cret' not in json.dumps(d)"

if [ -f "$tmp/link_secret" ]; then
	if [ "$(stat -c %a "$tmp/link_secret")" = "600" ]; then
		echo "  OK   the secret is stored with mode 600"
	else
		echo "  FAIL the secret file mode is $(stat -c %a "$tmp/link_secret"), expected 600"
		fails=$((fails + 1))
	fi
	if [ "$(cat "$tmp/link_secret")" = "s3cret-abcdefghij" ]; then
		echo "  OK   the secret file holds exactly the secret"
	else
		echo "  FAIL the secret file content is wrong"
		fails=$((fails + 1))
	fi
else
	echo "  FAIL the secret file was not written"
	fails=$((fails + 1))
fi

out=$(run 1 get_config "$(tb '{}')")
check "get_config reports only THAT a secret is set" "$out" "d['link_secret_set'] is True"
check "get_config never contains the secret" "$out" "'s3cret' not in json.dumps(d)"

# status reports the daemon's real argv from the kernel, and that argv now
# carries the output URL -- so a READ method must not hand the key back. The ubus
# double reports a fixed pid; the crafted cmdline is that process's argv.
mkdir -p "$tmp/proc/4242"
printf 'rist2rist\000-i\000rist://@0.0.0.0:5000\000-o\000rist://receiver:5000?bandwidth=20000&secret=s3cret-abcdefghij\000' \
	> "$tmp/proc/4242/cmdline"
out=$(run 1 status "$(tb '{}')")
check "status reports the running command line" "$out" \
	"d['running'] is True and 'receiver:5000' in d['argv']"
check "status redacts the secret's value" "$out" "'secret=REDACTED' in d['argv']"
check "status never contains the secret" "$out" "'s3cret' not in json.dumps(d)"

out=$(run 1 set_link_secret "$(tb '{"link_secret":"short"}')")
check "an implausibly short secret is refused" "$out" \
	"d['ok'] is False and d['error'] == 'bad_link_secret'"

out=$(run 1 set_link_secret "$(tb '{"link_secret":"bad secret with spaces"}')")
check "a secret with unsafe characters is refused" "$out" \
	"d['ok'] is False and d['error'] == 'bad_link_secret'"

out=$(run 1 set_link_secret "$(tb '{"link_secret":"goodsecret123","aes_type":"256"}')")
check "a secret cannot smuggle fields past the whitelist" "$out" \
	"d['ok'] is False and d['error'] == 'unknown_field'"

out=$(run 1 set_config "$(tb '{"link_secret":"goodsecret123"}')")
check "set_config does not accept a link secret" "$out" \
	"d['ok'] is False and d['error'] == 'unknown_field'"

out=$(run 1 set_config "$(tb '{"secret":"goodsecret123"}')")
check "set_config still refuses a secret-bearing URL field" "$out" \
	"d['ok'] is False and d['error'] == 'secret_field'"

out=$(run 0 set_link_secret "$(tb '{"link_secret":"goodsecret123"}')")
check "an unmanaged bridge refuses a link secret" "$out" \
	"d['ok'] is False and d['error'] == 'unmanaged'"

out=$(run 1 set_link_secret '{"link_secret":"goodsecret123"}')
check "a link secret without a token is refused" "$out" \
	"d['ok'] is False and d['error'] == 'token_required'"

out=$(run 1 set_link_secret "$(tb '{"link_secret":""}')")
check "an empty secret clears it" "$out" "d['ok'] is True and d['link_secret_set'] is False"
if [ -f "$tmp/link_secret" ]; then
	echo "  FAIL the cleared secret file still exists"
	fails=$((fails + 1))
else
	echo "  OK   clearing removes the secret file"
fi

echo
if [ "$fails" -eq 0 ]; then
	echo "ALL PASS"
else
	echo "$fails FAILED"
	exit 1
fi
