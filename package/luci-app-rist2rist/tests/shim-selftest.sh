#!/bin/sh
# Off-device test for the bridge's control endpoint: files/www-bridge/ubus.
#
#   sh tests/shim-selftest.sh
#
# The endpoint is the CGI that serves http://<lan-ip>:<api_port>/ubus -- the URL
# the encoder builds. It narrows the surface to the rist2rist object, and it must
# then accept exactly the methods the PLUGIN advertises and no more.
#
# Why this suite exists: the shim used to carry its own hardcoded method list,
# and `calibrate` was added to the plugin (and to rpcd's ACL) but not to that
# list. Every `ubus call` worked and every off-device test passed, while the only
# path the ENCODER actually uses answered "unknown method" -- found by pressing
# the button on the real box, not by any test. So the assertion here is not "these
# methods work" but "the accepted set IS the plugin's advertised set", which is
# what makes a second list impossible to keep in step and therefore detectable.
#
# Needs python3 (the jsonfilter double is Python). The shim and plugin are POSIX
# sh.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
shim="$here/../files/www-bridge/ubus"
plugin="$here/../root/usr/libexec/rpcd/rist2rist"
fails=0

chmod +x "$here"/bin/* "$here"/bin-shim/* 2>/dev/null || true
# bin-shim first: it supplies the `ubus` double this suite needs, while the
# jsonfilter double (real JSON parsing) comes from tests/bin.
PATH="$here/bin-shim:$here/bin:$PATH"
export PATH

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# call <method> [object] -> the shim's reply on stdout
call() {
	method="$1"
	obj="${2:-rist2rist}"
	printf '{"jsonrpc":"2.0","id":7,"method":"call","params":["00000000000000000000000000000000","%s","%s",{}]}' \
		"$obj" "$method" | "$shim"
}

# body <reply> -> the JSON after the CGI headers
body() {
	printf '%s' "$1" | tr -d '\r' | awk 'f{print} /^$/{f=1}'
}

# reply_has_result <reply> -> 0 when the shim passed the call through
reply_has_result() {
	body "$1" | python3 -c '
import json,sys
r=json.load(sys.stdin)
assert "result" in r and r["result"][0]==0, r
' 2>/dev/null
}

# reply_refused <reply> <code> -> 0 when the shim refused with that JSON-RPC code
reply_refused() {
	body "$1" | python3 -c "
import json,sys
r=json.load(sys.stdin)
assert r.get('error',{}).get('code')==$2, r
" 2>/dev/null
}

expect() { # expect <what> <0-or-1>
	if [ "$2" -eq 0 ]; then
		echo "ok   - $1"
	else
		echo "FAIL - $1"
		fails=$((fails + 1))
	fi
}

# The plugin's own advertised surface, read from the plugin itself. This is the
# single definition the shim is required to agree with.
FUNCTIONS_SH="$here/stub-functions.sh"
export FUNCTIONS_SH
advertised=$(sh "$plugin" list)
methods=$(printf '%s' "$advertised" | python3 -c '
import json,sys
print(" ".join(sorted(json.load(sys.stdin).keys())))
')
echo "plugin advertises: $methods"

# --- the surface agrees with the plugin, method by method ---------------------
for m in $methods; do
	out=$(call "$m")
	if reply_has_result "$out"; then r=0; else r=1; fi
	expect "the shim accepts '$m' (the plugin advertises it)" "$r"
done

# The specific regression, named: the encoder's calibrate call must reach the
# plugin. Called out separately so a failure says which method broke, not just
# that the sets diverged.
out=$(call calibrate)
if reply_has_result "$out"; then r=0; else r=1; fi
expect "calibrate reaches the plugin through the endpoint" "$r"

# --- and nothing beyond it ----------------------------------------------------
out=$(call reboot)
if reply_refused "$out" -32601; then r=0; else r=1; fi
expect "a method the plugin does NOT advertise is refused" "$r"

out=$(call get_config network)
if reply_refused "$out" -32601; then r=0; else r=1; fi
expect "another object is refused" "$r"

# A bogus method must not be accepted merely because the plugin's list is an
# object with keys: the check is membership, not "the list parsed".
out=$(call definitely_not_a_method)
if reply_refused "$out" -32601; then r=0; else r=1; fi
expect "an invented method is refused" "$r"

echo
if [ "$fails" -eq 0 ]; then
	echo "shim-selftest: all assertions pass"
else
	echo "shim-selftest: $fails assertion(s) FAILED"
	exit 1
fi
