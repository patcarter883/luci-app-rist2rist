#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Pat Carter

# Off-device test for the bridge's mDNS advertisement (DT-19 discovery).
#
#   sh tests/mdns-selftest.sh
#
# Sources the init script's own functions, using the SAME config_* stub the plugin
# selftest uses, and asserts the published TXT record. That record IS the DT-21
# contract the encoder reads, so getting it wrong is silent: a mismatched service
# name or a missing fingerprint means discovery finds nothing, or a claimed bridge
# looks claimable. Needs python3.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
fails=0

chmod +x "$here"/bin/* 2>/dev/null || true
PATH="$here/bin:$PATH"
export PATH

# shellcheck source=/dev/null
. "$here/stub-functions.sh"
# shellcheck source=/dev/null
. "$here/../files/rist2rist.init"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# The init hardcodes /etc/umdns; point it at the scratch dir.
MDNS_SERVICE_FILE="$tmp/rist2rist.json"

# The token a CLAIMED bridge was claimed with, and the hash the plugin stores.
TOKEN='test-token-abcdefghijklmnop'
TOKEN_HASH=$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)

assert() { # assert <name> <python expression over d (parsed advertisement)>
	if python3 -c "
import json
d = json.load(open('$MDNS_SERVICE_FILE'))
assert $2
" 2>/dev/null; then
		printf '  OK   %s\n' "$1"
	else
		printf '  FAIL %s\n' "$1"
		fails=$((fails + 1))
	fi
}

echo "-- a VIRGIN bridge: advertised, and nothing that would block a claim --"
STUB_main_pair_token_hash=""
STUB_main_managed=0
write_mdns_service 5000

assert "the advertisement is valid JSON with one instance" "len(d) == 1"
assert "the instance is a rist2rist-<mac> label" "list(d)[0].startswith('rist2rist-')"
assert "the service is _obr-rist._udp (what the encoder browses)" \
	"list(d.values())[0]['service'] == '_obr-rist._udp'"
assert "the SRV port is the RIST listen port" "list(d.values())[0]['port'] == 5000"
assert "it reports api=1" "'api=1' in list(d.values())[0]['txt']"
assert "it reports claimed=0" "'claimed=0' in list(d.values())[0]['txt']"
assert "it reports managed=0" "'managed=0' in list(d.values())[0]['txt']"
assert "it publishes the WEB port, not the RIST port" \
	"any(t.startswith('api_port=') for t in list(d.values())[0]['txt'])"
# The security-critical one: a virgin bridge must publish NO fingerprint, or an
# encoder with no token would read it as claimed and refuse to claim it.
assert "it publishes NO fingerprint while unclaimed" \
	"not any(t.startswith('fingerprint=') for t in list(d.values())[0]['txt'])"

echo
echo "-- a CLAIMED bridge: a fingerprint, so it cannot be taken again --"
STUB_main_pair_token_hash="$TOKEN_HASH"
STUB_main_managed=1
write_mdns_service 5000

assert "it reports claimed=1" "'claimed=1' in list(d.values())[0]['txt']"
assert "it reports managed=1" "'managed=1' in list(d.values())[0]['txt']"
assert "it publishes a fingerprint" \
	"any(t.startswith('fingerprint=') for t in list(d.values())[0]['txt'])"
assert "the fingerprint is the first 16 chars of the stored hash" \
	"('fingerprint=$(printf '%s' "$TOKEN_HASH" | cut -c1-16)') in list(d.values())[0]['txt']"

# H2: the advertisement is PUBLIC. Neither the token nor the full hash it is
# derived from may appear in it -- only the truncated fingerprint.
if grep -q "$TOKEN_HASH" "$MDNS_SERVICE_FILE" || grep -q "$TOKEN" "$MDNS_SERVICE_FILE"; then
	printf '  FAIL the token or its full hash is published in the advertisement\n'
	fails=$((fails + 1))
else
	printf '  OK   neither the token nor its full hash appears in the advertisement\n'
fi

echo
echo "-- a disabled bridge stops advertising --"
remove_mdns_service
if [ -f "$MDNS_SERVICE_FILE" ]; then
	printf '  FAIL the advertisement survived remove_mdns_service\n'
	fails=$((fails + 1))
else
	printf '  OK   remove_mdns_service removes the advertisement\n'
fi

echo
if [ "$fails" -eq 0 ]; then
	echo "ALL PASS"
else
	echo "$fails FAILED"
	exit 1
fi
