# Stub of the OpenWrt /lib/functions.sh config_* helpers, enough to exercise the
# rist2rist rpcd plugin off-device. Values mirror files/rist2rist.config, with a
# couple of overrides so the assertions are non-trivial.
#
# dash/zsh local variables are dynamically scoped, so `eval "$1=..."` here
# assigns the caller's own local -- exactly how the real config_get behaves.
#
# STUB_MAIN_MANAGED selects the managed flag so the write path can be exercised in
# both states without editing this file.

config_load() { :; }

# config_get <var> <section> <option> [default]
config_get() {
	eval "$1=\"\${STUB_${2}_${3}:-$4}\""
}

# config_get_bool <var> <section> <option> [default]
config_get_bool() {
	eval "$1=\"\${STUB_${2}_${3}:-${4:-0}}\""
}

# config_foreach <callback> <type>
config_foreach() {
	local cb="$1" type="$2"
	[ "$type" = "destination" ] || return 0
	# STUB_DESTINATIONS=0 models a VIRGIN bridge (no outputs configured), which is
	# the only state in which a claim is accepted.
	[ "${STUB_DESTINATIONS:-1}" = "0" ] && return 0
	eval "$cb dst_au"
	eval "$cb dst_eu"
}

# --- main ---
STUB_main_enabled=1
STUB_main_managed="${STUB_MAIN_MANAGED:-0}"
# STUB_MAIN_TOKEN_HASH = sha256 of a claimed bridge's token. Empty = unclaimed.
STUB_main_pair_token_hash="${STUB_MAIN_TOKEN_HASH:-}"
STUB_main_listen_url="rist://0.0.0.0:5000"
STUB_main_profile="advanced"
STUB_main_out_profile="advanced"
STUB_main_verbose_log=0
STUB_main_loglevel="6"
STUB_main_buffer_min="2000"
STUB_main_buffer_max="16000"
STUB_main_rtt_min="100"
STUB_main_rtt_max="980"
STUB_main_reorder_buffer="20"
STUB_main_telemetry_enabled=1
STUB_main_telemetry_target="192.0.2.10:9999"

STUB_dst_au_address="203.0.113.5:5000"
STUB_dst_au_interface="wan"
STUB_dst_au_weight="1"
STUB_dst_eu_address="198.51.100.7:5000"
STUB_dst_eu_interface="wanb"
STUB_dst_eu_weight="2"
