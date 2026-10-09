#!/bin/sh
##########################################################################
# rist2rist-wan.sh -- THE definition of "this box's WAN links" (DT-27.3).
#
# SOURCED, not executed: define the functions below, print nothing, change
# nothing. Sourced by BOTH the init script (to bind the RIST output leg to the
# interface CAKE shapes, even on a single-WAN box) and the measurement helper (to
# enumerate every WAN link to measure), so the two can never drift apart.
#
# READ-ONLY BY CONSTRUCTION. Nothing here writes config, reconfigures anything,
# logs, or touches the network: the only external call is a `uci` read.
#
# A WAN link is, BY DEFINITION, the UNION of:
#   (a) every interface named in a `config uplink` section -- the operator's
#       explicit bonding selection, which must never be dropped from the set; and
#   (b) every /etc/config/network interface whose proto is a WAN proto
#       (modemmanager|dhcp|pppoe|ppp|ncm|qmi|3g) -- the links the router itself
#       has. `lan`/`loopback` declare proto `static`, so they fall out WITHOUT
#       consulting the firewall, whose zone list is a CONSUMER of this config
#       rather than its source; deriving routing from it would invert that.
#
# Name-based inference (`wwanN`) is deliberately NOT used: `wwan0` is a genuine
# WAN link with no modem attached, and a name rule breaks the moment a modem is
# renamed. A single-WAN box is a normal leg set of ONE, not an empty one.
#
# Test hooks (unset on a device):
#   WAN_LIB_NETWORK_FIXTURE -- a file holding `uci -q show network`-style text, so
#                              the resolver can be exercised off-device.
#   WAN_LIB_SYSFS           -- the netdev root (default /sys/class/net), so a test
#                              can model a present or absent WAN link with no modem.
##########################################################################

WAN_LIB_SYSFS="${WAN_LIB_SYSFS:-/sys/class/net}"

# The interfaces named in `config uplink` sections, one per line. config_foreach
# runs its callback in THIS shell (it does not fork), and wan_links calls this
# inside a producer subshell, so stdout is the channel.
_wan_declared_iface() {
    local cfg="$1" interface
    config_get interface "$cfg" 'interface'
    [ -n "$interface" ] || return 0
    printf '%s\n' "$interface"
}

# The /etc/config/network interfaces whose proto is a WAN proto, one per line.
#
# Parsed from `uci show network` documentation text. Only an interface section
# carries a `.proto` option, so a section with a WAN proto IS a WAN interface and
# no section-type header is needed.
#
# The value bound to `miface=` must be a real NETDEV. A bare-name `device`/`ifname`
# (a `config interface 'wan'` over `eth1`) is that netdev and wins over the section
# name. A `device` holding a PATH is NOT: with proto modemmanager it is the modem's
# physical location (`/sys/devices/.../usb1/1-2`) and netifd names the netdev after
# the SECTION. Taking that path would bind a device that cannot exist -- it made
# wan_links_present empty on the production box and silently disabled the very
# binding this file exists to provide. So a path-like value is skipped and the
# section name is used, which is `wwan0`/`wwan1` there.
#
# Anonymous `@interface[n]` keys are not valid netifd config and are left in only
# to be dropped later by the presence check.
_wan_network_iface() {
    if [ -n "${WAN_LIB_NETWORK_FIXTURE:-}" ]; then
        [ -r "$WAN_LIB_NETWORK_FIXTURE" ] || return 0
        cat "$WAN_LIB_NETWORK_FIXTURE"
    else
        uci -q show network 2>/dev/null
    fi | awk -F"'" '
        /^network\.[^.=]+\.proto=/  {
            key = $1; sub(/^network\./, "", key); sec = key; sub(/\..*$/, "", sec)
            proto[sec] = $2; order[n++] = sec; next
        }
        /^network\.[^.=]+\.device=/ {
            key = $1; sub(/^network\./, "", key); sec = key; sub(/\..*$/, "", sec)
            if ($2 !~ /\// && dev[sec] == "") dev[sec] = $2; next
        }
        /^network\.[^.=]+\.ifname=/ {
            key = $1; sub(/^network\./, "", key); sec = key; sub(/\..*$/, "", sec)
            if ($2 !~ /\// && dev[sec] == "") dev[sec] = $2; next
        }
        END {
            for (i = 0; i < n; i++) {
                s = order[i]; p = proto[s]
                if (p == "modemmanager" || p == "dhcp" || p == "pppoe" || \
                    p == "ppp" || p == "ncm" || p == "qmi" || p == "3g")
                    print (dev[s] != "" ? dev[s] : s)
            }
        }
    '
}

# wan_links -- print ONE WAN interface name per line: the unique union of the
# declared uplinks and the router's WAN-proto interfaces. Unique, in first-seen
# order, no trailing blank line, no log output, no side effects.
wan_links() {
    {
        config_foreach _wan_declared_iface uplink
        _wan_network_iface
    } | awk 'NF && !seen[$0]++ { print }'
}

# wan_links_present -- the subset of wan_links whose device EXISTS, one per line.
# Built ON TOP of wan_links so the set itself has exactly one definition. Tests
# /sys/class/net via the same idiom bridge_uid() and the init already use, so
# there is no dependence on ip(8)/ifconfig being present in the image.
wan_links_present() {
    local iface
    wan_links | while IFS= read -r iface; do
        [ -n "$iface" ] || continue
        [ -e "${WAN_LIB_SYSFS}/${iface}" ] || continue
        printf '%s\n' "$iface"
    done
}
