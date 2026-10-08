# luci-app-rist2rist

OpenWrt/LuCI application for the **open-broadcast** bonding hop: one RIST
input from the encoder, one RIST peer out per WAN interface (`miface`), all
into a single receiver session port. It builds and installs a
telemetry-relaying `rist2rist` binary (from librist's `tools/`, with local
modifications) plus a LuCI configuration view, a UCI config schema, and a
procd init script.

Part of the open-broadcast stack:

| Repo | Role |
|------|------|
| [`open-broadcast-encoder`](https://github.com/patcarter883/open-broadcast-encoder) | encoder app — NDI/SDP/MPEG-TS in, RIST out |
| **`luci-app-rist2rist`** (this repo) | OpenWrt bonding hop between encoder and receiver |
| [`open-broadcast-receiver`](https://github.com/patcarter883/open-broadcast-receiver) | headless RIST receiver / restreamer |

Bonded links present as **multiple RIST peers on one session port** — the
`miface`-per-WAN outputs of `rist2rist` all target the same receiver
`host:port`. Every RIST hop runs `timing-mode=0` (SOURCE).

## Control API

The bridge is configured over ubus by the encoder through a **narrowed CGI
shim**, not by exposing ubus itself:

- `/www-bridge/ubus` forwards **only** the `rist2rist` object, so the endpoint
  cannot reconfigure anything else on the router. Its own procd-managed uhttpd
  instance (`/etc/init.d/obr-bridge-api`) serves it on the LAN at `api_port`
  (default 8080). This is deliberately **not** `uhttpd -a`, which disables the
  JSON-RPC session check for every ubus object reachable on that port.
- The advertised port comes from `rist2rist.main.api_port`. Advertising LuCI's
  port 80 instead sends clients to a `/ubus` mapping that cannot serve these
  calls.
- A claim token gates state-changing calls. It is minted from
  `head -c 32 /dev/urandom | hexdump …` rather than `base64`, which a stock
  OpenWrt userland does not ship.

The package postinst also restarts `rist2rist` when it is enabled — without
that, an upgrade brings the box back up with the relay stopped.

## RIST recovery window

Every RIST URL this package builds carries `bandwidth=` (Kbps) on **both** the
listen and the output leg. The libRIST default of 100000 assumes a 100 Mbit/s
link, which makes a 5000 ms buffer exceed the Advanced-profile NACK window
(~47492 packets against 32768): the tail is unrecoverable and the daemon warns
on every start. `maxbitrate` (default 20000 kbit/s) keeps the same buffer inside
the window. The URL parameter is `bandwidth` — `recovery-maxbitrate` is the
*library*-level name and the URL parser rejects it outright.

## Licensing

- The **LuCI application** (JS view, UCI schema, init script, packaging) is
  licensed under the **GNU Affero General Public License v3.0 or later**
  (AGPL-3.0-or-later). See [`LICENSE`](LICENSE).
- The **rist2rist tool patch** (the modifications to librist's
  `tools/rist2rist.c` built by this package) remains **BSD-2-Clause**, the
  license of upstream librist, so it stays upstreamable.

The OpenWrt package metadata accordingly declares
`PKG_LICENSE:=AGPL-3.0-or-later AND BSD-2-Clause`.

Contributions are accepted under the same split with a DCO sign-off — see
[`CONTRIBUTING.md`](CONTRIBUTING.md).
