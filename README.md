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
