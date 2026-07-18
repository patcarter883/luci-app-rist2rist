# Contributing to luci-app-rist2rist

## License and inbound policy

The LuCI application is licensed **AGPL-3.0-or-later** (see `LICENSE`); the
`rist2rist` tool patch remains **BSD-2-Clause** so it can be upstreamed to
librist. Contributions are accepted under the license of the part they touch —
inbound = outbound. There is no CLA.

Every commit must carry a **Developer Certificate of Origin** sign-off
(<https://developercertificate.org/>):

```
git commit -s
```

> **Note on future policy:** for *substantial* contributions the project may
> in future introduce a contributor license agreement. Any such change will be
> announced in advance and will never apply retroactively to work already
> merged under the DCO.

## Practical notes

- Never commit compiled binaries — CI rejects ELF/PE/Mach-O files.
- Changes to the rist2rist tool patch should stay upstream-friendly
  (BSD-2-Clause, minimal diff against librist `tools/`).
