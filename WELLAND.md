# welland dnsmasq fork — repo layout

This GitHub repo (`github.com/mithro/dnsmasq`) is a **monorepo of mirrors**: it
holds two upstream projects as separate branch namespaces, plus our own work and
the CI that wires it together. It produces an arm64 `dnsmasq` deb (stock dnsmasq +
streaming-AXFR patch) published to an apt repo at <https://mithro.github.io/dnsmasq/>.

## Branch namespaces

| Namespace | Source | Synced by CI |
|-----------|--------|--------------|
| `master`, `aws`, `rfc7440`, … (bare names) | upstream dnsmasq source (thekelleys `dnsmasq.git`) | yes |
| `mithro/*` | **our** source patches (e.g. `mithro/axfr-streaming`) and the build branch `mithro/welland` | no (excluded) |
| `dnsmasq-debian/kelley/*` | thekelleys' own packaging (`dnsmasq-debian.git`) | yes |
| `dnsmasq-debian/debian/salsa/*` | Debian maintainer git (salsa) | yes |
| `dnsmasq-debian/debian/dgit/*` | Debian archive state (dgit) | yes |
| `dnsmasq-debian/mithro/*` | **our** packaging (`dnsmasq-debian/mithro/welland`) | no (excluded) |

`.github/workflows/sync-upstream.yml` (on the `github-actions` branch) mirrors the
upstream branches daily, never touching the `mithro/*` / `dnsmasq-debian/mithro/*`
namespaces.

## The build branch: `mithro/welland`

`mithro/welland` = pristine upstream `master` + one commit that repoints the
`submodules/dnsmasq-debian` **submodule** at our own repo's
`dnsmasq-debian/mithro/welland` branch (a self-referencing submodule). The
upstream `debian` symlink (`debian -> submodules/dnsmasq-debian/debian`) then
resolves to our Debian packaging, so `dpkg-buildpackage` builds the welland deb:

```
mithro/welland (source)                 dnsmasq-debian/mithro/welland (packaging)
  src/  (pristine dnsmasq, auto-synced)   debian/  (Debian 2.92-1 packaging, Sven Geuer)
  debian -> submodules/.../debian  ───►     patches/series:
  .gitmodules: url=this repo,                 eliminate-privacy-breaches.patch  (Debian)
    branch=dnsmasq-debian/mithro/welland      axfr-streaming.patch              (ours)
```

The source stays pristine; our change rides as the quilt patch
`debian/patches/axfr-streaming.patch` (generated from `mithro/axfr-streaming`).

## The patch

`axfr-streaming.patch` implements RFC 5936 streaming AXFR so dnsmasq can serve
authoritative zones larger than 64KB (e.g. `welland.mithis.com`, ~93KB) to
secondary nameservers. The earlier `+welland2` segfault and `OPT_LOG_ONLY_FAILED`
fixes are gone — both are now upstream.

## CI

- `sync-upstream.yml` (branch `github-actions`): mirror upstreams daily.
- `deb.yml` (branch `mithro/welland`): build the arm64 deb in a `debian:trixie`
  container and publish a GPG-signed apt repo to GitHub Pages. Signing key
  `52BB8AD2DE80FF4C0E80ADA2C587965895C3858B`; the private key is the repo secret
  `APT_GPG_PRIVATE_KEY`.

Versioned `2.93-0+welland1` — sorts above the deployed Debian `2.92-1+welland2`,
so `apt upgrade` on ten64 picks it up.
