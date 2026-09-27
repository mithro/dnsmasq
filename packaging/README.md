# dnsmasq, packaged for Debian with streaming AXFR

This branch, `packaging`, builds Debian packages of
[dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html) with two changes of
ours: streaming AXFR, so dnsmasq can serve authoritative zones larger than
64 KB to secondary nameservers, and `--dump-config`, which prints the
configuration dnsmasq loaded. They are published as a signed apt
repository at <https://mith.ro/dnsmasq/>.

It follows the "Set A: someone else's code" layout of
[mithro/apt-repo-action's docs/packaging.md](https://github.com/mithro/apt-repo-action/blob/main/docs/packaging.md):
`upstream` is an unmodified mirror of dnsmasq's `master`, and `packaging`
(the default branch) is `upstream` plus our commits, Debian's `debian/`,
this `packaging/` directory and `.github/`.

## What the build follows

| | from | at |
|---|---|---|
| source | `git://thekelleys.org.uk/dnsmasq.git`, branch `master`, mirrored as `upstream` | a9880c59 (v2.93-30-ga9880c59, committed 2026-09-04) |
| `debian/` | Debian's packaging, `git://thekelleys.org.uk/dnsmasq-debian.git` branch `master` (the `Vcs-Git` Debian's own `debian/control` names), mirrored as `dnsmasq-debian/kelley/master` and merged in with its history | 5b343f90, Debian 2.93-3 (2026-09-16) |

The current commits are the ones `git log --first-parent packaging` shows
as "Merge upstream ..." and "Merge Debian packaging ..."; the table says
where the branch started.

## What we change, and why

1. **Streaming AXFR** (`src/auth.c`, `src/dnsmasq.h`, `src/forward.c`;
   the commit "Implement streaming AXFR for large zone transfers", also on
   branch `mithro/axfr-streaming`). Stock dnsmasq builds an AXFR reply in a
   single 64 KB DNS message, so a zone larger than that can't be
   transferred at all. This sends it as a stream of messages (RFC 5936,
   flushing at 60 KB, bracketed by the SOA). ten64 serves
   `welland.mithis.com` (about 93 KB) to its secondaries this way; on
   2026-06-23 an upgrade to Debian's stock 2.93-1 dropped the patch, the
   secondaries stopped syncing, and DNS-01 certificate renewals failed.
   Not yet sent upstream.
2. **`--dump-config`** (`src/dumpconf.c`, `src/option.c`; the commit "Add
   --dump-config option to dump loaded config and exit", from branch
   `mithro/dump-config`, and two fixes after it). Like `--test`, it reads
   every configuration file and exits, but first prints the whole resolved
   configuration in `dnsmasq.conf` syntax, for debugging a configuration
   split over many files (ten64's is in `/etc/dnsmasq.d/`). The dump reads
   back with `--test`. Not yet sent upstream.
3. **Upstream's `debian` submodule and symlink are removed**, so that
   `debian/` is a plain directory at the root (Debian's, merged with its
   history).
4. **`debian/control`**: `Maintainer` is ours and Debian's moves to
   `XSBC-Original-Maintainer`; `Vcs-Git`/`Vcs-Browser` point here. Package
   names are Debian's, so these packages replace Debian's on upgrade.
5. **debhelper compat 13, not 14**: Debian's 2.93-2 moved to compat 14,
   which needs debhelper 14, and trixie has that only in trixie-backports.
   Our commit reverts that one Debian commit, so all three suites build
   from the same tree. Drop the revert once the oldest suite we build has
   debhelper 14.

Debian's own quilt patch (`debian/patches/eliminate-privacy-breaches.patch`)
is still applied by the build, as Debian applies it.

Other branches with changes of ours (`mithro/lease-aware-dns`,
`mithro/pin-wildcard`, `mithro/auth-sec-servers-segfault`) are not in this
build. The segfault fix and the `OPT_LOG_ONLY_FAILED` fix they carry are
upstream now.

## Versions

`<Debian version>+welland<M>[~deb<R>][~pr<P>]`, from git, by
`packaging/deb-version.py` (docs/packaging.md, "Versions", Set A):
`<Debian version>` is the top entry of the committed `debian/changelog`
(`2.93-3`), `<M>` is `git rev-list --count upstream..HEAD`, `~deb<R>` is
the suite (13 trixie, 14 forky, none for sid) and `~pr<P>` marks a pull
request preview. For example `2.93-3+welland296~deb13`.

The base only moves when Debian's packaging is merged, not when upstream's
`master` is: between Debian releases the version keeps Debian's number
while the source is newer (`dnsmasq --version` gives upstream's own
`git describe`). `<M>` grows with every commit, so the version still goes
up with each push.

`packaging/deb-version.py` exists because apt-repo-action's shared version
script has no Set A form yet; delete it when that has.

## Updating

**New upstream commits.** `.github/workflows/sync-upstream.yml` runs weekly
(and on demand): it fast-forwards `upstream` from dnsmasq's repository
and, if `packaging` doesn't contain it, opens or updates the pull request
"Merge upstream <describe>" from `sync/upstream`. Its build is a
`workflow_dispatch` run of `deb.yml` on `sync/upstream` (a pull request a
workflow opens starts no checks). Review it, and merge it with a merge
commit. If it conflicts (most likely in the AXFR code, or in
`src/option.c`'s option numbers), the workflow fails and says what to
run:

```sh
git checkout -B sync/upstream origin/packaging
git merge --no-ff origin/upstream -m "Merge upstream $(git describe --tags origin/upstream)"
# resolve, build, test
git push origin sync/upstream
```

Never rebase `packaging`: that rewrites what has been published.

**New Debian packaging.** The same workflow fast-forwards
`dnsmasq-debian/kelley/master` from Debian's packaging repository and
opens "Merge Debian packaging <version>" from `sync/debian`. Merging it
raises the version's base to Debian's new version.

**A new patch of ours** is an ordinary commit on a branch, in a pull
request against `packaging`, with an `Upstream:` trailer saying where it
stands upstream.

## Building locally

```sh
git fetch origin upstream          # the version counts commits since it
sudo apt-get build-dep ./
python3 packaging/deb-version.py --suite sid --write-changelog
dpkg-buildpackage -us -uc -b
git checkout debian/changelog
```

`packaging/install-test.sh` is the install test CI runs, as root in a clean
`debian:<suite>` container with the `.deb`s in `/debs`.

## Install

The packages are built for trixie, forky and sid, on amd64, i386, arm64,
armhf and riscv64. Signing key fingerprint
`52BB 8AD2 DE80 FF4C 0E80  ADA2 C587 9658 95C3 858B`.

Debian 13 (trixie):

```sh
sudo install -d -m0755 /etc/apt/keyrings
curl -fsSL https://mith.ro/dnsmasq/dnsmasq.gpg | sudo tee /etc/apt/keyrings/dnsmasq.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/dnsmasq.gpg] https://mith.ro/dnsmasq/trixie/ ./" \
  | sudo tee /etc/apt/sources.list.d/dnsmasq.list
sudo apt update
```

Debian 14 (forky):

```sh
sudo install -d -m0755 /etc/apt/keyrings
curl -fsSL https://mith.ro/dnsmasq/dnsmasq.gpg | sudo tee /etc/apt/keyrings/dnsmasq.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/dnsmasq.gpg] https://mith.ro/dnsmasq/forky/ ./" \
  | sudo tee /etc/apt/sources.list.d/dnsmasq.list
sudo apt update
```

Debian unstable (sid):

```sh
sudo install -d -m0755 /etc/apt/keyrings
curl -fsSL https://mith.ro/dnsmasq/dnsmasq.gpg | sudo tee /etc/apt/keyrings/dnsmasq.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/dnsmasq.gpg] https://mith.ro/dnsmasq/sid/ ./" \
  | sudo tee /etc/apt/sources.list.d/dnsmasq.list
sudo apt update
```

Then `sudo apt install dnsmasq` (or `dnsmasq-base` alone, or
`dnsmasq-base-lua` for the Lua-scripting build). These versions sort above
Debian's own for the same Debian release, so `apt upgrade` keeps them
installed until Debian's version moves past ours: the signal to merge the
new Debian packaging.
