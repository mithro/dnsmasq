#!/usr/bin/env python3
"""Mirror every branch and tag of the repositories we follow into this one.

Run daily by .github/workflows/mirror-upstreams.yml. The mirrors follow
their source exactly, including a branch or tag the source rewrote or
moved (a forced update). They are there to keep every published ref of
upstream, whatever happens to it upstream, not to build from:
`upstream` (packaging/sync-upstream.py) is the branch the build follows,
and it only ever fast-forwards.

    source                                        branches -> here
    git://thekelleys.org.uk/dnsmasq.git           refs/heads/<b>          -> <b>
                                                  refs/remotes/origin/<b> -> <b>, unless a head <b> exists
                                                  refs/remotes/<r>/<b>    -> <r>/<b>
    git://thekelleys.org.uk/dnsmasq-debian.git    refs/heads/<b>          -> dnsmasq-debian/kelley/<b>
    https://salsa.debian.org/debian/dnsmasq.git   refs/heads/<b>          -> dnsmasq-debian/debian/salsa/<b>
    https://git.dgit.debian.org/dnsmasq           refs/heads/<b>          -> dnsmasq-debian/debian/dgit/<b>

thekelleys' dnsmasq.git publishes a single head, `master`. Its other
branches are only published as the refs/remotes/* of Simon Kelley's own
clone, so those are mirrored too: `origin` under bare names (as the
branches `aws`, `rfc7440`, ... always were here), any other remote under
its name.

Every source's tags go to refs/tags/<t>. Tags are one namespace, so if two
sources have the same tag at different objects, the one listed first
above wins, and the run says so.

Nothing of ours is ever written: a source ref that would land on
`packaging`, `upstream`, `github-actions`, `sync/*`, `convention/*`,
`mithro/*` or `dnsmasq-debian/mithro/*` is skipped, and the run fails
saying so. Nothing is deleted either: a ref that has gone from its source
stays here. The run lists those under dnsmasq-debian/kelley/* and
dnsmasq-debian/debian/*; a bare name that has gone can't be told apart
from one of our pull requests' branches, so it isn't listed.

Needs git, and a checkout of this repository with every branch and tag
(actions/checkout with fetch-depth: 0), so a push sends only new objects.
"""
from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys

SOURCES = [
    ("thekelleys", "git://thekelleys.org.uk/dnsmasq.git", None),
    ("kelley", "git://thekelleys.org.uk/dnsmasq-debian.git", "dnsmasq-debian/kelley/"),
    ("salsa", "https://salsa.debian.org/debian/dnsmasq.git", "dnsmasq-debian/debian/salsa/"),
    ("dgit", "https://git.dgit.debian.org/dnsmasq", "dnsmasq-debian/debian/dgit/"),
]
OURS = ["packaging", "upstream", "github-actions", "sync/*", "convention/*",
        "mithro/*", "dnsmasq-debian/mithro/*"]
FETCHED = "refs/mirror"
PUSH_BATCH = 100


def run(*cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    print("+", " ".join(cmd), flush=True)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.stdout.strip():
        print(r.stdout.rstrip())
    if r.stderr.strip():
        print(r.stderr.rstrip(), file=sys.stderr)
    if check and r.returncode != 0:
        fail(f"{' '.join(cmd)} exited {r.returncode}")
    return r


def fail(message: str) -> None:
    print(f"::error::{message}", flush=True)
    sys.exit(1)


def refs(*cmd: str) -> dict[str, str]:
    """ref -> object, from git for-each-ref or git ls-remote output."""
    r = subprocess.run(cmd, capture_output=True, text=True, check=True)
    out = {}
    for line in r.stdout.splitlines():
        sha, ref = line.split()
        if not ref.endswith("^{}"):
            out[ref] = sha
    return out


def is_ours(branch: str) -> bool:
    return any(fnmatch.fnmatchcase(branch, pattern) for pattern in OURS)


def wanted() -> tuple[dict[str, tuple[str, str]], list[str]]:
    """Fetch every source; return {our ref: (object, fetched ref)} and warnings."""
    want: dict[str, tuple[str, str]] = {}
    warnings = []
    for name, url, prefix in SOURCES:
        base = f"{FETCHED}/{name}"
        run("git", "fetch", "--no-tags", "--prune", url,
            f"+refs/heads/*:{base}/heads/*",
            f"+refs/remotes/*:{base}/remotes/*",
            f"+refs/tags/*:{base}/tags/*")
        got = refs("git", "for-each-ref", "--format=%(objectname) %(refname)", f"{base}/")
        heads = {r[len(f"{base}/heads/"):] for r in got if r.startswith(f"{base}/heads/")}
        for ref, sha in sorted(got.items()):
            kind, _, rest = ref[len(base) + 1:].partition("/")
            if kind == "tags":
                dst = f"refs/tags/{rest}"
                if dst in want and want[dst][0] != sha:
                    warnings.append(f"tag {rest}: {name} has it at {sha[:12]}, an earlier "
                                    f"source at {want[dst][0][:12]}; kept the earlier one")
                    continue
                want.setdefault(dst, (sha, ref))
                continue
            if kind == "heads":
                branch = rest
            elif kind == "remotes" and prefix is None:
                remote, _, b = rest.partition("/")
                if b == "HEAD":
                    continue
                if remote != "origin":
                    branch = f"{remote}/{b}"
                elif b in heads:
                    continue  # the head is the real branch; this is a stale copy of it
                else:
                    branch = b
            else:
                continue  # a packaging source's refs/remotes: not published branches
            branch = (prefix or "") + branch
            if is_ours(branch):
                warnings.append(f"{url} {ref[len(base) + 1:]} would overwrite our "
                                f"branch {branch}: skipped")
                continue
            want[f"refs/heads/{branch}"] = (sha, ref)
    return want, warnings


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dry-run", action="store_true", help="fetch and report, push nothing")
    args = ap.parse_args()

    want, warnings = wanted()
    have = refs("git", "ls-remote", "--heads", "--tags", "origin")
    stale = sorted(dst for dst, (sha, _) in want.items() if have.get(dst) != sha)
    print(f"{len(want)} mirrored refs; {len(stale)} to create or update")
    for dst in stale:
        old = have.get(dst)
        print(f"  {dst}: {old[:12] if old else '(new)'} -> {want[dst][0][:12]}")

    mirrored = ("refs/heads/dnsmasq-debian/kelley/", "refs/heads/dnsmasq-debian/debian/")
    gone = sorted(r for r in have if r.startswith(mirrored) and r not in want)
    if gone:
        print("Gone from their source, kept here:")
        for ref in gone:
            print(f"  {ref}")

    failed = []
    if not args.dry_run:
        for i in range(0, len(stale), PUSH_BATCH):
            batch = stale[i:i + PUSH_BATCH]
            specs = [f"+{want[dst][1]}:{dst}" for dst in batch]
            if run("git", "push", "origin", *specs, check=False).returncode != 0:
                # One bad ref fails the whole batch: retry them one by one.
                for spec in specs:
                    if run("git", "push", "origin", spec, check=False).returncode != 0:
                        failed.append(spec)

    for w in warnings:
        print(f"::warning::{w}", flush=True)
    if failed:
        fail(f"{len(failed)} refs weren't pushed: {' '.join(failed)}")
    if any("would overwrite our branch" in w for w in warnings):
        fail("a source has a branch in one of our namespaces; see the warnings above")


if __name__ == "__main__":
    main()
