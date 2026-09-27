#!/usr/bin/env python3
"""Fast-forward a mirror of one of our upstreams, and offer it as a merge.

Run by .github/workflows/sync-upstream.yml (apt-repo-action's
docs/packaging.md, "Workflows"), once for each thing this repository
follows:

    upstream  git://thekelleys.org.uk/dnsmasq.git master
              -> branch `upstream`; pull request "Merge upstream <describe>"
                 from `sync/upstream`
    debian    git://thekelleys.org.uk/dnsmasq-debian.git master (Debian's
              packaging: the Vcs-Git Debian's debian/control names)
              -> branch `dnsmasq-debian/kelley/master`; pull request
                 "Merge Debian packaging <version>" from `sync/debian`

For each:
1. Fetch the source's branch and fast-forward our mirror branch to it. A
   source whose history was rewritten (not a fast-forward) stops the run:
   the mirror only ever fast-forwards.
2. If `packaging` already contains it, stop.
3. Otherwise bring the sync branch up to date with `packaging`, merge the
   mirror into it with the pull request's title as the commit message, and
   open or update that pull request. A conflicting merge stops the run with
   what to do by hand.
4. Start deb.yml on the sync branch, since a pull request opened with the
   workflow's own token starts no workflows.

Never force-pushes: every push here is a fast-forward, or it fails.

Needs git and gh (GH_TOKEN), and a checkout with full history.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

DEFAULT_BRANCH = "packaging"
SOURCES = {
    "upstream": {
        "url": "git://thekelleys.org.uk/dnsmasq.git",
        "branch": "master",
        "mirror": "upstream",
        "sync": "sync/upstream",
        "tags": True,
    },
    "debian": {
        "url": "git://thekelleys.org.uk/dnsmasq-debian.git",
        "branch": "master",
        "mirror": "dnsmasq-debian/kelley/master",
        "sync": "sync/debian",
        "tags": False,
    },
}


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


def out(*cmd: str) -> str:
    return run(*cmd).stdout.strip()


def fail(message: str) -> None:
    print(f"::error::{message}", flush=True)
    sys.exit(1)


def exists(ref: str) -> bool:
    return run("git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", check=False).returncode == 0


def is_ancestor(a: str, b: str) -> bool:
    return run("git", "merge-base", "--is-ancestor", a, b, check=False).returncode == 0


def title_for(name: str, tip: str) -> str:
    if name == "upstream":
        return f"Merge upstream {out('git', 'describe', '--tags', tip)}"
    first = out("git", "show", f"{tip}:debian/changelog").splitlines()[0]
    m = re.match(r"\S+ \(([^)\s]+)\)", first)
    if not m:
        fail(f"can't read the version from debian/changelog: {first!r}")
    return f"Merge Debian packaging {m.group(1)}"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("source", choices=sorted(SOURCES))
    args = ap.parse_args()
    s = SOURCES[args.source]
    fetched = f"refs/sync/{args.source}"

    # 1. Fast-forward the mirror.
    refspecs = [f"+refs/heads/{s['branch']}:{fetched}"]
    run("git", "fetch", "--tags" if s["tags"] else "--no-tags", s["url"], *refspecs)
    tip = out("git", "rev-parse", fetched)
    mirror = f"origin/{s['mirror']}"
    if exists(mirror) and not is_ancestor(mirror, tip):
        fail(f"{s['url']} {s['branch']} ({tip[:12]}) is not a fast-forward of {s['mirror']} "
             f"({out('git', 'rev-parse', '--short=12', mirror)}): upstream rewrote its history. "
             "Nothing was pushed; decide by hand what to do.")
    if not exists(mirror) or out("git", "rev-parse", mirror) != tip:
        run("git", "push", "origin", f"{tip}:refs/heads/{s['mirror']}")
    else:
        print(f"{s['mirror']} is already at {tip[:12]}")
    if s["tags"]:
        # Upstream's release tags, which `git describe` (the pull request's
        # title, and dnsmasq's own version string) needs.
        run("git", "push", "origin", "--tags")

    # 2. Already merged?
    packaging = f"origin/{DEFAULT_BRANCH}"
    if is_ancestor(tip, packaging):
        print(f"{DEFAULT_BRANCH} already contains {s['mirror']} ({tip[:12]}): nothing to merge")
        return

    # 3. The merge, on the sync branch, and its pull request.
    title = title_for(args.source, tip)
    sync = s["sync"]
    start = f"origin/{sync}" if exists(f"origin/{sync}") else packaging
    run("git", "checkout", "--detach", start)
    if not is_ancestor(packaging, "HEAD"):
        if run("git", "merge", "--no-edit", packaging, check=False).returncode != 0:
            run("git", "merge", "--abort", check=False)
            fail(f"{sync} doesn't merge cleanly with {DEFAULT_BRANCH}: merge {DEFAULT_BRANCH} "
                 f"into {sync} by hand and push it, or delete {sync} to start it afresh.")
    if is_ancestor(tip, "HEAD"):
        print(f"{sync} already contains {tip[:12]}")
    elif run("git", "merge", "--no-ff", "-m", title, tip, check=False).returncode != 0:
        run("git", "merge", "--abort", check=False)
        fail(f"merging {s['mirror']} ({tip[:12]}) into {DEFAULT_BRANCH} conflicts. By hand: "
             f"git checkout -B {sync} origin/{DEFAULT_BRANCH} && git merge --no-ff {tip[:12]} "
             f"-m '{title}', resolve, push {sync}, then run this workflow again.")
    run("git", "push", "origin", f"HEAD:refs/heads/{sync}")

    body = (f"{s['url']} `{s['branch']}` is now at {tip[:12]}, which `{DEFAULT_BRANCH}` "
            f"doesn't contain yet. `{s['mirror']}` has been fast-forwarded to it; this merges "
            f"it.\n\nOpened by `.github/workflows/sync-upstream.yml`. Merge with a merge "
            f"commit, never squash or rebase (docs/packaging.md in mithro/apt-repo-action). "
            f"Its build is a `workflow_dispatch` run of `deb.yml` on `{sync}`, since a pull "
            f"request opened by a workflow starts no checks of its own.\n")
    prs = json.loads(out("gh", "pr", "list", "--head", sync, "--base", DEFAULT_BRANCH,
                         "--state", "open", "--json", "number"))
    if prs:
        run("gh", "pr", "edit", str(prs[0]["number"]), "--title", title, "--body", body)
    else:
        run("gh", "pr", "create", "--head", sync, "--base", DEFAULT_BRANCH,
            "--title", title, "--body", body)

    # 4. Build it: deb.yml publishes only from the default branch.
    run("gh", "workflow", "run", "deb.yml", "--ref", sync)


if __name__ == "__main__":
    main()
