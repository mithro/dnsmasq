#!/usr/bin/env python3
"""The package version and changelog entry for one build: the Set A form.

apt-repo-action's shared scripts/deb-version.py implements only the Set B
form so far (its docs/compliance-plan.md, section 3.1). Until it has Set A,
this script does the same job for this repository, following its
docs/packaging.md ("Versions", Set A, rule 1: debian/ came from Debian):

    <Debian version>+welland<M>[~deb<R>][~pr<P>]

- ``<Debian version>`` is the top entry of the committed debian/changelog,
  which is Debian's (2.93-3).
- ``<M>`` is the number of commits on this build's HEAD that aren't on
  ``upstream``: ``git rev-list --count upstream..HEAD``.
- ``~deb<R>`` is the suite's Debian release number; sid has none.
- ``~pr<P>`` goes last, on pull request previews only.

``--write-changelog`` puts the build's entry on top of the committed
debian/changelog: ``dnsmasq (<version>) <suite>``, "Built from
<owner>/<repo>@<sha>", the Maintainer from debian/control, and the commit's
committer time, which dpkg-buildpackage then uses as SOURCE_DATE_EPOCH.

apt-repo-action's build-deb runs this with ``--write-changelog`` only; the
suite and pull request number come from the SUITE and PR variables it sets
in the build container.

Delete this file in the commit that moves the build to the shared script,
once that has the Set A form.

Standard library only: it runs inside a bare debian:<suite> container.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

OWNER_TAG = "welland"
# Codename -> Debian release number, for ~deb<R>. sid has no suffix.
DEBIAN_RELEASE = {"bookworm": 12, "trixie": 13, "forky": 14}
BUILT_FROM = "  * Built from "
# Where the unmodified upstream branch is found: a local branch, or the
# remote-tracking one actions/checkout's full fetch makes.
UPSTREAM_REFS = ("upstream", "origin/upstream")


def fail(message: str) -> None:
    print(f"deb-version.py: error: {message}", file=sys.stderr)
    sys.exit(1)


def git(src: Path, *args: str) -> str:
    try:
        return subprocess.run(["git", "-C", str(src), *args], capture_output=True,
                              text=True, check=True).stdout.strip()
    except FileNotFoundError:
        fail("git is not installed")
    except subprocess.CalledProcessError as e:
        fail(f"git {' '.join(args)}: {e.stderr.strip()}")


def committed_changelog(src: Path) -> str:
    # The committed changelog, not the working tree's, so running this twice
    # doesn't stack two entries.
    r = subprocess.run(["git", "-C", str(src), "show", "HEAD:debian/changelog"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        fail(f"no committed debian/changelog: {r.stderr.strip()}")
    top = r.stdout.split("\n -- ", 1)[0]
    if BUILT_FROM in top:
        fail("the committed debian/changelog starts with a build's generated entry. "
             "Commit the changelog without it: the build adds its own.")
    return r.stdout


def debian_version(changelog: str) -> str:
    m = re.match(r"\S+ \(([^)\s]+)\)", changelog)
    if not m:
        fail(f"can't read the version from debian/changelog's first line: {changelog.splitlines()[0]!r}")
    version = m.group(1)
    if f"+{OWNER_TAG}" in version:
        fail(f"debian/changelog's top entry is ours ({version}), not Debian's: "
             "the base must be the Debian version debian/ came from")
    if re.match(r"\d+:", version):
        fail(f"Debian's version {version} has an epoch; that needs a declared exception")
    return version


def upstream_count(src: Path) -> int:
    if git(src, "rev-parse", "--is-shallow-repository") == "true":
        fail("this is a shallow clone, so the commit count would be wrong and the "
             "version would go backwards. Check out with `fetch-depth: 0`.")
    for ref in UPSTREAM_REFS:
        r = subprocess.run(["git", "-C", str(src), "rev-parse", "--verify", "--quiet",
                            f"{ref}^{{commit}}"], capture_output=True, text=True)
        if r.returncode == 0:
            return int(git(src, "rev-list", "--count", f"{ref}..HEAD"))
    fail(f"none of {', '.join(UPSTREAM_REFS)} exists: fetch the upstream branch")


def with_suffixes(base: str, suite: str, pr: int | None) -> str:
    codename = suite.removeprefix("raspbian-")
    if codename == "sid":
        out = base
    elif codename in DEBIAN_RELEASE:
        out = f"{base}~deb{DEBIAN_RELEASE[codename]}"
    else:
        fail(f"unknown suite {suite!r} (known: {', '.join([*DEBIAN_RELEASE, 'sid'])})")
    return f"{out}~pr{pr}" if pr else out


def control_field(control: str, field: str) -> str:
    source = control.split("\n\n", 1)[0]
    m = re.search(rf"^{field}:[ \t]*(.+)$", source, re.MULTILINE | re.IGNORECASE)
    if not m:
        fail(f"debian/control has no {field}: in its source paragraph")
    return m.group(1).strip()


def github_repository(src: Path) -> str:
    if os.environ.get("GITHUB_REPOSITORY"):
        return os.environ["GITHUB_REPOSITORY"]
    url = git(src, "remote", "get-url", "origin")
    m = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?/?$", url)
    if not m:
        fail(f"can't tell the GitHub repository from origin {url!r}; pass --repo")
    return m.group(1)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--suite", default=os.environ.get("SUITE"),
                    help="the suite being built (default: $SUITE)")
    ap.add_argument("--pr", default=os.environ.get("PR") or None,
                    help="pull request number, for a preview build (default: $PR)")
    ap.add_argument("--repo", default=None,
                    help="owner/name for the changelog (default: $GITHUB_REPOSITORY, else origin)")
    ap.add_argument("--source-dir", type=Path, default=Path("."),
                    help="the source tree (default: the current directory)")
    ap.add_argument("--write-changelog", action="store_true",
                    help="write this build's entry on top of the committed debian/changelog")
    args = ap.parse_args()
    if not args.suite:
        fail("no suite: pass --suite or set SUITE")
    pr = None
    if args.pr is not None:
        if not str(args.pr).isdigit() or int(args.pr) <= 0:
            fail(f"--pr must be a pull request number, not {args.pr!r}")
        pr = int(args.pr)
    src = args.source_dir
    old = committed_changelog(src)
    base = f"{debian_version(old)}+{OWNER_TAG}{upstream_count(src)}"
    version = with_suffixes(base, args.suite, pr)
    if args.write_changelog:
        control = (src / "debian/control").read_text()
        entry = (f"{control_field(control, 'Source')} ({version}) {args.suite}; urgency=medium\n\n"
                 f"{BUILT_FROM}{args.repo or github_repository(src)}@{git(src, 'rev-parse', 'HEAD')}\n\n"
                 f" -- {control_field(control, 'Maintainer')}  "
                 f"{git(src, 'log', '-1', '--format=%cd', '--date=rfc2822')}\n")
        (src / "debian/changelog").write_text(entry + "\n" + old)
    print(version)


if __name__ == "__main__":
    main()
