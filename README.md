# dnsmasq - Automatically Updated GitHub Mirror

This repository is an **automatically synchronised mirror** of the official upstream dnsmasq repository.

## Upstream Source

| | |
|---|---|
| **Official git** | `git://thekelleys.org.uk/dnsmasq.git` |
| **Official website** | https://thekelleys.org.uk/dnsmasq/doc.html |
| **Author** | Simon Kelley |

## How This Mirror Works

A GitHub Actions workflow runs **daily at 06:00 UTC** to:

1. Fetch all branches and tags from `git://thekelleys.org.uk/dnsmasq.git`
2. Push them to this repository

This ensures the mirror stays current with upstream without manual intervention.

## Repository Structure

| Branch | Purpose |
|--------|---------|
| `github-actions` | Contains only the sync workflow (this branch, the default) |
| `master` | Mirror of upstream `master` branch |
| All other branches | Mirrored directly from upstream |

The `github-actions` branch is **never touched** by the sync workflow - it only contains the automation infrastructure.

## Using This Mirror

To clone the dnsmasq source code:

```bash
# Clone the master branch (upstream mirror)
git clone -b master https://github.com/mithro/dnsmasq.git

# Or clone a specific version tag
git clone -b v2.91 https://github.com/mithro/dnsmasq.git
```

## Manual Sync

To trigger a manual sync: **Actions** → **Sync with Upstream dnsmasq** → **Run workflow**

## Why This Mirror Exists

The most popular GitHub mirror ([imp/dnsmasq](https://github.com/imp/dnsmasq)) has not been updated since May 2022. This mirror provides an automatically-updated alternative.

## License

dnsmasq is distributed under the GPL, version 2 or version 3 at your discretion.
See the COPYING file in the `master` branch for details.
