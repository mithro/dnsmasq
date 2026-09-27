#!/bin/sh
# Install test (apt-repo-action's docs/packaging.md, "Builds"): run as root in
# a clean debian:<suite> container, with the built .debs in /debs.
#
# 1. The packages install from the Debian archive's dependencies, both
#    flavours (dnsmasq-base, then dnsmasq-base-lua, which replaces it).
# 2. `dnsmasq --version` runs.
# 3. Our patch works: a zone far larger than one 64 KB DNS message transfers
#    completely over AXFR. Stock dnsmasq fails this; see packaging/README.md.
set -eu

DEBS=${DEBS:-/debs}
RECORDS=5000
PORT=5353
ZONE=axfr.test

export DEBIAN_FRONTEND=noninteractive
# No service starts in a container: without this dnsmasq's postinst would try
# to start the daemon.
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d

if [ -e /apt-sources/install.sh ]; then sh /apt-sources/install.sh; fi
apt-get update
apt-get install -y --no-install-recommends bind9-dnsutils

echo "== dnsmasq, dnsmasq-base, dnsmasq-utils"
apt-get install -y --no-install-recommends \
    "$DEBS"/dnsmasq_*.deb "$DEBS"/dnsmasq-base_*.deb "$DEBS"/dnsmasq-utils_*.deb
dpkg-query -W 'dnsmasq*'
dnsmasq --version

axfr_test() {
    dir=$(mktemp -d)
    i=0
    while [ "$i" -lt "$RECORDS" ]; do
        echo "10.$((i / 65536)).$((i / 256 % 256)).$((i % 256)) host-with-a-longish-name-$i.$ZONE"
        i=$((i + 1))
    done > "$dir/hosts"
    dnsmasq --keep-in-foreground --user=root --pid-file= \
        --port="$PORT" --listen-address=127.0.0.1 --bind-interfaces \
        --no-hosts --no-resolv --addn-hosts="$dir/hosts" \
        --auth-server="ns.$ZONE,127.0.0.1" --auth-zone="$ZONE" --auth-peer=127.0.0.1 \
        --log-facility="$dir/log" &
    pid=$!
    n=0
    until dig +short +time=1 +tries=1 -p "$PORT" @127.0.0.1 SOA "$ZONE" | grep -q .; do
        n=$((n + 1))
        if [ "$n" -ge 30 ]; then
            echo "dnsmasq didn't answer on port $PORT" >&2
            cat "$dir/log" >&2
            kill "$pid"
            exit 1
        fi
        sleep 1
    done
    dig +time=10 +tries=1 -p "$PORT" @127.0.0.1 AXFR "$ZONE" > "$dir/axfr"
    kill "$pid"
    wait "$pid" || true
    tail -n 4 "$dir/axfr"
    got=$(grep -c "[[:space:]]IN[[:space:]]A[[:space:]]" "$dir/axfr" || true)
    soa=$(grep -c "[[:space:]]IN[[:space:]]SOA[[:space:]]" "$dir/axfr" || true)
    bytes=$(sed -n 's/^;; XFR size:.* bytes \([0-9]*\)).*/\1/p' "$dir/axfr")
    echo "AXFR of $ZONE: $got A records (want $RECORDS), $soa SOA (want 2), ${bytes:-?} bytes"
    if [ "$got" -ne "$RECORDS" ] || [ "$soa" -ne 2 ]; then
        echo "AXFR incomplete: streaming AXFR is broken" >&2
        cat "$dir/log" >&2
        exit 1
    fi
    if [ -z "$bytes" ] || [ "$bytes" -le 65535 ]; then
        echo "the zone fitted in one message, so this tested nothing: raise RECORDS" >&2
        exit 1
    fi
    rm -rf "$dir"
}

axfr_test

echo "== dnsmasq-base-lua (replaces dnsmasq-base)"
apt-get install -y --no-install-recommends "$DEBS"/dnsmasq-base-lua_*.deb
dpkg-query -W 'dnsmasq*'
dnsmasq --version | grep -i 'lua'
axfr_test

echo "install test passed"
