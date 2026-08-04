#!/bin/sh
# Publish the lane gateway as this VM's DNS server, on every boot.
#
# The gateway (the default route, <base>.1) runs the split-horizon dnsmasq: it
# resolves the AD zone via the lane DCs and forwards everything else. It is
# therefore the only correct resolver, and its address is per-lane -- so it is
# derived from the routing table at runtime rather than baked in, which would be
# wrong on every lane but one.
#
# This is the belt-and-braces path for deploys that assign a STATIC IP, where
# there is no dhclient to publish DNS. Feeding resolvconf rather than writing
# /etc/resolv.conf directly keeps the /run/resolvconf symlink intact and lets
# this record coexist with dhclient's.
set -eu

for _ in $(seq 1 30); do
    GW=$(ip -4 route show default 2>/dev/null | awk '/default/{print $3; exit}')
    [ -n "${GW:-}" ] && break
    sleep 2
done

[ -z "${GW:-}" ] && exit 0

printf 'nameserver %s\n' "$GW" | resolvconf -a lo.cybercore-gw
