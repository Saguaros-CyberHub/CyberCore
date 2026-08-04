#!/usr/bin/env bash
# =============================================================================
# install-desktop.sh -- xfce, xrdp and the Kali tool metapackage.
#
# The preseed installs a `standard` system only. Everything heavy happens here
# instead, where a mirror hiccup surfaces as a failed Packer build with the apt
# error in the log, rather than as a headless installer stuck on a debconf
# prompt no one can see.
# =============================================================================
set -euo pipefail

TOOLSET="${KALI_TOOLSET:-default}"

# --force-confdef + --force-confold on every apt invocation. Without them dpkg
# prompts on conffile conflicts, reads EOF from the non-interactive stdin, and
# leaves packages half-configured -- the failure that made xrdp ship broken
# before. configure-xrdp.sh overwrites /etc/xrdp/startwm.sh after this script,
# so a conffile prompt on that exact file is a live possibility.
APT_OPTS=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

# Kali's unattended-upgrade timers race every apt call in this build. Stopping
# them is cleaner than looping on the dpkg lock; cleanup.sh re-enables them.
systemctl stop apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
systemctl stop unattended-upgrades.service 2>/dev/null || true

wait_for_dpkg() {
    local waited=0
    while pgrep -x 'apt-get|dpkg|unattended-upgr' >/dev/null 2>&1; do
        [ "$waited" -ge 300 ] && { echo "ERROR: dpkg still locked after 5 min" >&2; return 1; }
        sleep 5
        waited=$((waited + 5))
    done
}

if [ -n "${APT_PROXY:-}" ]; then
    echo "==> Using build-time apt proxy: ${APT_PROXY}"
    echo "Acquire::http::Proxy \"${APT_PROXY}\";" > /etc/apt/apt.conf.d/01-cybercore-build-proxy
fi

echo "==> Refreshing package lists..."
wait_for_dpkg
# kali-rolling moves fast enough that a mirror can be mid-sync; one retry turns
# the common transient failure into a non-event.
apt-get update || { sleep 30; apt-get update; }

# Kali rolling retires transitional packages without notice (policykit-1 ->
# polkitd, dnsutils -> bind9-dnsutils). Install the set one call at a time so a
# single renamed package cannot take the whole desktop down with it.
echo "==> Installing xfce + xrdp..."
wait_for_dpkg
apt-get install "${APT_OPTS[@]}" \
    kali-desktop-xfce \
    xrdp \
    xorgxrdp \
    dbus-x11 \
    libjpeg62-turbo \
    polkitd \
    xfce4-terminal

# Nice-to-haves that are not worth failing a 45-minute build over.
echo "==> Installing supporting packages..."
wait_for_dpkg
apt-get install "${APT_OPTS[@]}" \
    zram-tools \
    firefox-esr \
    || echo "WARNING: optional packages unavailable on this mirror -- continuing"

echo "==> Installing toolset: ${TOOLSET}"
case "$TOOLSET" in
    minimal)
        echo "    minimal: skipping the kali-linux-* metapackage"
        ;;
    default|large)
        wait_for_dpkg
        # Not guarded with `|| true`: a half-installed toolset is exactly the
        # kind of template that should never reach a student.
        apt-get install "${APT_OPTS[@]}" "kali-linux-${TOOLSET}"
        ;;
    *)
        echo "ERROR: KALI_TOOLSET must be minimal|default|large (got: ${TOOLSET})" >&2
        exit 1
        ;;
esac

echo "==> Desktop and toolset installed."
