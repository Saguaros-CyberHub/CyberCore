#!/usr/bin/env bash
# =============================================================================
# configure-cloud-init.sh -- point cloud-init at Proxmox's config drive.
#
# The preseed installs cloud-init but leaves it configured for a generic cloud:
# it probes EC2/Azure/GCE metadata endpoints, and on an isolated lane VLAN each
# probe runs to timeout before the boot continues.
#
# This is the whole reason the template exists. A clone with cloud-init
# misconfigured boots to a login prompt with no account the student knows,
# because ciuser/cipassword were never read.
# =============================================================================
set -euo pipefail

STAGE="/tmp/cybercore"

echo "==> Installing cloud-init datasource config..."
install -d -m 0755 /etc/cloud/cloud.cfg.d
install -m 0644 -o root -g root \
    "${STAGE}/cloud-init/99-cybercore.cfg" \
    /etc/cloud/cloud.cfg.d/99-cybercore.cfg

# The Debian package ships a fragment that hard-pins the datasource list to
# whatever was detected at install time (i.e. NoCloud only, or None). Ours sorts
# after it and wins, but leaving a stale one in place is a trap for the next
# person reading /etc/cloud/cloud.cfg.d.
rm -f /etc/cloud/cloud.cfg.d/90_dpkg.cfg

# Same idea for the "disable networking" fragment cloud-init writes when it
# decides it is running on bare metal. If it survives into the template, Proxmox
# ipconfig0 silently does nothing on every clone.
rm -f /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg

# --- Hand networking to cloud-init -------------------------------------------
# d-i writes a static `iface ens18 inet dhcp` stanza into /etc/network/
# interfaces. cloud-init's eni renderer writes its own into
# /etc/network/interfaces.d/50-cloud-init. Both present means the interface is
# configured twice and a Proxmox-assigned static IP loses to the DHCP stanza.
#
# Reducing /etc/network/interfaces to loopback plus a source line makes
# cloud-init's file the only interface config, on DHCP and static lanes alike.
echo "==> Reducing /etc/network/interfaces to a stub..."
cat > /etc/network/interfaces <<'EOF'
# Managed by cloud-init -- see /etc/network/interfaces.d/50-cloud-init.
# Only loopback is declared here so cloud-init's renderer owns every real
# interface. Adding a stanza for a physical NIC below will conflict with it.
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback
EOF
install -d -m 0755 /etc/network/interfaces.d

# kali-desktop-xfce pulls in NetworkManager. Debian's default is already
# `managed=false`, meaning NM keeps its hands off anything in
# /etc/network/interfaces -- but that default has flipped between releases and
# an NM that grabs ens18 first would strand every static-IP lane. Assert it.
if [ -d /etc/NetworkManager ]; then
    echo "==> Telling NetworkManager to leave ifupdown interfaces alone..."
    install -d -m 0755 /etc/NetworkManager/conf.d
    cat > /etc/NetworkManager/conf.d/10-cybercore-ifupdown.conf <<'EOF'
# cloud-init renders interface config through ifupdown (renderers: ['eni']).
# NetworkManager must not also claim those devices.
[ifupdown]
managed=false
EOF
fi

# cloud-init 24.3 renamed cloud-init.service to cloud-init-network.service and
# left an alias behind, so the unit set differs by release. Enable whatever this
# one actually ships rather than hardcoding a list that breaks on upgrade.
echo "==> Enabling cloud-init services..."
for unit in cloud-init-local cloud-init-network cloud-init cloud-config cloud-final; do
    if systemctl cat "${unit}.service" >/dev/null 2>&1; then
        systemctl enable "${unit}.service" >/dev/null 2>&1 \
            && echo "    enabled ${unit}.service" \
            || echo "    skipped ${unit}.service (alias or already enabled)"
    fi
done
systemctl enable cloud-init.target >/dev/null 2>&1 || true

echo "==> cloud-init configured."
