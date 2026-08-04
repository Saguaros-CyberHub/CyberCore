#!/usr/bin/env bash
# =============================================================================
# cleanup.sh -- generalize the image, then let Packer seal it.
#
# MUST BE THE LAST PROVISIONER. It revokes the build account's sudo rights and
# deletes the SSH host keys, so nothing can run over this session afterwards.
# The Packer config sets expect_disconnect for that reason.
#
# The Linux equivalent of Sysprep /generalize: strip everything that makes this
# machine *this* machine, so that a clone comes up as a new host rather than a
# duplicate of the template.
# =============================================================================
set -uo pipefail   # not -e: a failed cleanup step must not abandon the rest

echo "==> Removing build-time apt configuration..."
rm -f /etc/apt/apt.conf.d/01-cybercore-build-proxy

echo "==> Cleaning apt caches..."
apt-get autoremove -y --purge
apt-get clean
rm -rf /var/lib/apt/lists/*

# Re-arm what install-desktop.sh stopped, so clones still get security updates.
systemctl enable apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true

# --- DNS ---------------------------------------------------------------------
# /etc/resolv.conf must ship as resolvconf's symlink, not as a regular file.
# Anything that opens the path with O_TRUNC replaces the symlink, after which
# resolvconf still tracks DHCP-supplied servers internally but has nowhere to
# publish them -- and every clone boots with an empty resolv.conf while IP and
# routing look perfectly healthy. This exact bug shipped once already.
echo "==> Restoring /etc/resolv.conf as a resolvconf symlink..."
rm -f /etc/resolv.conf
ln -s ../run/resolvconf/resolv.conf /etc/resolv.conf

# --- Identity ----------------------------------------------------------------
# Host keys: without this every clone shares one key, so they are
# indistinguishable to SSH and any lane with two of them trips
# host-key-mismatch warnings. Emptying (not deleting) /etc/machine-id is what
# makes systemd generate a fresh one at first boot; deleting it outright makes
# some units fail early in boot instead.
echo "==> Removing SSH host keys..."
rm -f /etc/ssh/ssh_host_*

echo "==> Resetting machine-id..."
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -sf /etc/machine-id /var/lib/dbus/machine-id

# Random seeds are per-machine by definition; a shared one across a class of
# clones is a real weakness, not a cosmetic one.
rm -f /var/lib/systemd/random-seed
rm -f /var/lib/systemd/credential.secret

# --- Network state -----------------------------------------------------------
# The interface config cloud-init rendered during the build names the build
# VLAN's addressing. Leave it behind and a clone may briefly assert the build
# VM's identity on the lane.
echo "==> Dropping build-time network state..."
rm -f /etc/network/interfaces.d/50-cloud-init
rm -f /etc/netplan/50-cloud-init.yaml
rm -f /var/lib/dhcp/* /var/lib/dhcpcd/* 2>/dev/null
rm -f /etc/NetworkManager/system-connections/* 2>/dev/null
# udev pins interface names to the build NIC's MAC; the clone gets a new one.
rm -f /etc/udev/rules.d/70-persistent-net.rules

# --- cloud-init --------------------------------------------------------------
# Removes /var/lib/cloud/instances/*, including the cached instance-id. Without
# it cloud-init recognises the clone as the same instance it already configured
# and skips ciuser/cipassword entirely -- the clone boots with the build
# password and no student can log in.
echo "==> Running cloud-init clean..."
cloud-init clean --logs --seed || true

# --- Logs and history --------------------------------------------------------
echo "==> Truncating logs..."
journalctl --rotate 2>/dev/null || true
journalctl --vacuum-time=1s 2>/dev/null || true
find /var/log -type f \( -name '*.gz' -o -name '*.[0-9]' -o -name '*.old' \) -delete 2>/dev/null
find /var/log -type f -exec truncate -s 0 {} \; 2>/dev/null
rm -f /var/lib/systemd/coredump/* 2>/dev/null

rm -f /root/.bash_history "/home/${BUILD_USER}/.bash_history"
rm -rf /tmp/cybercore
rm -rf /var/tmp/* 2>/dev/null

# --- Revoke build privileges -------------------------------------------------
# From here on the build account is an ordinary sudo-group user, whose sudo
# needs the password cloud-init resets on first boot. Nothing further can run
# over this SSH session.
echo "==> Revoking NOPASSWD sudo for ${BUILD_USER}..."
rm -f /etc/sudoers.d/99-packer-build

# --- Reclaim space -----------------------------------------------------------
# fstrim returns the freed blocks to the Ceph pool, so the template (and every
# full clone of it) is as small as its contents. discard=on is set on the disk.
echo "==> Trimming free space..."
sync
fstrim -av 2>/dev/null || true

echo "==> Cleanup complete. Ready to seal."
