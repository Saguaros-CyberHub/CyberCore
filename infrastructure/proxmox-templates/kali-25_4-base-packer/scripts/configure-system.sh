#!/usr/bin/env bash
# =============================================================================
# configure-system.sh -- console, DNS, swap and SSH.
# =============================================================================
set -euo pipefail

STAGE="/tmp/cybercore"

# --- Serial console ----------------------------------------------------------
# The VM has vga=serial0 and no emulated graphics card at all, so ttyS0 is the
# only console there is. d-i normally propagates the installer's console=
# argument into the target's GRUB config, but that has silently regressed
# before, and getting it wrong means `qm terminal` and the Proxmox noVNC console
# both show nothing on every clone -- with no way to debug a network problem.
echo "==> Configuring GRUB and getty for the serial console..."
install -d -m 0755 /etc/default/grub.d
cat > /etc/default/grub.d/99-cybercore-serial.cfg <<'EOF'
GRUB_CMDLINE_LINUX_DEFAULT="console=tty0 console=ttyS0,115200n8"
GRUB_TERMINAL="console serial"
GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"
# Show the menu briefly: a clone that fails to boot is otherwise a black
# rectangle with no way to reach a recovery entry.
GRUB_TIMEOUT=3
GRUB_TIMEOUT_STYLE=menu
EOF
update-grub

systemctl enable serial-getty@ttyS0.service

# --- Lane DNS ----------------------------------------------------------------
echo "==> Installing the lane-gateway DNS resolver service..."
install -m 0755 -o root -g root \
    "${STAGE}/dns/cybercore-resolv-gw.sh" \
    /usr/local/sbin/cybercore-resolv-gw.sh
install -m 0644 -o root -g root \
    "${STAGE}/dns/cybercore-resolv-gw.service" \
    /etc/systemd/system/cybercore-resolv-gw.service
systemctl daemon-reload
systemctl enable cybercore-resolv-gw.service

# --- Swap --------------------------------------------------------------------
# The preseed deliberately creates no swap partition, so that root can be the
# last partition on the disk and cloud-init's growpart can extend it. zram gives
# the swap back without a partition and without inflating the template image --
# it compresses into RAM, and sizes itself to whatever memory the clone gets.
if [ -f /etc/default/zramswap ]; then
    echo "==> Configuring zram swap..."
    sed -i 's/^#\?PERCENT=.*/PERCENT=25/' /etc/default/zramswap
    grep -q '^PERCENT=' /etc/default/zramswap || echo 'PERCENT=25' >> /etc/default/zramswap
    systemctl enable zramswap.service 2>/dev/null || true
else
    echo "WARNING: zram-tools not installed -- this template ships with no swap"
fi

# --- SSH ---------------------------------------------------------------------
# Password auth stays on: cloud-init sets cipassword, and not every lane deploy
# path injects an SSH key. Root login stays off, matching the preseed.
echo "==> Configuring sshd..."
install -d -m 0755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/10-cybercore.conf <<'EOF'
PasswordAuthentication yes
PermitRootLogin no
UseDNS no
EOF
systemctl enable ssh

# --- Guest agent -------------------------------------------------------------
# Already enabled by the preseed; asserted here because Proxmox's clone tooling
# and the lane deployer both read the clone's IP through it.
systemctl enable qemu-guest-agent

# --- Housekeeping ------------------------------------------------------------
# discard=on is set on the template's disk, so let the guest actually issue the
# trims that reclaim space on the Ceph pool.
systemctl enable fstrim.timer

timedatectl set-timezone "$(cat /etc/timezone)" 2>/dev/null || true

echo "==> System configured."
