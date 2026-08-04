#!/usr/bin/env bash
# =============================================================================
# configure-xrdp.sh -- make xrdp actually serve an xfce desktop on 3389.
#
# Clones are reached through Guacamole (rdp.saguaroscyberhub.org), so xrdp is
# the primary way anyone uses this template. A clone that boots fine but shows a
# blank blue screen on connect is indistinguishable from a broken VM to a
# student, which is why every step here has a matching assertion in verify.sh.
# =============================================================================
set -euo pipefail

STAGE="/tmp/cybercore"

echo "==> Installing xrdp session launcher..."
install -m 0755 -o root -g root "${STAGE}/xrdp/startwm.sh" /etc/xrdp/startwm.sh

echo "==> Installing polkit rule for RDP sessions..."
install -d -m 0755 /etc/polkit-1/rules.d
install -m 0644 -o root -g root \
    "${STAGE}/polkit/50-xrdp-no-prompt.rules" \
    /etc/polkit-1/rules.d/50-xrdp-no-prompt.rules

# xrdp reads the snakeoil key under /etc/ssl/private/, which is group ssl-cert
# and mode 0640. Without this the service starts and then refuses every
# connection with a TLS error.
echo "==> Granting xrdp access to /etc/ssl/private..."
adduser xrdp ssl-cert || true

# Headless by design: the console is a serial port (vga=serial0) so a graphical
# greeter has nothing to draw on, and xrdp creates its own X sessions on demand.
# Leaving lightdm enabled also produces the "noVNC shows a login screen that
# eats the session" confusion.
echo "==> Disabling the graphical display manager..."
systemctl set-default multi-user.target
systemctl disable lightdm.service 2>/dev/null || true
systemctl disable gdm3.service 2>/dev/null || true
systemctl stop lightdm.service 2>/dev/null || true

echo "==> Enabling xrdp..."
systemctl enable xrdp
systemctl enable xrdp-sesman
systemctl restart xrdp-sesman
systemctl restart xrdp

# Give the sockets a moment to bind before verify.sh looks for them.
sleep 3

echo "==> xrdp configured."
