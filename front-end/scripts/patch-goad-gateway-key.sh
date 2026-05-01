#!/bin/bash
# ============================================================================
# patch-goad-gateway-key.sh
# ----------------------------------------------------------------------------
# Adds the GOAD controller's public key to gateway template 1692's
# /root/.ssh/authorized_keys, so the controller VM can SSH-in and write
# DHCP reservations during a GOAD deploy without the orchestrator needing
# SSH access to Proxmox nodes.
#
# Companion to scripts/bake-goad-controller-vm.sh. That script generates
# the keypair at /root/.ssh/goad-controller-deploy.key{,.pub} on this node
# and embeds the private key into template 1700. This script reads the
# public half and bakes it into 1692.
#
# Templates on Ceph use protected base- snapshots, so we use the same
# clone-fix-replace dance we used for the sshd autostart fix.
#
# Run on the same Proxmox node where bake-goad-controller-vm.sh ran.
# Idempotent: if the key is already in authorized_keys, it's a no-op.
# ============================================================================
set -euo pipefail

GW_VMID=${GW_VMID:-1692}
TMP_VMID=${TMP_VMID:-9991}
DEPLOY_KEY_PATH=${DEPLOY_KEY_PATH:-/root/.ssh/goad-controller-deploy.key}
PUBKEY_PATH="${DEPLOY_KEY_PATH}.pub"
STORAGE=${STORAGE:-vmpool}
DUMP_DIR=${DUMP_DIR:-/var/lib/vz/dump}

# ---------- 0. Sanity ----------
if [ ! -f "$PUBKEY_PATH" ]; then
  echo "ERROR: Public key not found at $PUBKEY_PATH"
  echo "       Run scripts/bake-goad-controller-vm.sh first to generate the keypair."
  exit 1
fi
PUBKEY="$(cat "$PUBKEY_PATH")"
echo "==> Will add key: ${PUBKEY:0:60}..."

if ! pct config $GW_VMID >/dev/null 2>&1; then
  echo "ERROR: Gateway template CT $GW_VMID not found."
  exit 1
fi
IS_TEMPLATE="$(pct config $GW_VMID | awk '/^template:/ {print $2}')"
if [ "$IS_TEMPLATE" != "1" ]; then
  echo "ERROR: CT $GW_VMID is not flagged as a template (template=$IS_TEMPLATE)."
  echo "       This script expects 1692 to be a template; aborting."
  exit 1
fi

if pct status $TMP_VMID >/dev/null 2>&1; then
  echo "ERROR: Temp CTID $TMP_VMID already exists. Set TMP_VMID env var or destroy it."
  exit 1
fi

# ---------- 1. Clone gateway → temp ----------
echo "==> Cloning $GW_VMID → $TMP_VMID..."
pct clone $GW_VMID $TMP_VMID --hostname gw-key-patch --full --storage "$STORAGE"

# ---------- 1b. Clean up orphan host-side veths from any previous attempt ----------
# pct start renames veth pairs to the configured names (wan0, lan0). If a
# previous failed start left those names lingering on the host's network
# namespace, the rename collides with "File exists". Clear them first.
# (Template's net0/net1 config is preserved — the gateway needs lan0 with
# 192.18.0.1/24 on the lane VNet, which admin.js overrides per-deploy.)
ip link delete lan0 2>/dev/null || true
ip link delete wan0 2>/dev/null || true

# ---------- 2. Add key inside the temp clone ----------
echo "==> Starting temp CT $TMP_VMID..."
pct start $TMP_VMID

# Wait for /root/.ssh to exist (clone is fast but be defensive)
for _ in 1 2 3 4 5; do
  pct exec $TMP_VMID -- /bin/sh -c "test -d /root/.ssh" 2>/dev/null && break
  sleep 1
  pct exec $TMP_VMID -- /bin/sh -c "mkdir -p /root/.ssh && chmod 700 /root/.ssh"
done

echo "==> Appending public key to authorized_keys (idempotent)..."
pct exec $TMP_VMID -- /bin/sh -c "
  set -e
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh
  touch /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
  if ! grep -qF -- '$PUBKEY' /root/.ssh/authorized_keys; then
    echo '$PUBKEY' >> /root/.ssh/authorized_keys
    echo 'Added GOAD controller key.'
  else
    echo 'Key already present — no change.'
  fi
"

# Allow the GOAD controller (192.18.0.5 on lan0) to SSH the gateway. The
# gateway's INPUT policy is DROP and lan0 only permits DHCP/DNS/NTP/ICMP
# by default — students on lan0 still can't SSH; only the controller IP
# is allowed. Append to /etc/local.d/50-gateway.start so it survives reboot.
echo "==> Adding firewall exception for controller (192.18.0.5 -> lan0:22)..."
pct exec $TMP_VMID -- /bin/sh -c "
  set -e
  RULE_LINE='iptables -I INPUT -i lan0 -s 192.18.0.5 -p tcp --dport 22 -j ACCEPT  # GOAD controller'
  HOOK=/etc/local.d/50-gateway.start
  mkdir -p /etc/local.d
  if [ ! -f \$HOOK ]; then
    printf '%s\n%s\n' '#!/bin/sh' '# Gateway dynamic firewall rules' > \$HOOK
    chmod +x \$HOOK
  fi
  if ! grep -qF 'GOAD controller' \$HOOK; then
    echo \"\$RULE_LINE\" >> \$HOOK
    echo 'Added controller SSH allow rule.'
  else
    echo 'Controller rule already present — no change.'
  fi
"

# Make sure sshd is enabled (should be from earlier 1692 work, but be safe)
pct exec $TMP_VMID -- /bin/sh -c "rc-update add sshd default 2>/dev/null || systemctl enable ssh 2>/dev/null || true"

echo "==> Stopping temp CT..."
pct stop $TMP_VMID

# ---------- 3. Backup, destroy old template, restore as the gateway ----------
mkdir -p "$DUMP_DIR"
echo "==> Backing up temp CT to $DUMP_DIR..."
vzdump $TMP_VMID --dumpdir "$DUMP_DIR" --compress zstd >/dev/null
DUMP_FILE=$(ls -t "$DUMP_DIR"/vzdump-lxc-${TMP_VMID}-*.tar.zst | head -1)
echo "==> Backup: $DUMP_FILE"

echo "==> Destroying old gateway template $GW_VMID..."
pct destroy $GW_VMID --purge

echo "==> Restoring backup as $GW_VMID..."
pct restore $GW_VMID "$DUMP_FILE" --storage "$STORAGE" >/dev/null

# Defensive: re-assert the gateway template's expected net config in case
# the vzdump→restore round-trip changed it (any prior buggy version of
# this script may have stripped net1; this puts it back).
echo "==> Re-asserting gateway template net config..."
pct set $GW_VMID --net0 'name=wan0,bridge=crucible,firewall=0,ip=dhcp,type=veth'
pct set $GW_VMID --net1 'name=lan0,bridge=vmbr0,ip=192.18.0.1/24,type=veth'

pct set $GW_VMID --template 1

echo "==> Cleanup..."
pct destroy $TMP_VMID --purge
rm -f "$DUMP_FILE"

# ---------- 4. Verify by re-cloning and checking the key landed ----------
VERIFY_VMID=${VERIFY_VMID:-9992}
if ! pct status $VERIFY_VMID >/dev/null 2>&1; then
  echo "==> Verifying: cloning $GW_VMID → $VERIFY_VMID and checking key..."
  pct clone $GW_VMID $VERIFY_VMID --hostname gw-verify --full --storage "$STORAGE" >/dev/null
  ip link delete lan0 2>/dev/null || true
  ip link delete wan0 2>/dev/null || true
  pct start $VERIFY_VMID
  sleep 4
  if pct exec $VERIFY_VMID -- /bin/sh -c "grep -qF -- '$PUBKEY' /root/.ssh/authorized_keys"; then
    echo "==> Key verified in cloned gateway."
  else
    echo "WARNING: key not found in verification clone — investigate before deploying."
  fi
  pct stop $VERIFY_VMID
  pct destroy $VERIFY_VMID --purge
fi

echo ""
echo "==================================================================="
echo "  Gateway template $GW_VMID patched with GOAD controller key"
echo "==================================================================="
echo "  Verify:        pct config $GW_VMID"
echo "  Inspect:       pct clone $GW_VMID 9999 --full --storage $STORAGE && \\"
echo "                 pct start 9999 && pct exec 9999 -- cat /root/.ssh/authorized_keys"
echo "==================================================================="
