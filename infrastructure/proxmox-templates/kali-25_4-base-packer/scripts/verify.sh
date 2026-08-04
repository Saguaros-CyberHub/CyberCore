#!/usr/bin/env bash
# =============================================================================
# verify.sh -- refuse to seal a broken template.
#
# Ported from the pre-seal check in front-end/scripts/bake-kali-template.sh,
# which exists because a prior template shipped a 0-byte
# /usr/lib/x86_64-linux-gnu/libjpeg.so.62.4.0 and xrdp died on every connection
# with "error while loading shared libraries: file too short". Nothing about
# that is visible from `qm config`, and it was found by students.
#
# Anything that fails here fails the Packer build, leaving the build VM up for
# inspection instead of converting it to a template.
#
# Runs BEFORE cleanup.sh, so it sees the live system with services running.
# =============================================================================
set -uo pipefail   # NOT -e: every check must run so the report is complete.

FAIL=0

pass() { printf '    [ ok ] %s\n' "$1"; }
fail() { printf '    [FAIL] %s\n' "$1"; FAIL=1; }

echo "==> Verifying template ${TEMPLATE_NAME:-?} (vmid ${TEMPLATE_VMID:-?})"

# --- libjpeg integrity -------------------------------------------------------
# The exact corruption that shipped before. A torn mirror write leaves the file
# present but truncated, so existence alone proves nothing -- check the size.
LIBJPEG=""
for candidate in /usr/lib/x86_64-linux-gnu/libjpeg.so.62.*; do
    [ -f "$candidate" ] && { LIBJPEG="$candidate"; break; }
done
if [ -z "$LIBJPEG" ]; then
    fail "libjpeg.so.62 not found"
else
    SIZE=$(stat -c %s "$LIBJPEG")
    if [ "$SIZE" -lt 50000 ]; then
        fail "$(basename "$LIBJPEG") is ${SIZE} bytes -- truncated (expected >50KB)"
    else
        pass "$(basename "$LIBJPEG") is ${SIZE} bytes"
    fi
fi

# Catches the same class of damage anywhere else in xrdp's link map.
if ldd /usr/sbin/xrdp 2>&1 | grep -q 'not found\|file too short'; then
    fail "xrdp has broken shared library dependencies:"
    ldd /usr/sbin/xrdp 2>&1 | grep 'not found\|file too short' | sed 's/^/           /'
else
    pass "xrdp shared libraries resolve"
fi

# --- xrdp listening ----------------------------------------------------------
if ss -ltn '( sport = :3389 )' | grep -q LISTEN; then
    pass "xrdp listening on 3389"
else
    fail "xrdp is NOT listening on 3389"
    systemctl --no-pager --lines=20 status xrdp 2>&1 | sed 's/^/           /'
fi

if ss -ltn '( sport = :3350 )' | grep -q LISTEN; then
    pass "xrdp-sesman listening on 3350"
else
    fail "xrdp-sesman is NOT listening on 3350"
fi

# --- Desktop session -----------------------------------------------------------
# startwm.sh execs this path directly; a missing binary is a blank blue screen
# on every RDP connection.
if [ -x /usr/bin/startxfce4 ]; then
    pass "startxfce4 present"
else
    fail "/usr/bin/startxfce4 missing -- RDP sessions will show a blank screen"
fi

if grep -q startxfce4 /etc/xrdp/startwm.sh; then
    pass "startwm.sh launches xfce"
else
    fail "startwm.sh was not replaced (a dpkg conffile prompt probably won)"
fi

# --- Services enabled for the clone ------------------------------------------
# cloud-init.service was renamed to cloud-init-network.service in 24.3; the
# other three stage units have kept their names, so check those instead.
for unit in ssh qemu-guest-agent xrdp xrdp-sesman cloud-init-local \
            cloud-config cloud-final cybercore-resolv-gw serial-getty@ttyS0; do
    if systemctl is-enabled "${unit}.service" >/dev/null 2>&1; then
        pass "${unit} enabled"
    else
        fail "${unit} is not enabled -- it will not start on a clone"
    fi
done

if systemctl get-default | grep -q multi-user; then
    pass "default target is multi-user"
else
    fail "default target is $(systemctl get-default) -- expected multi-user.target"
fi

# --- cloud-init --------------------------------------------------------------
if [ -f /etc/cloud/cloud.cfg.d/99-cybercore.cfg ]; then
    pass "cloud-init datasource config installed"
else
    fail "/etc/cloud/cloud.cfg.d/99-cybercore.cfg missing -- clones will ignore ciuser/cipassword"
fi

NETDISABLE=""
for candidate in /etc/cloud/cloud.cfg.d/*disable-network-config*; do
    [ -e "$candidate" ] && { NETDISABLE="$candidate"; break; }
done
if [ -n "$NETDISABLE" ]; then
    fail "$NETDISABLE survives -- Proxmox ipconfig0 will do nothing on clones"
else
    pass "no cloud-init network-disable fragment"
fi

# growpart is the only reason root is the last partition on the disk. If the
# preseed recipe ever regresses to `atomic`, a resized clone gets no extra space
# and this is the cheapest place to notice.
ROOT_PART=$(findmnt -no SOURCE / | sed 's|/dev/||')
LAST_PART=$(lsblk -lno NAME,TYPE | awk '$2=="part"{p=$1} END{print p}')
if [ "$ROOT_PART" = "$LAST_PART" ]; then
    pass "root ($ROOT_PART) is the last partition -- growpart can extend it"
else
    fail "root is $ROOT_PART but the last partition is $LAST_PART -- growpart will not resize clones"
fi

# --- Toolset -----------------------------------------------------------------
case "${KALI_TOOLSET:-default}" in
    minimal) pass "toolset minimal -- no metapackage expected" ;;
    *)
        if dpkg-query -W -f='${Status}' "kali-linux-${KALI_TOOLSET}" 2>/dev/null | grep -q 'install ok installed'; then
            pass "kali-linux-${KALI_TOOLSET} installed"
        else
            fail "kali-linux-${KALI_TOOLSET} is not fully installed"
        fi
        ;;
esac

# --- Build account -----------------------------------------------------------
if id "${BUILD_USER}" >/dev/null 2>&1; then
    pass "build account ${BUILD_USER} exists"
else
    fail "build account ${BUILD_USER} is missing"
fi

# --- Disk headroom -----------------------------------------------------------
# kali-linux-large on a 64G disk is tight. Better to say so now than to have a
# clone run out of space during a class.
AVAIL_MB=$(df --output=avail -m / | tail -1 | tr -d ' ')
if [ "$AVAIL_MB" -lt 3072 ]; then
    fail "only ${AVAIL_MB}MB free on / -- raise disk_size for this toolset"
else
    pass "${AVAIL_MB}MB free on /"
fi

echo
if [ "$FAIL" -ne 0 ]; then
    cat >&2 <<EOF
===================================================================
  Refusing to seal a broken template.
===================================================================
The build VM is left running for inspection. Useful next steps:
  ssh ${BUILD_USER}@<build-vm-ip>
  journalctl -u xrdp -u xrdp-sesman --no-pager
  systemctl --failed
Fix the root cause, then re-run the build.
EOF
    exit 1
fi

echo "==> All template checks passed."
