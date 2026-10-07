#!/bin/bash
# ============================================================================
# bake-caldera-server.sh
# ----------------------------------------------------------------------------
# ############################################################################
# # THIS SCRIPT HAS NEVER BEEN EXECUTED.                                     #
# #                                                                          #
# # Not one line of it has run on a Proxmox node, against a real MITRE       #
# # Caldera release, or against any VM. There is no Caldera anywhere in this  #
# # repository and no Caldera server exists on any cluster, so nothing here   #
# # has been validated end to end and NOTHING HERE SHOULD BE TRUSTED AS       #
# # WORKING. Specifically unverified:                                        #
# #                                                                          #
# #   - that CALDERA_REF below is a real, current, installable tag           #
# #   - that Caldera's dependency set installs on Rocky/RHEL 9 at all         #
# #     (upstream CI targets Ubuntu; the Python and Go versions here are      #
# #     inferred from upstream's README, not measured)                        #
# #   - every conf key name in the rendered local.yml                        #
# #   - that /api/v2/health answers unauthenticated on this release          #
# #   - that a sandcat agent compiles and beacons                            #
# #                                                                          #
# # Treat the FIRST run of this script as the experiment, not the deploy.     #
# # Every pre-seal marker below exists so that experiment fails loudly at     #
# # bake time instead of quietly in a classroom.                              #
# ############################################################################
#
# Bakes a LANE-LOCAL MITRE Caldera command-and-control server: one per student
# lane, reachable only from inside that lane, driving real adversary emulation
# against the lane's own Windows assets. Agents beacon to it. It exists to
# EXECUTE, and it is the only kind of machine this script builds — there is no
# role switch and no second template.
#
# THE AUTHORING INSTANCE IS NOT A VM AND IS NOT BAKED HERE.
# A previous revision of this file carried a second role that produced a
# standalone, agent-less VM for instructors to build adversaries on. That
# placement is superseded. The authoring instance has NO agents and executes
# NOTHING — it is a web app in front of a content store — so it is a DOCKER
# CONTAINER on the CyberCore host now, a compose service with no published host
# port, reached only through Caddy, exactly like Guacamole. Section 6 of the
# hand-off block at the bottom says what that means for whoever deploys this
# template; config/caddy/Caddyfile and docker-compose.yml are the authority.
#
# So everything below is about the EXECUTOR, because there is nothing else.
#
# This is Track E phase E9, which is DROPPABLE and which ships nothing until the
# E8 cluster gate has passed. EXECUTION — which is the whole of what this
# template is — stays gated on that. Read the hand-off block at the bottom
# before doing anything with the template this produces.
#
# ----------------------------------------------------------------------------
# WHY LANE-LOCAL, AND WHY THAT IS NOT NEGOTIABLE
# ----------------------------------------------------------------------------
# A C2 server exists to make agents run commands. An agent that can reach a
# controller OUTSIDE its own lane is precisely the thing the lane isolation was
# built to prevent: one compromised or curious student's box, beaconing to a
# controller shared with thirty other students, is a live pivot into every other
# lane in the cohort. The isolation is not a hardening nicety here — it is the
# only thing standing between "a teaching lab" and "a real botnet with a class
# roster".
#
# So the shape is one Caldera per lane, on the lane's own segment, resolved by a
# lane-published name, with no route off the lane. Concretely:
#
#   - the image is a TEMPLATE, cloned per lane; there is no shared instance
#   - agents are told to beacon to ${CALDERA_CONTACT_HOST}, a name the LANE
#     GATEWAY publishes (dnsmasq host-record from the catalog row's
#     metadata.dns_aliases), exactly as the loggen sensor already resolves
#     'elk'. Nothing in the image is per-lane, which is what makes that work.
#   - the sanity block below REFUSES to bake if that name is a public one or a
#     routable literal address. It is a syntactic check, not a routing proof,
#     but it catches the one mistake that would matter: someone pointing every
#     baked agent at a central server "just for testing".
#
# What this script CANNOT prove is that the lane gateway actually drops egress.
# That is a deploy-time property of the lane, not a bake-time property of the
# image, and it is listed in the hand-off block as something to verify per lane.
#
# ----------------------------------------------------------------------------
# WHERE THE AUTHORING INSTANCE WENT, AND WHY IT IS NOT A TEMPLATE
# ----------------------------------------------------------------------------
# Instructors still need one good place to build an adversary, and Caldera's own
# web UI is that place. But building an adversary needs no agent, no operation
# and no target — it is content authoring against the ability catalog — so the
# authoring instance has no contact host, nothing staged, and nothing to execute
# with. A machine that executes nothing does not need to be a machine.
#
# It is a CONTAINER on the CyberCore host now, alongside Guacamole:
#
#   - a compose service on cybercore-net that publishes NO host port. With no
#     port binding it is unreachable except through Caddy — structurally, with
#     no firewall rule to maintain and no "we meant to close that" to drift.
#   - Caddy's /caldera* handle fronts it in BOTH site blocks of
#     config/caddy/Caddyfile, gated by an authorization subrequest the app
#     answers, which is the same shape /guacamole* already uses.
#   - CyberCore reads an authored adversary back over the REST API and
#     replicates it into each lane's own executor at launch.
#
# HOW THAT GATE WORKS IS NOT RESTATED HERE. Read config/caddy/Caddyfile and
# front-end/src/routes/caldera-authoring.js. A bake script carrying its own copy
# of somebody else's security mechanism is a copy that goes stale in silence,
# and the stale copy is the one people believe.
#
# WHAT IT MEANS FOR THIS FILE: the template baked here never talks to the
# authoring instance, and the authoring instance never talks to a lane.
# Replication INTO lanes goes over guest-exec (agentShellExec via the Proxmox
# API), which is how everything else in this codebase reaches a lane VM. There
# is no IP route from the orchestrator into a lane and this design does not add
# one. If you find yourself writing a firewall rule between a container on the
# CyberCore host and a lane, stop: the design has been misread.
#
# ----------------------------------------------------------------------------
# WHY THE API KEY IS A FILE INSIDE THE GUEST AND NEVER A SCRIPT ARGUMENT
# ----------------------------------------------------------------------------
# This is cross-cutting rule 4 of the Track E plan and it is not stylistic.
#
# CyberCore delivers deploy-time scripts through src/utils/script-executor.js,
# which interpolates `script_args` UNQUOTED onto a command line:
#
#     PowerShell   script-executor.js:249   & '<path>' ${scriptArgs} *>&1 | ...
#     sh           script-executor.js:624   sh '<path>' ${scriptArgs} > ...
#
# and src/utils/password-generator.js:13 guarantees at least one character from
#
#     SYMBOLS = '!@#$%&*'
#
# in every generated secret. A single '&' in that position BACKGROUNDS the
# command; '#' truncates the rest of the line; '$' expands to nothing. The
# failure is not an error — the script "succeeds", having run half of itself
# with an empty secret, and the symptom appears days later as an agent that
# cannot authenticate.
#
# So the key never travels as an argument. It is base64-encoded on the bake host
# (base64 because the cloud-init heredoc below is UNQUOTED, so a literal '$' or
# backtick in a key would expand on the host — the same reasoning
# bake-cybr400-loggen-template.sh uses for its helper scripts), written by
# cloud-init into a root-owned 0600 FILE in the guest, and read from that file by
# a render script that never puts it on a command line either.
#
# The same rule applies to every future toucher of this image: the per-lane
# rotation seam is "overwrite /opt/cybercore/caldera-api-key.red and restart the
# service", never "pass the new key to a script".
#
# HONESTY ABOUT THE BAKED SECRET: it is IDENTICAL IN EVERY CLONE. That matches
# this repo's existing `bake-debug` convention for lab templates and is
# defensible only because the server is lane-local and the lane is per-student.
# It is written down here rather than discovered later. If a cohort needs
# distinct keys, re-bake per cohort or rewrite the key file at postDeploy — the
# render script exists to make the second option one file and one restart.
#
# ----------------------------------------------------------------------------
# WHY THE BASE IS A CLONE OF 1001 RATHER THAN A DOWNLOADED CLOUD IMAGE
# ----------------------------------------------------------------------------
# Same reasoning as bake-cybr400-loggen-template.sh, its closest sibling: 1001
# (rocky-linux-template) is the hand-built base that already carries this
# platform's cloud-init account contract and hardening, so this script owns
# exactly one thing — the Caldera layer. It also means the guest-agent
# unblocking and SELinux handling below are the SAME code paths the sensor bake
# already proved on this distro, rather than a second untested variant.
#
# The cost is real and is stated plainly: upstream Caldera's CI targets
# Ubuntu/Debian. Rocky 9 is a plausible host and nothing more. If the dependency
# install fails, the honest fix is to re-point SRC_VMID at a Debian base rather
# than to fight RHEL's Python packaging.
#
# Run on a Proxmox node with internet access. Idempotent: refuses if VMID
# already exists. To re-bake: qm destroy 1008 --purge
# ============================================================================
set -euo pipefail

# ---------- TOMBSTONE: CALDERA_ROLE is gone, and silence would be worse -------
# This script used to take CALDERA_ROLE=executor|authoring and bake two images
# that were opposites. The authoring half is a container on the CyberCore host
# now (see the header, and hand-off section 6), so there is one image and no
# switch — the variable is not read anywhere below.
#
# It is refused rather than ignored because ignoring it is the dangerous half. A
# stale runbook or an exported shell variable would otherwise bake a LANE-LOCAL
# C2 — contact host, sandcat, Go toolchain, everything an implant needs — and
# hand it to somebody who believes they just built the agent-less authoring box.
# Eight lines here turn that into a named error at second zero.
if [ -n "${CALDERA_ROLE:-}" ]; then
  echo "ERROR: CALDERA_ROLE is no longer a thing ('$CALDERA_ROLE' was passed)." >&2
  echo "       This script bakes exactly one image: the LANE-LOCAL EXECUTOR, and it" >&2
  echo "       always has a contact host, sandcat and a Go toolchain. It is a C2." >&2
  echo "       The AUTHORING instance is a Docker container on the CyberCore host now:" >&2
  echo "       a compose service with no published host port, reached only through" >&2
  echo "       Caddy's /caldera* handle. There is no template to bake for it and" >&2
  echo "       nothing on a Proxmox node to point at. See hand-off section 6." >&2
  echo "       Unset CALDERA_ROLE and re-run." >&2
  exit 1
fi

VMID=${VMID:-1008}
SRC_VMID=${SRC_VMID:-1001}                  # rocky-linux-template
NAME=${NAME:-caldera-server-template}
STORAGE=${STORAGE:-vmpool}
SNIPPET_STORAGE="${SNIPPET_STORAGE:-}"
BAKE_BRIDGE="${BAKE_BRIDGE:-vmbr0}"
BAKE_VLAN="${BAKE_VLAN:-20}"
BAKE_DNS="${BAKE_DNS:-100.100.0.1}"
# Caldera's server is a single asyncio process, but it compiles agent payloads
# with the Go toolchain on demand, and that is what actually wants the memory.
MEMORY=${MEMORY:-4096}
CORES=${CORES:-2}
DISK_GROW=${DISK_GROW:-12G}                 # Go toolchain + pip tree + plugins

TEMPLATE_USER="${TEMPLATE_USER:-caldera}"
TEMPLATE_PASSWORD="${TEMPLATE_PASSWORD:-bake-debug}"

# ---------- The pin ----------
# UNVERIFIED. Check this tag against upstream releases before the first bake;
# it is written here so the bake is reproducible, not because it is known good.
#
# Pin a TAG, never a branch. Caldera's plugin submodules move independently of
# the server, and a floating clone means the ability catalog the compiler in
# front-end/src/incident/caldera/adversary.js was tested against is not the
# catalog the server actually serves — which shows up as an adversary the server
# rejects with a 404 on an ability id, hours after an instructor pressed launch.
CALDERA_REPO="${CALDERA_REPO:-https://github.com/mitre/caldera.git}"
CALDERA_REF="${CALDERA_REF:-5.0.0}"
CALDERA_PY="${CALDERA_PY:-python3.11}"

# The address AGENTS are told to beacon to. Published per lane by the gateway's
# dnsmasq, exactly like 'elk' for the loggen sensor — set
# metadata.dns_aliases = ["caldera"] on the catalog row and every lane resolves
# this name to its OWN server. Nothing in the image is per-lane, which is the
# point, and it is also what keeps the bake lane-local without hardcoding an
# octet that a topology change would silently invalidate.
#
# DEFAULTED UNCONDITIONALLY, and note that ${VAR:-default} substitutes for an
# EMPTY value as well as an unset one. There is exactly one kind of machine in
# this file, it needs an address, and an empty string is never a legal one — so
# no path through this script bakes an image with no contact host, and the
# lane-local check below never has an empty case to consider.
CALDERA_CONTACT_HOST="${CALDERA_CONTACT_HOST:-caldera.cybercore.lan}"
CALDERA_PORT="${CALDERA_PORT:-8888}"

# ---------- Secrets: REQUIRED, no defaults, delivered as files ----------
# No default on purpose. A defaulted C2 API key is a shared credential across
# every cohort that ever deploys this image, and the failure mode of a default
# is that nobody ever notices it is still in place.
CALDERA_API_KEY_RED="${CALDERA_API_KEY_RED:-}"
CALDERA_API_KEY_BLUE="${CALDERA_API_KEY_BLUE:-}"
# Caldera encrypts stored objects with this. It MUST be stable for the life of
# the image: change it and every previously encrypted object becomes
# undecryptable — the same class of trap the E3b ELK notes document for Kibana's
# encryptedSavedObjects.encryptionKey, and with the same silent symptom.
CALDERA_ENCRYPTION_KEY="${CALDERA_ENCRYPTION_KEY:-}"
CALDERA_CRYPT_SALT="${CALDERA_CRYPT_SALT:-}"

# SELinux mode written into the image. Same reasoning as the sensor bake: the
# guest agent runs confined in virt_qemu_ga_t on RHEL derivatives and cannot
# stage files or fork detached processes, which breaks every guest-exec-based
# deploy step. Set SELINUX_MODE=enforcing to opt out and supply a policy module.
SELINUX_MODE="${SELINUX_MODE:-permissive}"

# ---------- 0. Sanity ----------
if qm status $VMID >/dev/null 2>&1; then
  echo "ERROR: VM $VMID already exists. Destroy first: qm destroy $VMID --purge" >&2
  exit 1
fi
if pct status $VMID >/dev/null 2>&1; then
  echo "ERROR: LXC $VMID exists at the same VMID." >&2
  exit 1
fi
if ! qm status $SRC_VMID >/dev/null 2>&1; then
  echo "ERROR: source template $SRC_VMID (rocky-linux-template) not found on this node." >&2
  echo "       Run this on the node that holds it, or set SRC_VMID." >&2
  exit 1
fi

require_secret() {  # require_secret <name> <value> <min-length>
  local name="$1" value="$2" min="$3"
  if [ -z "$value" ]; then
    echo "ERROR: $name is required and has no default." >&2
    echo "       A defaulted C2 credential is a shared credential across every cohort," >&2
    echo "       and the failure mode of a default is that nobody notices it." >&2
    echo "       Generate one:  $name=\$(openssl rand -hex 24) $0" >&2
    return 1
  fi
  if [ "${#value}" -lt "$min" ]; then
    echo "ERROR: $name is shorter than $min characters." >&2
    return 1
  fi
  # A key with whitespace or a newline in it survives this script (it is
  # base64'd) and then breaks the HTTP header it eventually becomes.
  if printf '%s' "$value" | grep -q '[[:space:]]'; then
    echo "ERROR: $name contains whitespace. It becomes an HTTP header value; it cannot." >&2
    return 1
  fi
  return 0
}

FAIL_ARGS=0
require_secret CALDERA_API_KEY_RED      "$CALDERA_API_KEY_RED"      24 || FAIL_ARGS=1
require_secret CALDERA_API_KEY_BLUE     "$CALDERA_API_KEY_BLUE"     24 || FAIL_ARGS=1
require_secret CALDERA_ENCRYPTION_KEY   "$CALDERA_ENCRYPTION_KEY"   32 || FAIL_ARGS=1
require_secret CALDERA_CRYPT_SALT       "$CALDERA_CRYPT_SALT"       16 || FAIL_ARGS=1

# Upstream's shipped placeholders. They are in every tutorial, every blog post
# and every scanner's wordlist, and a C2 with a documented key is not a C2.
for BAD in ADMIN123 BLUEADMIN123 REPLACE_WITH_RANDOM_VALUE admin password; do
  for VAL in "$CALDERA_API_KEY_RED" "$CALDERA_API_KEY_BLUE" "$CALDERA_ENCRYPTION_KEY"; do
    if [ "$VAL" = "$BAD" ]; then
      echo "ERROR: a supplied secret is Caldera's shipped default ('$BAD')." >&2
      FAIL_ARGS=1
    fi
  done
done

# LANE-LOCAL ENFORCEMENT. Syntactic, UNCONDITIONAL, and it is the one mistake
# worth catching at bake time: a contact host that is public or routable means
# every baked agent beacons off-lane, which is the failure this whole design
# exists to prevent. Nothing branches around this check — there is one kind of
# image and it is always subject to it.
case "$CALDERA_CONTACT_HOST" in
  *.lan|*.local|*.internal|localhost)
    : ;;
  10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|100.100.*|127.*)
    : ;;
  *)
    echo "ERROR: CALDERA_CONTACT_HOST='$CALDERA_CONTACT_HOST' is not lane-local." >&2
    echo "       Agents beacon to this address. A public name or a routable literal here" >&2
    echo "       means every cloned lane's agents phone home to ONE controller, which is" >&2
    echo "       a live pivot between student lanes — the exact thing lane isolation exists" >&2
    echo "       to prevent. Use a name the lane gateway publishes (default:" >&2
    echo "       caldera.cybercore.lan) and tag the catalog row metadata.dns_aliases." >&2
    FAIL_ARGS=1
    ;;
esac

if ! printf '%s' "$CALDERA_PORT" | grep -Eq '^[0-9]{2,5}$'; then
  echo "ERROR: CALDERA_PORT='$CALDERA_PORT' is not a port number." >&2
  FAIL_ARGS=1
fi

[ "$FAIL_ARGS" -ne 0 ] && exit 1

pick_snippet_storage() {
  if [ -n "${SNIPPET_STORAGE:-}" ]; then
    if pvesm status -content snippets 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$SNIPPET_STORAGE"; then
      echo "$SNIPPET_STORAGE"; return 0
    fi
    echo "ERROR: SNIPPET_STORAGE='$SNIPPET_STORAGE' set but missing 'snippets' content." >&2
    return 1
  fi
  local first
  first=$(pvesm status -content snippets 2>/dev/null | awk 'NR>1 {print $1}' | head -1)
  if [ -n "$first" ]; then echo "$first"; return 0; fi
  echo "==> Enabling 'snippets' on local storage..." >&2
  local cur
  cur=$(awk '/^[a-z]+: local$/{flag=1} flag && /^\s*content/{print $2; flag=0}' /etc/pve/storage.cfg)
  [ -z "$cur" ] && cur="iso,vztmpl,backup"
  [[ "$cur" != *snippets* ]] && pvesm set local --content "${cur},snippets" >&2
  echo "local"
}
SNIPPET_STORAGE=$(pick_snippet_storage)

USERDATA_FILE="caldera-server-bake-${VMID}.yaml"
case "$SNIPPET_STORAGE" in
  local)  USERDATA_PATH="/var/lib/vz/snippets/${USERDATA_FILE}" ;;
  cephfs) USERDATA_PATH="/mnt/pve/cephfs/snippets/${USERDATA_FILE}" ;;
  *)      USERDATA_PATH="/var/lib/vz/snippets/${USERDATA_FILE}" ;;
esac
mkdir -p "$(dirname "$USERDATA_PATH")"
# The snippet holds the secrets in transit. It is deleted at seal time, but it
# exists on the node for the duration of the bake, so it is created private
# rather than made private afterwards.
umask 077

echo "==> Baking $NAME as VMID $VMID from source template $SRC_VMID"
echo "    Caldera       : ${CALDERA_REF}  (UNVERIFIED PIN — see the header)"
echo "    Agent contact : http://${CALDERA_CONTACT_HOST}:${CALDERA_PORT}  (lane-local)"
echo "    Secrets       : delivered as 0600 files in the guest, never as script args"

# ---------- 0b. Guest helper: render the config from the key FILES ----------
# Written here as real shell, then base64'd into cloud-init write_files. The
# userdata heredoc below is UNQUOTED so ${CALDERA_PORT} and friends expand,
# which means anything containing $, backticks or backslashes cannot be pasted
# into it literally. base64 with `encoding: b64` sidesteps the whole class of
# escaping bug — the same reason bake-cybr400-loggen-template.sh does it.
#
# WHY THIS SCRIPT EXISTS AT ALL, rather than cloud-init writing local.yml
# directly: it is the per-lane rotation seam. Overwrite a key file, restart the
# unit, and the config is re-rendered from the new value — no argument passing,
# no template re-render on the app side, and nothing that puts a secret on a
# command line. It runs as the unit's ExecStartPre so the rendered file can
# never be staler than the key files.
read -r -d '' RENDER_CONF_SH <<'RENDER_EOF' || true
#!/bin/sh
# Render /opt/caldera/conf/local.yml from the key files in /opt/cybercore.
# Run as ExecStartPre of caldera.service. Root only; the output is 0600.
#
# NEVER echo a key, never pass one as an argument, never put one in a here-doc
# that something else could read. Everything below goes file -> variable ->
# file, all as root, all mode 0600.
set -eu

CONF_DIR=/opt/caldera/conf
KEY_DIR=/opt/cybercore
ENV_FILE=/etc/cybercore-caldera.env

[ -f "$ENV_FILE" ] || { echo "render-conf: $ENV_FILE missing" >&2; exit 1; }
# shellcheck disable=SC1090
. "$ENV_FILE"

# Defaulted before the guard below rather than relied on: this script runs under
# `set -u`, so an env file someone deleted the key out of would otherwise abort
# here with "unbound variable" instead of with the reason.
CALDERA_CONTACT_HOST="${CALDERA_CONTACT_HOST:-}"

# THE EMPTY-CONTACT-HOST GUARD, and it is not a formality. With no contact
# address the block below renders
#
#     app.contact.http: http://:8888
#
# which Caldera ACCEPTS. The server then comes up healthy, serves its UI, and
# tells every agent to beacon at a hostless URL that resolves to nothing. The
# symptom is a lane whose C2 is up and on which no agent ever appears —
# indistinguishable from a lane where the agent install failed, so it sends
# whoever debugs it to the wrong half of the system entirely. A dead unit with
# this line in the journal is strictly better than a healthy one nothing can
# use, which is why this refuses rather than warns.
if [ -z "$CALDERA_CONTACT_HOST" ]; then
  echo "render-conf: CALDERA_CONTACT_HOST is empty or absent in $ENV_FILE." >&2
  echo "render-conf: agents would be told to beacon at a hostless URL, which Caldera" >&2
  echo "render-conf: accepts and no agent can ever use. Refusing to start." >&2
  exit 1
fi

read_secret() {  # read_secret <file>
  [ -r "$1" ] || { echo "render-conf: $1 missing or unreadable" >&2; exit 1; }
  # `head -c` rather than $(cat) so a trailing newline never becomes part of an
  # HTTP header value. tr strips any that survive.
  tr -d '\r\n' < "$1"
}

# YAML single-quoted scalars escape a quote by doubling it. Everything else --
# including the '!@#$%&*' the platform password generator emits -- is literal
# inside single quotes, which is exactly why this is the only quoting style used
# below.
yq_quote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"; }

API_RED=$(read_secret "$KEY_DIR/caldera-api-key.red")
API_BLUE=$(read_secret "$KEY_DIR/caldera-api-key.blue")
ENC_KEY=$(read_secret "$KEY_DIR/caldera-encryption-key")
CRYPT_SALT=$(read_secret "$KEY_DIR/caldera-crypt-salt")
UI_RED=$(read_secret "$KEY_DIR/caldera-ui-password.red")
UI_BLUE=$(read_secret "$KEY_DIR/caldera-ui-password.blue")

mkdir -p "$CONF_DIR"
TMP="$CONF_DIR/.local.yml.tmp"
umask 077

# Staged write then mv, never a redirect onto the live file: Caldera reads this
# at start and a half-written YAML is a server that boots with a default config,
# which is a server with the documented default API key.
{
  echo "# Rendered by /opt/cybercore/caldera-render-conf.sh at service start."
  echo "# DO NOT EDIT: rewritten on every restart from the key files in $KEY_DIR."
  echo "# To rotate a secret, replace the key file and restart caldera.service."
  echo "host: 0.0.0.0"
  echo "port: ${CALDERA_PORT}"
  # The address agents are told to beacon to. Non-empty by the guard above.
  echo "app.contact.http: http://${CALDERA_CONTACT_HOST}:${CALDERA_PORT}"
  echo "api_key_red: $(yq_quote "$API_RED")"
  echo "api_key_blue: $(yq_quote "$API_BLUE")"
  echo "encryption_key: $(yq_quote "$ENC_KEY")"
  echo "crypt_salt: $(yq_quote "$CRYPT_SALT")"
  echo "users:"
  echo "  red:"
  echo "    red: $(yq_quote "$UI_RED")"
  echo "  blue:"
  echo "    blue: $(yq_quote "$UI_BLUE")"
  # PLUGINS. sandcat is the agent: it compiles the implant, serves it for
  # download, and owns the HTTP endpoints an agent beacons into. stockpile is
  # where the abilities an adversary is built FROM live.
  echo "plugins:"
  echo "  - access"
  echo "  - sandcat"
  echo "  - stockpile"
  echo "  - compass"
  echo "  - response"
} > "$TMP"

chmod 600 "$TMP"
mv -f "$TMP" "$CONF_DIR/local.yml"
RENDER_EOF

RENDER_CONF_B64=$(printf '%s\n' "$RENDER_CONF_SH" | base64 -w0)

# Secrets, base64'd on the HOST so no literal '$' or backtick ever reaches the
# unquoted heredoc below and expands there.
API_RED_B64=$(printf '%s' "$CALDERA_API_KEY_RED"    | base64 -w0)
API_BLUE_B64=$(printf '%s' "$CALDERA_API_KEY_BLUE"  | base64 -w0)
ENC_KEY_B64=$(printf '%s' "$CALDERA_ENCRYPTION_KEY" | base64 -w0)
SALT_B64=$(printf '%s' "$CALDERA_CRYPT_SALT"        | base64 -w0)
# UI logins are separate from the API keys on purpose: an instructor pasting a
# UI password into a browser and an engine adapter sending an API header are
# different blast radii, and reusing one value for both means rotating either
# rotates both.
UI_RED_B64=$(printf '%s' "${CALDERA_UI_PASSWORD_RED:-$CALDERA_API_KEY_RED}"   | base64 -w0)
UI_BLUE_B64=$(printf '%s' "${CALDERA_UI_PASSWORD_BLUE:-$CALDERA_API_KEY_BLUE}" | base64 -w0)

# ---------- 1. cloud-init user-data ----------
cat > "$USERDATA_PATH" <<CLOUDINIT
#cloud-config
hostname: caldera-server
manage_etc_hosts: true

users:
  - name: ${TEMPLATE_USER}
    groups: [wheel]
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    shell: /bin/bash
    lock_passwd: false

chpasswd:
  list: |
    ${TEMPLATE_USER}:${TEMPLATE_PASSWORD}
    root:${TEMPLATE_PASSWORD}
  expire: false

ssh_pwauth: true

write_files:
  # ------------------------------------------------------------------------
  # THE MOST IMPORTANT FILE IN THIS BAKE, for the same reason it is in the
  # sensor bake: distro qemu-guest-agent packages ship a default that
  # BLACKLISTS the guest-exec and guest-file-* RPCs. With it in place every
  # agentShellExec returns HTTP 596 while guest-ping and network-get-interfaces
  # succeed — so the VM looks perfectly healthy and nothing can be dispatched
  # into it at all. On RHEL/Rocky the setting lives here under two different
  # names depending on version; both are cleared, because which one is honoured
  # varies across qemu-ga releases and setting the unused one is harmless.
  # ------------------------------------------------------------------------
  - path: /etc/sysconfig/qemu-ga
    permissions: '0644'
    content: |
      # Cleared by bake-caldera-server.sh. Every postDeploy step that installs
      # a sandcat agent, rotates a key or reads this box's state goes over
      # guest-exec. Re-enabling either list below silently disables all of it.
      BLACKLIST_RPC=
      BLOCK_RPCS=
      FSFREEZE_HOOK_PATHNAME=/etc/qemu-ga/fsfreeze-hook

  # The base image ships 'PasswordAuthentication no', and cloud-init's
  # 'ssh_pwauth: true' does NOT survive templating: 'cloud-init clean' at seal
  # time discards this bake's user-data and the clone's deploy-time cloud-init
  # never re-asserts it. A drop-in file does survive.
  #
  # 00- so it sorts ahead of 50-redhat.conf: in sshd_config the FIRST occurrence
  # of a keyword wins, not the last — the opposite of most configs.
  #
  # NOTE: this is for STAFF access. See the hand-off block — no student console
  # is ever published for this machine.
  - path: /etc/ssh/sshd_config.d/00-cybercore.conf
    permissions: '0600'
    content: |
      PasswordAuthentication yes

  # ---- Non-secret bake facts, read by the render script and by humans ----
  - path: /etc/cybercore-caldera.env
    permissions: '0644'
    content: |
      CALDERA_REF=${CALDERA_REF}
      CALDERA_PORT=${CALDERA_PORT}
      # Agents beacon to the name below and the LANE GATEWAY publishes it.
      # Emptying it or deleting the line does not produce a server with no
      # agents — caldera.service's ExecStartPre refuses to render a config
      # without it, so the unit fails loudly instead of coming up telling every
      # agent to beacon at a hostless URL. Rotating it means re-installing
      # every agent in the lane.
      CALDERA_CONTACT_HOST=${CALDERA_CONTACT_HOST}

  # ---- THE SECRETS. Files, 0600, root. Never arguments. See the header. ----
  - path: /opt/cybercore/caldera-api-key.red
    permissions: '0600'
    owner: root:root
    encoding: b64
    content: ${API_RED_B64}
  - path: /opt/cybercore/caldera-api-key.blue
    permissions: '0600'
    owner: root:root
    encoding: b64
    content: ${API_BLUE_B64}
  - path: /opt/cybercore/caldera-encryption-key
    permissions: '0600'
    owner: root:root
    encoding: b64
    content: ${ENC_KEY_B64}
  - path: /opt/cybercore/caldera-crypt-salt
    permissions: '0600'
    owner: root:root
    encoding: b64
    content: ${SALT_B64}
  - path: /opt/cybercore/caldera-ui-password.red
    permissions: '0600'
    owner: root:root
    encoding: b64
    content: ${UI_RED_B64}
  - path: /opt/cybercore/caldera-ui-password.blue
    permissions: '0600'
    owner: root:root
    encoding: b64
    content: ${UI_BLUE_B64}

  - path: /opt/cybercore/caldera-render-conf.sh
    permissions: '0700'
    owner: root:root
    encoding: b64
    content: ${RENDER_CONF_B64}

  - path: /etc/systemd/system/caldera.service
    permissions: '0644'
    content: |
      [Unit]
      Description=MITRE Caldera (lane-local C2)
      After=network-online.target
      Wants=network-online.target

      [Service]
      Type=simple
      WorkingDirectory=/opt/caldera
      # Re-render the config from the key FILES on every start. This is the
      # per-lane rotation seam: replace a key file, restart, done. Nothing here
      # ever puts a secret on a command line.
      ExecStartPre=/opt/cybercore/caldera-render-conf.sh
      ExecStart=/opt/caldera-venv/bin/python server.py --insecure
      Restart=always
      RestartSec=10
      User=root
      Environment=PYTHONUNBUFFERED=1

      [Install]
      WantedBy=multi-user.target
CLOUDINIT
echo "==> Wrote bake snippet: $USERDATA_PATH"

cat >> "$USERDATA_PATH" <<CLOUDINIT

runcmd:
  # ---- DNS first: everything below needs the internet ----
  - [ sh, -c, 'rm -f /etc/resolv.conf; printf "nameserver ${BAKE_DNS}\n" > /etc/resolv.conf' ]

  # ---- Base packages ----
  #      golang is not optional: sandcat COMPILES its agent binary on demand
  #      when an operator requests a payload. Without a toolchain the download
  #      endpoint returns a 500 and the only symptom is "the agent link is
  #      broken", days after the bake.
  - [ sh, -c, 'dnf install -y --allowerasing git tar coreutils util-linux qemu-guest-agent golang ${CALDERA_PY} ${CALDERA_PY}-devel gcc make' ]

  # ---- SELinux. Identical reasoning to the sensor bake: qemu-ga runs confined
  #      in virt_qemu_ga_t on RHEL derivatives and cannot write files or fork
  #      detached processes, so every guest-exec-driven deploy step against this
  #      machine fails while the VM looks perfectly healthy. ----
  - [ sh, -c, 'setsebool -P virt_qemu_ga_run_unconfined 1 2>/dev/null || true' ]
  - [ sh, -c, 'sed -i "s/^SELINUX=.*/SELINUX=${SELINUX_MODE}/" /etc/selinux/config || true' ]
  - [ sh, -c, 'setenforce 0 2>/dev/null || true' ]

  # ---- Caldera at the pinned tag. --recursive because the plugins ARE
  #      submodules, and a non-recursive clone produces a server that starts,
  #      serves a UI and has no abilities at all. ----
  - [ sh, -c, 'git clone --recursive --branch ${CALDERA_REF} ${CALDERA_REPO} /opt/caldera' ]
  - [ sh, -c, 'cd /opt/caldera && git submodule update --init --recursive' ]

  # ---- Python deps in a venv, NOT into the system interpreter. Rocky's
  #      /usr/bin/python3 is a platform dependency (dnf itself uses it); pip
  #      installing a large tree over it is how a base image stops being able
  #      to update itself. ----
  - [ sh, -c, '${CALDERA_PY} -m venv /opt/caldera-venv' ]
  - [ sh, -c, '/opt/caldera-venv/bin/pip install --upgrade pip wheel' ]
  - [ sh, -c, 'cd /opt/caldera && /opt/caldera-venv/bin/pip install -r requirements.txt' ]
CLOUDINIT

cat >> "$USERDATA_PATH" <<CLOUDINIT

  # ---- Render the config from the key files, then start ----
  - [ sh, -c, 'mkdir -p /opt/cybercore && chmod 700 /opt/cybercore' ]
  - [ sh, -c, '/opt/cybercore/caldera-render-conf.sh' ]
  - [ systemctl, daemon-reload ]
  - [ systemctl, enable, caldera ]
  - [ systemctl, start, caldera ]

  # ---- Services ----
  - [ systemctl, enable, qemu-guest-agent ]
  - [ systemctl, restart, qemu-guest-agent ]

  # ---- Give the server time to bind before the API marker is taken. Caldera
  #      loads every plugin at start and that is not instant on a cold page
  #      cache; a marker taken too early records a healthy bake as broken. ----
  - [ sh, -c, 'for i in \$(seq 1 60); do curl -fsS -o /dev/null "http://127.0.0.1:${CALDERA_PORT}/api/v2/health" && break; sleep 5; done' ]

  # ---- Pre-seal markers, read back over the guest agent before sealing ----
  - [ sh, -c, 'systemctl is-enabled qemu-guest-agent >/dev/null && echo "GUEST_AGENT_ENABLED=yes" >> /etc/cybercore-bake.env || echo "GUEST_AGENT_ENABLED=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'grep -Eq "^(BLACKLIST_RPC|BLOCK_RPCS)=\$" /etc/sysconfig/qemu-ga && echo "GUEST_AGENT_UNBLOCKED=yes" >> /etc/cybercore-bake.env || echo "GUEST_AGENT_UNBLOCKED=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'grep -q "^SELINUX=${SELINUX_MODE}" /etc/selinux/config && echo "SELINUX_MODE_SET=yes" >> /etc/cybercore-bake.env || echo "SELINUX_MODE_SET=no" >> /etc/cybercore-bake.env' ]

  # THE PIN. Two markers, because they fail differently: a tag that does not
  # exist makes the clone fail outright, while a tag that MOVED leaves a healthy
  # checkout at the wrong commit — and the ability catalog is what silently
  # diverges then.
  - [ sh, -c, 'cd /opt/caldera && echo "CALDERA_TAG_ACTUAL=\$(git describe --tags --always 2>/dev/null)" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'cd /opt/caldera && echo "CALDERA_SHA_ACTUAL=\$(git rev-parse HEAD)" >> /etc/cybercore-bake.env' ]

  # THE SERVICE.
  - [ sh, -c, 'systemctl is-enabled caldera >/dev/null 2>&1 && echo "CALDERA_SERVICE_ENABLED=yes" >> /etc/cybercore-bake.env || echo "CALDERA_SERVICE_ENABLED=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'systemctl is-active caldera >/dev/null 2>&1 && echo "CALDERA_SERVICE_ACTIVE=yes" >> /etc/cybercore-bake.env || echo "CALDERA_SERVICE_ACTIVE=no" >> /etc/cybercore-bake.env' ]

  # THE API ANSWERS ON LOCALHOST. Unauthenticated /api/v2/health on purpose:
  # authenticating here would put the API key in curl's argv, which is exactly
  # the class of exposure this bake exists to avoid. What is being proven is
  # "the server is listening and serving", not "the key works" — the key is
  # proven by the first real operation, on a lane, after E8.
  - [ sh, -c, 'curl -fsS -o /dev/null -m 10 "http://127.0.0.1:${CALDERA_PORT}/api/v2/health" && echo "CALDERA_API_LOCAL=yes" >> /etc/cybercore-bake.env || echo "CALDERA_API_LOCAL=no" >> /etc/cybercore-bake.env' ]

  # THE SECRETS ARE FILES, AND THEY ARE PRIVATE.
  - [ sh, -c, 'test -s /opt/cybercore/caldera-api-key.red && echo "API_KEY_FILE=yes" >> /etc/cybercore-bake.env || echo "API_KEY_FILE=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'echo "API_KEY_PERMS=\$(stat -c %a /opt/cybercore/caldera-api-key.red 2>/dev/null)" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'grep -q "ADMIN123" /opt/caldera/conf/local.yml && echo "KEY_IS_DEFAULT=yes" >> /etc/cybercore-bake.env || echo "KEY_IS_DEFAULT=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'echo "CONF_PERMS=\$(stat -c %a /opt/caldera/conf/local.yml 2>/dev/null)" >> /etc/cybercore-bake.env' ]
  # local.yml must WIN over the shipped default.yml, or the server runs with
  # Caldera's documented placeholder key and nothing anywhere says so.
  - [ sh, -c, 'grep -q "api_key_red" /opt/caldera/conf/local.yml && echo "CONF_RENDERED=yes" >> /etc/cybercore-bake.env || echo "CONF_RENDERED=no" >> /etc/cybercore-bake.env' ]

  # THE CONTACT HOST, PROVEN THREE WAYS. Two of these came in with the role
  # split and are kept because neither was ever about the role: each asks a
  # different question about the one address that decides whether this image is
  # a lane's own C2 or a pivot between lanes.
  #
  #   CONTACT_CONFIGURED   the rendered config has an app.contact.http key at
  #                        all. Without one the server is up and no agent can
  #                        ever reach it.
  #   CONTACT_ENV_PRESENT  the guest's env file still carries the key that the
  #                        ExecStartPre render reads, so the NEXT boot — in a
  #                        lane, weeks from now — renders too. Without this
  #                        marker the only symptom of a lost key is
  #                        "caldera.service is not active", which reads like a
  #                        dependency failure and sends you to the wrong place.
  #   CONTACT_LANE_LOCAL   the address is the exact lane-local name this bake
  #                        was told to use, not merely present.
  - [ sh, -c, 'grep -q "^app.contact.http:" /opt/caldera/conf/local.yml && echo "CONTACT_CONFIGURED=yes" >> /etc/cybercore-bake.env || echo "CONTACT_CONFIGURED=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'grep -q "^CALDERA_CONTACT_HOST=" /etc/cybercore-caldera.env && echo "CONTACT_ENV_PRESENT=yes" >> /etc/cybercore-bake.env || echo "CONTACT_ENV_PRESENT=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'grep -q "app.contact.http: http://${CALDERA_CONTACT_HOST}:${CALDERA_PORT}" /opt/caldera/conf/local.yml && echo "CONTACT_LANE_LOCAL=yes" >> /etc/cybercore-bake.env || echo "CONTACT_LANE_LOCAL=no" >> /etc/cybercore-bake.env' ]

  # AGENT DELIVERY. sandcat is what compiles and serves the agent; stockpile is
  # where the abilities the adversary compiler maps onto actually live. Either
  # missing is a server that starts and cannot do the one thing it is for.
  - [ sh, -c, 'test -d /opt/caldera/plugins/sandcat/gocat && echo "SANDCAT_PLUGIN=yes" >> /etc/cybercore-bake.env || echo "SANDCAT_PLUGIN=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'test -d /opt/caldera/plugins/stockpile/data/abilities && echo "STOCKPILE_ABILITIES=yes" >> /etc/cybercore-bake.env || echo "STOCKPILE_ABILITIES=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'command -v go >/dev/null && echo "GO_TOOLCHAIN=yes" >> /etc/cybercore-bake.env || echo "GO_TOOLCHAIN=no" >> /etc/cybercore-bake.env' ]
  - [ sh, -c, 'test -x /opt/caldera-venv/bin/python && echo "PY_VENV=yes" >> /etc/cybercore-bake.env || echo "PY_VENV=no" >> /etc/cybercore-bake.env' ]
CLOUDINIT

# BAKE_COMPLETE is written LAST, on its own, and the host polls for it. Anything
# appended after this line would be running after the host has already decided
# the bake is finished.
cat >> "$USERDATA_PATH" <<CLOUDINIT

  - [ sh, -c, 'echo "BAKE_COMPLETE=yes" >> /etc/cybercore-bake.env' ]
CLOUDINIT
echo "==> Appended runcmd"

# ---------- 2. Clone + configure ----------
echo "==> Cloning $SRC_VMID -> $VMID (full clone onto $STORAGE)"
qm clone "$SRC_VMID" "$VMID" --name "$NAME" --full 1 --storage "$STORAGE"

qm set $VMID \
  --memory "$MEMORY" \
  --cores "$CORES" \
  --agent enabled=1 \
  --net0 "virtio,bridge=${BAKE_BRIDGE},tag=${BAKE_VLAN}" \
  --ipconfig0 ip=dhcp \
  --nameserver "$BAKE_DNS" \
  --ciuser "$TEMPLATE_USER" \
  --cipassword "$TEMPLATE_PASSWORD" \
  --cicustom "user=${SNIPPET_STORAGE}:snippets/${USERDATA_FILE}"

echo "==> Growing disk by ${DISK_GROW}"
qm resize $VMID scsi0 "+${DISK_GROW}" 2>/dev/null || qm resize $VMID virtio0 "+${DISK_GROW}" 2>/dev/null || \
  echo "WARNING: could not grow the disk — check free space before first use"

# ---------- 3. Boot + wait for the bake ----------
echo "==> Starting $VMID and waiting for cloud-init"
qm start $VMID

# Poll the marker file through the guest agent rather than mounting the disk.
# Reading it live works on any storage AND proves guest-exec itself is
# functional — which for this template matters as much as it does for the
# sensor, because every per-lane step against this box (key rotation, agent
# install, state read) goes over exactly that RPC.
DEADLINE=$(( $(date +%s) + 2400 ))
BAKE_ENV=""
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  if OUT=$(qm guest exec $VMID -- /bin/sh -c 'cat /etc/cybercore-bake.env 2>/dev/null' 2>/dev/null); then
    # `qm guest exec` returns JSON, and out-data is a JSON STRING: the file's
    # real newlines arrive as the two-character escape \n. Decode them with
    # printf %b, or the whole marker file parses as ONE line and every marker
    # after the first reads as part of the first one's value — which looks
    # exactly like a bake that did nothing, on a bake that did everything.
    # [^"] rather than .* so the match stops at out-data's own closing quote
    # instead of running on to the last quote in the JSON object.
    BAKE_ENV=$(printf '%s' "$OUT" | sed -n 's/.*"out-data"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    [ -z "$BAKE_ENV" ] && BAKE_ENV="$OUT"
    BAKE_ENV=$(printf '%b' "$BAKE_ENV")
    if printf '%s' "$BAKE_ENV" | grep -q 'BAKE_COMPLETE=yes'; then
      echo "==> cloud-init finished"
      break
    fi
  fi
  echo "    ... still baking ($(( (DEADLINE - $(date +%s)) / 60 ))m budget left)"
  sleep 20
done

if ! printf '%s' "$BAKE_ENV" | grep -q 'BAKE_COMPLETE=yes'; then
  echo "ERROR: bake did not complete within the budget. VM $VMID left running for inspection:" >&2
  echo "       qm guest exec $VMID -- /bin/sh -c 'tail -80 /var/log/cloud-init-output.log'" >&2
  echo "       qm guest exec $VMID -- /bin/sh -c 'journalctl -u caldera -n 80 --no-pager'" >&2
  echo "" >&2
  echo "  REMINDER: this script has never been executed. A first-run failure here is the" >&2
  echo "  expected outcome, not an anomaly. The most likely causes, in order:" >&2
  echo "    1. CALDERA_REF is not a real tag                       (git clone --branch fails)" >&2
  echo "    2. Caldera's requirements.txt does not build on Rocky  (pip install fails)" >&2
  echo "    3. ${CALDERA_PY} is not in Rocky's AppStream            (dnf install fails)" >&2
  exit 1
fi

# ---------- 4. Pre-seal verification ----------
echo "==> Verifying bake markers"
marker() { printf '%s' "$BAKE_ENV" | awk -F= -v k="$1" '$1==k {print $2; exit}'; }

FAIL=0
check() {  # check <marker> <expected> <explanation of what breaks>
  local got; got=$(marker "$1")
  printf '    %-24s %s\n' "$1:" "${got:-unset}"
  if [ "$got" != "$2" ]; then
    echo "    ERROR: $3" >&2
    FAIL=1
  fi
}

check GUEST_AGENT_ENABLED   yes "qemu-guest-agent is not enabled — nothing can reach this VM to install an agent, rotate a key or read its state"
check GUEST_AGENT_UNBLOCKED yes "guest-exec is still blacklisted in /etc/sysconfig/qemu-ga — every dispatch returns 596 while the VM looks healthy"
check SELINUX_MODE_SET      yes "SELinux is still enforcing — guest-exec runs confined in virt_qemu_ga_t and cannot stage or fork anything, so every per-lane step against this box fails silently"
check PY_VENV               yes "/opt/caldera-venv is missing — the unit's ExecStart points at an interpreter that does not exist and the service will restart-loop forever"
check CALDERA_SERVICE_ENABLED yes "caldera.service is not enabled — a cloned lane boots with no C2 and the only symptom is agents that never appear"
check CALDERA_SERVICE_ACTIVE  yes "caldera.service is enabled but not running — read 'journalctl -u caldera'; a config error looks identical to a dependency error from outside"
check CALDERA_API_LOCAL     yes "the API does not answer on 127.0.0.1 — the server is not serving, so no adapter and no agent will ever reach it. This is the single marker that most nearly proves the bake worked"
check CONF_RENDERED         yes "conf/local.yml was not rendered — Caldera then falls back to the shipped conf/default.yml, which carries the DOCUMENTED PLACEHOLDER API KEY, and nothing anywhere says so"
check API_KEY_FILE          yes "the API key file is missing — the render script has nothing to read and the config falls back to defaults"
check API_KEY_PERMS         600 "the API key file is not 0600 — a C2 credential readable by any local account on a machine whose whole job is running commands"
check CONF_PERMS            600 "conf/local.yml is not 0600 — it holds every secret in this image in plaintext"
check KEY_IS_DEFAULT        no  "Caldera's shipped placeholder key is still in the rendered config"
check STOCKPILE_ABILITIES   yes "the stockpile plugin has no abilities — src/incident/caldera/adversary.js maps techniques onto ability ids from this catalog, so an empty one makes EVERY scenario step unmapped"

# ---- The contact host: present, readable on the NEXT boot, and lane-local ----
#
# Three checks on one address, and they fail differently. CONTACT_CONFIGURED is
# about the config the server is running RIGHT NOW; CONTACT_ENV_PRESENT is about
# whether the ExecStartPre render will still succeed after the clone reboots in
# a lane; CONTACT_LANE_LOCAL is about whether the address is the RIGHT one. A
# bake can pass the first and fail either of the others.
check CONTACT_CONFIGURED  yes "conf/local.yml has no app.contact.http key — agents have no address to beacon to, and the symptom is a healthy lane C2 that no agent ever appears on"
check CONTACT_ENV_PRESENT yes "/etc/cybercore-caldera.env has no CALDERA_CONTACT_HOST — this bake's render happened to run with one in the environment, but caldera.service's ExecStartPre reads that FILE and will refuse to start on the next boot. Every clone of this template would come up dead, in a lane, with nobody watching"
check CONTACT_LANE_LOCAL  yes "app.contact.http is not the lane-local name — agents baked from this image would beacon somewhere other than their own lane's server, which is a live pivot between student lanes"
check SANDCAT_PLUGIN      yes "the sandcat plugin is missing — the server cannot produce an agent, so nothing can ever be executed. Almost always a non-recursive clone"
check GO_TOOLCHAIN        yes "no Go toolchain — sandcat compiles its agent binary on demand and the download endpoint 500s without one"

ACTUAL_TAG=$(marker CALDERA_TAG_ACTUAL)
ACTUAL_SHA=$(marker CALDERA_SHA_ACTUAL)
printf '    %-24s %s\n' "CALDERA_TAG_ACTUAL:" "${ACTUAL_TAG:-unset}"
printf '    %-24s %s\n' "CALDERA_SHA_ACTUAL:" "${ACTUAL_SHA:-unset}"
# The pin, checked rather than assumed. `git describe --tags` on an exact tag
# returns the tag; on a moved or re-pointed one it returns tag-N-gSHA, which is
# the case worth catching — the checkout is healthy and the ability catalog is
# not the one anything was written against.
case "$ACTUAL_TAG" in
  "$CALDERA_REF") : ;;
  *)
    echo "    ERROR: checked out '${ACTUAL_TAG:-nothing}', expected exactly '$CALDERA_REF'." >&2
    echo "           The adversary compiler in front-end/src/incident/caldera/adversary.js maps" >&2
    echo "           techniques onto ABILITY IDS, and those ids belong to a specific stockpile" >&2
    echo "           revision. A drifted pin produces adversaries this server 404s on." >&2
    echo "           Record ${ACTUAL_SHA:-?} alongside the template registration either way." >&2
    FAIL=1
    ;;
esac

if [ "$FAIL" -ne 0 ]; then
  echo "" >&2
  echo "ERROR: verification failed. VM $VMID left RUNNING and unsealed for inspection." >&2
  echo "       qm guest exec $VMID -- /bin/sh -c 'journalctl -u caldera -n 100 --no-pager'" >&2
  echo "       qm guest exec $VMID -- /bin/sh -c 'tail -100 /var/log/cloud-init-output.log'" >&2
  exit 1
fi
echo "==> All markers good"

# ---------- 5. Seal ----------
echo "==> Cleaning cloud-init state and sealing"
# Stop first: Caldera writes its object store continuously and a template
# snapshotted mid-write hands every clone a half-flushed database.
qm guest exec $VMID -- /bin/sh -c 'systemctl stop caldera' >/dev/null 2>&1 || true
# Bake-time state must not travel into every lane: agents that checked in during
# the bake, operations, and any agent binary already compiled for a different
# contact address.
qm guest exec $VMID -- /bin/sh -c 'rm -rf /opt/caldera/data/results/* /opt/caldera/data/object_store /opt/caldera/data/payloads/sandcat* 2>/dev/null || true' >/dev/null 2>&1 || true
qm guest exec $VMID -- /bin/sh -c 'rm -rf /opt/caldera/logs/* 2>/dev/null || true' >/dev/null 2>&1 || true
qm guest exec $VMID -- /bin/sh -c 'cloud-init clean --logs --seed 2>/dev/null || true' >/dev/null 2>&1 || true
qm guest exec $VMID -- /bin/sh -c 'truncate -s 0 /etc/machine-id' >/dev/null 2>&1 || true

qm shutdown $VMID --timeout 120 || qm stop $VMID
for _ in $(seq 1 30); do
  [ "$(qm status $VMID | awk '{print $2}')" = "stopped" ] && break
  sleep 3
done

echo "==> Clearing bake-time cicustom + cloud-init fields"
qm set $VMID --delete cicustom
qm set $VMID --delete cipassword 2>/dev/null || true
# The snippet held every secret in transit. It goes now, not later.
rm -f "$USERDATA_PATH"

qm template $VMID
echo "==> Template $VMID ($NAME) sealed"
# ---------- 6. What still has to happen by hand ----------
cat <<NEXTSTEPS
============================================================================
 Template $VMID ($NAME) is built: a LANE-LOCAL Caldera executor, one clone per
 student lane. Nothing about it is wired into CyberCore yet.

 0. WHAT IS GATED ON E8, AND WHAT IS NOT.

    Caldera is Track E phase E9 and E9 is explicitly DROPPABLE. The E8 cluster
    gate — a defensive_monitoring engagement deployed end to end, the synthetic
    scenario landing in Kibana, a student board submitted and released — is what
    proves the incident engine works AT ALL.

    EXECUTION — WHICH IS THIS TEMPLATE — IS GATED ON IT, and stays gated.
    Standing a real C2 up on top of an unproven pipeline means every failure has
    two candidate causes. As of this bake:

      - 'caldera' is legal in cybercore_incident_run's engine CHECK but is NOT
        registered in front-end/src/incident/engines/index.js: engineFor()
        THROWS a named error for it and registeredEngines() is ["synthetic"].
        That gate is deliberate and correct. Do not open it here.
      - front-end/src/incident/caldera/adversary.js compiles an adversary and
        an answer key; front-end/src/incident/engines/caldera.js is a complete
        nine-method adapter that nothing reaches.
      - there is no route and no UI that dispatches to Caldera. Do not add one,
        and do not let a route read an engine name off a request body.

    AUTHORING IS NOT GATED ON IT, and authoring is not this template — it is a
    container. See section 6. An authoring instance has no agents, no contact
    host and no path into any lane, so an instructor building adversaries on it
    cannot affect a student machine: there is nothing on it to affect one with.
NEXTSTEPS

cat <<NEXTSTEPS

 1. REGISTER THE TEMPLATE.

    Admin -> Workstation Templates (or the os_template path, if this machine
    is placed as a spec VM rather than an extra):

        os_family      linux
        os_name        Rocky Linux (Caldera C2)
        template_vmid  $VMID
        template_key   caldera-server-template
        metadata       {"console_protocol": "ssh", "dns_aliases": ["caldera"]}

    console_protocol=ssh is not cosmetic: resolveConsole() defaults to rdp, so
    leaving it unset publishes a gateway DNAT to 3389 on a Linux box that is
    not listening there.

    dns_aliases is what makes the whole lane-local design work. The image tells
    every agent to beacon to ${CALDERA_CONTACT_HOST}, and that name is
    published by the LANE GATEWAY's dnsmasq as a host-record pointing at
    whatever address this box took in that lane. Without the alias the agents
    resolve nothing, and the symptom is a healthy server with no agents — the
    same silent failure E3a documents for the sensor and 'elk'.

    Then POST /api/admin/vm-templates/sync-nodes so 'node' is filled in.
    Do NOT add a seed migration: front-end/migrations/ has no runner, so a file
    there would never execute.

 2. TAG role_hints SO A RESOLVER CAN FIND IT — AND CANNOT CONFUSE IT.

    role_hints is not writable from any admin UI, so it is one SQL statement:

        UPDATE cybercore_template_catalog
           SET role_hints = '{caldera}'
         WHERE template_key = 'caldera-server-template';

    Mirror of the 'loggen' and 'elk' tags. A missing tag must become a NAMED
    400 at deploy time in whatever resolver eventually reads it — never a lane
    that deploys happily with no C2.

    'caldera' is the ONLY Caldera role hint there is, and it must resolve to
    this template and nothing else. There is no 'caldera-authoring' template to
    confuse it with any more — authoring is a container, see section 6 — so the
    mistake left to make is a lane whose C2 resolves to something OUTSIDE the
    lane. That is one controller holding implants from every student at once,
    with no lane isolation in front of it.

 3. NEVER PUBLISH A STUDENT CONSOLE FOR THIS MACHINE.

    This box holds the operation, the adversary, the link results and the API
    keys. A student with a session on it has the entire answer key, and no
    amount of care in src/incident/projection.js matters after that.

      - keep it out of consoleTargets in the installConsoleDnat call
      - do not give it a console_role
      - if it is placed as an extraWorkstation it WILL get cloud-init
        credentials and a Guacamole connection; place it as a spec VM, or
        explicitly exclude it from the console plan

    The SSH password-auth drop-in baked in above is for STAFF reaching it from
    inside the lane, and for nothing else.

    To confirm over guest-exec that a machine really is a lane's own C2, read
    the address its agents were told to beacon to — that is the fact that
    matters, and it is the one the service refuses to start without:

        qm guest exec $VMID -- /bin/sh -c 'cat /etc/cybercore-caldera.env'
        -> CALDERA_CONTACT_HOST=${CALDERA_CONTACT_HOST}

 4. WHAT THIS SCRIPT COULD NOT VERIFY, AND WHO HAS TO.

    Everything below needs a lane, and none of it is provable at bake time:

      a. That the lane gateway actually drops egress from this box. Bake-time
         checks confirmed the CONFIGURED contact address is lane-local; they
         cannot confirm the ROUTE is. Verify per lane:
             getent hosts ${CALDERA_CONTACT_HOST}
             curl -m 5 https://example.com     # must FAIL
      b. That a sandcat agent compiles, installs and beacons. Deliver the
         agent's key as a FILE through post_clone_scripts / postDeploy, never
         through script_args — see this file's header for exactly why.
      c. That the ability catalog this server serves matches what the compiler
         was tested against. This is the check that matters most, and it is
         one command plus one function call:
             curl -s -H "KEY: <red key>" \\
               http://127.0.0.1:${CALDERA_PORT}/api/v2/abilities > abilities.json
         then feed that array to compileAdversary({scenario, abilities}) in
         front-end/src/incident/caldera/adversary.js and read its 'warnings'
         and 'unmapped'. Every unmapped technique is a scenario step that will
         NOT happen — an exercise whose answer key would otherwise describe
         activity that never occurred.
      d. That /api/v2/health is in fact unauthenticated on ${CALDERA_REF}. The
         marker above assumes it is. If the marker fails while the server is
         demonstrably up, that assumption is what is wrong — fix the marker,
         do not authenticate it, because authenticating puts the API key in
         curl's argv and that is the exposure this bake is built to avoid.

 5. THE BAKED SECRETS ARE THE SAME IN EVERY CLONE.

    That matches the existing bake-debug convention for lab templates and is
    acceptable only because this server is lane-local and lanes are
    per-student. Rotate per lane by overwriting the key file and restarting:

        /opt/cybercore/caldera-api-key.red     (0600, root)
        /opt/cybercore/caldera-api-key.blue
        /opt/cybercore/caldera-encryption-key  <- see the warning below
        /opt/cybercore/caldera-crypt-salt
        /opt/cybercore/caldera-ui-password.red
        /opt/cybercore/caldera-ui-password.blue

        systemctl restart caldera    # ExecStartPre re-renders conf/local.yml

    DO NOT rotate caldera-encryption-key on a server that already holds
    objects: everything encrypted under the old key becomes undecryptable, and
    the symptom is a server that starts fine and has lost its operations.
NEXTSTEPS

cat <<NEXTSTEPS

 6. THE AUTHORING INSTANCE IS NOT THIS TEMPLATE, AND IS NOT A VM AT ALL.

    An earlier revision of this script carried a second role that baked a
    standalone, agent-less authoring VM. That is gone. The authoring instance
    has NO agents and executes NOTHING — it is a web app in front of a content
    store — so it is a DOCKER CONTAINER on the CyberCore host now:

      - a compose service in docker-compose.yml on cybercore-net that publishes
        NO host port. That is the security property and it is structural: with
        no port binding there is nothing to reach except through Caddy, so there
        is no firewall rule to maintain and none to forget.
      - fronted by the /caldera* handle in BOTH site blocks of
        config/caddy/Caddyfile, gated by an authorization subrequest the app
        answers — the same shape /guacamole* already uses.
      - front-end/src/routes/caldera-authoring.js answers that gate. Read it and
        the Caddyfile before touching either. The mechanism is deliberately NOT
        restated in this script: a second copy of somebody else's security
        decision goes stale in silence, and the stale copy is the one people
        believe.

    So there is nothing to register: no 'caldera-authoring' template row, no VM
    to bake, no 'caldera-authoring' role hint on any catalog row. There is
    nothing on a Proxmox node to point one at.

    THE TWO ARE NEVER SUBSTITUTABLE. This template is a lane's own C2 and it is
    the only thing that should ever answer to the 'caldera' role hint. The
    authoring container must never become selectable as an EXECUTION engine, and
    no lane must ever resolve its C2 to something outside the lane — one
    controller, every student, no isolation in front of it is precisely the
    failure the whole lane-local design exists to prevent.

    GATING, RESTATED BECAUSE IT IS ASYMMETRIC AND EASY TO GET BACKWARDS:
    AUTHORING is not gated on E8, because it cannot touch a lane. EXECUTION —
    this template — still is: engineFor('caldera') throws and registeredEngines()
    is ["synthetic"].

 Test clone: qm clone $VMID 9993 --name caldera-test --full --storage $STORAGE
============================================================================
NEXTSTEPS
