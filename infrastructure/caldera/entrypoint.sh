#!/bin/sh
# =============================================================================
# CALDERA AUTHORING — CONTAINER ENTRYPOINT
# =============================================================================
# Two jobs, in this order:
#
#   1. FAIL CLOSED on a missing or weak SSO configuration. The login handler is
#      the ONLY door into this instance (conf/local.yml sets
#      auth.login.handler.module and gives every account an unknown random
#      password). If CALDERA_SSO_SECRET is absent or too short, the handler
#      cannot verify a token, and a container that starts anyway is a container
#      whose only door is in an undefined state. Refusing to start is loud,
#      immediate, and appears in `docker compose ps` as a restart loop with the
#      reason on the first line of the log — which is exactly what you want.
#
#   2. RENDER conf/local.yml from conf/local.yml.template, filling the
#      secret-bearing keys from the environment. Rendering is done by PyYAML
#      rather than sed/envsubst so that a secret containing a quote, a colon or a
#      newline cannot break out of its YAML scalar and silently rewrite the
#      config — which for `auth.login.handler.module` would mean rewriting the
#      lock.
#
# NOTHING BELOW EVER PRINTS A SECRET. Every diagnostic names the VARIABLE, never
# its value, and the render step reads the environment inside Python instead of
# interpolating it into a shell command line where `ps` could see it.
# =============================================================================
set -eu

APP_DIR="/usr/src/app"
TEMPLATE="${APP_DIR}/conf/local.yml.template"
TARGET="${APP_DIR}/conf/local.yml"
# Lives in the named volume, so a value generated on first boot survives every
# rebuild of the image. Losing it means losing the encrypted object store.
STATE_FILE="${APP_DIR}/data/.cybercore-crypto"

die() {
    echo "caldera-entrypoint: FATAL: $*" >&2
    exit 1
}

# --- 1. Fail closed ----------------------------------------------------------
# 32 bytes is the contract's floor, matched on the CyberCore side by
# front-end/src/utils/caldera-sso.js. `wc -c` counts BYTES, which is the right
# unit for an HMAC key; a multibyte character must not be allowed to pass a
# length check it does not really satisfy.
: "${CALDERA_SSO_SECRET:=}"
if [ -z "${CALDERA_SSO_SECRET}" ]; then
    die "CALDERA_SSO_SECRET is not set. There is no default and there will never
be one: without it the login handler cannot verify a token and the only door
into this instance would be in an undefined state. Generate one with
  openssl rand -hex 32
and put it in the .env file next to docker-compose.yml."
fi
SECRET_BYTES="$(printf '%s' "${CALDERA_SSO_SECRET}" | wc -c | tr -d ' ')"
if [ "${SECRET_BYTES}" -lt 32 ]; then
    die "CALDERA_SSO_SECRET is ${SECRET_BYTES} bytes; the contract requires at least 32."
fi

# The handler burns each token's jti against CyberCore before honouring it, so a
# replay inside the 60-second window fails. Without this URL there is no burn and
# the token stops being single-use, which is a real downgrade rather than a
# missing convenience — so it is fatal too.
: "${CYBERCORE_REDEEM_URL:=}"
if [ -z "${CYBERCORE_REDEEM_URL}" ]; then
    die "CYBERCORE_REDEEM_URL is not set. Without the single-use burn a token is
replayable for its whole 60-second lifetime. Expected value:
  http://app:3000/api/caldera/redeem"
fi

# --- 2. Render the config ----------------------------------------------------
# Python, not sed: see the header. The template is the source of truth for every
# NON-secret key; this only fills the ones the template leaves empty.
STATE_FILE="${STATE_FILE}" TEMPLATE="${TEMPLATE}" TARGET="${TARGET}" python - <<'PYRENDER'
import os
import secrets
import sys

import yaml

template_path = os.environ["TEMPLATE"]
target_path = os.environ["TARGET"]
state_path = os.environ["STATE_FILE"]

with open(template_path, "r", encoding="utf-8") as fh:
    conf = yaml.safe_load(fh)

if not isinstance(conf, dict):
    sys.exit("caldera-entrypoint: FATAL: conf/local.yml.template is not a mapping")


def persistent(name):
    """A value that MUST be identical on every start of this volume.

    encryption_key and crypt_salt decrypt the object store on disk. Regenerating
    them would leave the named volume full of ciphertext nothing can read, and
    the symptom is an empty adversary list rather than an error — so the value is
    generated exactly once and kept in the volume beside the data it protects.

    An environment value always wins, so an operator who wants these in their own
    secret store can have them there.
    """
    from_env = os.environ.get(name)
    if from_env:
        return from_env
    state = {}
    if os.path.exists(state_path):
        with open(state_path, "r", encoding="utf-8") as fh:
            state = yaml.safe_load(fh) or {}
    if not state.get(name):
        state[name] = secrets.token_hex(32)
        # 0600 before anything is written: the file is created by open(), so the
        # mode has to be set on the descriptor, not afterwards.
        fd = os.open(state_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            yaml.safe_dump(state, fh, default_flow_style=False)
    return state[name]


# Stable across restarts — see persistent().
conf["encryption_key"] = persistent("CALDERA_ENCRYPTION_KEY")
conf["crypt_salt"] = persistent("CALDERA_CRYPT_SALT")

# The v2 API keys. Pinned from the environment when an operator has set them
# (src/incident/caldera/client.js will need api_key_red when the engine adapter
# is finally wired up); otherwise ephemeral, which is safe today because nothing
# reads them yet and is far better than the published upstream constant.
conf["api_key_red"] = os.environ.get("CALDERA_API_KEY_RED") or secrets.token_hex(32)
conf["api_key_blue"] = os.environ.get("CALDERA_API_KEY_BLUE") or secrets.token_hex(32)

# Account passwords: random every start, never printed, never stored. The SSO
# handler attaches an already-authenticated instructor to the account by NAME, so
# nothing anywhere needs to know these — which is precisely what makes the
# built-in login form a dead end rather than a second door.
users = conf.get("users") or {}
for group, accounts in users.items():
    for account in list(accounts or {}):
        accounts[account] = secrets.token_hex(32)
conf["users"] = users

# The handler reads its own settings from the environment, not from here, so the
# signing key is never written to disk. Nothing below is a secret.
tmp_path = target_path + ".tmp"
fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    yaml.safe_dump(conf, fh, default_flow_style=False, sort_keys=True)
# Atomic replace, so a crash mid-render cannot leave a half-written config that
# Caldera would read as "no login handler configured".
os.replace(tmp_path, target_path)

print("caldera-entrypoint: rendered conf/local.yml "
      "(plugins=%s, contacts=none)" % ",".join(conf.get("plugins") or []))
PYRENDER

# --- 3. Hand off -------------------------------------------------------------
# exec so Caldera becomes the process tini supervises and receives SIGTERM
# directly; without exec, this shell would hold PID 1's child slot and every
# `docker compose restart` would wait out the SIGKILL timeout.
exec "$@"
