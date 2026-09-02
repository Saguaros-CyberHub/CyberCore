# syntax=docker/dockerfile:1
# =============================================================================
# CALDERA — AUTHORING INSTANCE  (container, not a VM)
# =============================================================================
# WHAT THIS IS, AND WHY IT IS A CONTAINER AT ALL
# -----------------------------------------------------------------------------
# There is exactly ONE authoring Caldera on this platform. It has no agents, no
# implants and no agent contact, so it EXECUTES NOTHING: instructors open its web
# UI to BUILD adversaries, and CyberCore later reads an adversary back out and
# replicates it into each lane's own lane-local Caldera. The per-lane EXECUTOR
# Calderas are still VMs (infrastructure/proxmox-templates/vm-templates/
# bake-caldera-server.sh, CALDERA_ROLE=executor) and are NOT built here.
#
# A web app plus a content store is a container, not a Proxmox guest. Modelled on
# the `guacamole` service in docker-compose.yml: it publishes NO host ports, sits
# only on cybercore-net, and Caddy reaches it by service name. With no port
# binding the container is unreachable except through Caddy — structurally, with
# no firewall rule to keep correct.
#
# WHY WE BUILD INSTEAD OF PULLING mitre/caldera
# -----------------------------------------------------------------------------
# MITRE publishes mitre/caldera on Docker Hub but its tags lag the releases, and
# the install docs are explicit that the supported install is
#   git clone --recursive --branch <release>
# --recursive is LOAD-BEARING: every Caldera plugin (magma, stockpile, atomic,
# compass, fieldmanual) is a git SUBMODULE. A non-recursive clone yields empty
# plugin directories and a server that starts with no UI and no abilities, which
# looks like a config problem and is not.
#
# NOTHING IN THIS REPOSITORY HAS EVER TALKED TO A RUNNING CALDERA. This file has
# never been built. Treat the version pin, the plugin list and the conf keys as
# careful reading of upstream, not as verified facts, and read the FIRST-BUILD
# NOTES at the bottom before debugging anything.
# =============================================================================

# --- The version pin. Bumping Caldera is THIS ONE LINE. ----------------------
# A release TAG, never a branch and never `master`: a floating ref would let an
# unreviewed upstream change land on the next `docker compose build`, and this
# image is reachable (through the gate) by every instructor.
# List the real tags before bumping:
#   git ls-remote --tags --refs https://github.com/mitre/caldera.git
# then rebuild:  docker compose build caldera && docker compose up -d caldera
ARG CALDERA_VERSION=5.3.0

# Caldera wants Python 3.9+. 3.11 is chosen over 3.12 deliberately: several of
# its pinned dependencies ship prebuilt wheels for 3.11 but not always for the
# newest interpreter, and a missing wheel turns this into a from-source compile
# in the deps stage below.
ARG PYTHON_TAG=3.11-slim-bookworm

# =============================================================================
# STAGE 1 — SOURCE.  Clone, then REMOVE what an authoring box must never have.
# =============================================================================
FROM python:${PYTHON_TAG} AS source
ARG CALDERA_VERSION

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# --shallow-submodules keeps the plugin submodules to one commit each; stockpile
# and atomic carry years of ability history that nothing here reads.
RUN git clone \
      --branch "${CALDERA_VERSION}" \
      --depth 1 \
      --recursive \
      --shallow-submodules \
      https://github.com/mitre/caldera.git /src/caldera

WORKDIR /src/caldera

# -----------------------------------------------------------------------------
# PLUGIN PRUNE — this is a SECURITY control, not a size optimisation.
# -----------------------------------------------------------------------------
# sandcat and manx are the AGENT PAYLOAD plugins. sandcat compiles and serves the
# agent binary; manx serves a reverse shell. Deleting them means this image
# contains no agent to hand out and no endpoint that hands one out, which is the
# durable form of "this instance must never take a check-in" — stronger than a
# config key, because a config key can be re-added by an operator in a hurry and
# a deleted plugin cannot be re-added without editing this file.
#
# Deleting sandcat is also why there is no Go toolchain anywhere below: sandcat
# is the only thing in Caldera that needs one, and it is the single largest
# contributor to the upstream image size.
#
# The others go because an authoring surface has no use for them: access (runs
# offensive tooling), human (drives agents to emulate user activity), response
# (blue-team autonomous response), training, gameboard, debrief (reports on
# operations that will never run here).
#
# KEPT: magma (the UI — mandatory in Caldera 5), stockpile (the ability and
# adversary library that authoring actually edits), atomic (the Atomic Red Team
# ability corpus — authoring value is the entire point of this box), compass
# (ATT&CK-navigator-style adversary building), fieldmanual (the in-app docs).
#
# `rm -rf` is intentionally quiet about names that do not exist so a version bump
# that renames a plugin does not fail the build; the `ls` that follows prints the
# surviving set into the build log, which is where you notice a rename.
RUN rm -rf \
      plugins/sandcat \
      plugins/manx \
      plugins/access \
      plugins/human \
      plugins/response \
      plugins/training \
      plugins/gameboard \
      plugins/debrief \
      plugins/emu \
      plugins/ssl \
 && echo "--- plugins surviving the prune ---" && ls -1 plugins

# -----------------------------------------------------------------------------
# CONTACT PRUNE — remove every module that OPENS A LISTENER for agents.
# -----------------------------------------------------------------------------
# conf/local.yml deliberately defines no `app.contact.*` key at all (see the note
# there). These modules are removed as well so that "no contact" is a property of
# the IMAGE rather than of a config file: contact_tcp/udp/websocket/dns/ftp each
# bind a socket at startup when configured, and gist/slack/html reach OUT to a
# third party to collect beacons. None of them has a purpose on a box with no
# agents.
#
# `rm -f` tolerates a name that moved between releases. The `ls` prints what is
# left, which is how a rename becomes visible instead of silent.
RUN rm -f \
      app/contacts/contact_tcp.py \
      app/contacts/contact_udp.py \
      app/contacts/contact_websocket.py \
      app/contacts/contact_dns.py \
      app/contacts/contact_ftp.py \
      app/contacts/contact_gist.py \
      app/contacts/contact_slack.py \
      app/contacts/contact_html.py \
      app/contacts/contact_tunnel_ssh.py \
 && echo "--- contacts surviving the prune ---" && ls -1 app/contacts

# The clone's git metadata is dead weight in the final image (and, for the
# submodules, a second copy of every ability file). -prune stops find descending
# INTO the directories it is about to delete, which otherwise produces a page of
# "No such file or directory" noise on an otherwise successful build.
RUN find /src/caldera -maxdepth 4 -name '.git' -prune -exec rm -rf {} +

# =============================================================================
# STAGE 2 — MAGMA.  Build the Vue UI here so Node never reaches the final image.
# =============================================================================
# Caldera 5 ships its UI as the `magma` plugin, a Vue app that must be compiled.
# Upstream does it by running `python server.py --build`, which starts the whole
# server just to shell out to npm. Building the plugin directly instead keeps the
# build hermetic — no config, no database, no network calls from the app itself —
# and leaves the node_modules tree behind in a stage that is thrown away.
FROM node:20-bookworm-slim AS magma
COPY --from=source /src/caldera/plugins/magma /magma
WORKDIR /magma
# Node's default old-space ceiling is ~2 GB, and magma's `vite build` exceeds it:
# the first build of 5.3.0 died at 1915.8 MB with
#   FATAL ERROR: CALL_AND_RETRY_LAST Allocation failed - JavaScript heap out of memory
# after ~120 s in `transforming...`, exiting 134. It is not a leak and not a
# broken tag — vite 2.9.15 holds the whole module graph in memory, and magma
# vendors every plugin's GUI source into one bundle (prebundle.js copies them in
# first), so the graph is large by construction.
#
# Raised here rather than in the compose build args because it is a property of
# THIS build step, not of the deployment: a `docker build` run by hand needs it
# just as much. 4096 is roughly double the observed peak — the BUILD HOST needs
# that much free RAM, so bump it here if a future magma grows past it.
ARG MAGMA_HEAP_MB=4096
ENV NODE_OPTIONS="--max-old-space-size=${MAGMA_HEAP_MB}"
# `npm ci` when a lockfile is present (reproducible), `npm install` otherwise —
# older magma tags do not ship package-lock.json.
RUN if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; \
    else npm install --no-audit --no-fund; fi \
 && npm run build \
 && rm -rf node_modules

# =============================================================================
# STAGE 3 — PYTHON DEPS.  Compilers live here and nowhere else.
# =============================================================================
# A virtualenv rather than a system install so the final stage copies ONE
# directory and inherits no apt build chain. build-essential and the -dev headers
# are needed only for the handful of requirements without a wheel; all of that
# weight stays in this stage.
FROM python:${PYTHON_TAG} AS deps
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libffi-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*
COPY --from=source /src/caldera/requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

# =============================================================================
# STAGE 4 — RUNTIME
# =============================================================================
FROM python:${PYTHON_TAG} AS runtime
ARG CALDERA_VERSION

LABEL org.opencontainers.image.title="CyberCore Caldera (authoring)" \
      org.opencontainers.image.description="MITRE Caldera, authoring role: no agents, no contacts, SSO-only login." \
      org.opencontainers.image.version="${CALDERA_VERSION}"

# tini so the container has a real PID 1 that reaps children and forwards
# SIGTERM. Without it every `docker compose restart` of this service waits out
# the full 10-second SIGKILL timeout.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# The runtime account is created BEFORE the COPYs so every COPY can set
# ownership as it writes. A `chown -R` afterwards would be correct but would
# also rewrite every file into a fresh layer — an extra full copy of the whole
# application, stockpile and atomic included, in the final image.
RUN useradd --system --create-home --home-dir /home/caldera --shell /usr/sbin/nologin caldera

# The venv stays ROOT-OWNED and is only read at runtime, so a compromise of the
# application user cannot rewrite a dependency in place.
COPY --from=deps /opt/venv /opt/venv

COPY --from=source --chown=caldera:caldera /src/caldera /usr/src/app
# The compiled UI, dropped in where the plugin expects to find it.
COPY --from=magma  --chown=caldera:caldera /magma/dist /usr/src/app/plugins/magma/dist

WORKDIR /usr/src/app

# -----------------------------------------------------------------------------
# THE SSO LOGIN HANDLER
# -----------------------------------------------------------------------------
# Caldera 5 lets a deployment replace its username/password login entirely via
# the `auth.login.handler.module` config key, which names a PYTHON IMPORT PATH to
# a module exposing load(). Copied to the top of the application directory, so
# the import path is the bare module name `cybercore_login_handler` — server.py
# runs from /usr/src/app, which therefore leads sys.path.
#
# The handler verifies the X-CyberCore-Auth token Caddy copies onto the request
# (HMAC over the payload, constant-time compare, expiry, role, path prefix, and a
# single-use burn against CyberCore's redeem endpoint). It is owned by another
# author; see infrastructure/caldera/login_handler.py. If that file is missing
# this COPY fails the build, which is the correct outcome — an image with no
# login handler and no password is a locked door with no key.
COPY --chown=caldera:caldera login_handler.py /usr/src/app/cybercore_login_handler.py

# The config TEMPLATE, not the config. entrypoint.sh renders conf/local.yml from
# it at start so that per-deployment secrets arrive from the environment and are
# never baked into a layer. See conf/local.yml for what each key does and, more
# importantly, for the keys that are deliberately ABSENT.
COPY --chown=caldera:caldera conf/local.yml /usr/src/app/conf/local.yml.template
# Root-owned and merely executable: the runtime user runs the entrypoint but
# cannot edit it, so nothing inside the container can rewrite its own startup.
COPY entrypoint.sh /usr/local/bin/caldera-entrypoint

# The two directories the runtime user must be able to WRITE: data/ (the object
# store, the authored content, and the persisted crypto keys — this is also the
# named volume's mount point, and Docker seeds a new volume from the image's
# ownership here) and the exfil dir, which exists only because the file service
# needs the path to resolve. Nothing exfiltrates: there are no agents.
RUN chmod 0755 /usr/local/bin/caldera-entrypoint \
 && mkdir -p /usr/src/app/data /tmp/caldera \
 && chown caldera:caldera /usr/src/app/data /tmp/caldera
USER caldera

# DOCUMENTATION ONLY. EXPOSE publishes nothing; docker-compose.yml deliberately
# has no `ports:` mapping for this service, which is what keeps the container
# unreachable from anywhere but cybercore-net.
EXPOSE 8888

# Any HTTP answer means the server is up. A 4xx from the login page counts —
# demanding a 200 would report a correctly-secured instance as unhealthy, the
# same trap probeReachable() calls out in src/routes/caldera-authoring.js.
# start-period is generous because Caldera loads every stockpile and atomic
# ability from YAML on first boot, which is slow on a cold volume.
HEALTHCHECK --interval=30s --timeout=10s --start-period=180s --retries=3 \
  CMD ["python", "-c", "import urllib.request as r, urllib.error as e, sys\ntry:\n    r.urlopen('http://127.0.0.1:8888/', timeout=5)\nexcept e.HTTPError:\n    pass\nexcept Exception:\n    sys.exit(1)\n"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/caldera-entrypoint"]
# --environment local selects conf/local.yml, which the entrypoint has just
# rendered. No --build: magma was compiled in stage 2. No --insecure: that flag
# makes Caldera fall back to its shipped default config, which carries the
# published ADMIN123 credentials and a full set of agent contacts.
CMD ["python", "server.py", "--environment", "local"]

# =============================================================================
# FIRST-BUILD NOTES — the three things most likely to bite, in order
# =============================================================================
#  1. THE VERSION TAG. `git clone --branch 5.3.0` fails loudly if that tag does
#     not exist upstream. That is the intended failure mode; run the ls-remote
#     above and set ARG CALDERA_VERSION to a real tag.
#  2. THE MAGMA BUILD. Two distinct failures, and they look nothing alike.
#     a) OOM — OBSERVED AND FIXED, kept here because it will recur if the heap
#        ARG is lowered or magma grows. The first 5.3.0 build died at 1915.8 MB
#        with "FATAL ERROR: ... JavaScript heap out of memory", exit 134, after
#        ~120 s in `transforming...`. Node's default old-space ceiling is ~2 GB
#        and vite 2.9.15 holds the whole module graph at once. Fixed by
#        MAGMA_HEAP_MB (default 4096) in stage 2. THE BUILD HOST MUST HAVE THAT
#        MUCH FREE RAM — if it does not, the same OOM returns and the fix is
#        more memory on the builder, not a smaller number here.
#     b) Wrong Node major — if npm itself refuses, check what magma's
#        package.json asks for and change the `node:20-bookworm-slim` base.
#     Either way a magma that fails to build yields a server with a working API
#     and a blank page, which reads like a proxy problem and is not.
#  3. THE SUBPATH. Caddy serves this under /caldera via handle_path, which STRIPS
#     the prefix — but magma emits root-absolute URLs (/api/v2/*, /assets/*).
#     If the login page renders and its assets 404, the fix is a dedicated
#     hostname, not a rewrite: see the long note at the bottom of
#     config/caddy/Caddyfile, and COPY THE GATE INTO ANY NEW BLOCK — the test in
#     front-end/test/caldera-container-config.test.js fails a /caldera block that
#     lacks the header strip or the forward_auth.
# =============================================================================
