# syntax=docker/dockerfile:1
# =============================================================================
# CALDERA CENTRAL SERVER (container, not a VM)
# =============================================================================
# WHAT THIS IS, AND WHY IT IS A CONTAINER AT ALL
# -----------------------------------------------------------------------------
# The central Caldera authors adversaries and controls explicitly installed
# lane agents. Sandcat reaches only the token-gated HTTP ingress through Caddy;
# the console and REST API retain the instructor gate. Lane-local executor VMs
# remain a separate deployment option.
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
# The agent ingress is integration-tested with Caddy. Image rebuilds and live
# Sandcat check-ins still require validation against the deployment environment.
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
# STAGE 1 - SOURCE. Clone the release and keep only the supported surface.
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

# Keep generated agents on verified HTTPS, bind beacons/results to the token
# identity, and retain full CyberCore paws when filing exercise uploads.
# Every change requires one exact pinned upstream match or the build fails.
COPY agent_guard.py /src/caldera/cybercore_agent_guard.py
COPY patch_upstream.py /tmp/cybercore-patch-upstream.py
RUN python /tmp/cybercore-patch-upstream.py && rm /tmp/cybercore-patch-upstream.py

# -----------------------------------------------------------------------------
# PLUGIN PRUNE — this is a SECURITY control, not a size optimisation.
# -----------------------------------------------------------------------------
# Sandcat supplies lane agents. Keep the authoring and reporting plugins and
# remove unrelated reverse shells, external transports and initial-access
# tooling. Caddy separates agent contacts from the instructor console; enabling
# Sandcat does not grant agent tokens access to console/API routes.
#
# WHAT IS KEPT, AND WHY EACH ONE CLEARS THE BAR
#   debrief   Reporting only. Server-side rendering of an operation that already
#             ran; it opens no listener and reaches no agent. For a blue-team
#             exercise it IS the instructor's answer key — what actually
#             executed, on which host, in what order.
#   response  Abilities, executed through the EXISTING Sandcat contact like any
#             other ability. It adds no channel. This one is a deliberate
#             departure from "remove autonomous plugins": its value is defensive
#             (response and containment drills), and the autonomy it can express
#             is bounded by the same operation the instructor already launches.
#
# WHAT STAYS REMOVED, AND WHY
#   manx / ssl              additional agent channels. HTTP is the only contact
#                           the Caddy capability gate understands; a second
#                           transport is a second, ungated way in.
#   access                  initial-access tooling aimed OUTWARD from the
#                           server. Nothing in a lane exercise needs it.
#   human                   deploys a SEPARATE process over its own endpoint,
#                           which /agent/<token> does not cover. Restoring it is
#                           a new ingress route and must be reviewed as one.
#   emu                     wants to fetch the CTID Adversary Emulation Library
#                           from GitHub AT RUNTIME on first start, plus a second
#                           download_payloads.sh phase and pyminizip/zlib for the
#                           encrypted payloads. This image is deliberately
#                           hermetic and pinned; restoring emu means VENDORING
#                           those plans at build time against a pinned ref, not
#                           granting the container runtime egress.
#   training / gameboard    unrelated to how this deployment is used.
RUN rm -rf \
      plugins/manx \
      plugins/access \
      plugins/human \
      plugins/training \
      plugins/gameboard \
      plugins/emu \
      plugins/ssl \
 && echo "--- plugins surviving the prune ---" && ls -1 plugins

# -----------------------------------------------------------------------------
# ATOMIC RED TEAM DATA — vendored here because the runtime cannot fetch it.
# -----------------------------------------------------------------------------
# The atomic plugin ships its CODE as a Caldera submodule but NOT its data. On
# first load it shells out to `git clone` for Red Canary's atomic-red-team into
# plugins/atomic/data/atomic-red-team. That cannot work in this image, twice
# over: the runtime stage installs no git (only ca-certificates, tini and
# golang-go), and the container is deliberately hermetic.
#
# The failure is SILENT, which is why it survived so long. The plugin loads, the
# console lists it, and its ability count simply stays blank forever.
#
# So the fetch happens in THIS stage, which already has git, at a PINNED commit.
# Sparse and blobless: `atomics/` is the only tree the plugin ingests, while the
# full repository is ~610 MB of which almost none is read.
#
# Moving the pin is a deliberate act — it changes which technique tests the
# class can run. Same rule as CALDERA_VERSION above.
# The final guard is not ceremony: an empty atomics tree would reproduce the
# silent-empty-plugin symptom in a new way, and a build that fails here is the
# only thing that distinguishes "vendored" from "looked vendored".
ARG ATOMIC_RED_TEAM_REF=388942adbd9641f4dfdcf079d7efe9a75ec0ac43
RUN set -eu; \
    test -d plugins/atomic; \
    mkdir -p plugins/atomic/data/atomic-red-team; \
    cd plugins/atomic/data/atomic-red-team; \
    git init -q; \
    git remote add origin https://github.com/redcanaryco/atomic-red-team.git; \
    git sparse-checkout init --cone; \
    git sparse-checkout set atomics; \
    git fetch -q --depth 1 --filter=blob:none origin "${ATOMIC_RED_TEAM_REF}"; \
    git checkout -q FETCH_HEAD; \
    rm -rf .git; \
    count=$(find atomics -name 'T*.yaml' | wc -l); \
    if [ "$count" -lt 100 ]; then \
      echo "atomic-red-team vendored only $count technique files" >&2; \
      exit 1; \
    fi; \
    echo "--- atomic-red-team vendored at ${ATOMIC_RED_TEAM_REF}: $count techniques ---"

# -----------------------------------------------------------------------------
# CONTACT PRUNE: HTTP is the only agent channel. Websocket remains loopback
# for Caldera's own event bus. All other listeners/transports remain removed.
# -----------------------------------------------------------------------------
RUN rm -f \
      app/contacts/contact_tcp.py \
      app/contacts/contact_udp.py \
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
# BUILD IT WHERE UPSTREAM PUTS IT. Copying plugins/magma to a bare /magma and
# building there fails, and the failure is spectacularly indirect:
#
#   ✓ 46 modules transformed.
#   [vite:build-import-analysis] Set maximum size exceeded
#   file: /magma/src/views/PluginView.vue
#   RangeError: Set maximum size exceeded
#       at ReaderSync.walkSync ... ProviderSync.api        (fast-glob)
#
# PluginView.vue resolves its sibling plugins with a dynamic glob relative to
# its own location. Upstream that location is caldera/plugins/magma, so the
# glob's parent is plugins/ and the walk is small. At a bare /magma the parent
# is the CONTAINER ROOT, so fast-glob walks /proc, /sys and /dev — whose
# symlink loops and synthetic entries are effectively unbounded — until the Set
# backing the visited-paths check exceeds V8's ~16.7M element ceiling.
#
# So the tree layout is a build input, not a convenience. Copy the whole source
# and build in place. It costs a little build time in a stage that is thrown
# away, and it costs nothing in the final image.
COPY --from=source /src/caldera /src/caldera
WORKDIR /src/caldera/plugins/magma
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
# vite bakes `base` into index.html at BUILD time, so where this console is
# served is a build input, not just a proxy setting. It is served at its own
# HOSTNAME (the {$CALDERA_HOST} blocks in config/caddy/Caddyfile), so the
# correct value is root.
#
# DO NOT set a subpath here. It was tried, together with
# app.frontend.api_base_url in conf/local.yml, and a subpath cannot work:
# magma bootstraps from GET /api/v2/config/main at the ORIGIN ROOT, so it
# uses the default base for the one call that would have told it otherwise.
# Observed: assets resolved correctly under /caldera/assets/... while the SPA
# 404'd on /api/v2/config/main and rendered a login form, because its API was
# unreachable rather than because anything was unauthenticated.
#
# `npm run build -- --base=...` forwards the flag through the npm script to
# vite, whose CLI value wins over anything in vite.config.
ARG CALDERA_BASE_PATH=/
RUN if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; \
    else npm install --no-audit --no-fund; fi \
 && npm run build -- --base="${CALDERA_BASE_PATH}" \
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

LABEL org.opencontainers.image.title="CyberCore Caldera (central)" \
      org.opencontainers.image.description="MITRE Caldera, gated instructor console and token-scoped lane agents." \
      org.opencontainers.image.version="${CALDERA_VERSION}"

# tini so the container has a real PID 1 that reaps children and forwards
# SIGTERM. Without it every `docker compose restart` of this service waits out
# the full 10-second SIGKILL timeout.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini golang-go \
 && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    GOPATH=/home/caldera/go \
    GOCACHE=/home/caldera/.cache/go-build

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
COPY --from=magma  --chown=caldera:caldera /src/caldera/plugins/magma/dist /usr/src/app/plugins/magma/dist

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
# Caldera reads agent defaults separately from the main environment config.
# Replace upstream's bootstrap ability so installation only registers the agent.
COPY --chown=caldera:caldera conf/agents.yml /usr/src/app/conf/agents.yml
# Root-owned and merely executable: the runtime user runs the entrypoint but
# cannot edit it, so nothing inside the container can rewrite its own startup.
COPY entrypoint.sh /usr/local/bin/caldera-entrypoint

# The two directories the runtime user must be able to WRITE: data/ (the object
# store, authored content and persisted crypto keys, on the named volume)
# and the temporary exercise-upload directory.
RUN chmod 0755 /usr/local/bin/caldera-entrypoint \
 && mkdir -p /usr/src/app/data /tmp/caldera \
 && chown caldera:caldera /usr/src/app/data /tmp/caldera
USER caldera

# Fetch Sandcat's pinned modules during the image build so the first agent
# download can compile without reaching public Go module servers at runtime.
RUN cd plugins/sandcat/gocat && go mod download

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
#     b) "Set maximum size exceeded" from fast-glob — OBSERVED AND FIXED. It
#        means magma is being built OUTSIDE the caldera tree, so PluginView.vue's
#        sibling-plugin glob escapes into / and walks /proc and /sys. Stage 2
#        copies the whole source and builds in place for exactly this reason; do
#        not "simplify" it back to copying plugins/magma alone.
#     c) Wrong Node major — if npm itself refuses, check what magma's
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
