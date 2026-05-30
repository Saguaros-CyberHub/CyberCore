FROM node:18-alpine

# Runtime tools the app shells out to:
#   - curl       : proxmoxFormPOST in lane-deploy.js spawn('curl', …) for every
#                  Proxmox /agent/exec call.
#   - docker-cli : DooD — the CIAB vuln-app builder runs `docker build` +
#                  `docker save` against the orchestrator VM's daemon via the
#                  /var/run/docker.sock mount declared in docker-compose.yml.
#                  Kaniko was tried as a daemonless alternative but clobbered
#                  the app container's filesystem on every build (it extracts
#                  the base image into /), making deploys deterministically
#                  break the orchestrator. DooD is back; the security tradeoff
#                  is documented in utils/vuln-app-builder.js + the project
#                  threat-model notes.
#   - docker-cli-buildx : BuildKit CLI plugin. Docker 23+ defaults to BuildKit
#                  and outright fails on `docker build` without buildx; the
#                  Alpine `docker-cli` package does NOT bundle it. Symptom
#                  without this: `ERROR: BuildKit is enabled but the buildx
#                  component is missing or broken`. We set DOCKER_BUILDKIT=1
#                  in vuln-app-builder.js so this needs to be present.
#   - ca-certificates : keeps TLS happy for outbound HTTPS (Anthropic, registry
#                       pulls during builds, Tailscale).
RUN apk add --no-cache curl docker-cli docker-cli-buildx ca-certificates

WORKDIR /app

# Install dependencies first (cache layer)
COPY package*.json ./
RUN npm install --omit=dev

# Copy application code
COPY . .

# Create logs directory (mount a volume here in production to persist logs)
RUN mkdir -p /app/logs

# Log level: error | warn | info | http | debug
ENV LOG_LEVEL=info
ENV LOG_DIR=/app/logs

EXPOSE 3000

CMD ["node", "src/server.js"]
