# Stage 1: pull the kaniko executor binary. Daemonless container image build —
# replaces the prior DooD/docker.sock approach so the app container no longer
# has a path to host-VM root. Pin a specific kaniko tag for reproducibility;
# bump as needed.
FROM gcr.io/kaniko-project/executor:v1.23.2 AS kaniko

FROM node:18-alpine

# Runtime tools the app shells out to. `curl` is required by proxmoxFormPOST
# in lane-deploy.js (spawn('curl', args) — used for every /agent/exec call to
# the Proxmox API). It used to come in transitively via the docker-cli package
# the old DooD build installed, so removing docker-cli also removed curl —
# re-add it explicitly. `ca-certificates` keeps TLS happy for outbound HTTPS
# (Anthropic, kaniko base image pulls, Tailscale).
RUN apk add --no-cache curl ca-certificates

# Kaniko (vuln-app builder). Build runs via /kaniko/executor — no Docker
# daemon, no /var/run/docker.sock mount, no host-VM escape path. LLM-authored
# Dockerfile RUN steps still run with this container's privileges, so don't
# treat the build environment as a hard sandbox; the win is removing the
# daemon-socket pivot. See utils/vuln-app-builder.js.
COPY --from=kaniko /kaniko /kaniko
ENV PATH="/kaniko:$PATH"

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
