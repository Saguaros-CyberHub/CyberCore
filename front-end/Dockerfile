FROM node:26-alpine

# Runtime tools the app shells out to:
#   - curl
#   - docker-cli
#   - docker-cli-buildx
#   - ca-certificates
#   - openssh-client (lane-deployer.js SSHes into lane gateways via `pct` to
#     configure per-lane DHCP reservations and NAT rules — see configureGatewayAccess())
RUN apk add --no-cache curl docker-cli docker-cli-buildx ca-certificates openssh-client \
  && apk upgrade --no-cache

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

RUN mkdir -p /app/logs

ENV LOG_LEVEL=info
ENV LOG_DIR=/app/logs

EXPOSE 3000

CMD ["node", "src/server.js"]
