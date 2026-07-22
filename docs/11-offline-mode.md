# CyberHub — Offline / LAN Mode

By default CyberHub uses Caddy to serve over HTTPS with an automatic Let's Encrypt certificate. This requires a public domain name and ports 80 and 443 reachable from the internet.

If you want to run CyberHub on a local network or air-gapped machine without touching the internet, two changes are needed: one in `.env` and one in `docker-compose.yml`.

---

## Option A — LAN / Lab mode (HTTP, accessible on your local network)

Use this when the machine running CyberHub is accessible to other devices on your network, but you don't want HTTPS or a public domain.

**1. In `.env`:**

```env
CYBERHUB_HOST=:80
```

**2. In `docker-compose.yml` — the Caddy service ports are already `0.0.0.0`, so no change needed.**

Caddy sees `:80` as a bare port with no hostname — it skips HTTPS entirely and serves plain HTTP. Users on your network reach CyberHub at `http://<host-ip>`.

---

## Option B — Localhost only (single machine, no network exposure)

Use this when CyberHub is for local development or a single-user machine.

**1. In `.env`:**

```env
CYBERHUB_HOST=localhost
```

**2. In `docker-compose.yml` — change the Caddy ports to loopback only:**

```yaml
  caddy:
    ports:
      - "127.0.0.1:80:80"
      - "127.0.0.1:443:443"
      - "127.0.0.1:443:443/udp"
```

Access CyberHub at `http://localhost`.

---

## Switching back to HTTPS (public mode)

**1. In `.env`:**

```env
CYBERHUB_HOST=yourdomain.example.edu
```

**2. In `docker-compose.yml` — restore Caddy ports to `0.0.0.0`:**

```yaml
  caddy:
    ports:
      - "0.0.0.0:80:80"
      - "0.0.0.0:443:443"
      - "0.0.0.0:443:443/udp"
```

Also set `COOKIE_SECURE=true` in the `app` service environment since traffic is now over HTTPS.

Caddy will automatically obtain and renew a Let's Encrypt certificate for your domain on first startup. Ensure ports 80 and 443 are open on your firewall and your domain's DNS A record points to the host.

---

## Notes

- The CyberHub app (port 3000) and Guacamole (port 8080) are never exposed directly — all traffic goes through Caddy regardless of mode.
- The Guacamole default admin credentials are `guacadmin` / `guacadmin`. Change the password immediately after first login via the Guacamole admin panel at `/guacamole/`.
- Port 3000 is bound to `127.0.0.1` for local debugging only and is not part of normal user traffic.
