# CyberSaguaros — SSRF Research Portal

An attachable CyberCore challenge module: a custom vulnerable web application
themed as the **CyberSaguaros Research Group**, a fictional cactus research
group applying "cyber algorithms" to cactus research.

It delivers the web-exploitation front of the multi-stage attack-path lab:
**SSRF → admin access → file-upload RCE → reverse shell → Linux privilege
escalation**. The GOAD / Active Directory pivot is a separate module — this
box only foreshadows it (planted notes).

## Deployment

This is an **attachable module**. Once the template (VMID 1703) is baked and
migration `020_seed_cybersaguaros_module.sql` is applied:

```
POST /api/admin/lanes/<laneId>/modules
  { "challenge_key": "cybersaguaros-ssrf", "module": "crucible" }
```

The attach-module system clones template 1703 into the target lane, assigns a
VMID in the 800000-899999 range and a lane IP in the `.100+` range, and starts
it. Reachable from that lane's Kali at `http://<lane-base>.<octet>/`. Detach
with `DELETE /api/admin/lanes/<laneId>/modules/<moduleInstanceId>` or the admin
UI **Modules** button.

Bake the template with `front-end/scripts/bake-cybersaguaros-template.sh`
(run from inside a CyberCore checkout — it tars this `challenges/cybersaguaros/`
directory into the cloud-init payload).

## Layout

```
app/public/      nginx webroot — portal, chat, gallery, admin, APIs
app/includes/    config / db / auth / layout (outside webroot, not reachable)
app/db/          schema.sql + seed.sql
deploy/          nginx site config + PHP-FPM pool config
```

## Assets

- **Logo** — the header shows `app/public/assets/logo.png` (the real
  transparent CyberSaguaros logo). Until that file is committed, it falls
  back to the shipped placeholder `assets/logo.svg`. Commit the real
  `logo.png` to the repo before baking — the template clones from GitHub.
- **Gallery** — `gallery.php` auto-lists every image in `assets/gallery/`
  (curated) and `public/uploads/` (contributed). The repo ships stylised
  SVG saguaro scenes as defaults; drop real saguaro photos (e.g. from
  cactiguide.com, genus *Carnegiea*) into `app/public/assets/gallery/` and
  they appear automatically — no DB or code change.

## Intended solve path

| Stage | Action |
|-------|--------|
| Recon | `/etc/hosts`: `cybersaguaros.local` → lane IP. `ffuf` finds `/chat`, `/gallery`, `/admin`, `/api/`. |
| SQLi (secondary) | `/research.php?q=` is injectable — `sqlmap` dumps `users`. Hashes are unsalted SHA-256 of rockyou words; `hashcat -m 1400` + rockyou.txt cracks them. |
| **SSRF** | SaguaroBot's "dataset integrity check" (`/api/verify.php`) fetches any URL. |
| Steal admin session | SSRF `http://127.0.0.1/api/internal/provision.php` → response leaks an `admin_session` token. |
| Admin access | Set cookie `admin_session=<token>` → `/admin/` authorises. |
| **RCE** | `/admin/storage.php` ("Cloud Storage") only checks the client `Content-Type`. Upload a `.php` webshell with `Content-Type: image/png`. It lands in `/uploads/` where PHP-FPM executes it. |
| shellpop | Browse the webshell → reverse shell as `saguarobot`. |
| LinPE → root | `linpeas` surfaces: SUID `/usr/bin/find`; world-writable root cron `/opt/saguaro/datasync.sh`; `sudo NOPASSWD tar` for `dvalmont` (creds in `/opt/saguaro/research-notes.txt`). |

## Credential / artifact reference (instructors)

Portal accounts — unsalted SHA-256 of rockyou-wordlist words, so the
sqlmap-dumped `users` table cracks with `hashcat -m 1400` + rockyou.txt:
- `dr.prickle` / `arizona` — admin role
- `rgreen` / `cactus` — researcher
- `dvalmont` / `sunshine` — researcher (also a Linux user on the box)

Linux:
- `saguarobot` — PHP-FPM pool user; the webshell/reverse-shell foothold.
- `dvalmont` / `sunshine` — has `sudo NOPASSWD: /usr/bin/tar`.
- LinPE artifacts planted by the bake script:
  - SUID `/usr/bin/find`
  - `/opt/saguaro/datasync.sh` (0777) run every minute by root cron
  - `/opt/saguaro/research-notes.txt` — `dvalmont` password + AD-pivot hint

The bot/SSRF is reachable without any login — the researcher login + SQLi is a
secondary recon path, not on the critical line.
