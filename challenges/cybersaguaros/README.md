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
| Recon | `/etc/hosts`: `cybersaguaros.local` → lane IP. `ffuf` finds `/chat`, `/gallery`, `/admin`, `/api/`. `/robots.txt` discloses the SaguaroBot endpoint `/api/verify.php`. |
| SQLi (secondary) | `/research.php?q=` is injectable — `sqlmap` dumps `users`. Hashes are unsalted SHA-256 of rockyou words; `hashcat -m 1400` + rockyou.txt cracks them. |
| **SSRF** | SaguaroBot's "dataset integrity check" (`/api/verify.php`) fetches any URL. |
| Steal admin session | SSRF `http://127.0.0.1/api/internal/provision.php` → response leaks an `admin_session` token. |
| Admin access | Set cookie `admin_session=<token>` → `/admin/` authorises. |
| **RCE** | `/admin/storage.php` ("Cloud Storage") validates only the *last* file extension — `shell.php` is rejected, but `shell.php.jpg` passes (last ext `.jpg`). nginx runs PHP on any path *containing* `.php` (`location ~ \.php`) and PHP-FPM's `security.limit_extensions` is widened, so the double-extension webshell executes from `/uploads/`. |
| shellpop | Browse the webshell → reverse shell as `saguarobot`. |
| LinPE → root | `sudo -l` (surfaced by `linpeas`) shows `saguarobot` may run `/usr/bin/python3` as root, NOPASSWD. Escalate: `sudo python3 -c 'import os; os.execl("/bin/sh","sh")'`. |

## Credential / artifact reference (instructors)

Portal accounts — unsalted SHA-256 of rockyou-wordlist words, so the
sqlmap-dumped `users` table cracks with `hashcat -m 1400` + rockyou.txt:
- `dr.wagner` / `arizona` — admin role
- `rgreen` / `cactus` — researcher
- `dvalmont` / `sunshine` — researcher (also an ordinary Linux user on the box)

Linux:
- `saguarobot` — PHP-FPM pool user; the webshell/reverse-shell foothold.
- `dvalmont` / `sunshine` — ordinary login, no sudo (portal/SQLi flavour only).
- Bake-script artifacts:
  - `/etc/sudoers.d/saguarobot-python` — `saguarobot` may run `/usr/bin/python3`
    as root (NOPASSWD). The only privesc path; `linpeas` / `sudo -l` surfaces it.
    Escalate: `sudo python3 -c 'import os; os.execl("/bin/sh","sh")'`
  - `/opt/saguaro/research-notes.txt` — DB app creds + AD-pivot hint

The bot/SSRF is reachable without any login — the researcher login + SQLi is a
secondary recon path, not on the critical line.
