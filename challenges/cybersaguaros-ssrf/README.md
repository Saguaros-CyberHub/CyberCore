# CyberSaguaros — SSRF Research Portal

A single-VM **Crucible challenge**: a custom vulnerable web application themed
as the **CyberSaguaros Research Group**, a fictional cactus research group
applying "cyber algorithms" to cactus research.

The challenge is the web-exploitation front of a multi-stage attack path:
**SSRF → admin access → file-upload RCE → reverse shell as `saguarobot` →
lateral movement to `hrivera` via a leaked deploy key → SSH → user flag →
Linux privilege escalation → root flag**. The GOAD / Active Directory pivot is
its own challenge — this box only foreshadows it (planted notes).

## Deploying the challenge

Once the template (VMID 1703) is baked and migration
`020_seed_cybersaguaros_module.sql` has registered the challenge, drop it into
a lane:

```
POST /api/admin/lanes/<laneId>/modules
  { "challenge_key": "cybersaguaros-ssrf", "module": "crucible" }
```

Deploying clones template 1703 into the target lane, assigns a VMID in the
800000-899999 range and a lane IP in the `.100+` range, and starts it. Players
reach it from that lane's Kali at `http://<lane-base>.<octet>/`. Tear it down
with `DELETE /api/admin/lanes/<laneId>/modules/<moduleInstanceId>` or the admin
UI **Modules** button.

Bake the template with `front-end/scripts/bake-cybersaguaros-template.sh`
(run on a Proxmox node — the VM git-clones the CyberCore repo at bake time and
copies this `challenges/cybersaguaros-ssrf/` directory into
`/var/www/cybersaguaros`). Override the source with `CHALLENGE_REPO_URL` /
`CHALLENGE_REPO_REF` / `CHALLENGE_DIR`.

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
| **SSRF** | SaguaroBot's "dataset integrity check" (`/api/verify.php`) fetches any URL. |
| Steal admin session | SSRF `http://127.0.0.1/api/internal/provision.php` → response leaks an `admin_session` token. |
| Admin access | Set cookie `admin_session=<token>` → `/admin/` authorises. |
| **RCE** | `/admin/storage.php` ("Cloud Storage") validates only the *last* file extension — `shell.php` is rejected, but `shell.php.jpg` passes (last ext `.jpg`). nginx runs PHP on any path *containing* `.php` (`location ~ \.php`) and PHP-FPM's `security.limit_extensions` is widened, so the double-extension webshell executes from `/uploads/`. |
| shellpop | Browse the webshell → reverse shell as `saguarobot`. **`saguarobot` has no sudo at all** — `sudo -l` is a dead end by design. |
| Find the deploy key | `/opt/saguaro/field-sync.sh` is world-readable and, being a real sync script, names the key it authenticates with: `ssh -i /opt/saguaro/deploy/id_rsa`. `linpeas` also flags the readable private key directly. |
| **Crack the passphrase** | The key is mode 0644 but passphrase-protected. `ssh2john id_rsa > k.hash` then `john --wordlist=/usr/share/wordlists/rockyou.txt k.hash`. It is a legacy RSA-PEM key (AES-128-CBC), so this falls in seconds. |
| SSH in | `chmod 600 id_rsa` first — OpenSSH refuses a world-readable key with "UNPROTECTED PRIVATE KEY FILE". Then `ssh -i id_rsa hrivera@<target>` → `cat ~/user.txt`. |
| **LinPE → root** — pick any | Enumerate with `id` and `find / -perm -4000 -type f 2>/dev/null`. All three routes are gated to the `fieldops` group, which only `hrivera` is in. |
| &nbsp;&nbsp;SUID `find` | `/opt/saguaro/bin/find . -exec /bin/sh -p \; -quit` |
| &nbsp;&nbsp;SUID `python3` | `/opt/saguaro/bin/python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'` |
| &nbsp;&nbsp;writable root cron | `/etc/cron.d/saguaro-fieldsync` runs `/opt/saguaro/field-sync.sh` as root every minute; the script is `0775 root:fieldops`. Append a payload and wait 60s. |
| root flag | `cat /root/root.txt` |
| SQLi (off-path) | `/research.php?q=` is injectable — `sqlmap` dumps `users`. Hashes are unsalted SHA-256 of rockyou words; `hashcat -m 1400` cracks them. **`hrivera` is deliberately absent from that table**, so this route cannot shortcut the chain. |
| XSS (off-path) | `/research.php?q=<script>alert(1)</script>` reflects unencoded. Always on; no victim bot and no session worth stealing — a demo target only. |

### Notes for the instructor

- **Both SUID binaries are copies.** `/usr/bin/find` and `/usr/bin/python3` are
  untouched at 0755. The copies live in `/opt/saguaro/bin` (deliberately *not*
  on the default `PATH`, so they shadow nothing) at `4750 root:fieldops`, and
  `saguarobot` is **not** in `fieldops`. RCE therefore cannot skip the SSH
  stage. The only thing crossing between the two accounts is the readable
  deploy key.
- **`/tmp` is `nosuid`** (systemd tmpfs on Debian 13), so the classic
  `cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash` cron payload silently
  fails. Use `/var/tmp`, or drop a sudoers file:
  `echo 'hrivera ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/zz-hrivera`.
  The bake records the actual mount options as `TMP_OPTS` in
  `/etc/cybercore-bake.env`.
- **`/opt/saguaro` is `0755 root:root`**, so `field-sync.sh` can be *modified*
  but not *replaced*. `echo … >> file` works; editors that save by writing a
  temp file and renaming over the original will not.
- **The private key ships mode 0644 on purpose.** Students must copy it and
  `chmod 600` before `ssh -i` will accept it. That is a teaching point, not a
  bug.
- **`sudo -l` as `saguarobot` returns nothing.** This is enforced by the
  `SUDOERS_CLEAN` bake marker. See the sudo guard note below for why that took
  two layers.

## Credential / artifact reference (instructors)

Portal accounts — unsalted SHA-256 of rockyou-wordlist words, so the
sqlmap-dumped `users` table cracks with `hashcat -m 1400` + rockyou.txt:
- `dr.wagner` / `arizona` — admin role
- `rgreen` / `cactus` — researcher
- `dvalmont` / `sunshine` — researcher (also an ordinary Linux user on the box)

Linux accounts:
- `saguarobot` — PHP-FPM pool user; the webshell / reverse-shell foothold.
  **No sudo, and not in `fieldops`.**
- `hrivera` / `Sag-F1eld-Ops-2026!` — field-station sysadmin; the SSH and
  user-flag account, and the only member of `fieldops`. The password is
  deliberately **not** in rockyou and is there for instructor console access
  only — the intended way in is the deploy key. `hrivera` is also deliberately
  **absent from the portal `users` table**, so the SQLi cannot shortcut past
  SSRF and RCE.
- `dvalmont` / `sunshine` — red herring. Real SSH login, no sudo, no group
  membership, nothing behind it.
- `root` — bake-debug password for instructor inspection.

Groups:
- `fieldops` — `hrivera` only. Gates the setuid toolkit and the cron script.

Bake-script artifacts:
- `/opt/saguaro/deploy/id_rsa` — **0644**, RSA-PEM, passphrase `mariposa`
  (a rockyou word). The lateral-movement path. Its public half is in
  `/home/hrivera/.ssh/authorized_keys`, which keeps normal `0700`/`0600` perms
  — sshd `StrictModes` is left **on**.
- `/opt/saguaro/field-sync.sh` — `0775 root:fieldops`. Names the key (it really
  uses it) and is the cron privesc target.
- `/etc/cron.d/saguaro-fieldsync` — runs the above as root every minute.
- `/opt/saguaro/bin/{find,python3}` — `4750 root:fieldops` copies, plus a
  `README` explaining the "field ops setuid toolkit" cover story.
- `/home/hrivera/user.txt` (`0640 hrivera:hrivera`), `/root/root.txt` (`0600`).
  Static values; override at bake time with `USER_FLAG_VALUE` /
  `ROOT_FLAG_VALUE`. Nothing in CyberCore validates flags today, so they are
  proof-of-ownership only.
- `/opt/saguaro/research-notes.txt` — DB app creds + AD-pivot hint. Ambient
  flavour; it deliberately does **not** point at the deploy key.
- `/etc/cloud/cloud.cfg.d/99-cybercore-default-user.cfg` and
  `cybercore-sudo-guard.service` — the sudo guard. Proxmox lane clones boot on
  Proxmox's *generated* cloud-init user-data, which carries `users: [default]`;
  cloud-init then applies `system_info.default_user` from `/etc/cloud/cloud.cfg`
  and writes `/etc/sudoers.d/90-cloud-init-users`, silently handing `saguarobot`
  `NOPASSWD:ALL` on every lane. Without both layers the entire challenge
  collapses at the RCE stage. The bake asserts this via `SUDO_GUARD`.

Every intentional vulnerability is verified at bake time — see the marker block
in `bake-cybersaguaros-template.sh`. It refuses to seal a broken template, and
three of the markers (`SUID_GATED`, `KEY_ENCRYPTED`, `SUDOERS_CLEAN`) are
*negative* assertions that catch a collapsed chain rather than a missing file.

The bot/SSRF is reachable without any login — the researcher login, the SQLi and
the reflected XSS are secondary recon / demo surfaces, not on the critical line.
