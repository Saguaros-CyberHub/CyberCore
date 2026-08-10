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

Bake the template with `infrastructure/proxmox-templates/vm-templates/bake-cybersaguaros-template.sh`
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
| **LinPE → root** — pick any | `sudo -l` is the money shot and needs **no password** — the entries are `NOPASSWD`, and sudoers' `listpw` default of `any` means they list password-free. It prints `(root) NOPASSWD: /usr/bin/find, /usr/bin/python3`. The grant is scoped to the `fieldops` group, which only `hrivera` is in. |
| &nbsp;&nbsp;sudo `find` | `sudo find . -exec /bin/sh \; -quit` |
| &nbsp;&nbsp;sudo `python3` | `sudo python3 -c 'import os; os.system("/bin/bash")'` |
| &nbsp;&nbsp;writable root cron | `/etc/cron.d/saguaro-fieldsync` runs `/opt/saguaro/field-sync.sh` as root every minute; the script is `0775 root:fieldops`. Append a payload and wait 60s. |
| root flag | `cat /root/root.txt` |
| SQLi (off-path) | `/research.php?q=` is injectable — `sqlmap` dumps `users`. Hashes are unsalted SHA-256 of rockyou words; `hashcat -m 1400` cracks them. **`hrivera` is deliberately absent from that table**, so this route cannot shortcut the chain. |
| XSS (off-path) | `/research.php?q=<script>alert(1)</script>` reflects unencoded. Always on; no victim bot and no session worth stealing — a demo target only. |

### Notes for the instructor

- **The privesc is sudo, not setuid.** `/usr/bin/find` and `/usr/bin/python3`
  are completely untouched at 0755 with no setuid bit — there are no setuid
  binaries on this box beyond the distro's own set, which the `NO_STRAY_SUID`
  bake marker enforces. All the scoping is done by
  `/etc/sudoers.d/fieldops-maint`, which grants `%fieldops` only, and
  `saguarobot` is **not** in `fieldops`. RCE therefore cannot skip the SSH
  stage; the only thing crossing between the two accounts is the readable
  deploy key.
- **Why sudo rather than a setuid bit.** Bad sudoers rules are the single
  highest-yield finding in a real Linux engagement, which is why `sudo -l` is
  the first command most operators run; an admin actually running
  `chmod u+s /usr/bin/find` is largely a CTF trope. sudo is also the cleaner
  gate here: per-user and per-group scoping is precisely what sudoers exists
  for, whereas setuid has no such concept and previously needed an invented
  `4750 root:fieldops` wrapper directory to keep `saguarobot` out.
- **`/tmp` is `nosuid`** (systemd tmpfs on Debian 13), so the classic
  `cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash` cron payload silently
  fails. This bites students on the *cron* route specifically. Use `/var/tmp`
  instead, or append a payload that widens sudoers — note the nested quoting,
  since the outer `echo` has to write a shell command into the script:
  ```sh
  echo "echo 'hrivera ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/zz-hrivera" \
    >> /opt/saguaro/field-sync.sh
  ```
  The bake records the actual mount options as `TMP_OPTS` in
  `/etc/cybercore-bake.env`.
- **`/opt/saguaro` is `0755 root:root`**, so `field-sync.sh` can be *modified*
  but not *replaced*. `echo … >> file` works; editors that save by writing a
  temp file and renaming over the original will not.
- **The private key ships mode 0644 on purpose.** Students must copy it and
  `chmod 600` before `ssh -i` will accept it. That is a teaching point, not a
  bug.
- **`saguarobot` has no sudo at all**, enforced by the `SUDOERS_CLEAN` bake
  marker — see the sudo guard note below for why that took two layers. As
  `saguarobot`, `sudo -l` prompts for a password it cannot satisfy and then
  reports no rights. That is normal sudo behaviour and a deliberate dead end.
- **Worth teaching: SSH authentication method and sudo are unrelated.** A key
  session does not grant passwordless sudo — sudo re-authenticates the invoking
  user through PAM against their *Linux* password on every call and has no idea
  whether the session came from a key, a password, the console or `su`. Only a
  `NOPASSWD:` tag or `!authenticate` in sudoers suppresses the prompt. That is
  exactly why `hrivera` gets a prompt-free `sudo -l` (the `fieldops` entries are
  `NOPASSWD`) while `saguarobot` gets a password wall (no entries at all) —
  despite both being ordinary shells. sudo also authenticates *before* revealing
  that a user has no rights, so unauthenticated users cannot enumerate policy.
- **`hrivera`'s password is `Sag-F1eld-Ops-2026!`** — deliberately absent from
  rockyou, so the deploy key stays the only intended way in. Students never need
  it, since the sudo grant is `NOPASSWD`; it exists for instructor console
  access and demos.

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
- `fieldops` — `hrivera` only. Carries the sudo `NOPASSWD` grant and owns the
  cron script. Joining this group *is* the privesc, so nothing else may.

Bake-script artifacts:
- `/opt/saguaro/deploy/id_rsa` — **0644**, RSA-PEM, passphrase `mariposa`
  (a rockyou word). The lateral-movement path. Its public half is in
  `/home/hrivera/.ssh/authorized_keys`, which keeps normal `0700`/`0600` perms
  — sshd `StrictModes` is left **on**.
- `/opt/saguaro/field-sync.sh` — `0775 root:fieldops`. Names the key (it really
  uses it) and is the cron privesc target.
- `/etc/cron.d/saguaro-fieldsync` — runs the above as root every minute.
- `/etc/sudoers.d/fieldops-maint` — `0440 root:root`, the primary privesc:
  `%fieldops ALL=(root) NOPASSWD: /usr/bin/find, /usr/bin/python3`, framed as a
  maintenance grant for nightly sweeps and telemetry reindexing. The bake runs
  `visudo -c` against it and refuses to seal if it does not parse, because a
  syntax error here breaks `sudo` for every user on the box.
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
four of the markers (`SUDO_GATED`, `KEY_ENCRYPTED`, `SUDOERS_CLEAN`,
`NO_STRAY_SUID`) are
*negative* assertions that catch a collapsed chain rather than a missing file.

The bot/SSRF is reachable without any login — the researcher login, the SQLi and
the reflected XSS are secondary recon / demo surfaces, not on the critical line.
