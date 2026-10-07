# CyberSaguaros — SSRF Research Portal

A single-VM **Crucible challenge**: a custom vulnerable web application themed
as the **CyberSaguaros Research Group**, a fictional cactus research group
applying "cyber algorithms" to cactus research.

The challenge is the web-exploitation front of a multi-stage attack path:
**admin access → file-upload RCE → reverse shell as `saguarobot` →
lateral movement to `hrivera` via a leaked deploy key → SSH → user flag →
Linux privilege escalation → root flag**. The GOAD / Active Directory pivot is
its own challenge — this box only foreshadows it (planted notes).

**Two independent routes reach the admin panel, and both are complete:**

1. **SSRF** — SaguaroBot's dataset verifier fetches the loopback-only
   provisioning API, which hands back an `admin_session` token.
2. **SQLi → crack → sign in** — dump `users` from `/research.php?q=`, crack
   the unsalted SHA-256 rockyou hashes, and sign in at `/login.php` as
   `dr.wagner`, whose portal role is `admin`. Legitimate functionality,
   abused — which is what most operators would reach for first.

They converge at the **RCE** row below. `hrivera` stays deliberately absent
from the portal `users` table, so route 2 is a second way *in* and not a way
*past* — it still cannot shortcut the SSH, lateral-movement or privesc stages.

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
  (curated) and `public/uploads/` (contributed), filtering on the *last*
  extension — so a `.php` object never appears there. `/admin/storage.php`
  lists everything in the `uploads` table instead, which is where a webshell
  becomes visible. The repo ships stylised
  SVG saguaro scenes as defaults; drop real saguaro photos (e.g. from
  cactiguide.com, genus *Carnegiea*) into `app/public/assets/gallery/` and
  they appear automatically — no DB or code change.

## Intended solve path

| Stage | Action |
|-------|--------|
| Recon | `/etc/hosts`: `cybersaguaros.local` → lane IP. `ffuf` finds `/chat`, `/gallery`, `/admin`, `/api/`. `/robots.txt` discloses the SaguaroBot endpoint `/api/verify.php`. |
| *— route 1 —* | |
| **SSRF** | SaguaroBot's "dataset integrity check" (`/api/verify.php`) fetches any URL. |
| Steal admin session | SSRF `http://127.0.0.1/api/internal/provision.php` → response leaks an `admin_session` token. |
| Admin access | Set cookie `admin_session=<token>` → `/admin/` authorises. The panel reports *"Authorised by an admin session token"*, naming which surface let you in. |
| *— route 2 —* | |
| **SQLi** | `/research.php?q=` concatenates straight into a `LIKE` — `sqlmap` dumps `users`: three accounts, unsalted SHA-256. |
| **Crack** | `hashcat -m 1400 hashes rockyou.txt` → `arizona` / `cactus` / `sunshine`. |
| Which account? | The hashes alone do not say which one matters. `/publications.php` and `/article.php` byline the corresponding author as **`@dr.wagner`**, and `/author.php?u=dr.wagner` labels the role *Portal administrator*. Note the convention is **not** uniform — `rgreen` and `dvalmont` are finitial+lastname, `dr.wagner` is not — so the admin username has to be read off the site, not guessed. This is also the discovery path for a login brute-force / spray. |
| Admin access | Sign in at `/login.php` as `dr.wagner` / `arizona`. The role is `admin`, so the redirect lands on `/admin/` and the header shows an **Admin Panel** button. |
| *— both routes converge —* | |
| **RCE** | `/admin/storage.php` ("Cloud Storage") accepts a filename if an image extension appears **anywhere** in it — an unanchored `preg_match` — and then stores the file under its original name. `shell.php` is rejected; `shell.png.php` passes, lands in `/uploads/` and executes, because the file on disk genuinely ends in `.php`. The server config is stock (nginx `location ~ \.(php\|phar\|phtml)$`, PHP-FPM `security.limit_extensions = .php .phar .phtml`) — nothing is misconfigured, the bug is entirely in the intake filter. The panel lists stored objects, so the URL comes straight off the page. |
| shellpop | Browse the webshell → reverse shell as `saguarobot`. **`saguarobot` has no sudo at all** — `sudo -l` is a dead end by design. |
| Find the deploy key | `/opt/saguaro/field-sync.sh` is world-readable and, being a real sync script, names the key it authenticates with: `ssh -i /opt/saguaro/deploy/id_rsa`. `linpeas` also flags the readable private key directly. |
| **Crack the passphrase** | The key is mode 0644 but passphrase-protected. `ssh2john id_rsa > k.hash` then `john --wordlist=/usr/share/wordlists/rockyou.txt k.hash`. It is a legacy RSA-PEM key (AES-128-CBC), so this falls in seconds. |
| SSH in | `chmod 600 id_rsa` first — OpenSSH refuses a world-readable key with "UNPROTECTED PRIVATE KEY FILE". Then `ssh -i id_rsa hrivera@<target>` → `cat ~/user.txt`. |
| **LinPE → root** — pick any | `sudo -l` is the money shot and needs **no password** — the entries are `NOPASSWD`, and sudoers' `listpw` default of `any` means they list password-free. It prints `(root) NOPASSWD: /usr/bin/find, /usr/bin/python3`. The grant is scoped to the `fieldops` group, which only `hrivera` is in. |
| &nbsp;&nbsp;sudo `find` | `sudo find . -exec /bin/sh \; -quit` |
| &nbsp;&nbsp;sudo `python3` | `sudo python3 -c 'import os; os.system("/bin/bash")'` |
| &nbsp;&nbsp;writable root cron | `/etc/cron.d/saguaro-fieldsync` runs `/opt/saguaro/field-sync.sh` as root every minute; the script is `0775 root:fieldops`. Append a payload and wait 60s. |
| root flag | `cat /root/root.txt` |
| Researcher login (recon) | `rgreen` / `cactus` and `dvalmont` / `sunshine` grant **no** admin, but they do reveal two unpublished working papers on `/publications.php`. One explains why `/api/internal/` was left unauthenticated — a legitimate accelerator for route 1, not a shortcut. |
| XSS (off-path) | `/research.php?q=<script>alert(1)</script>` reflects unencoded. Always on; no victim bot and no session worth stealing — a demo target only. |

### Notes for the instructor

**The upload bug is in the app, not in the server.** `admin/storage.php` tests
the filename with an unanchored `preg_match('/\.(jpe?g|png|gif|svg|webp)/i')` and
keeps the name it was given; nginx and PHP-FPM are stock. What that admits:

| Payload | Uploads? | Executes? |
| --- | --- | --- |
| `shell.png.php`, `shell.PNG.php`, `shell.png.jpg.php` | yes | **yes** |
| `shell.png.phtml`, `shell.png.phar` | yes | **yes** |
| `shell.php.png` | yes | no — served as inert `image/png` |
| `shell.php#.png`, `shell.php%0a.png`, `shell.png.Php5` | yes | no |
| `shell.php`, `shell.pHp`, `shell.php.`, `shell.php%20` | **no** | — |
| `shell.php%00.png` | no (PHP 8 refuses a NUL in a path) | — |

- **Expect "the box is broken" reports about `shell.php.jpg`.** It is the first
  thing anyone who has done DVWA or PortSwigger will try, it uploads cleanly,
  and then it serves its own source back with a `200`. That is the lesson — PHP
  does not execute a `.jpg` without a server misconfiguration — but a student who
  reads the echoed source as partial success can burn a long time on it. The
  intake draft on `/publications.php` is the nudge: it complains that the filter
  never checks what a name *ends* in.
- **Case variants do not execute, and that is correct.** nginx `location ~` and
  PHP-FPM's `security.limit_extensions` are both case-sensitive on Linux, so
  `shell.pHp` is a download. Making it run would mean emptying
  `security.limit_extensions`, which is exactly the bespoke misconfiguration this
  design exists to avoid. `.pHp` is an Apache/IIS trick.
- **Do not "fix" `/uploads/` in the nginx config.** A `location ^~ /uploads/ { }`
  static-only block is the textbook remediation for this bug and kills the
  challenge in one line. `UPLOAD_EXEC` catches it at bake time; nothing catches
  it if you edit the deployed lane by hand.
- **The filter constrains nothing about the final extension**, so
  `payload.png.html` uploads and is served as `text/html`, and `payload.svg`
  executes script in-origin. Both are stored XSS. This is left in deliberately:
  it is *why* "an allowed extension appears somewhere" is a bad check, and a
  deny-list bolted on top would reintroduce exactly the artificial shape this
  design removed. Neither is a shortcut — the upload is `require_admin()`-gated
  and there is no victim bot on this box.
- **Editing `app/db/seed.sql` needs a re-bake, not a redeploy.** The SQL is
  loaded once at bake time and the directory is then deleted from the image
  (asserted by `SQL_SRC_REMOVED`), so a lane redeploy will not pick up a changed
  hint article.
- **Nothing on the deployed box explains the challenge.** The app source, the
  nginx site and the PHP-FPM pool carry no answer-key comments, and the host
  deletes `/etc/cybercore-bake.env` and `/etc/cybercore-cloud-init.log` from the
  image after verification (they are `chmod 600` as a fallback on nodes where the
  disk cannot be mapped for verification). This README is the answer key and it
  is never copied onto the VM — the bake copies only `app/` and `deploy/*`, and
  removes its repo clone before sealing.

- **Two surfaces reach `/admin/`, and `require_admin()` accepts either.**
  `admin_identity()` in `app/includes/auth.php` resolves them: a portal
  session whose `users.role` is `admin`, or a valid `admin_sessions` row
  keyed by the `admin_session` cookie. The control panel prints *which* one
  authorised the request, which is the clearest way to show a class that two
  independent chains ended at the same door.
- **Only `role = 'admin'` counts on the session side.** This is the single
  most fragile line in the app. A regression from
  `($r['role'] ?? '') === 'admin'` to a bare `if ($r)` would hand admin — and
  therefore the upload RCE — to `rgreen` and `dvalmont` as well, and
  `dvalmont` is also a real Linux SSH account whose password is in the SQLi
  dump. Nothing in the bake asserts this; if you touch `auth.php`, confirm by
  hand that `rgreen` / `cactus` still gets a **403** from `/admin/`.
- **The role badge on `/author.php` is the difficulty knob.** It tells a
  student outright which cracked hash is the administrator's. That is
  deliberate — it is what makes route 2 discoverable rather than a guessing
  game. Removing that one badge is the cleanest way to make the box harder.
- **Articles are DB-backed** (`articles` table, `author_id` → `users.id`).
  `status = 'draft'` hides a piece from anonymous visitors and shows it to
  *any* signed-in portal account, which is the entire payoff for a non-admin
  login. Drafts carry hints, never credentials — keep it that way.
- **`/admin/chat.php` renders raw visitor input.** Every field is
  `htmlspecialchars()`'d on purpose: students will have typed XSS payloads
  into SaguaroBot long before an instructor opens the transcript page, and an
  unescaped render there would be an accidental stored-XSS sink firing inside
  the admin panel. `/research.php` is the only *SQL* injection surface in this
  app; for the HTML/script surfaces see the upload notes below.
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
- **Flags are not baked into the template.** `src/utils/flag-manager.js` plants
  them at *deploy* time through `plantFlagsForLane()`, which `attached-modules.js`
  calls on every lane attach, so each lane gets its own unique 32-hex value that
  is wired into the submission/verification and instructor-dashboard tables.
  Two `spec` fields drive this and both are load-bearing:
  - `vms[].os: "linux"` — skips guest-OS probing; planting fails outright if the
    OS can be neither read nor detected.
  - `vms[].flags.user.path: "/home/hrivera/user.txt"` — **without this override**
    `plantLinuxUserFlag()` writes `user.txt` into *every* `/home/*` directory,
    including `saguarobot`'s, handing the webshell foothold the user flag and
    skipping the entire SSH stage.

  The planter writes `user.txt` mode `0644` and does not `chown` it when given
  an explicit path, so containment rests entirely on `/home/hrivera` being
  `0750 hrivera:hrivera` — `saguarobot` cannot traverse in, so it cannot read a
  world-readable file inside. The bake asserts exactly that with `HOME_PERMS`
  (it drops a decoy at the planter's own mode and confirms `saguarobot` is
  refused), and asserts `ROOT_DIR_CLOSED` so `hrivera` cannot list `/root`
  before escalating. `/root/root.txt` is planted `0600 root:root`.
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
seven of the markers (`SUDO_GATED`, `KEY_ENCRYPTED`, `SUDOERS_CLEAN`,
`NO_STRAY_SUID`, `UPLOAD_STATIC_NOEXEC`, `UPLOAD_FILTER_BLOCKS_NAIVE`,
`SQL_SRC_REMOVED`) are
*negative* assertions that catch a collapsed chain rather than a missing file.

The upload stage in particular is asserted in four parts, because the
vulnerability now lives entirely in `admin/storage.php` and a marker that only
writes a file to `/uploads/` with `printf` would never touch it:

| Marker | Asserts |
| --- | --- |
| `UPLOAD_EXEC` | `/uploads/x.png.php` executes |
| `UPLOAD_STATIC_NOEXEC` | `/uploads/x.php.png` comes back as **raw source** — catches a revert of either config file |
| `UPLOAD_FILTER_BYPASS` | an admin session + a real multipart POST of `x.png.php` through `storage.php` lands an executing file |
| `UPLOAD_FILTER_BLOCKS_NAIVE` | the same POST of a bare `x.php` is **refused** — without this, "accept everything" would pass every other marker |

The bot/SSRF is reachable without any login. It is **one** of two critical
lines, not the only one: SQLi → crack → portal sign-in is a complete second
route to the same RCE. The off-path surfaces are the reflected XSS on
`/research.php` and the upload filter's indifference to the final extension
(`payload.png.html`, `payload.svg`) — no victim bot, no session worth stealing,
live demo targets for the lesson and nothing more.
