# cc-web — the curated web tier

This tree builds the one machine on a CIAB lane that the paper describes in
detail: the dual-homed DMZ web host. It exists so that a student who runs `nmap`
against the lane reads about the same company they were handed on paper.

---

## Why this is a separate tree from GOAD's `ansible/roles/`

`ansible/roles/` in the pinned GOAD fork is **shared core and read-only**.

`front-end/test/ciab-goad-role-manifest.test.js` asserts that
`bake-goad-controller-vm.sh`'s `GOAD_REF` and the vendored
`goad-role-manifest.json` name the **same 40-character commit**. A local edit
inside `ansible/roles/` makes that SHA a lie without changing a single tracked
byte — `GOAD-main/` is gitignored and has zero tracked files, so the edit appears
in no diff, on no other machine, and in no review. The correct place for
CyberCore behaviour is therefore a tree CyberCore owns.

The layout is **upstream's own extension pattern**, not an invention.
`extensions/{exchange,guacamole,lx01,ws01}/ansible/ansible.cfg` each carry

```ini
; add default roles folder into roles_path
roles_path = ./roles:../../../ansible/roles
```

We do the same thing from a sibling directory instead of from inside
`extensions/`, so a `git pull` on the fork never touches us and we never touch
it.

### `roles_path`: local first, and why that is not the safety property

```ini
roles_path = ./roles:/opt/goad/ansible/roles:../../../GOAD-main/ansible/roles:$HOME/.ansible/roles:/etc/ansible/roles
```

Ansible resolves a role name left to right and takes the **first** hit. Local
first means `cc_web` always resolves here, and nothing in this tree ever needs a
file inside GOAD to change.

But first-wins is exactly what makes shadowing *possible*, so precedence alone
guarantees nothing. The actual guarantee is a naming rule:

> **Every role in `./roles` is named `cc_<something>`.**

Upstream has no `cc_`-prefixed role, so no ordering of this path can change which
directory a GOAD play resolves. `ciab-cc-web-role.test.js` enforces the prefix;
convention does not.

Collisions here are not hypothetical. The pinned tree already contains **two
different roles called `adcs_templates`** — `ansible/roles/adcs_templates` and
`ansible/roles/vulns/adcs_templates` — reached by different playbooks through
different path entries. A third arriving from a CyberCore tree would be picked by
whichever entry came first, silently, ninety minutes into a bake.

The GOAD roles are listed twice because they live in two places: `/opt/goad` on
the baked controller template (where `bake-goad-controller-vm.sh` clones them)
and `../../../GOAD-main` in a developer's working copy. Ansible skips
`roles_path` entries that do not exist, so one config file works in both.

---

## What the role delivers, and why each piece is load-bearing

The generated scan documents assert a precise web tier: a server product and
version, a port set, a TLS protocol list, specific paths. Today's lane deploys an
LLM-chosen container on port 80 with **no TLS listener at all**, at whatever
routes the model invented. The reports still carry POODLE and TLS 1.0 findings,
because `service-inference.js` resolves every `:443` through `PORT_DEFAULTS`. The
student's `sslscan` finds nothing to find.

`roles/cc_web` closes that:

| The paper claims | The role delivers |
| --- | --- |
| a server product and version | apache2, with `ServerTokens` set so the Server header discloses the version the facts declare |
| a port set | `ports.conf` rewritten to exactly the declared listen set |
| a TLS protocol list | a real 443 listener with `SSLProtocol -all +<each declared protocol>`, *plus* the system OpenSSL relaxation a weak protocol actually needs |
| specific paths | one file per declared route under the docroot |
| a domain service account on the web host | an app config file naming it, outside the docroot by default |

### The pivot credential is the point

The web box is the lane's **one** dual-homed machine — `engagement-model.js`
pins exactly one pivot per lane, at `.240` on both segments. The banner, the
ports and the weak TLS are scenery that makes the report true. The credential is
the mechanism: reading a file off a compromised web server becomes an Active
Directory foothold. Without it the external engagement dead-ends at a defaced
homepage.

The role **never domain-joins this host**. A joined host is already inside the
domain, so compromising it proves nothing. Its only AD relationship is that a
file on it names a domain account.

---

## The contract

The role is driven entirely by variables and contains **no** company name,
hostname, credential or copy. The AI generates the content; this role installs
it.

`cc_web_facts` is `asset.web_facts` **verbatim** — the same object documented in
`front-end/modules/crucible/plugins/ciab/ai/scan-documents/service-inference.js`
and read there by `readWebFacts()`:

```yaml
cc_web_facts:
  product: apache          # spelled the way nmap -sV names it
  version: "2.4.62"        # '' when the image pins no version
  ports: [80, 443]         # every TCP port the web server really binds
  tls:
    enabled: true          # true ONLY if a TLS listener really exists
    port: 443
    protocols: ["TLSv1.0", "TLSv1.2"]
  paths: ["/", "/login", "/portal"]
```

One contract, two consumers: the generator reads it to decide what the report is
allowed to claim, the role reads it to decide what to build. That is what turns
"paper matches lane" from something a checker verifies after the fact into
something that cannot be false.

The rest:

```yaml
cc_web_server_name: web01.lane.example         # vhost ServerName; REQUIRED
cc_web_docroot: /var/www/cc-web                # has a default
cc_web_routes:                                 # REQUIRED — the generated site
  - path: /
    content: "<!doctype html>…"
  - path: /login
    content: "<!doctype html>…"
    file: login/index.html                     # optional explicit filename

cc_web_pivot:                                  # REQUIRED — never defaulted
  path: /etc/cc-web/app.env
  format: dotenv                               # dotenv | php | json | ini | xml
  domain: EXAMPLE
  username: svc-intranet
  password: "{{ vault_cc_web_pivot_password }}"
  mode: "0640"                                 # QUOTE IT
```

Route paths named in `cc_web_facts.paths` **must** have content. The reverse is
not required: a route the paper does not mention is legitimate exercise design
(find the admin panel), while a declared path that serves nothing is the paper
lying.

`cc_web_pivot` is `{}` in `defaults/`. A password with a default is a password
that ships; pass it from a vaulted vars file or the runner's generated
extra-vars.

---

## Three traps that cost a day each

**1. Route content is templated on the way through, and the role cannot stop
it.** Ansible renders variable values recursively. If a route's `content`
contains `{{ … }}`, Ansible evaluates it while substituting the variable — long
before the copy task sees the bytes. AI-authored HTML that ships a Vue, Angular
or Handlebars template will either raise `AnsibleUndefinedVariable` (loud, fine)
or silently evaluate to something else (quiet, not fine). By the time the role
reads `cc_web_routes` the damage is done, so the **caller** must tag it:

```yaml
cc_web_routes:
  - path: /
    content: !unsafe "<div>{{ product.name }}</div>"
```

**2. A weak protocol needs two changes, and the second one is invisible.**
`SSLProtocol +TLSv1` on Debian 12 produces a listener that *advertises* TLS 1.0
and then fails every handshake, because OpenSSL 3 applies
`/etc/ssl/openssl.cnf`'s `[system_default_sect]` policy to httpd as a library
consumer. Nothing logs a complaint: apache starts, the port is open, and
`openssl s_client -tls1` says "no protocols available". `tasks/tls.yml` relaxes
that policy when — and only when — a weak protocol was declared, refuses to
proceed if the section it needs to edit is absent, and `tasks/verify.yml` proves
the handshake afterwards.

**3. The declared version cannot be faked, so it is verified instead.** httpd
builds the `Server` header in its core output filter, where `mod_headers` cannot
reach it; the only way to present a foreign banner is mod_security's
`SecServerSignature`, a dependency this role does not pull in. So:

* an unsupported `product` is a **fail-fast**, not a best effort — the role
  refuses to serve apache under another product's name;
* a `version` that does not match the installed binary is a **failed
  verification** that prints what the host really serves. The fix is to correct
  `web_facts.version` or to pin a base image, never to relax the check.

`tasks/verify.yml` publishes what it **observed** to
`/etc/cybercore/cc-web-observed.json`, shaped like `asset.web_facts` so
`readWebFacts()` can consume it. That is the return path: a generator that reads
it writes a report about the host that exists.

---

## The quality rules this role holds itself to

An audit of upstream GOAD found **twenty** places where a task reports SUCCESS
and did nothing. Three ship as vulnerabilities that are simply not there:

* `vulns/adcs_esc7` — the `Get-Module -ListAvailable` guard is inverted and the
  preceding task installs the module, so `ManageCA` is never granted;
* `move_to_ou` — `$target_ou = Get-ADOrganizationalUnit -Identity $ou_path > $null`
  consumes the success stream, so the variable is always null, and a bad OU path
  is swallowed by a typed catch;
* `vulns/no_ldap_signing` — writes
  `HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\LDAPServerSigningRequirements`, a
  path Windows does not read, while its sibling `no_ldap_integrity` targets the
  correct `NTDS\Parameters`.

Tree-wide, `changed_when` appears exactly **twice** and `error_action: stop`
**six** times, so neither "changed" nor the exit code carries information. This
role therefore:

1. sets an explicit `changed_when` on **every** `shell`/`command` task;
2. sets `error_action: stop` on every `win_powershell` task — there are none
   today because the role is Linux-only, and the test proves the checker would
   catch one rather than passing vacuously;
3. declares its required variables and **fails fast with a named message**
   naming the variable, rather than templating an empty string;
4. ends with a verification pass that re-reads the **host** — config off disk,
   ports from `ss`, the banner from a live response, each declared TLS protocol
   from a completed handshake (and each undeclared one from a failed handshake),
   each route from a fetch, the credential file from a grep;
5. is safely re-runnable: the certificate is guarded by `creates:` so a replay
   never changes the fingerprint under a student mid-exercise, every other write
   is idempotent, and the whole verification pass is read-only. The runner's
   entire recovery model is "replay the failed playbook".

---

## Layout

```
infrastructure/ansible/cc-web/
├── ansible.cfg                    roles_path — local tree first
├── cc-web.yml                     the play (NOT site.yml — see its header)
├── README.md
└── roles/cc_web/
    ├── defaults/main.yml          the contract; no identity, no secrets
    ├── vars/main.yml              lookup tables only (Debian paths, TLS vocabulary)
    ├── meta/main.yml              dependencies: [] on purpose
    ├── handlers/main.yml          restart, addressed by `listen`
    ├── tasks/
    │   ├── main.yml               resolve → assert → build → flush → verify
    │   ├── resolve.yml            normalises web_facts; pure, touches nothing
    │   ├── assert.yml             the fail-fast gate
    │   ├── packages.yml           apache2 + the verification tools
    │   ├── content.yml            docroot and routes
    │   ├── banner.yml             ServerTokens / ServerSignature
    │   ├── tls.yml                cert, vhost protocol set, OpenSSL policy
    │   ├── vhosts.yml             listen set, vhosts, configtest
    │   ├── pivot_credential.yml   the domain account in an app config
    │   └── verify.yml             re-reads the host; publishes observed facts
    └── templates/                 banner, ports, vhosts, credential formats
```

Tests: `front-end/test/ciab-cc-web-role.test.js`, run by
`cd front-end && npm test`.
