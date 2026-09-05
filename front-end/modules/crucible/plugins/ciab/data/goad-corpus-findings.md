# GOAD corpus findings — the calibrated baseline

`goad-lab-validate.js` run against every lab in the pinned GOAD fork produces
**exactly 11 findings across 8 labs**. This file is the record of what each one
is and why it is there.

**Read this when the corpus output changes.** The expected set is pinned in
`front-end/test/ciab-goad-lab-validate.test.js` (`EXPECTED`), so a change shows
up as a failing assertion naming the lab, the code and the location. That
assertion tells you *what* moved; this file tells you whether the movement is
good news.

> **Tracking note.** `.gitignore:4` is a blanket `**/data/*`, so this file is
> invisible to git until someone adds `!**/data/goad-corpus-findings.md`
> alongside the negations already there for `goad-role-manifest.json` and
> `threat-scenario-library.json`. That negation was not added here because
> `.gitignore` sits outside this change's lane. Until it exists, this document
> is present on the authoring machine and absent everywhere else — the exact
> invisibility the manifest negation was written to fix.

## Provenance

| | |
|---|---|
| Fork | `https://github.com/joshmp087/GOAD.git` |
| Pinned commit | `0fb45a48e1865fa65054dda22f5e924eea56369c` |
| Labs | DRACARYS, GOAD, GOAD-Light, GOAD-Mini, MINILAB, NHA, SCCM, TEMPLATE |
| Validated inputs | `ad/<LAB>/data/config.json` + `ad/<LAB>/data/inventory` |

All 16 of those files are byte-identical (modulo CRLF) between a clean clone of
the pinned SHA and the working `GOAD-main/` checkout the test reads. Line
numbers below are from the pinned clone and are therefore also correct for
`GOAD-main/`.

## Verdict

**11 findings. 11 true positives. 0 false positives. No rule was changed.**

Every finding was checked against the upstream Ansible role or playbook that
consumes the value, not against the validator's own docstring. Each section
below names the file and line on both sides — the lab data that triggers it and
the upstream code that makes it matter.

### Settling the count

An earlier pass reported "five". Five is a correct count of a different thing.
The units, all of which are true at the pinned SHA:

| Unit | Count |
|---|---|
| Findings emitted (what the test pins) | **11** |
| Distinct config sites | 7 |
| Distinct upstream defects in the 7 *deployable* labs | **5** |
| Defects anticipated before the corpus was run | 3 |

The five are: GOAD's `shares` split-brain, GOAD's `adcs_esc7`, GOAD-Light's
inherited `shares` line, GOAD-Light's dead `CorporateResources` edge, and
GOAD-Mini's dead `AcrossTheNarrowSea` edge. TEMPLATE's three password findings
fall outside that count because TEMPLATE is the authoring skeleton, not a lab
anyone deploys (F-09..F-11). Two of the five collapse into one defect *class*
(`shares`) and two into another (dead ACL edge), which is how one corpus can be
honestly described as 11, 7, 5 or 3 depending on the unit. The test pins 11,
because emitted findings are the only unit a regression can be measured in.

## The corpus is not vacuously quiet

Six of the eight labs produce two findings or fewer. That is only reassuring if
the rules actually ran, so traversal was measured rather than assumed: every
field the corpus contains was mutated to a known-bad value and the resulting
findings counted.

| Surface | Total in corpus | Reached by a rule |
|---|---|---|
| Hosts | 25 | 25 |
| Domains | 12 | 12 |
| Users | 115 | 115 |
| ACL entries | 59 | 59 |
| Groups | 59 | (not separately probed) |
| Organisational units | 25 | (not separately probed) |
| `vulns`/`security` role references | 90 | (not separately probed) |

100% on every surface probed. The quiet is real.

---

## F-01 · GOAD · dc02 lists a broken role

* **Finding** — `error NEVER_EMIT_ROLE@hosts.dc02.vulns[7]`
* **Verdict** — TRUE POSITIVE

**Evidence.** `ad/GOAD/data/config.json:53` ends dc02's `vulns` array with
`"shares"` (index 7). `ansible/roles/vulns/shares/tasks/perm.yml` is included
four times from `tasks/main.yml:22,31,39,47`, each passing
`item.value.<full|change|read|deny> | split(',') | trim | default([])`.
`split` yields a list; Jinja's `trim` is a string filter. The trailing
`default([])` substitutes only for an *undefined* left-hand side and sits after
the filter that mangles or throws, so it rescues nothing. The vendored manifest
carries the full analysis in this role's `never_emit_reason`.

**Consequence.** With vars present the play either dies mid-role — leaving
shares created and unpermissioned — or hands `win_acl` one mangled principal.
On dc02 specifically it does neither, because F-02 means the loop is empty. The
finding is here so nobody *adds* vars to this line and inherits the breakage.

---

## F-02 · GOAD · dc02 runs `shares` over an empty dict

* **Finding** — `warning ROLE_VARS_MISSING@hosts.dc02.vulns[7]`
* **Verdict** — TRUE POSITIVE

**Evidence.** dc02's `vulns_vars` (`ad/GOAD/data/config.json:54`-`95`) has no
`shares` key. `ansible/vulnerabilities.yml:14` binds
`vulns_vars : "{{ lab.hosts[dict_key].vulns_vars[vuln] | default({}) }}"`, so
the role receives `{}`. Every task in `roles/vulns/shares/tasks/main.yml` is
`with_dict: "{{ vulns_vars }}"` — zero iterations.

**Consequence.** This is the silent half. No directory, no share, no ACL, and
Ansible prints green for eight tasks that looped over nothing. A warning rather
than an error because two shipped labs do exactly this, and refusing to build
them would be a worse outcome than saying so.

*F-01 and F-02 share an id on purpose.* They are two independent facts about one
line — the role is broken, **and** it was given nothing to do — and both survive
the deliberate fall-through in `validateRoleList()`. Anyone porting dc02 off
`shares` needs to know there were no vars to port.

---

## F-03 · GOAD · srv02 defines `shares` vars it never runs

* **Finding** — `error ORPHAN_ROLE_VARS@hosts.srv02.vulns_vars.shares`
* **Verdict** — TRUE POSITIVE

**Evidence.** `ad/GOAD/data/config.json:129`-`137` defines
`vulns_vars.shares.thewall` — `path: C:\thewall`, `full: NORTH\Stark`,
`change: NORTH\jon.snow,NORTH\samwell.tarly`, `read: Users`. srv02's `vulns`
array (`:106`) is
`["directory","disable_firewall","openshares","files","permissions"]`. `shares`
is not in it. `vulnerabilities.yml:18` loops the `vulns` array, so a
`vulns_vars` key that nothing lists is never read by anything.

**Consequence, and why this pair is the flagship case.** F-01/F-02 and F-03 are
one defect torn in half across two hosts: the host that *lists* the role has no
vars, and the host that *has* the vars does not list the role. The `thewall`
share is therefore never created on any machine in the lab. Meanwhile
`ad/GOAD/data/config.json:506` gives `jon.snow` the SPN
`HTTP/thewall.north.sevenkingdoms.local`. The kerberoastable service principal
exists and resolves to nothing. A student enumerating SPNs finds the target,
goes looking for the share, and finds no such thing — with no error anywhere in
the deploy log to explain it.

---

## F-04 · GOAD · dc03's ESC7 grant is unreachable code

* **Finding** — `error NEVER_EMIT_ROLE@hosts.dc03.vulns[2]`
* **Verdict** — TRUE POSITIVE

**Evidence.** `ad/GOAD/data/config.json:187` lists `adcs_esc7` at index 2, and
`:189`-`193` supplies `viserys.ca_manager = "essos\\viserys.targaryen"`. So
unlike `shares`, this role runs with real data. In
`ansible/roles/vulns/adcs_esc7/tasks/main.yml`:

* line 5 — the immediately preceding task runs `Install-Module PSPKI -Force`
* line 15 — `if (Get-Module -ListAvailable -Name PSPKI) {`
* line 16 — the *true* branch is `$Ansible.Changed = $false` and nothing else
* line 21 — `Add-CertificationAuthorityAcl … -AccessMask "ManageCa"` sits in the
  `else`, which also opens with `Import-Module -Name PSPKI` — a call that could
  only be reached in the state where the module is absent, where it cannot work

The guard is inverted. Line 5 guarantees line 15 is true, so line 21 is dead
code on every run.

**Consequence.** `viserys.targaryen` never receives ManageCA on the essos CA.
Compensating control checked and absent: **`grep -rn "ManageCA" ad/` across the
pinned clone returns nothing** — no lab grants the right by the working route
(the domain-level `acl` role with `right: "Ext-ManageCA"`), so nothing anywhere
makes up for it. GOAD's documented ESC7 path does not exist in the deployed lab,
and the task reports `Changed=false`, which is indistinguishable from a correct
idempotent re-run.

---

## F-05 · GOAD-Light · dc02 inherits the `shares` line

* **Finding** — `error NEVER_EMIT_ROLE@hosts.dc02.vulns[8]`
* **Verdict** — TRUE POSITIVE

**Evidence.** `ad/GOAD-Light/data/config.json:70` ends dc02's `vulns` with
`"shares"` at index 8. Same broken role as F-01.

---

## F-06 · GOAD-Light · that line has no vars anywhere in the lab

* **Finding** — `warning ROLE_VARS_MISSING@hosts.dc02.vulns[8]`
* **Verdict** — TRUE POSITIVE

**Evidence.** GOAD-Light contains no `vulns_vars.shares` on any host. The other
`shares` hits in that file are unrelated: `:126`/`:127` are `directory` keys
named `shares`/`all`, `:134` is a `files` key `letter_in_shares`.

**Consequence.** GOAD-Light is a re-skin of GOAD, and it inherited dc02's dead
`shares` line without inheriting srv02's `thewall` block. So it is *worse* than
GOAD's version of the same bug: there is not even dead config left to show what
the line was supposed to do. It is pure vestige — a role name that costs one
no-op task per deploy and plants nothing.

---

## F-07 · GOAD-Light · `CorporateResources` holds a GenericAll nobody can reach

* **Finding** — `warning DEAD_ACL_EDGE@domains["cybersaguaros.local"].acls.GenericAll_group_corporateresources_dc`
* **Verdict** — TRUE POSITIVE

**Evidence.** `CorporateResources` appears in exactly two places in the entire
GOAD-Light tree:

* `ad/GOAD-Light/data/config.json:363` — the domainlocal group declaration,
  carrying nothing but `path`
* `:379` — `{"for": "CorporateResources", "to": "TUC-DC01$", "right": "GenericAll", "inheritance": "None"}`

All four membership routes are absent: no `members` key on the group, no user's
`groups` array names it, `multi_domain_groups_member` is `{}` (`:368`), and no
ACL has it as `to`. `TUC-DC01$` is the forest-root DC (host `dc01`, domain
`cybersaguaros.local`).

**Why it is dead rather than deliberate.** The rest of the domain is a
one-for-one re-skin of GOAD's `sevenkingdoms.local`:

| GOAD | GOAD-Light |
|---|---|
| `Small Council` → `DragonStone` | `LeadershipBoard` → `ProjectAlpha` |
| `DragonStone` → `KingsGuard` | `ProjectAlpha` → `SecurityTeam` |
| `KingsGuard` → `stannis.baratheon` | `SecurityTeam` → `steven.banks` |
| `stannis.baratheon` → `kingslanding$` | `steven.banks` → `TUC-DC01$` |
| `AcrossTheNarrowSea` → `kingslanding$` | `CorporateResources` → `TUC-DC01$` |

In GOAD the last row is live: `multi_domain_groups_member` puts
`essos.local\daenerys.targaryen` into `AcrossTheNarrowSea`
(`ad/GOAD/data/config.json:584`-`587`). GOAD-Light has a second domain
(`tumamoc.cybersaguaros.local`) but no essos analogue, so the member had nowhere
to come from and the entry was dropped — while the ACL that depended on it was
kept.

**Consequence.** The ACE is written correctly and the deploy is green; the group
exists and holds full control over the root DC's computer object. What is broken
is the attack path. BloodHound collects a `GenericAll` edge from
`CORPORATERESOURCES@CYBERSAGUAROS.LOCAL` to `TUC-DC01$` and will happily route a
shortest-path-to-Domain-Admins query through it — a route no principal in the
forest can enter. The student follows the tool's own recommendation into a dead
end. Warning, not error, precisely because nothing failed.

---

## F-08 · GOAD-Mini · the same edge, left behind by the reduction

* **Finding** — `warning DEAD_ACL_EDGE@domains["sevenkingdoms.local"].acls.GenericAll_group_acrrosdom_dc`
* **Verdict** — TRUE POSITIVE

**Evidence.** GOAD-Mini is GOAD reduced to one host and one domain
(`sevenkingdoms.local`; essos and north are gone). `AcrossTheNarrowSea` survives
at `ad/GOAD-Mini/data/config.json:88` and its ACL at `:104` — character-identical
to GOAD's `:598`. But `multi_domain_groups_member` is now empty (`:93`-`94`)
where GOAD's holds `essos.local\daenerys.targaryen`. The group name appears
nowhere else in the pinned clone except `docs/olddocs/diagram.drawio`.

**The contrast is the proof.** Same lab family, same ACL key, same group,
opposite verdict — reachable in GOAD, dead in GOAD-Mini — and the single
differing field is the one the rule reads. That contrast is pinned as its own
test so neither half can drift alone.

**Consequence.** Identical to F-07: an unreachable GenericAll on `kingslanding$`.

### Calibration of the DEAD_ACL_EDGE rule

The corpus contains **17 ACLs whose `for` is a group the config declares**.
Exactly 2 are dead, and they are exactly F-07 and F-08. The other 15 are
exempted, and three of the rule's four membership routes are genuinely
exercised:

* **user `groups` array** — `Small Council`, `LeadershipBoard`, `Sanin`, `Hokage`
* **inbound ACL granting membership** — `DragonStone`, `KingsGuard`,
  `ProjectAlpha`, `SecurityTeam`
* **`multi_domain_groups_member`** — `Spys`, `DragonsFriends`, and GOAD's
  `AcrossTheNarrowSea`
* **explicit `members` list** — *not exercised by any ACL-sourcing group in the
  corpus.* The key is real and honoured upstream
  (`ansible/roles/ad/tasks/main.yml:43,50,57` feeds it to
  `win_domain_group_membership`) and is used by GOAD `:277,:282` and SCCM
  `:121,:130`, but never on a group that also sources an ACL. This exemption is
  proven by fixture only, not by corpus.

Two config keys were checked and correctly **not** treated as membership grants:

* **`managed_by`** — `roles/ad/tasks/main.yml:18`-`37` passes it to
  `win_domain_group: managed_by:`, which sets the `managedBy` attribute only. It
  does not set "Manager can update membership list", so it delegates nothing.
  (TEMPLATE's `managed_by` values are therefore also inert, but that is cosmetic,
  not a broken attack path.)
* **host `local_groups`** — local group membership on one machine, not domain
  group membership; it cannot put a principal into a domain group.

---

## F-09 · TEMPLATE · dc01's local admin password fails the default policy

* **Finding** — `error WEAK_LOCAL_ADMIN_PASSWORD@hosts.dc01.local_admin_password`
* **Verdict** — TRUE POSITIVE

**Evidence.** `ad/TEMPLATE/data/config.json:7` —
`"local_admin_password": "dc_and_domain_password"`. Lowercase plus underscore is
2 of the 4 Windows character classes; the policy requires 3. dc01 is `type: dc`,
so this string is also the domain password (`:48`, identical) and therefore
`win_domain`'s `safe_mode_password`.

**Consequence.** Loud, not silent: `dcpromo` validates the DSRM password against
the *default* policy, which runs long before `password_policy` relaxes anything.
The promotion fails. TEMPLATE as shipped cannot deploy.

---

## F-10 · TEMPLATE · srv01's local admin password is a placeholder

* **Finding** — `error WEAK_LOCAL_ADMIN_PASSWORD@hosts.srv01.local_admin_password`
* **Verdict** — TRUE POSITIVE — **and the one finding with a house-rule component**

**Evidence.** `ad/TEMPLATE/data/config.json:29` —
`"local_admin_password": "srv_password"`. Same 2-of-4 classes.

**The honest argument against it.** srv01 is a member server. A standalone
Windows box ships with complexity *disabled* and no minimum length, so Windows
itself would accept `srv_password`. Nothing in the deploy breaks. This rule is
CyberCore's, not Microsoft's.

**Why it stands anyway.**

1. **It fires on zero deployable labs.** All 7 labs that ship an
   `inventory_disable_vagrant` pass it. TEMPLATE is the only lab of the eight
   without one — it is the authoring skeleton you copy, not a lab anyone
   deploys. A rule that never fires on a working lab is not a false-positive
   generator.
2. **The string is a literal placeholder.** `srv_password` and
   `dc_and_domain_password` are TEMPLATE's way of saying "put your value here";
   `ad/TEMPLATE/README.md` documents the field as the thing you set. Flagging an
   unfilled placeholder in the skeleton this repo generates labs *from* is the
   rule working, not misfiring.
3. **The blast radius is per-cohort.** This credential is what the lane's console
   and WinRM login use, it is handed to students, and every lane in a cohort is
   built from one definition. One weak string is a platform-wide exposure, not a
   per-VM one.

**The condition that would make it a false positive**, stated so a future
maintainer can test it rather than re-argue it: *this rule firing on a lab that
carries an `inventory_disable_vagrant`.* If that ever happens, the rule is too
strict for a real lab and should be relaxed for non-DC hosts. It has not
happened at the pinned SHA, and a test asserts TEMPLATE is still the only lab
without one.

---

## F-11 · TEMPLATE · the domain password is the DSRM password

* **Finding** — `error WEAK_DOMAIN_PASSWORD@domains["template.lab"].domain_password`
* **Verdict** — TRUE POSITIVE

**Evidence.** `ad/TEMPLATE/data/config.json:48` — the same
`"dc_and_domain_password"` string. Pure Windows rule, no house component. See
F-09 for the failure.

---

## Deliberate non-findings

Things the corpus contains that the validator saw and correctly stayed quiet
about. These matter as much as the findings: each is a rule that could
plausibly have misfired and did not.

### DRACARYS is not valid JSON, and that is fine

`ad/DRACARYS/data/config.json:128` ends the last entry of the `acls` dict with a
comma, so `JSON.parse` fails at line 129 column 13. The lab deploys anyway.
Nothing in GOAD feeds that file to a JSON parser — the playbooks load it through
`vars_files`, i.e. PyYAML, and YAML 1.1 flow collections tolerate a trailing
comma. `.json` is a naming convention here, not a contract.

`parseLabConfig()` therefore reports `strict: false`,
`repairs: ['trailing-comma']` and **zero findings**. Flagging it would be the one
error class this validator must never produce: rejecting a lab that works. The
write path stays strict (`toStrictJson()`), so the tolerance never propagates to
anything this repo emits.

DRACARYS also exercises two rules nothing else does: the `security` namespace
(`directory`, `files`, `ldaps` on dc01) and the domain-only extended right
`Ext-Write-SPN`.

### SCCM's `elk` is not an undeclared host

SCCM's inventory puts `elk` in `[elk_server]` with no `config.json` entry,
because it is a Linux appliance built by `elk.yml` rather than an AD member.
`MEMBER_GROUPS` is scoped to `['domain', 'linux_domain']` for exactly this
reason; an unscoped inverse rule would reject a lab upstream deploys daily.

### MINILAB and NHA are clean

No findings, and the traversal probe confirms all of their hosts, domains, users
and ACLs were reached.

---

## Known gap: `use_laps` with no `laps_path`

Not a finding — a defect in the corpus the validator does **not** currently
detect. Recorded here so the next reader does not mistake its absence from the
baseline for evidence that it is fine.

`ad/TEMPLATE/data/config.json:32` sets `"use_laps": true` on srv01, and
`template.lab` declares no `laps_path`. `ansible/laps.yml:14,23,33,42` resolves
`laps_path` to the literal `false` when the domain does not declare it, and then:

* `roles/laps/dc/tasks/main.yml:3,7` — install **and** the OU move are
  `when: laps_path != false`
* `roles/laps/server/tasks/main.yml:3` — install is
  `when: laps_path != false and use_laps == true`

Everything is skipped. No LAPS, no OU move, no `laps_readers` permissions, and
Ansible reports green. This is "a computer never moved" in its purest form: a
host asks for LAPS, the domain never offers the OU, and the disagreement is
resolved by silence. (TEMPLATE's inventory compounds it — `[laps_dc]`,
`[laps_server]` and `[laps_workstation]` are all empty, so the plays target no
host either way.)

A second, related silence lives in `roles/laps/dc/tasks/move_server_to_ou.yml`,
which wraps `Move-ADObject` in a `try` that catches
`ADIdentityNotFoundException` and returns `$false` — so a `laps_path` naming an
OU that `organisation_units` never declares also fails quietly.

Both would be cheap rules (`use_laps: true` requires `laps_path` on the host's
domain; `laps_path` must resolve to a declared container). Neither was added
here: this pass was scoped to calibration, and adding a rule would move the
baseline in the same change that establishes it. At the pinned SHA the only lab
affected is TEMPLATE, which already cannot deploy for F-09/F-11.

---

## Reproducing this

```js
const V = require('./front-end/modules/crucible/plugins/ciab/utils/goad-lab-validate.js');
const parsed = V.parseLabConfig(fs.readFileSync(`ad/${lab}/data/config.json`, 'utf8'));
const r = V.validateLab({
  lab: parsed.lab,
  inventory: fs.readFileSync(`ad/${lab}/data/inventory`, 'utf8'),
  labName: lab,
});
r.findings.map((f) => `${f.severity} ${f.code}@${f.id}`);
```

`npm test` in `front-end/` runs this over `GOAD-main/` automatically. The corpus
tests self-skip when `GOAD-main/` is absent (it is gitignored with zero tracked
files, so it exists on the authoring machine and not in CI); every rule is also
proven against hand-built fixtures that need no checkout.
