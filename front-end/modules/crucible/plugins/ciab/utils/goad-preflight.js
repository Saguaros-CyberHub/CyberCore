/**
 * goad-preflight.js — resolve, ON THE ORCHESTRATOR, every GOAD variable that
 * Ansible would resolve ON THE GUEST, before a single VM boots.
 * ============================================================================
 * WHY THIS FILE EXISTS
 * A GOAD lab is not one `ansible-playbook` run. playbooks.yml lists a CHAIN —
 * sixteen separate invocations for the `default` lab — and each one is a fresh
 * process that parses only the playbooks it imports. Nothing in
 * vulnerabilities.yml (last in the chain) is even READ until every DC has been
 * promoted, every trust built and every server enrolled: roughly ninety minutes
 * of a bake spent before the file is opened.
 *
 * The only pre-flight the system has today is
 *   pct exec 9994 -- ansible-playbook --syntax-check main.yml
 * (bake-goad-controller.sh:374), and it is wrong twice over:
 *
 *   1. main.yml is NOT the chain that runs. `goad` builds the run from
 *      playbooks.yml, whose per-lab lists differ from main.yml and from each
 *      other — SCCM and NHA comment out ad-child_domain.yml and laps.yml,
 *      DRACARYS drops servers.yml, adcs.yml and ad-trusts.yml entirely.
 *   2. --syntax-check does not descend into include_role, and include_role is
 *      how every roles/vulns/* and roles/security/* task file is invoked. No
 *      YAML under those two trees is syntax-checked by anything, ever.
 *
 * So the expensive, detectable class of failure is an UNDEFINED VARIABLE. Every
 * play in the chain opens its `vars:` block by dereferencing the loaded lab
 * dict — `domain: "{{lab.hosts[dict_key].domain}}"`, `sa_password:
 * "{{lab.hosts[dict_key].mssql.sa_password}}"` — and the ones this module checks
 * carry NO `| default(...)`. An undefined dereference in a play's `vars:` is an
 * AnsibleUndefinedVariable at PLAY START, which fails every host in that play at
 * once. Depending on where the play sits in the chain that lands anywhere from
 * ~30% (ad-parent_domain.yml, the third invocation) to ~95% (vulnerabilities.yml)
 * into the bake, and the operator has already paid for all of it.
 *
 * WHAT THIS MODULE IS NOT
 * It is pure and offline: no Ansible, no Proxmox, no network, no filesystem walk
 * of GOAD-main/ (which is gitignored, so anything that walked it would go
 * silently permissive on a fresh clone or in CI — the same trap documented at
 * the top of goad-role-manifest.js). Everything it needs is passed in.
 *
 * SEVERITY MEANS SOMETHING HERE
 *   error   — Ansible raises AnsibleUndefinedVariable and the play dies. The
 *             bake stops. Loud, expensive, unambiguous.
 *   warning — the dereference IS guarded upstream, so the play stays green and
 *             quietly does nothing. That is the worse outcome of the two (see
 *             the laps_path check), it just is not a build break.
 *
 * The core never throws; assertGoadLabPreflight() is the thin boundary that
 * turns errors into a 422 for a route.
 *
 * RELATIONSHIP TO goad-lab-validate.js
 * Sibling, not duplicate, and the split is on purpose. goad-lab-validate asks
 * "is this lab WELL-FORMED for Active Directory" — sAMAccountName lengths,
 * password complexity, DN syntax. This file asks the narrower, cheaper question
 * "will the CHAIN resolve every variable it dereferences with no default", which
 * needs things AD validation does not: the provider inventory's per-host
 * dict_key/ansible_host, and which playbooks are actually in this lab's chain.
 * The finding shape is deliberately identical ({ id, code, severity, message },
 * severity 'error'|'warning') so one caller can concat both lists and one
 * renderer can draw them; the GOAD_PF_ prefix keeps the code vocabularies from
 * colliding when it does. Both files carry their own stripTrailingCommas and
 * parseInventory — this one tracks hostVars and [grp:children], which the other
 * has no use for. If they are ever merged, merge toward the richer parser.
 */

const SEVERITY = Object.freeze({
  ERROR: 'error',
  WARNING: 'warning',
});

/**
 * Every code this module can emit. Registered, not free-form, for the same
 * reason engagement-plan.js registers its problem codes: a caller has to be able
 * to switch on the set, and a typo'd code is a finding nobody can route.
 */
const CODE = Object.freeze({
  CONFIG_UNPARSEABLE: 'GOAD_PF_CONFIG_UNPARSEABLE',
  CONFIG_SHAPE: 'GOAD_PF_CONFIG_SHAPE',
  INVENTORY_VAR_MISSING: 'GOAD_PF_INVENTORY_VAR_MISSING',
  GROUP_EMPTY: 'GOAD_PF_GROUP_EMPTY',
  GROUP_HOST_UNKNOWN: 'GOAD_PF_GROUP_HOST_UNKNOWN',
  HOST_KEY_MISSING: 'GOAD_PF_HOST_KEY_MISSING',
  HOST_NOT_IN_INVENTORY: 'GOAD_PF_HOST_NOT_IN_INVENTORY',
  DOMAIN_UNDECLARED: 'GOAD_PF_DOMAIN_UNDECLARED',
  DOMAIN_KEY_MISSING: 'GOAD_PF_DOMAIN_KEY_MISSING',
  DOMAIN_DC_UNRESOLVED: 'GOAD_PF_DOMAIN_DC_UNRESOLVED',
  PROVIDER_HOST_MISSING: 'GOAD_PF_PROVIDER_HOST_MISSING',
  PROVIDER_DICT_KEY_MISMATCH: 'GOAD_PF_PROVIDER_DICT_KEY_MISMATCH',
  PROVIDER_DICT_KEY_UNKNOWN: 'GOAD_PF_PROVIDER_DICT_KEY_UNKNOWN',
  PROVIDER_ANSIBLE_HOST_MISSING: 'GOAD_PF_PROVIDER_ANSIBLE_HOST_MISSING',
  PROVIDER_ANSIBLE_HOST_MALFORMED: 'GOAD_PF_PROVIDER_ANSIBLE_HOST_MALFORMED',
  PROVIDER_ANSIBLE_HOST_DUPLICATE: 'GOAD_PF_PROVIDER_ANSIBLE_HOST_DUPLICATE',
  TRUST_MISSING: 'GOAD_PF_TRUST_MISSING',
  TRUST_UNDECLARED: 'GOAD_PF_TRUST_UNDECLARED',
  CA_SERVER_MISSING: 'GOAD_PF_CA_SERVER_MISSING',
  MSSQL_SA_PASSWORD_MISSING: 'GOAD_PF_MSSQL_SA_PASSWORD_MISSING',
  CHILD_PARENT_UNDECLARED: 'GOAD_PF_CHILD_PARENT_UNDECLARED',
  LAPS_PATH_MISSING: 'GOAD_PF_LAPS_PATH_MISSING',
});

const CODE_SET = new Set(Object.values(CODE));

/**
 * Groups the inventory comments mark "(mandatory)". Deliberately SHORT.
 *
 * MINILAB ships with [server], [child_dc], [trust], [mssql], [iis], [webdav]
 * and both laps server groups absent or empty, and it is a supported lab.
 * Requiring the full group vocabulary would reject upstream's own labs, so the
 * rule is: these three must have members, everything else is checked only for
 * the members it happens to have.
 */
const MANDATORY_GROUPS = Object.freeze(['domain', 'dc', 'parent_dc']);

/**
 * Inventory vars every chain dereferences with no default.
 *
 * This is not hypothetical. ad/TEMPLATE/data/inventory — upstream's documented
 * starting point for authoring a new lab — omits BOTH, so copying TEMPLATE and
 * filling in config.json produces a lab that cannot complete
 * ad-parent_domain.yml, the third playbook in the chain.
 */
const REQUIRED_INVENTORY_VARS = Object.freeze(['admin_user', 'dns_server_forwarder']);

/** Where each required var dies, so the message can name a real line. */
const INVENTORY_VAR_SITES = Object.freeze({
  admin_user:
    'ad-parent_domain.yml:17, ad-data.yml:17, ad-acl.yml:17, adcs.yml:15 and servers.yml:25 '
    + 'build a domain login from it with no default (~40 sites in all)',
  dns_server_forwarder:
    'roles/domain_controller/tasks/main.yml:66 (run from ad-parent_domain.yml) and '
    + 'roles/child_domain/tasks/main.yml:110 pass it straight to xDnsServerForwarder',
});

/** Suggested value for the remedy sentence — upstream's own for every lab but AWS/Azure. */
const INVENTORY_VAR_EXAMPLE = Object.freeze({
  admin_user: 'administrator',
  dns_server_forwarder: '1.1.1.1',
});

/** Keys on lab.hosts[k] that some play dereferences with no default. */
const REQUIRED_HOST_KEYS = Object.freeze(['hostname', 'domain', 'path', 'local_admin_password', 'type']);

/** Keys on lab.domains[d] that some play dereferences with no default. */
const REQUIRED_DOMAIN_KEYS = Object.freeze(['domain_password', 'netbios_name', 'dc', 'users', 'groups']);

/**
 * Groups whose members are cross-checked against lab.hosts.
 *
 * NOT every group in the file. [elk_server] holds `elk` in ad/SCCM, and
 * [linux_domain] holds `lx01` in ad/DRACARYS — hosts that legitimately exist in
 * the inventory. `elk` is not in lab.hosts at all (it is a Linux appliance the
 * lab dict never describes), so a blanket "every inventory host is a config key"
 * rule would reject a shipped lab. Only the groups whose plays index
 * lab.hosts[dict_key] are listed.
 */
const HOST_GROUPS = Object.freeze([
  'domain', 'dc', 'parent_dc', 'child_dc', 'server', 'workstation',
  'trust', 'adcs', 'adcs_customtemplates', 'mssql', 'mssql_ssms',
  'laps_dc', 'laps_server', 'laps_workstation',
]);

/** The playbook that consumes each conditional group — see chainForLab(). */
const PLAYBOOK = Object.freeze({
  TRUSTS: 'ad-trusts.yml',
  CHILD_DOMAIN: 'ad-child_domain.yml',
  ADCS: 'adcs.yml',
  SERVERS: 'servers.yml',
  LAPS: 'laps.yml',
});

/**
 * playbooks.yml `default:`, verbatim — the chain for GOAD, GOAD-Light, MINILAB,
 * TEMPLATE and any lab with no entry of its own. Sixteen invocations.
 *
 * Hardcoded so the module stays offline. Callers that HAVE playbooks.yml should
 * pass chainForLab(text, labName) instead; this is only the fallback.
 */
const DEFAULT_CHAIN = Object.freeze([
  'build.yml',
  'ad-servers.yml',
  'ad-parent_domain.yml',
  'ad-child_domain.yml',
  'wait5m.yml',
  'ad-members.yml',
  'ad-trusts.yml',
  'ad-data.yml',
  'ad-gmsa.yml',
  'laps.yml',
  'ad-relations.yml',
  'adcs.yml',
  'ad-acl.yml',
  'servers.yml',
  'security.yml',
  'vulnerabilities.yml',
]);

// ── small helpers ───────────────────────────────────────────────────────────

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/**
 * Present AND carrying something — and "something" is a different question per
 * type, which is why this is four rules and not `!!v`.
 *
 * STRING — trimmed, because Ansible does not. `"trust": ""` is upstream's own
 *   encoding for "this domain trusts nothing" (ad/GOAD ships it on
 *   north.sevenkingdoms.local), so a bare key-presence check calls it
 *   configured; ad-trusts.yml:16 then sets remote_forest to '' and dies on
 *   lab.domains[''].dc. A whitespace-only value is the same hole in a disguise,
 *   and it has a second edge: every other read in this module goes through
 *   str(), which trims, so calling "  " filled would leave the rest of the file
 *   treating a "present" field as ''. Unfilled is not the same as invalid —
 *   §7 is the only caller that asks about .trust, and only for a domain with a
 *   host in [trust], which is exactly why `trust: ""` stays legal everywhere
 *   else.
 *
 * ARRAY — [] is not a list of anything. No REQUIRED_* key is a list today, so
 *   this branch is for the generator that emits `users: []` where a dict
 *   belongs: it iterates to the same nothing an absent key does.
 *
 * OBJECT — an empty dict is not "present", and this is the line the gate turns
 *   on. ad-data.yml:20-22 binds ad_users / ad_groups straight off
 *   lab.domains[d].users / .groups with no `| default(...)`, so an ABSENT key is
 *   an undefined dereference at play start. An EMPTY one fails the other way,
 *   the way this repo ranks as worse: it resolves, roles/ad/tasks/users.yml:20
 *   and groups.yml:9-28 iterate it zero times, and the DC comes up carrying not
 *   one user, group or ACL — a green bake that built an empty lab. Both are a
 *   REQUIRED key the composer never supplied, so both raise the same finding.
 *   Without this line a chassis whose payload was never filled in pre-flights
 *   completely clean, and the bake finds out at ad-data.yml — 8th playbook of
 *   the default chain, ~60 minutes into a ~90-minute build.
 *
 * NUMBER / BOOLEAN — present. `0` and `false` are values Ansible resolves, so
 *   emptiness has nothing to say about them. The one field where `false` means
 *   "do nothing" is laps_path, and that is laps.yml's private sentinel rather
 *   than a fact about the value, so it is decided at its own site (§11).
 */
function filled(v) {
  if (v === null || v === undefined) return false;
  if (typeof v === 'string') return v.trim() !== '';
  if (Array.isArray(v)) return v.length > 0;
  if (isPlainObject(v)) return Object.keys(v).length > 0;
  return true;
}

function str(v) { return v === null || v === undefined ? '' : String(v).trim(); }

/** hosts[k] / domains[d] are attacker-shaped input as far as this module cares:
 *  a generator can hand us a null or a string where an object belongs. */
function obj(v) { return isPlainObject(v) ? v : {}; }

function has(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }

// ── config.json ─────────────────────────────────────────────────────────────

/**
 * Remove a comma that is followed only by whitespace and a closing brace or
 * bracket, without touching anything inside a string literal.
 *
 * The naive regex would corrupt any password containing `,}`, and these files
 * hold hundreds of generated passwords.
 */
function stripTrailingCommas(text) {
  let out = '';
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (inString) {
      out += ch;
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') { inString = true; out += ch; continue; }
    if (ch === ',') {
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j])) j += 1;
      if (text[j] === '}' || text[j] === ']') continue;
    }
    out += ch;
  }
  return out;
}

/**
 * Parse a GOAD data/config.json the way GOAD actually parses it.
 *
 * ansible/data.yml loads it through `vars_files:`, which is Ansible's YAML
 * loader, which is PyYAML — and PyYAML accepts a trailing comma in a flow
 * mapping. ad/DRACARYS/data/config.json has one (in the acls block), so it is a
 * perfectly runnable lab that strict JSON.parse rejects. A checker that refused
 * it would be reporting a defect upstream does not have, and a pre-flight gate
 * that cries wolf is a pre-flight gate somebody switches off.
 *
 * Strict parse is tried first, so a file that IS valid JSON never goes near the
 * rewriter.
 */
function parseGoadConfigJson(text) {
  const src = String(text === null || text === undefined ? '' : text);
  try {
    return JSON.parse(src);
  } catch (strictErr) {
    try {
      return JSON.parse(stripTrailingCommas(src));
    } catch (err) {
      const e = new Error(
        `config.json is not parseable even after trailing-comma repair: ${strictErr.message}`);
      e.cause = strictErr;
      throw e;
    }
  }
}

// ── inventory ───────────────────────────────────────────────────────────────

/**
 * Split an inventory host line into tokens, honouring quotes.
 *
 * ad/DRACARYS/providers/proxmox/inventory carries
 * `ansible_ssh_common_args='-o StrictHostKeyChecking=no'` — a value with a space
 * AND an inner `=`. A plain whitespace split turns that into two bogus tokens
 * and a third bogus key.
 */
function splitInventoryLine(line) {
  const parts = [];
  let cur = '';
  let quote = null;
  for (const ch of line) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; continue; }
    if (ch === ' ' || ch === '\t') {
      if (cur !== '') { parts.push(cur); cur = ''; }
      continue;
    }
    cur += ch;
  }
  if (cur !== '') parts.push(cur);
  return parts;
}

/**
 * Parse an Ansible INI inventory.
 *
 * Only FULL-LINE comments are stripped. An inline `;` or `#` is left alone
 * because these files hold passwords and connection strings, and upstream never
 * writes a trailing comment on a host line.
 *
 * `[grp:vars]` becomes groupVars[grp]; `[grp:children]` is recorded separately
 * because its entries are group names, not hosts — folding them into groups[]
 * would invent hosts that do not exist.
 *
 * @returns {{groups: object, groupVars: object, children: object, hostVars: object, hostNames: string[]}}
 */
function parseInventory(text) {
  const out = { groups: {}, groupVars: {}, children: {}, hostVars: {}, hostNames: [] };
  let section = null;
  let kind = 'hosts';

  for (const raw of String(text === null || text === undefined ? '' : text).split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith(';') || line.startsWith('#')) continue;

    const header = line.match(/^\[([^\]]+)\]$/);
    if (header) {
      const parts = header[1].split(':');
      section = parts[0].trim();
      kind = parts.length > 1 ? parts[1].trim() : 'hosts';
      if (kind === 'hosts' && !out.groups[section]) out.groups[section] = [];
      if (kind === 'vars' && !out.groupVars[section]) out.groupVars[section] = {};
      if (kind === 'children' && !out.children[section]) out.children[section] = [];
      continue;
    }
    if (section === null) continue;

    if (kind === 'vars') {
      const eq = line.indexOf('=');
      if (eq > 0) out.groupVars[section][line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
      continue;
    }
    if (kind === 'children') {
      out.children[section].push(line);
      continue;
    }

    const tokens = splitInventoryLine(line);
    if (tokens.length === 0) continue;
    const host = tokens[0];
    out.groups[section].push(host);
    if (!out.hostNames.includes(host)) out.hostNames.push(host);
    if (!out.hostVars[host]) out.hostVars[host] = {};
    for (const tok of tokens.slice(1)) {
      const eq = tok.indexOf('=');
      if (eq > 0) out.hostVars[host][tok.slice(0, eq)] = tok.slice(eq + 1);
    }
  }
  return out;
}

/** Accept either raw text or an already-parsed inventory, so a caller that read
 *  the file once does not have to hand the text back for every check. */
function asInventory(v) {
  if (v && typeof v === 'object' && isPlainObject(v.groups)) return v;
  return parseInventory(v);
}

/**
 * Every host a group matches, following `[grp:children]` the way Ansible does.
 *
 * A group can be populated entirely through its children — Ansible expands them
 * before matching a play's `hosts:` — so counting only the direct members would
 * report a group that has hosts as empty, and a gate that cries wolf is a gate
 * somebody adds a --force flag to. `seen` breaks the cycle a hand-written
 * inventory can describe (a:children -> b, b:children -> a); Ansible rejects
 * that outright and this module's job is not to be the thing that hangs on it.
 */
function membersOf(inv, name, seen) {
  const visited = seen || new Set();
  if (visited.has(name)) return [];
  visited.add(name);
  const groups = obj(inv.groups);
  const children = obj(inv.children);
  const out = Array.isArray(groups[name]) ? groups[name].slice() : [];
  for (const child of (Array.isArray(children[name]) ? children[name] : [])) {
    for (const host of membersOf(inv, child, visited)) {
      if (!out.includes(host)) out.push(host);
    }
  }
  return out;
}

// ── playbooks.yml ───────────────────────────────────────────────────────────

/**
 * Read the chain a lab actually runs out of playbooks.yml.
 *
 * PLAYBOOK GATING, and why it is not optional: SCCM and NHA comment out
 * `# - laps.yml` and `# - ad-child_domain.yml`; DRACARYS has no servers.yml,
 * adcs.yml or ad-trusts.yml at all. A checker that demanded mssql.sa_password
 * from every [mssql] member regardless would reject labs where the play that
 * reads it never runs.
 *
 * A commented-out entry is dropped by the leading-`#` rule, which is the whole
 * point: in this file `# - laps.yml` is a semantic statement, not a note.
 *
 * @returns {string[]|null} the lab's own list, else `default:`, else null.
 */
function chainForLab(playbooksText, labName) {
  const byLab = {};
  let current = null;
  const text = String(playbooksText === null || playbooksText === undefined ? '' : playbooksText);
  for (const raw of text.split(/\r?\n/)) {
    const trimmed = raw.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;
    const key = raw.match(/^([A-Za-z0-9._-]+)\s*:\s*$/);
    if (key) { current = key[1]; byLab[current] = []; continue; }
    const item = raw.match(/^\s+-\s+(\S+)\s*$/);
    if (item && current !== null) byLab[current].push(item[1]);
  }
  if (labName && has(byLab, labName)) return byLab[labName];
  if (has(byLab, 'default')) return byLab.default;
  return null;
}

/** null/undefined means "the caller does not know" — assume the default chain
 *  rather than skipping every gated check, which would be a silent free pass. */
function chainSet(playbooks) {
  const list = Array.isArray(playbooks) && playbooks.length > 0 ? playbooks : DEFAULT_CHAIN;
  return new Set(list.map((p) => String(p).trim().replace(/^.*[\\/]/, '')));
}

// ── the core ────────────────────────────────────────────────────────────────

/**
 * Statically resolve every no-default dereference the chain will perform.
 *
 * @param {object} input
 * @param {string} [input.labName]                 ad/<name>, used in messages
 * @param {object|string} input.config             data/config.json, parsed or raw
 * @param {object|string} input.inventory          data/inventory, parsed or raw
 * @param {object|string} input.providerInventory  providers/<p>/inventory
 * @param {string[]} [input.playbooks]             the chain; defaults to DEFAULT_CHAIN
 * @returns {{ok: boolean, findings: object[], errors: object[], warnings: object[]}}
 */
function preflightGoadLab(input) {
  const opts = obj(input);
  const labName = str(opts.labName) || 'lab';
  const findings = [];

  const add = (code, severity, id, message) => {
    // Same guard, same reason, as engagement-plan.js emit(): an unregistered
    // code is a finding no caller can route, and dropping it is the lesser evil.
    if (!CODE_SET.has(code)) return;
    findings.push({ id: id === null || id === undefined ? null : String(id), code, severity, message });
  };
  const err = (code, id, message) => add(code, SEVERITY.ERROR, id, message);
  const warn = (code, id, message) => add(code, SEVERITY.WARNING, id, message);
  const done = () => {
    const errors = findings.filter((f) => f.severity === SEVERITY.ERROR);
    const warnings = findings.filter((f) => f.severity === SEVERITY.WARNING);
    return { ok: errors.length === 0, findings, errors, warnings };
  };

  // ── 0. the lab dict ───────────────────────────────────────────────────────
  let parsed = opts.config;
  if (typeof parsed === 'string') {
    try {
      parsed = parseGoadConfigJson(parsed);
    } catch (e) {
      err(CODE.CONFIG_UNPARSEABLE, `${labName}/data/config.json`,
        `${labName}: data/config.json cannot be parsed (${e.message}). ansible/data.yml loads it `
        + 'through vars_files, so this kills the very first invocation of the chain. Fix the JSON.');
      return done();
    }
  }
  // Accept the file shape {"lab": {...}} or the unwrapped lab dict, because a
  // caller that generated the lab in memory has no reason to add the wrapper.
  const lab = isPlainObject(parsed) && isPlainObject(parsed.lab) ? parsed.lab : parsed;
  if (!isPlainObject(lab) || !isPlainObject(lab.hosts) || !isPlainObject(lab.domains)) {
    err(CODE.CONFIG_SHAPE, `${labName}/data/config.json`,
      `${labName}: config.json must contain lab.hosts and lab.domains objects. Every play in the `
      + 'chain indexes lab.hosts[dict_key] and lab.domains[domain]; neither is optional.');
    return done();
  }

  const hosts = lab.hosts;
  const domains = lab.domains;
  const hostKeys = Object.keys(hosts);
  const domainNames = Object.keys(domains);
  const declared = domainNames.length > 0 ? domainNames.join(', ') : 'none';

  const inv = asInventory(opts.inventory);
  const prov = asInventory(opts.providerInventory);
  const runs = chainSet(opts.playbooks);
  const group = (name) => (Array.isArray(inv.groups[name]) ? inv.groups[name] : []);
  const invHosts = new Set(inv.hostNames);

  // ── 1. inventory vars with no default anywhere ────────────────────────────
  // Both inventories are consulted: goad passes data/inventory AND
  // providers/<p>/inventory to ansible-playbook, and ad/*/providers/aws and
  // /azure legitimately override admin_user to `goadmin` there.
  const globals = Object.assign({}, inv.groupVars.all || {}, prov.groupVars.all || {});
  for (const name of REQUIRED_INVENTORY_VARS) {
    if (filled(globals[name])) continue;
    err(CODE.INVENTORY_VAR_MISSING, name,
      `${labName}: neither data/inventory nor the provider inventory defines ${name}. `
      + `${INVENTORY_VAR_SITES[name]}, so the play raises AnsibleUndefinedVariable at play start `
      + `and every host in it fails at once. Add "${name}=${INVENTORY_VAR_EXAMPLE[name]}" under `
      + '[all:vars] in data/inventory.');
  }

  // ── 2. mandatory groups ───────────────────────────────────────────────────
  // ABSENT and PRESENT-BUT-EMPTY are deliberately one finding. To Ansible, `[dc]`
  // with its hosts deleted and no `[dc]` at all are the same thing: `hosts: dc`
  // matches nothing, the play is SKIPPED rather than failed, and the run stays
  // green having promoted no domain controller. That is the expensive half of
  // the pair — a group name that vanished is at least loud in a diff, a group
  // that quietly lost its members is one blank line and builds a lab with a
  // hole in it.
  //
  // Membership through `[dc:children]` counts, because Ansible expands children
  // before it matches. This is the ONLY check that expands them: §4 asks the
  // opposite question — "is every host this group NAMES a key of lab.hosts" —
  // and expanding there would drag in the appliance hosts a parent group
  // inherits (ad/SCCM's `elk`, ad/DRACARYS's `lx01`), which lab.hosts
  // deliberately never describes.
  for (const name of MANDATORY_GROUPS) {
    if (membersOf(inv, name).length > 0) continue;
    err(CODE.GROUP_EMPTY, name,
      `${labName}: inventory group [${name}] is empty. The inventory marks it mandatory and it is `
      + 'the `hosts:` of at least one play in the chain, so an empty one means that play matches '
      + `nothing and the lab is never built. List the relevant hosts under [${name}].`);
  }

  // ── 3. host keys ──────────────────────────────────────────────────────────
  // Checked for EVERY host, not just group members, because
  // roles/move_to_ou/tasks/main.yml:30 iterates `with_dict: {{lab.hosts}}` and
  // reads item.value.type / .hostname / .domain with no default. One host
  // missing `type` therefore kills ad-data.yml's "Move to OU" play even if that
  // host belongs to no group the chain targets.
  for (const key of hostKeys) {
    const host = obj(hosts[key]);
    for (const field of REQUIRED_HOST_KEYS) {
      if (filled(host[field])) continue;
      err(CODE.HOST_KEY_MISSING, key,
        `${labName}: lab.hosts.${key} has no ${field}. Plays dereference `
        + `lab.hosts[dict_key].${field} with no default (ad-servers.yml:17-18, ad-data.yml:15-30, `
        + `roles/move_to_ou/tasks/main.yml:30). Set ${field} on ${key} in config.json.`);
    }
    if (!invHosts.has(key)) {
      err(CODE.HOST_NOT_IN_INVENTORY, key,
        `${labName}: lab.hosts.${key} appears in no inventory group. A config host Ansible never `
        + 'targets is silently never built, and any play that resolves hostvars for it fails. Add '
        + `${key} to [domain] (or [linux_domain]) in data/inventory, or drop it from config.json.`);
    }
  }

  // ── 4. groups reference real config hosts ─────────────────────────────────
  for (const name of HOST_GROUPS) {
    for (const host of group(name)) {
      if (has(hosts, host)) continue;
      err(CODE.GROUP_HOST_UNKNOWN, host,
        `${labName}: [${name}] lists ${host}, which is not a key of lab.hosts. Every play driven `
        + 'by that group opens with lab.hosts[dict_key].domain, so it dies on the first host it '
        + `reaches. Add ${host} to config.json or remove it from [${name}].`);
    }
  }

  // ── 5. domains ────────────────────────────────────────────────────────────
  // `.dc` is not just a string: ad-enroll_linux.yml:15, dhcp.yml:15 and
  // ad-child_domain.yml:23-25 feed it back into lab.hosts[...] AND into
  // hostvars[...].ansible_host, so it has to name a host that both config.json
  // and Ansible know about — the two halves fail differently and neither is
  // caught by the other.
  const dcResolvable = (domainName) => {
    const dc = str(obj(domains[domainName]).dc);
    return dc !== '' && has(hosts, dc) && invHosts.has(dc);
  };

  const referenced = new Set();
  for (const key of hostKeys) {
    const d = str(obj(hosts[key]).domain);
    if (d !== '') referenced.add(d);
  }
  for (const name of referenced) {
    if (!has(domains, name)) {
      err(CODE.DOMAIN_UNDECLARED, name,
        `${labName}: a host claims domain "${name}" but lab.domains has no such key (declared: `
        + `${declared}). Every play resolves lab.domains[domain] immediately after `
        + `lab.hosts[dict_key].domain. Declare "${name}" in config.json, or fix the host's domain.`);
      continue;
    }
    const dom = obj(domains[name]);
    for (const field of REQUIRED_DOMAIN_KEYS) {
      if (filled(dom[field])) continue;
      err(CODE.DOMAIN_KEY_MISSING, name,
        `${labName}: lab.domains["${name}"] has no ${field}. It is dereferenced with no default `
        + `(ad-parent_domain.yml:18-19, ad-data.yml:20-22, adcs.yml:16-17). Set ${field} on `
        + `"${name}" in config.json.`);
    }
    const dc = str(dom.dc);
    if (dc !== '' && !dcResolvable(name)) {
      err(CODE.DOMAIN_DC_UNRESOLVED, name,
        `${labName}: lab.domains["${name}"].dc = "${dc}" is not both a lab.hosts key and an `
        + 'inventory host. It is used as lab.hosts[<dc>].hostname and hostvars[<dc>].ansible_host, '
        + 'so an unresolvable value fails the play rather than skipping it. Point .dc at a host '
        + 'listed in both config.json and data/inventory.');
    }
  }

  // ── 6. the three-way join ─────────────────────────────────────────────────
  // dict_key is the hinge of the whole scheme: every play says
  // lab.hosts[dict_key], and dict_key is set per host in the PROVIDER inventory
  // while the config key lives in config.json and the Ansible host name lives in
  // data/inventory. Nothing upstream cross-checks the three, and a mismatch does
  // not error — it silently configures one machine with another's identity.
  const seenAnsibleHost = new Map();
  for (const host of prov.hostNames) {
    const vars = obj(prov.hostVars[host]);
    const dictKey = str(vars.dict_key);
    if (dictKey === '') {
      err(CODE.PROVIDER_DICT_KEY_MISMATCH, host,
        `${labName}: provider inventory host ${host} sets no dict_key. Every play indexes `
        + `lab.hosts[dict_key]; without it the host resolves nothing. Add "dict_key=${host}".`);
    } else if (dictKey !== host) {
      err(CODE.PROVIDER_DICT_KEY_MISMATCH, host,
        `${labName}: provider inventory host ${host} sets dict_key=${dictKey}. The two must match `
        + `or ${host} is built from ${dictKey}'s config — wrong hostname, wrong domain, wrong local `
        + `admin password, and no error anywhere. Set "dict_key=${host}".`);
    }
    if (dictKey !== '' && !has(hosts, dictKey)) {
      err(CODE.PROVIDER_DICT_KEY_UNKNOWN, host,
        `${labName}: provider inventory host ${host} has dict_key=${dictKey}, which is not a key of `
        + `lab.hosts. Add "${dictKey}" to config.json, or correct the dict_key.`);
    }

    const ansibleHost = str(vars.ansible_host);
    if (ansibleHost === '') {
      err(CODE.PROVIDER_ANSIBLE_HOST_MISSING, host,
        `${labName}: provider inventory host ${host} has no ansible_host. Ansible has no address to `
        + 'connect to, and ad-trusts.yml:34 / ad-child_domain.yml:25 read '
        + `hostvars[<dc>].ansible_host to aim DNS at it. Add "ansible_host=..." for ${host}.`);
    } else {
      // Upstream's own header comment: "ansible_host *MUST* be an IPv4 address
      // or setting things like DNS servers will break." Provider files carry the
      // {{ip_range}} placeholder that goad substitutes at run time, so a literal
      // is validated strictly and a templated one is only checked for shape.
      const templated = ansibleHost.includes('{{');
      const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ansibleHost);
      const octetsOk = !!ipv4 && ipv4.slice(1).every((o) => Number(o) <= 255);
      if (!templated && !octetsOk) {
        err(CODE.PROVIDER_ANSIBLE_HOST_MALFORMED, host,
          `${labName}: provider inventory host ${host} has ansible_host="${ansibleHost}", which is `
          + 'not an IPv4 address. A hostname here silently breaks DNS configuration on the guest — '
          + 'the inventory header says so itself. Use a literal IPv4 address.');
      }
      const prior = seenAnsibleHost.get(ansibleHost);
      if (prior) {
        err(CODE.PROVIDER_ANSIBLE_HOST_DUPLICATE, host,
          `${labName}: ${host} and ${prior} both claim ansible_host="${ansibleHost}". Two guests on `
          + 'one address means one of them is unreachable and the DNS records point at the wrong '
          + `machine. Give ${host} its own address.`);
      } else {
        seenAnsibleHost.set(ansibleHost, host);
      }
    }
  }
  const provKeys = new Set(prov.hostNames);
  for (const key of hostKeys) {
    if (provKeys.has(key)) continue;
    err(CODE.PROVIDER_HOST_MISSING, key,
      `${labName}: lab.hosts.${key} has no entry in the provider inventory, so it has neither an `
      + 'ansible_host nor a dict_key. It is never reached, and any hostvars lookup against it fails '
      + `the play that makes it. Add a "${key} ansible_host=<ip> dict_key=${key}" line.`);
  }

  // ── 7. trusts (ad-trusts.yml) ─────────────────────────────────────────────
  if (runs.has(PLAYBOOK.TRUSTS)) {
    for (const host of group('trust')) {
      const d = str(obj(hosts[host]).domain);
      if (d === '' || !isPlainObject(domains[d])) continue; // already reported in §4/§5
      const remote = str(domains[d].trust);
      if (remote === '') {
        err(CODE.TRUST_MISSING, host,
          `${labName}: ${host} is in [trust] but lab.domains["${d}"].trust is missing or empty. `
          + 'ad-trusts.yml:16 sets remote_forest from it with no default and line 18 immediately '
          + 'does lab.domains[remote_forest].dc, so the play dies before its first task. Set .trust '
          + `on "${d}", or remove ${host} from [trust].`);
        continue;
      }
      if (!isPlainObject(domains[remote])) {
        err(CODE.TRUST_UNDECLARED, host,
          `${labName}: ${host} trusts "${remote}", which is not a declared domain (declared: `
          + `${declared}). ad-trusts.yml:18 and :32-33 read lab.domains[remote_forest].dc and `
          + `.domain_password with no default. Declare "${remote}" in config.json.`);
        continue;
      }
      if (!filled(domains[remote].domain_password)) {
        err(CODE.DOMAIN_KEY_MISSING, remote,
          `${labName}: trust target "${remote}" has no domain_password. ad-trusts.yml:32 uses it as `
          + 'remote_admin_password with no default. Set it in config.json.');
      }
      if (!dcResolvable(remote)) {
        err(CODE.DOMAIN_DC_UNRESOLVED, remote,
          `${labName}: trust target "${remote}" has no .dc that is both a lab.hosts key and an `
          + 'inventory host. ad-trusts.yml:33-34 resolves remote_dc and then '
          + `hostvars[remote_dc].ansible_host to build the conditional forwarder. Point `
          + `lab.domains["${remote}"].dc at a real host.`);
      }
    }
  }

  // ── 8. ADCS custom templates (adcs.yml) ───────────────────────────────────
  if (runs.has(PLAYBOOK.ADCS)) {
    for (const host of group('adcs_customtemplates')) {
      const d = str(obj(hosts[host]).domain);
      if (d === '' || !isPlainObject(domains[d])) continue;
      if (filled(domains[d].ca_server)) continue;
      err(CODE.CA_SERVER_MISSING, host,
        `${labName}: ${host} is in [adcs_customtemplates] but lab.domains["${d}"] has no ca_server. `
        + 'adcs.yml:29 sets ca_host from it with no default — and the sibling ca_web_enrollment one '
        + 'play above IS defaulted, which is what makes this omission so easy to miss. Set '
        + `ca_server on "${d}" to the CA host's short name.`);
    }
  }

  // ── 9. MSSQL (servers.yml) ────────────────────────────────────────────────
  if (runs.has(PLAYBOOK.SERVERS)) {
    for (const host of group('mssql')) {
      const mssql = obj(obj(hosts[host]).mssql);
      if (filled(mssql.sa_password)) continue;
      err(CODE.MSSQL_SA_PASSWORD_MISSING, host,
        `${labName}: ${host} is in [mssql] but lab.hosts.${host}.mssql.sa_password is missing. `
        + 'servers.yml:31 is the ONLY line in that play without a `| default(...)` — svcaccount, '
        + 'sysadmins, executeaslogin, executeasuser and linked_servers all have one — so this '
        + `single key decides whether the MSSQL play starts at all. Set mssql.sa_password on ${host}.`);
    }
  }

  // ── 10. child domains (ad-child_domain.yml) ───────────────────────────────
  if (runs.has(PLAYBOOK.CHILD_DOMAIN)) {
    for (const host of group('child_dc')) {
      const d = str(obj(hosts[host]).domain);
      if (d === '') continue;
      // ad-child_domain.yml:20 — parent_domain: "{{'.'.join(domain.split('.')[1:])}}"
      // There is no validation and no default: the parent is DERIVED by dropping
      // the first label of the child FQDN, so "north.sevenkingdoms.local" only
      // works because "sevenkingdoms.local" happens to be declared as well.
      const parent = d.split('.').slice(1).join('.');
      if (parent === '' || !isPlainObject(domains[parent])) {
        err(CODE.CHILD_PARENT_UNDECLARED, host,
          `${labName}: ${host} is in [child_dc] with domain "${d}", so ad-child_domain.yml:20 `
          + `derives parent_domain "${parent || '(empty)'}" by dropping the first label — and that `
          + `is not a declared domain (declared: ${declared}). Lines 22-25 then read `
          + 'lab.domains[parent_domain].domain_password and .dc with no default. Declare '
          + `"${parent || 'the parent domain'}" in config.json, or give ${host} a domain whose `
          + 'parent is declared.');
        continue;
      }
      if (!filled(domains[parent].domain_password)) {
        err(CODE.DOMAIN_KEY_MISSING, parent,
          `${labName}: parent domain "${parent}" of child DC ${host} has no domain_password. `
          + 'ad-child_domain.yml:22 uses it to join the parent forest, with no default. Set it in '
          + 'config.json.');
      }
      if (!dcResolvable(parent)) {
        err(CODE.DOMAIN_DC_UNRESOLVED, parent,
          `${labName}: parent domain "${parent}" of child DC ${host} has no .dc that is both a `
          + 'lab.hosts key and an inventory host. ad-child_domain.yml:23-25 resolve '
          + 'lab.hosts[<parent dc>].hostname and hostvars[<parent dc>].ansible_host. Point '
          + `lab.domains["${parent}"].dc at a host declared in config.json and listed in `
          + 'data/inventory.');
      }
    }
  }

  // ── 11. LAPS (laps.yml) ───────────────────────────────────────────────────
  // WARNING, not error, and the distinction is the whole point. laps.yml guards
  // every read as `lab.domains[domain].laps_path if ... is defined else false`,
  // and roles/laps/dc/tasks/main.yml then gates BOTH of its imports on
  // `when: laps_path != false`. The play does not fail — it reports green having
  // installed nothing. An operator reads "ok" and hands out a lab with no LAPS,
  // which is the failure mode this repo treats as worse than a crash: a lane
  // that fails loudly gets retried, a lane that lies gets graded.
  if (runs.has(PLAYBOOK.LAPS)) {
    const seen = new Set();
    for (const name of ['laps_dc', 'laps_server', 'laps_workstation']) {
      for (const host of group(name)) {
        const cfg = obj(hosts[host]);
        const d = str(cfg.domain);
        if (d === '' || !isPlainObject(domains[d])) continue;
        const lapsPath = domains[d].laps_path;
        // `false` is not a value here, it is laps.yml's sentinel: line 14
        // substitutes `false` when laps_path is undefined, and
        // roles/laps/dc/tasks/main.yml:3,7 gate both imports on
        // `laps_path != false`. A config that writes the sentinel out literally
        // therefore lands in precisely the silent no-op an omitted key produces.
        // filled() is right that a boolean is a present value; this one field is
        // the exception, and it is laps.yml that makes it one.
        if (lapsPath !== false && filled(lapsPath)) continue;
        if (seen.has(host)) continue;
        seen.add(host);
        const why = lapsPath === false
          ? 'sets laps_path to false, the value laps.yml itself substitutes for "not configured"'
          : 'has no laps_path';
        warn(CODE.LAPS_PATH_MISSING, host,
          `${labName}: ${host} is in [${name}] but lab.domains["${d}"] ${why}. laps.yml `
          + 'defaults it to false and roles/laps/dc gates its install on "laps_path != false", so '
          + 'the play succeeds while installing no LAPS at all — a silent no-op, not a failure. '
          + `Set laps_path on "${d}" (e.g. "OU=Laps,${str(cfg.path) || 'DC=example,DC=lab'}"), or `
          + `remove ${host} from [${name}].`);
      }
    }
  }

  return done();
}

/**
 * Asserting boundary. Throws on any ERROR finding; warnings never throw.
 *
 * 422 rather than 400: the request itself is well-formed, the lab it describes
 * is not. Same convention as the 409 the lane mutex raises.
 */
function assertGoadLabPreflight(input) {
  const result = preflightGoadLab(input);
  if (result.ok) return result;
  const e = new Error(
    `GOAD pre-flight failed with ${result.errors.length} error(s); no VM was created.\n`
    + result.errors.map((f) => `  [${f.code}] ${f.id === null ? '' : `${f.id}: `}${f.message}`).join('\n'));
  e.status = 422;
  e.findings = result.findings;
  throw e;
}

module.exports = {
  SEVERITY,
  CODE,
  MANDATORY_GROUPS,
  REQUIRED_INVENTORY_VARS,
  REQUIRED_HOST_KEYS,
  REQUIRED_DOMAIN_KEYS,
  HOST_GROUPS,
  DEFAULT_CHAIN,
  parseGoadConfigJson,
  parseInventory,
  chainForLab,
  preflightGoadLab,
  assertGoadLabPreflight,
};
