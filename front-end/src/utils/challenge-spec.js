/**
 * challenge-spec.js — building the pieces of `crucible_challenge.spec` that
 * describe a challenge's network, on the create path.
 *
 * ── Why this exists ─────────────────────────────────────────────────────────
 * POST /create-lab built each spec VM from a fixed object literal inline in the
 * route. That literal whitelisted nine keys, so `nics` (which segments a machine
 * attaches to) and `layout` (where it sits on the canvas) were silently dropped,
 * and `spec.network` was never written at all. A topology authored on the canvas
 * therefore deployed with DERIVED placement and lost every position — and nothing
 * surfaced until deploy time. PUT /lab-templates/:id merges whole objects, which
 * is why editing an existing challenge preserved them and creating one did not.
 *
 * The same silent drop was still happening to seven MORE keys the Designer
 * canvas authors — console_role, console_protocol, console_port, ipOctet,
 * os_family, post_clone_scripts and dns_aliases — so the student-console picker
 * that exists in two UIs never survived challenge CREATION and only worked if
 * the challenge was subsequently edited. See buildSpecVm for the list and what
 * each one does.
 *
 * ── The contract ────────────────────────────────────────────────────────────
 * Everything here is omit-when-absent. A caller that sends no nics/layout/network
 * gets byte-identical output to the pre-refactor literal, which is what keeps the
 * flat Create Challenge form and the CLE course provisioner behaving exactly as
 * before. test/challenge-spec-create.test.js transcribes that literal and asserts
 * the equivalence case by case; if one fails, this file has changed behaviour it
 * was not allowed to change.
 *
 * Pure — no DB, no Proxmox, no I/O. Lives here rather than in the route per the
 * README's "keep route handlers thin" convention, and so it is unit-testable
 * without booting Express.
 */

const { resolveSegments } = require('./lane-networking');

/**
 * Normalise an authored NIC list.
 *
 * Order is load-bearing: `nics[]` order IS net0, net1, … in the Proxmox config
 * that resolveVmNics emits, and it is the order the canvas draws edges in.
 *
 * ── THE EMPTY-NICS CONTRACT (read this with resolveVmSegments) ───────────────
 * An EMPTY `nics` array and an ABSENT `nics` key mean the SAME THING: "nothing
 * authored — derive the placement". Returning null here (so the caller omits the
 * key) is what keeps every legacy spec byte-identical, and it is deliberately
 * NOT changed.
 *
 * The consequence is the trap. A canvas detach produces `segments: []`, which
 * syncFromCanvas writes as `nics: []`, which lands here as null, which omits the
 * key, which makes resolveVmSegments (lane-networking.js) fall through to the
 * derivation — so the machine deploys ATTACHED while the canvas shows it
 * floating. Each of the four steps is locally reasonable; together they are a
 * silent lie.
 *
 * The decision, and it is a platform decision rather than a serialisation one:
 * a machine must always have at least one NIC. A VM with no network here is
 * useless — no DHCP lease, no Guacamole target, no vuln scripts. So an
 * author-intended detach is REFUSED at the editor (it never becomes `[]` in the
 * first place) and, for a spec that arrives that way from an import or an older
 * editor, flagged by topology-validate's `no-nic` error. It is never ENCODED as
 * `[]`, because `[]` already means "derive" and must not be made to mean two
 * things. If a genuinely isolated host is ever wanted it needs its own flag
 * (`isolated: true`), not an overloaded empty array.
 */
function normaliseNics(nics) {
  if (!Array.isArray(nics)) return null;
  // Rebuilt entry by entry, so client bookkeeping (__topoId, ip, mac, whatever a
  // future editor adds) cannot ride along into the database.
  const out = nics
    .filter(n => n && n.segment !== undefined && n.segment !== null && n.segment !== '')
    .map(n => ({ segment: String(n.segment) }));
  return out.length ? out : null;
}

/**
 * Normalise a canvas position. Cosmetic data, so it is accepted from the client
 * as-is — but only when both coordinates are real numbers, since a NaN would
 * serialise to null and leave the renderer with a half-defined position.
 */
function normaliseLayout(layout) {
  if (!layout || typeof layout !== 'object') return null;
  const x = Number(layout.x);
  const y = Number(layout.y);
  if (!Number.isFinite(x) || !Number.isFinite(y)) return null;
  return { x: Math.round(x), y: Math.round(y) };
}

/**
 * `console_role` — which machine the student actually opens.
 *
 * Exactly two values are meaningful, and both are load-bearing at deploy time:
 * resolveConsolePlan throws when two machines claim 'primary', and it puts
 * 'primary'/'secondary' machines (and nothing else) in the console list. So a
 * free-typed third value would produce a spec that silently designates nothing —
 * anything unrecognised is omitted rather than stored.
 */
function normaliseConsoleRole(role) {
  const v = String(role == null ? '' : role).trim().toLowerCase();
  return (v === 'primary' || v === 'secondary') ? v : null;
}

/**
 * A whole number inside a closed range, or null.
 *
 * `Number`, not `parseInt`: parseInt('80abc') is 80 and parseInt('3389 ') is
 * 3389, so a typo becomes a plausible-looking port instead of being rejected.
 *
 * And a RANGE, not a bare isFinite: Number('') is 0, which is not a listenable
 * port and is not a usable host octet either — the deployer's own check
 * (resolveSpecAddressing PASS 1) makes the same point about 0, negatives, 300
 * and 80.5 all reaching macForOctet(octet & 0xFF) and producing a reservation
 * for an address nobody asked for.
 */
function normaliseIntInRange(value, min, max) {
  // typeof first, because Number() is happy to invent a number from things that
  // are not one: Number(true) is 1, Number([42]) is 42, Number(new Date()) is a
  // timestamp. Only a number or the numeric string an HTML form posts counts.
  if (typeof value !== 'number' && typeof value !== 'string') return null;
  if (value === '') return null;
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) return null;
  return n;
}

/**
 * A non-empty trimmed string, or null. Used for the two free-form passthrough
 * keys (`console_protocol`, `os_family`).
 *
 * NO ENUM for `console_protocol`, deliberately. lane-deployer.resolveConsole
 * owns the protocol allowlist (CONSOLE_PROTOCOLS) and already falls back to
 * 'rdp' for anything it does not know; restating that set here would be a second
 * source of truth that silently drops a protocol the deployer supports the day
 * one is added. It would also make the create path disagree with
 * PUT /lab-templates/:id, which merges the whole object and stores whatever the
 * client sent — and "create and edit store different things" is the exact class
 * of bug this module exists to close.
 */
function normaliseText(value) {
  if (typeof value !== 'string') return null;
  const v = value.trim();
  return v ? v : null;
}

/**
 * `post_clone_scripts` — the vuln-script slugs CiAB's lane-provision turns into
 * the deployer's `vulnScripts` shape (lane-provision.js:162).
 *
 * Returns null for an empty result so the key is omitted: downstream reads it as
 * `vm.post_clone_scripts || []`, so an empty array and an absent key are already
 * indistinguishable, and omitting keeps a spec that declares none byte-identical
 * to one written before this key existed.
 */
function normalisePostCloneScripts(scripts) {
  if (!Array.isArray(scripts)) return null;
  const out = [];
  for (const entry of scripts) {
    if (typeof entry !== 'string') continue;
    const slug = entry.trim();
    if (slug) out.push(slug);
  }
  return out.length ? out : null;
}

// A DNS label: letters, digits and inner hyphens, max 63 octets.
//
// ── Why this literal is duplicated, and why that is the lesser evil ──────────
// The OWNER of this rule is lane-deployer.js (DNS_LABEL_RE, near LANE_DNS_DOMAIN),
// and challenge-lane-deployer routes spec aliases through its resolveDnsAliases
// (challenge-lane-deployer.js:507 wraps each vmSpec as `metadata.dns_aliases`).
// Importing it here would be the obvious move — but lane-deployer pulls
// cybercore-db, site-config, guacamole and tailscale at module load, and this
// file is PURE by contract (no DB, no Proxmox, no I/O) precisely so a route can
// build a spec without booting any of that. So the pattern is the same one
// `ipOctet` already uses: mirror the rule, and pin the agreement with a test
// that runs BOTH implementations over the same input
// (test/challenge-spec-whitelist.test.js). If the two ever drift, that test
// fails rather than a lane coming up with half its DNS.
const DNS_LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;

/**
 * `dns_aliases` — stable in-lane DNS names for this machine.
 *
 * ── The silent failure this closes ──────────────────────────────────────────
 * A lane reservation's hostname is per-lane, so it is useless as a link target:
 * a baked config on one machine cannot know the other machine's lane name. An
 * alias is the SAME in every lane while resolving to that lane's own box, which
 * is what lets one baked elastic-agent.yml point at `elk.cybercore.lan`
 * everywhere. The plan authors ELK as an ordinary spec VM on the Designer canvas
 * (`{ name:'elk', role:'siem', ipOctet:24, dns_aliases:['elk'] }`); dropped here,
 * that machine still got its pinned address and its DHCP reservation but NO
 * host-record — so the sensor's agent resolved nothing while reporting perfectly
 * healthy and shipping zero events. It survived only through
 * PUT /lab-templates/:id, whose whole-object merge preserves unknown keys.
 *
 * ── Why invalid labels are DROPPED, not passed through ──────────────────────
 * These become `host-record=` lines in a dnsmasq config file, and ONE malformed
 * line stops dnsmasq from starting — which takes DHCP down for the whole lane,
 * not just this machine. resolveDnsAliases drops them (with a warning) for that
 * reason, so this must agree: a spec that stores an alias the deployer will
 * refuse is a spec whose canvas is lying about what the lane will answer to.
 *
 * Normalise-then-validate, in the deployer's exact order: `String(entry)`, trim,
 * lowercase, then test. The lowercase is load-bearing rather than cosmetic —
 * 'ELK' must be STORED as 'elk', because that is the string the deployer would
 * have published, and a spec holding 'ELK' would compare unequal to the lane's
 * real record. The String() coercion is inherited deliberately too: it means a
 * numeric alias (42) survives in both paths rather than one path quietly
 * disagreeing with the other about what is legal.
 *
 * De-duplicated because the deployer de-duplicates; note that DUPLICATES ACROSS
 * MACHINES are a different rule that this file cannot see and must not attempt —
 * challenge-lane-deployer.js:493 throws on an alias claimed by two machines on
 * one lane, which is correct there and would be a create-time rejection of a
 * whole challenge here.
 *
 * Returns null for an empty result so the key is omitted entirely, the same
 * omit-when-absent contract every other additive key follows.
 */
function normaliseDnsAliases(aliases) {
  if (!Array.isArray(aliases)) return null;
  const out = [];
  for (const entry of aliases) {
    const alias = String(entry == null ? '' : entry).trim().toLowerCase();
    if (!DNS_LABEL_RE.test(alias)) continue;   // omitted, never coerced
    if (!out.includes(alias)) out.push(alias);
  }
  return out.length ? out : null;
}

/**
 * One entry of `spec.vms`.
 *
 * The first nine keys reproduce the pre-refactor literal exactly, including its
 * quirks: `parseInt(template_vmid)` with no guard (an absent id becomes NaN and
 * JSON-serialises to null — callers are expected to have validated first), and
 * `parseInt(vm_offset) || 600000`, which treats an explicit 0 as absent.
 * `services`/`default_scripts` are passed through by reference exactly as before;
 * the route JSON-stringifies the spec immediately, so there is nothing to alias.
 *
 * ── Why the whitelist grew ──────────────────────────────────────────────────
 * It is still an enumerated whitelist, and the entries are still rebuilt one by
 * one so client bookkeeping (`__topoId`, `ip`, `mac`, whatever a future editor
 * adds) cannot ride along into the database. But seven keys the Designer canvas
 * genuinely authors were being DROPPED here and preserved by
 * PUT /lab-templates/:id, which merges the whole object:
 *
 *   console_role        the student-console picker (topology-editor.js:335)
 *   console_protocol    ditto
 *   console_port        ditto
 *   ipOctet             the author's contract with the generated paper —
 *                       resolveSpecAddressing PASS 1 honours it outright
 *   os_family           picks the NIC model (resolveSpecNicModel); a Windows
 *                       guest on virtio has no driver and never DHCPs
 *   post_clone_scripts  the per-machine vuln scripts
 *   dns_aliases         the stable in-lane names a BAKED config points at
 *                       (`elk.cybercore.lan`); without the host-record the agent
 *                       resolves nothing and still reports healthy
 *
 * So an author could set a student console on the canvas, POST it, and have
 * create-lab throw it away — the challenge deployed with no designated console
 * and nothing said so. Every value is validated on the way in, and anything
 * invalid is OMITTED rather than coerced: a coerced value is a silently wrong
 * lane, while an absent key falls back to a documented default.
 */
function buildSpecVm(vm, idx, challengeKey) {
  const out = {
    name: vm.name || `vm${idx + 1}`,
    role: vm.role || 'Server',
    os: vm.os || 'Unknown',
    template_vmid: parseInt(vm.template_vmid),
    type: vm.type || 'qemu',
    vm_offset: parseInt(vm.vm_offset) || 600000,
    services: vm.services || [],
    default_scripts: vm.default_scripts || [],
    hostname: `${vm.name || challengeKey}.local`,
  };

  const nics = normaliseNics(vm.nics);
  if (nics) out.nics = nics;

  const layout = normaliseLayout(vm.layout);
  if (layout) out.layout = layout;

  const consoleRole = normaliseConsoleRole(vm.console_role);
  if (consoleRole) out.console_role = consoleRole;

  const consoleProtocol = normaliseText(vm.console_protocol);
  if (consoleProtocol) out.console_protocol = consoleProtocol;

  // 1-65535: a guest port, so the full TCP range. 0 is not a listenable port and
  // a negative or fractional one reaches Guacamole as a connection that cannot
  // be opened.
  const consolePort = normaliseIntInRange(vm.console_port, 1, 65535);
  if (consolePort !== null) out.console_port = consolePort;

  // 2-254 mirrors resolveSpecAddressing PASS 1's range check exactly
  // (challenge-lane-deployer.js). .1 is the lane gateway and .255 is broadcast;
  // outside that range macForOctet(octet & 0xFF) happily builds a reservation
  // for an address that is not the one requested. The deployer THROWS on a bad
  // octet — this omits instead, because a create-time throw would reject the
  // whole challenge over a cosmetic field, and an omitted octet simply draws
  // from the .80-.99 band like every unpinned machine.
  const ipOctet = normaliseIntInRange(vm.ipOctet, 2, 254);
  if (ipOctet !== null) out.ipOctet = ipOctet;

  const osFamily = normaliseText(vm.os_family);
  if (osFamily) out.os_family = osFamily;

  const postCloneScripts = normalisePostCloneScripts(vm.post_clone_scripts);
  if (postCloneScripts) out.post_clone_scripts = postCloneScripts;

  const dnsAliases = normaliseDnsAliases(vm.dns_aliases);
  if (dnsAliases) out.dns_aliases = dnsAliases;

  return out;
}

/**
 * `spec.network` — the segment list plus canvas positions.
 *
 * The client's `segments` are DISCARDED and regenerated from the subnet scheme.
 * Segment ids are derived from `subnet_scheme`, never free-typed (see
 * migrations/030_spec_network_topology.sql): v1/v2 have one `lan`, v3 has `ext`
 * and `int`. Accepting a client-supplied id would let a spec claim a segment no
 * lane will ever have, and resolveVmNics then throws partway through building a
 * lane — a failure a long way from its cause. The `layout` map is cosmetic and is
 * accepted, entry by entry.
 *
 * Returns null when the caller sent nothing worth storing, so the route can omit
 * the key and leave a spec that was never opened on a canvas free of topology
 * keys — the same back-compat rule the editor follows for `nics`.
 */
function buildSpecNetwork(network, subnetScheme) {
  if (!network || typeof network !== 'object') return null;
  if (!Array.isArray(network.segments) || network.segments.length === 0) return null;

  const layout = {};
  const src = (network.layout && typeof network.layout === 'object') ? network.layout : {};
  for (const key of Object.keys(src)) {
    const pos = normaliseLayout(src[key]);
    if (pos) layout[key] = pos;
  }

  return {
    version: 1,
    segments: resolveSegments(subnetScheme),
    layout,
  };
}

module.exports = { buildSpecVm, buildSpecNetwork, normaliseNics, normaliseLayout };
