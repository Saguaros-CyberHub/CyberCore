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
 * Returns null when nothing survives, and the caller then omits the key entirely
 * rather than writing `nics: []`. That distinction matters — validateTopology
 * flags an empty array as `malformed-nics`, while an absent key correctly reads
 * as "not authored, fall back to the derivation".
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
 * One entry of `spec.vms`.
 *
 * The first nine keys reproduce the pre-refactor literal exactly, including its
 * quirks: `parseInt(template_vmid)` with no guard (an absent id becomes NaN and
 * JSON-serialises to null — callers are expected to have validated first), and
 * `parseInt(vm_offset) || 600000`, which treats an explicit 0 as absent.
 * `services`/`default_scripts` are passed through by reference exactly as before;
 * the route JSON-stringifies the spec immediately, so there is nothing to alias.
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
