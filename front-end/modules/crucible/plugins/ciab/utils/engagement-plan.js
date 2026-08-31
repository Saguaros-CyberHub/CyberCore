/**
 * ============================================================================
 * engagement-plan.js — Track B, phase B0: the PURE ENGAGEMENT COMPILE
 * ----------------------------------------------------------------------------
 * Turn (engagement row, synthesized spec, client profile) into ONE plain object
 * that answers every question the Engagements tab, the brief, the scan
 * documents and the deploy path ask about a piece of work:
 *
 *   who is the client, which machines are in scope, which are out, which single
 *   host bridges the outside to the inside, where the tester starts, which
 *   techniques are permitted, which accounts the client agreed to hand over,
 *   what the objectives are worth, and everything the compile could NOT derive.
 *
 * ─── PURE, SYNCHRONOUS, DETERMINISTIC, TOTAL ────────────────────────────────
 *
 * No DB, no fs, no clock, no randomness, no network. Compiling the same inputs
 * twice deepStrictEquals, and the result JSON round-trips.
 *
 * IT NEVER THROWS FOR ANY JSON-DERIVED VALUE. Not for null, not for {}, not for
 * {vms:'nope'}, not for a number where an array belongs, not when a sibling
 * module misbehaves. That is the real contract, and it is stated as a contract
 * rather than as an absolute because an absolute here would be FALSE: an object
 * carrying a THROWING ACCESSOR — `Object.defineProperty(vm,'name',{get(){throw}})`
 * — propagates that throw out of specFingerprint, and defending against a
 * hostile getter would mean wrapping every property read in this file in a
 * try/catch to buy nothing. Every input this module can actually receive is
 * JSON: a jsonb column, a request body, a synthesized spec. All of those are
 * plain data with plain accessors, and for all of those the guarantee is total.
 *
 * The guarantee is a repair, not a defensive habit: the
 * synthesizer's assignLaneAddressing (profile-to-spec.js:181-192) raises a bare
 * `new Error` with no statusCode, and routes/profile-deploy.js:585-591 renders
 * `err.statusCode || 500` — so a self-correctable authoring mistake becomes an
 * unexplained 500 with no field to point at. Every condition that would throw
 * there is a PROBLEM here, with a code, a severity and a ref, and the caller
 * decides whether it blocks (hasBlockingProblem) or merely warns.
 *
 * ─── THE ARCHITECTURAL RULE ─────────────────────────────────────────────────
 *
 *   THE HOST UNIVERSE IS spec.vms[] AND NOTHING ELSE.
 *
 * `profile` is read ONLY for narrative client facts — company name, industry,
 * public domain, declared subnets, stakeholders, weaknesses — through
 * readClientFacts. It is NEVER used to build a host list.
 *
 * Three profile-to-host derivations already exist in this tree and they
 * disagree with each other:
 *   * profile-to-spec.js:83-90        — net.assets, role === 'server'
 *   * ai/scan-documents/index.js:39-48 — net.assets, role server OR network
 *     (its own comment at :40-42 claims parity with the deploy orchestrator;
 *      that claim is false)
 *   * utils/asset-register-generator.js:82-101 — it.servers, a different branch
 *     of the profile entirely
 * A fourth would guarantee that the paper and the lane disagree. Reading the
 * SPEC instead means this module can only ever name a host that actually
 * deploys, at the octet it actually gets.
 *
 * ─── IMPORT, DO NOT MIRROR ──────────────────────────────────────────────────
 *
 * isWebServer, dnsLabel and the SPEC_OCTET_MIN/MAX band are imported from
 * profile-to-spec.js so the vuln-app target, the short-name rule and the
 * pinning capacity are PHYSICALLY unable to drift from the synthesizer's.
 * ipInCidr is imported so there is no second CIDR matcher in the repo.
 * inferServices is imported because it is the repo's only existing service
 * derivation. isWebServer is called with EXACTLY ONE ARGUMENT, always —
 * vuln-app-generator.js:52 does `assets.find(isWebServer)`, so its arity is
 * load-bearing and a second argument would be the array index.
 *
 * ─── THE DEPENDENCY LIST IS A CONTRACT ──────────────────────────────────────
 *
 * Five imports, and no more: ./engagement-model (zero imports of its own),
 * ../../../../../src/utils/ipv4, ../ai/scan-documents/service-inference,
 * ./profile-to-spec, and node:crypto. A source scan in
 * test/ciab-engagement-model.test.js pins that list. Two things break the
 * moment it grows:
 *   * ./db must NEVER appear. test/ciab-reservation.test.js:225-229 stubs
 *     CiAB's utils/db.js as a poison pill that throws on any query, and B1 will
 *     load this module from routes/profile-deploy.js's module scope.
 *   * src/utils/lane-networking.js, challenge-lane-deployer.js and anything
 *     under src/utils that reaches site-config.js:29-30 do an unguarded
 *     fs.readFileSync of config/site.json, which is ABSENT from this checkout.
 *     Importing one of them turns every stubbed-cache test into an ENOENT that
 *     names the wrong file.
 * This is why the two segment rules below are RESTATED here from source rather
 * than imported — see THE MIRROR THAT DRIFTED.
 *
 * ─── THE PERIMETER IS NOT PUBLISHED. THERE IS NO DNAT. ──────────────────────
 *
 * An earlier draft of this phase had an engagement PUBLISH a service on the
 * gateway's ext0. That is cut, deliberately and permanently: the environment
 * stays internal, and only the lane can reach the site. The mechanism that
 * makes an external engagement work without any gateway change already exists:
 *
 *   * lane-networking.js:379 — a v3 spec VM with role 'dmz' (or an explicit
 *     nics array, which wins first at :374) is DUAL-HOMED on ext AND int.
 *   * challenge-lane-deployer.js:758-772 pins that host to .240 on BOTH
 *     segments (:770-771), and says so itself: .240 is above the gateway's
 *     DHCP pool (.10-.200), so no lease can claim it and no gateway re-bake is
 *     needed.
 *   * topology-validate.js:26 — EXTERNAL_ROLES = {'dmz','attacker'}: a 'dmz'
 *     VM is deliberately external.
 *
 * So the external exercise is: Kali on ext (.50) reaches the site on ext (.240)
 * as an L2 NEIGHBOUR — no DNAT, no rule ordering, no 3389 hazard — and because
 * that same host is ALSO homed on int, compromising it IS the pivot.
 *
 * This module therefore records PLACEMENT, never publishing:
 *   'pivot'    role 'dmz' / explicit two-NIC — dual-homed ext+int, pinned .240
 *   'public'   single-homed ext (the v3 default for an ordinary VM)
 *   'internal' single-homed int; needs an explicit nics array on the spec
 *
 * EXACTLY ONE PIVOT PER LANE, and that is a teaching constraint rather than a
 * limitation to route around: the deployer defines exactly one dual-homed
 * address, so a second pivot has nowhere to land. Extra EXPOSED hosts are free
 * — 'public' is the v3 default and costs nothing — and they are the cheap way
 * to make "which host is the bridge?" a real question rather than a host count
 * of one.
 *
 * ─── THE MIRROR THAT DRIFTED, AND WHY THIS MODULE CLOSES IT ─────────────────
 *
 * Two files answer "is this VM single-homed, and therefore pinnable?" with two
 * different rules:
 *
 *   profile-to-spec.js:176-179   !(Array.isArray(vm.nics) && vm.nics.length > 1)
 *   challenge-lane-deployer.js:310-311
 *                                resolveVmSegments(...).length > 1  -> skip
 *
 * For a role:'dmz' VM carrying NO explicit nics they DISAGREE. The synthesizer
 * believes it is single-homed and stamps an ipOctet in the .80-.99 band; the
 * deployer treats it as dual-homed and pins .240. The LANE is right either way
 * — the deployer never writes a .8x reservation for that host — so this is not
 * a deploy bug. It is a PAPER-vs-LANE divergence: the spec would carry .8x for
 * a machine that lives at .240, and B2's IP writeback, Track C's manifest and
 * every scan document read the spec.
 *
 * It is latent today only because nothing in the tree emits role:'dmz'. B0 is
 * where that starts, so B0 is where it gets closed — BY CONSTRUCTION, not by
 * coincidence:
 *
 *   * profile-to-spec.js is NOT modified (ciab-deploy-parity.test.js pins it).
 *   * resolveVmSegments is NOT imported (it would break the purity contract).
 *   * instead, every host this compile emits carries the EXPLICIT `nics` array
 *     B2 will write onto the spec. A pivot arrives at the synthesizer with
 *     nics.length === 2, which assignLaneAddressing's EXISTING filter already
 *     excludes from the band. The two rules then agree because they are being
 *     asked the same question about the same explicit data.
 *   * and hosts[].ip_octet for a pivot is DUAL_HOMED_OCTET (240), not a band
 *     octet and not null, because .240 is where the deployer actually puts it
 *     and the paper has to say so.
 *
 * ─── RELATED WORK THIS PHASE DOES NOT TOUCH ─────────────────────────────────
 *
 * utils/answer-key-risk-assessment.js:35-46 (unpackContext) is readClientFacts'
 * older twin and is to be collapsed into it in a later phase. B0 does not edit
 * it: it is reachable from live answer-key generation and has no test of its
 * own. Same for utils/asset-register-generator.js, utils/profile-to-intake.js
 * and ai/scan-documents/index.js.
 * ============================================================================
 */

const M = require('./engagement-model');
const { ipInCidr } = require('../../../../../src/utils/ipv4');
const { inferServices } = require('../ai/scan-documents/service-inference');
const {
  isWebServer, dnsLabel, SPEC_OCTET_MIN, SPEC_OCTET_MAX,
} = require('./profile-to-spec');
const crypto = require('node:crypto');

// ─── Constants ──────────────────────────────────────────────────────────────

/** Bump when the SHAPE of a compiled plan changes, so B2 and Track C can tell a
 *  stale stored proposal from a current one without diffing it field by field.
 *
 *  2 — hosts[] gained `segments`, `segment_for_address` and `goad_lab_vm`. An
 *      octet with no segment beside it is half a fact: an AD lab host's .10 is
 *      on the internal base and an ordinary host's .80 is on the external one,
 *      and a reader that joined either to the wrong base would name an address
 *      nothing lives at — which is the whole subject of this module. */
const ENGAGEMENT_COMPILE_VERSION = 2;

/**
 * The lane WAN transit pool (src/utils/lane-wan-allocator.js's block). Every
 * lane's gateway wan0 lives in here, which makes it the one range that is
 * always out of scope: it is the plumbing that carries the exercise, not part
 * of the client's estate. It is emitted as a DOCUMENTARY rule — see
 * declared_only — because a spec VM carries an ipOctet, not an address.
 */
const MANAGEMENT_CIDR = '100.100.60.0/22';

/**
 * Where the deployer actually puts a dual-homed host: .240 on BOTH segments.
 *
 * Authority: src/utils/challenge-lane-deployer.js:758-772, the pin itself at
 * :770-771 (`ipconfig0: ip=<ext>.240/24` + `ipconfig1: ip=<int>.240/24`). Its
 * own comment records why it is 240 and not 50: the gateway firstboot reserves
 * ext .50 for Kali's RDP DNAT, and .240 sits above the DHCP pool (.10-.200), so
 * no lease can claim it and no gateway re-bake is needed.
 *
 * Exported because the paper must be able to say .240 out loud — and because a
 * later reader that hardcodes 240 somewhere else is a second copy of a fact
 * that lives in exactly one place. engagement-model.js is that place: this
 * takes ITS value whenever it has one, and carries the literal only so that a
 * sibling which has not landed the constant cannot make the compile throw at
 * load. Two spellings of 240 is the exact failure mode this whole file exists
 * to prevent.
 */
const DUAL_HOMED_OCTET = (M && Number.isInteger(M.DUAL_HOMED_OCTET)) ? M.DUAL_HOMED_OCTET : 240;

/**
 * ─── THE ROLES THAT LIVE OUTSIDE, MIRRORED FROM SHARED CORE ─────────────────
 *
 * AUTHORITY: src/utils/topology-validate.js:25-26, verbatim —
 *
 *     // Roles that are meant to sit outside the AD network, so a non-lab name
 *     // on them is intentional rather than a typo. 'dmz' is the dual-homed
 *     // pivot host; 'attacker' is the per-lane Kali the template editor adds
 *     // by default.
 *     const EXTERNAL_ROLES = new Set(['dmz', 'attacker']);
 *
 * MIRRORED RATHER THAN IMPORTED, and the reason is the same one the header
 * gives for lane-networking.js: topology-validate.js requires ./lane-networking
 * and ./goad-deploy, and that graph reaches site-config.js:29-30's unguarded
 * fs.readFileSync of config/site.json — ABSENT from this checkout. Importing it
 * would turn every stubbed-cache test into an ENOENT naming the wrong file, and
 * it would break the five-import contract test/ciab-engagement-model.test.js
 * pins. A source-scan guard test asserts this mirror against that file's own
 * text, the same way the SPEC_OCTET band parity guard does, so it cannot drift.
 *
 * Both roles are REAL and COMMON: public/js/topology/topology-seed.js:203-208
 * and public/js/admin/admin-challenges.js:177,186,277,544,586 emit them, and
 * topology-editor.js:318 documents them in the editor's own field help.
 */
const EXTERNAL_ROLES = Object.freeze(['dmz', 'attacker']);

/** The dual-homed bridge role. lane-networking.js:379 compares it with ===, so
 *  the comparison here is case-SENSITIVE too: a spec carrying 'DMZ' is not
 *  dual-homed by the deployer, and claiming otherwise here would be exactly the
 *  paper-vs-lane divergence this module exists to close. */
const PIVOT_ROLE = 'dmz';

/** The per-lane Kali. The DEPLOYER owns its addressing — the gateway firstboot
 *  reserves ext .50 for its RDP DNAT (wan0:3389 -> ext.50), which is the same
 *  reservation that pushed the dual-homed pin to .240 — so this compile places
 *  it nowhere and proposes no nics for it. */
const ATTACKER_ROLE = 'attacker';

function isExternalRole(role) {
  return EXTERNAL_ROLES.includes(role == null ? '' : String(role));
}

/**
 * ─── THE AD LAB HOST TABLE, MIRRORED FROM goad-deploy.js ────────────────────
 *
 * WHY THIS EXISTS. `isGoadVm` is the third rung of resolveVmSegments, and a
 * previous version of this mirror OMITTED it on the reasoning that a rung
 * returning one segment behaves like the rung below it, which also returns one.
 * That reasoning was wrong, and it is the whole of finding N-A: the two rungs
 * return a DIFFERENT segment, and the segment is what picks the subnet base
 * (challenge-lane-deployer.js:315 — `segs[0] === 'int' ? goadSubnetBase :
 * laneSubnetBase`). One segment is not one segment.
 *
 * CAN IT BE DECIDED OFFLINE? YES — and that was worth establishing before
 * guessing either way. The deployer does not consult the lane, Proxmox, or a
 * database for it. cloneChallengeVm (challenge-lane-deployer.js:696-697) reads
 *
 *     const goadVm   = goadMacs[vmName];
 *     const isGoadVm = !!goadVm;
 *
 * and `goadMacs` is goad-deploy.prepareGoadMacs(spec, vxlanId, base), a PURE
 * function of the spec (goad-deploy.js:286-320):
 *
 *     if (!spec?.goad?.enabled) return {};          // nothing is a GOAD VM
 *     if (!Array.isArray(spec.vms)) return {};
 *     const labName = spec.goad.version || 'GOAD-Light';
 *     const labDef  = GOAD_LABS[labName] || GOAD_LABS['GOAD-Light'];   // unknown -> default
 *     byName = labDef.vms keyed by name.toLowerCase()
 *     a spec VM is a GOAD VM iff byName[vm.name.toLowerCase()] exists
 *
 * vxlanId and the subnet base affect the MAC and the IP string, never
 * membership. So membership is a pure function of (goad.enabled, goad.version,
 * vm.name) plus the lab table — and the lab table is static source text. It is
 * mirrored here rather than guessed, and a source-scan guard test asserts every
 * lab name and every VM name in it against goad-deploy.js's own GOAD_LABS text,
 * so a lab added upstream fails a test instead of silently producing a wrong
 * address.
 *
 * THE OCTETS ARE PART OF THE MIRROR TOO, because membership alone still leaves
 * the paper wrong. prepareGoadMacs gives each matched VM
 * `static_ip: buildIp(goadSubnetBase, labVm.ipOctet)`, and resolveSpecAddressing
 * SKIPS it outright (challenge-lane-deployer.js:306, `if (goadMacs[name])
 * continue;`) — so a GOAD host never takes a band reservation, and its real
 * address is the LAB's octet on the INTERNAL base, not the ipOctet its spec
 * carries. Mirroring the names without the octets would have replaced one wrong
 * address with another.
 *
 * AUTHORITY: src/utils/goad-deploy.js:90-150 (GOAD_LABS), :241 (DEFAULT_LAB),
 * :286-320 (prepareGoadMacs).
 */
const GOAD_DEFAULT_LAB = 'GOAD-Light';

/** lab name -> { lower-case VM name: ipOctet }. Mirrors GOAD_LABS' vms[]. */
const GOAD_LAB_VMS = Object.freeze({
  'GOAD-Light': Object.freeze({ dc01: 10, dc02: 11, srv02: 22 }),
  GOAD: Object.freeze({ dc01: 10, dc02: 11, dc03: 12, srv02: 22, srv03: 23 }),
  'GOAD-Mini': Object.freeze({ dc01: 10 }),
  NHA: Object.freeze({ dc01: 10, dc02: 11, srv01: 21, srv02: 22, srv03: 23 }),
  SCCM: Object.freeze({ dc01: 40, srv01: 41, srv02: 42, ws01: 43 }),
  DRACARYS: Object.freeze({ dc01: 10, srv01: 11, lx01: 12 }),
});

/**
 * The AD lab octet this VM will really be given, or null when it is not a lab
 * host — which is the same thing as `isGoadVm`, since every matched host has an
 * octet and no unmatched one does.
 *
 * The comparison is `String(name).toLowerCase()` and NOT this file's `lc()`,
 * because lc() trims and prepareGoadMacs does not: a spec name of ' DC01 ' is
 * not a lab host to the deployer, and pretending otherwise here would be a
 * second flavour of the same divergence.
 *
 * @param {object} specObj the WHOLE spec — goad.enabled and goad.version live there
 * @param {*} rawName      vm.name exactly as the spec carries it
 * @returns {number|null}
 */
function goadLabOctet(specObj, rawName) {
  const spec = isObj(specObj) ? specObj : {};
  const goad = isObj(spec.goad) ? spec.goad : null;
  if (!goad || !goad.enabled) return null;
  if (!Array.isArray(spec.vms)) return null;      // prepareGoadMacs returns {} first
  const lab = GOAD_LAB_VMS[goad.version || GOAD_DEFAULT_LAB] || GOAD_LAB_VMS[GOAD_DEFAULT_LAB];
  if (!lab || rawName == null) return null;
  const key = String(rawName).toLowerCase();
  return Object.prototype.hasOwnProperty.call(lab, key) ? lab[key] : null;
}

/**
 * THE SEGMENT IDS THIS LANE WILL ACTUALLY HAVE.
 *
 * A LOCAL MIRROR OF src/utils/lane-networking.js resolveSegmentBridges
 * (~347-352), which is the table resolveVmNics' `bridgeFor` looks a segment up
 * in — and THROWS on a miss:
 *
 *     throw new Error(`VM '<name>' attaches to segment '<id>', which this lane
 *                      does not have. Available: <ids>.`)
 *
 * v3 has exactly ext and int. v1/v2 has one VNet and maps lan, ext AND int all
 * onto it, deliberately, so a spec authored at v3 does not explode when its
 * challenge is switched to v2. Anything else — 'dmz', 'mgmt', a typo — is a
 * hard deploy-time throw, which is why finding N-C exists: the compile used to
 * emit a healthy-looking plan for a lane that cannot come up at all.
 */
function laneSegmentIds(isV3) {
  return isV3 ? ['ext', 'int'] : ['lan', 'ext', 'int'];
}

/**
 * WHAT SEGMENTS WILL THE DEPLOYER ACTUALLY GIVE THIS VM?
 *
 * A LOCAL MIRROR OF src/utils/lane-networking.js:374-381 resolveVmSegments,
 * precedence for precedence:
 *
 *     explicit vmSpec.nics  >  v3 + role 'dmz' + qemu  >  v3 + isGoadVm  >  v3 ext / lan
 *
 * It CANNOT be imported: lane-networking.js is on the graph that reaches
 * site-config.js:29-30 (see the header, and EXTERNAL_ROLES above), and the
 * import list is a pinned contract. A source-scan guard test asserts this
 * mirror against lane-networking.js's own text.
 *
 * FOUR RUNGS, AND THE MIRROR CARRIES ALL FOUR. There is no such thing as a rung
 * that is safe to leave out. An earlier version of this function omitted rung 3
 * on the stated reasoning that `['int']` and `['ext']` are both ONE segment, so
 * neither pinnability (challenge-lane-deployer.js:310-311 tests
 * `segs.length > 1`) nor the .240 pin (:758-772, dual-homed only) could move.
 * That reasoning was WRONG, and it is finding N-A: :315 picks the SUBNET BASE
 * off `segs[0] === 'int'`, so the two rungs differ in the only thing an address
 * is made of. The rungs are numbered below and a guard test counts them against
 * the authority's own returns, so an omission is a test failure, not a plan
 * that quietly names an address nothing lives at.
 *
 * @param {object} vm    a spec VM
 * @param {boolean} isV3
 * @param {boolean} isGoadVm  see goadLabOctet — decided from the spec, offline
 * @returns {string[]} segment names, in NIC order
 */
function resolveSpecVmSegments(vm, isV3, isGoadVm) {
  const spec = isObj(vm) ? vm : {};
  // MIRROR RUNG 1/4 — explicit vmSpec.nics, filtered to entries having a
  // segment, WINS OUTRIGHT. Authored ORDER is returned exactly as written.
  //
  // BYTE-EXACT WITH THE AUTHORITY, DELIBERATELY. lane-networking.js filters on
  // raw truthiness (`n && n.segment`) and maps with String(). This file's own
  // str() helper trims and maps null to '', and using it here made three shapes
  // diverge: a segment of '   ' (the deployer keeps it and then HARD-THROWS on
  // an unknown bridge, while we silently fell through to the role rung and
  // published .240), and 0 or false (the deployer filters them and the machine
  // really is the bridge, while we raised a false unknown-segment error).
  // Do not 'tidy' this back into str(): the mirror is only worth having if it
  // is wrong in exactly the same places the authority is.
  const explicit = asArray(spec.nics).filter(n => isObj(n) && n.segment);
  if (explicit.length) return explicit.map(n => String(n.segment));

  const type = spec.type || 'qemu';   // verbatim, as every authority reads it
  // MIRROR RUNG 2/4 — v3 AND role 'dmz' AND type !== 'lxc' -> the dual-homed
  // pivot host. This rung is ABOVE the AD-lab rung in the authority, so a lab
  // host that is also given the bridge role really is dual-homed.
  if (isV3 && spec.role === PIVOT_ROLE && type !== 'lxc') return ['ext', 'int'];
  // MIRROR RUNG 3/4 — v3 AND isGoadVm -> the INTERNAL segment. NOT
  // interchangeable with rung 4: both return one segment, a DIFFERENT one, and
  // challenge-lane-deployer.js:315 reads the subnet base off exactly that.
  if (isV3 && isGoadVm === true) return ['int'];
  // MIRROR RUNG 4/4 — everything else: single ext on v3, single lan on v1/v2.
  return [isV3 ? 'ext' : 'lan'];
}

/**
 * WILL THE DEPLOYER ACTUALLY GIVE THIS MACHINE TWO CARDS, AND PIN IT TO .240?
 *
 * THE ONE PREDICATE. Segments are what a spec ASKS FOR; this is what the deploy
 * path will DO about it. Nothing in this file may stamp the 'pivot' placement,
 * emit the .240 octet, or print a .240 starting URL
 * without this returning true, because each of those three is a promise that
 * one specific machine answers on one specific address.
 *
 * TWO GATES, BOTH LOAD-BEARING, BOTH READ OFF THE DEPLOYER'S OWN SOURCE:
 *
 *   type !== 'lxc'
 *     resolveVmNics' container branch (src/utils/lane-networking.js:465-471)
 *     returns `dualHomed: false` and `segments.slice(0, 1)` — ONE card, on the
 *     FIRST segment, whatever the spec asked for. An explicit two-entry nics
 *     array does not survive it, and neither does role 'dmz'. A CONTAINER CAN
 *     NEVER BE DUAL-HOMED. The same type also hits `continue` in
 *     resolveSpecAddressing (src/utils/challenge-lane-deployer.js:303), so it
 *     takes no band reservation either: a container has NO static address at
 *     all in a deployed lane.
 *
 *   subnetScheme === 'v3'
 *     The .240 write (src/utils/challenge-lane-deployer.js:768-772) sits behind
 *     `if (isV3)`. On a v1/v2 lane a multi-NIC qemu machine still gets both
 *     cards, but NOTHING is pinned — and there is only one flat lan0 for them
 *     to sit on anyway (src/utils/lane-networking.js:381).
 *
 *   NOT AN AD LAB HOST THE ENVIRONMENT HAS ALREADY PLACED INTERNALLY
 *     Rung 3 of resolveVmSegments puts a lab host on ['int'] and prepareGoadMacs
 *     has already reserved it at the LAB's octet there. Proposing 'pivot' for
 *     one writes [{ext},{int}] onto its spec, and rung 1 would then honour it —
 *     so the machine really would move to .240, out from under the reservation
 *     the lab made and out from under the playbook, which drives the lab at the
 *     addresses its own definition names (goad-deploy.js runGoadPlaybook's
 *     winrmIPs are built from labDef octets). The deploy does not fail loudly;
 *     the directory lab simply never builds.
 *
 *     `alreadyDualHomed` is the exception, and it is the authority's own: rung 2
 *     (role 'dmz') sits ABOVE the lab rung, so a lab host carrying the bridge
 *     role IS dual-homed by the environment whatever this compile thinks. This
 *     predicate must not contradict that — it refuses to CREATE a bridge on a
 *     lab host, it does not deny one the environment already made. That case
 *     gets GOAD_HOST_IS_BRIDGE instead, which is a warning about a real lane.
 *
 * All three gates together answer ONE question — "is there really a bridge here,
 * at .240?" — which is the only question a placement, an octet or a brief URL is
 * entitled to assume the answer to.
 *
 * @param {object} vm    a spec VM
 * @param {boolean} isV3
 * @param {object} [ctx] { isGoadVm, alreadyDualHomed } — see above
 * @returns {boolean}
 */
function canBeDualHomed(vm, isV3, ctx) {
  const spec = isObj(vm) ? vm : {};
  const c = isObj(ctx) ? ctx : {};
  const type = spec.type || 'qemu';   // verbatim, as every authority reads it
  if (isV3 !== true || type === 'lxc') return false;
  if (c.isGoadVm === true && c.alreadyDualHomed !== true) return false;
  return true;
}

/** Why canBeDualHomed said no, in the words a plan reader needs. Kept beside
 *  the predicate so the reason and the rule cannot drift apart. */
function bridgeBlockText(blockedBy) {
  if (blockedBy === 'container') {
    return 'it is a container, and the environment gives a container exactly one network card — '
      + 'whatever its role or its card list says';
  }
  if (blockedBy === 'flat_lane') {
    return 'this engagement is scheduled on ONE flat segment, so there is no second segment to bridge to '
      + 'and no fixed outward address to hand out';
  }
  if (blockedBy === 'ad_lab_host') {
    return 'it is one of the directory lab’s own machines, which the lab itself addresses on the internal '
      + 'segment — moving it to the outward address would take it out from under the lab’s own build';
  }
  return 'the environment does not home it on both segments';
}

/**
 * THE SINGLE ANSWER TO "where does this machine actually land?"
 *
 * Every reader below — the host block, the derived exposure, the pivot count,
 * the capacity count — asks THIS and nothing else, so there is exactly one
 * place in this file that knows the deployer's rules.
 *
 *   segments    resolveSpecVmSegments, above — all four rungs
 *   dual_homed  segments.length > 1 — the deployer's own test at :310-311
 *   pinnable    NOT an AD lab host, AND qemu, AND single-homed — the eligibility
 *               filter at :306 (`if (goadMacs[name]) continue;`), :303 (lxc) and
 *               :310-311 (`segs.length > 1`), IN THAT ORDER, which is the rule
 *               profile-to-spec.js:176-179 approximates by counting vm.nics. The
 *               two agree for every shape EXCEPT a role 'dmz' VM with no explicit
 *               nics — the subject of THE MIRROR THAT DRIFTED in the header — and
 *               an AD lab host, which prepareGoadMacs has already addressed.
 *   ip_octet    .240 on both segments for a dual-homed host, and ONLY on v3
 *               (challenge-lane-deployer.js:768-771 gates the pin behind isV3);
 *               the LAB's own octet for an AD lab host, on the internal base
 *               (goad-deploy.js:310, `static_ip: buildIp(goadSubnetBase,
 *               labVm.ipOctet)`) — NOT the ipOctet its spec happens to carry;
 *               otherwise the octet the spec carries, or null.
 *   segment_for_address
 *               which segment ip_octet is an octet OF. A GOAD host's .10 is on
 *               the INTERNAL base and an ordinary host's .80 is on the external
 *               one, so an octet with no segment beside it is half a fact.
 *
 * @param {object} vm
 * @param {boolean} isV3
 * @param {number|null} goadOctet  goadLabOctet's answer for this VM; null = not a lab host
 */
function laneAddressing(vm, isV3, goadOctet) {
  const spec = isObj(vm) ? vm : {};
  const isGoadVm = Number.isInteger(goadOctet);
  const segments = resolveSpecVmSegments(spec, isV3, isGoadVm);
  const type = spec.type || 'qemu';   // verbatim, as every authority reads it

  // TWO DIFFERENT QUESTIONS, AND CONFLATING THEM WAS THE WHOLE BUG.
  //   wantsTwo  — what the SPEC asks for. resolveVmSegments' answer, and the
  //               exact test both deployer skip rules apply
  //               (challenge-lane-deployer.js:303 for the type, :310-311 for
  //               `segs.length > 1`), so it alone decides pinnability.
  //   capable   — what the DEPLOYER will actually DO about it. canBeDualHomed.
  // A container asking for two cards gets one; a qemu machine asking for two on
  // a flat lane gets two cards and no address. Only the INTERSECTION is a real
  // bridge at a real .240.
  const wantsTwo = segments.length > 1;
  const capable = canBeDualHomed(spec, isV3, { isGoadVm, alreadyDualHomed: wantsTwo });
  const dualHomed = wantsTwo && capable;
  // `!isGoadVm` FIRST, because it is first in the deployer: :306 skips an AD lab
  // host before either the type test or the segment count is reached. Its
  // address does not come from this band at all — prepareGoadMacs already gave
  // it a MAC-keyed reservation at the lab's own octet.
  const pinnable = !isGoadVm && type !== 'lxc' && !wantsTwo;

  // THE SEGMENTS THE DEPLOYER WILL REALLY LOOK UP A BRIDGE FOR. resolveVmNics'
  // container branch calls bridgeFor(segments[0]) and nothing else — it
  // truncates with `segments.slice(0, 1)` — so an LXC's second card is never
  // validated because it is never built. Every other shape validates all of
  // them: the multi-NIC branch maps bridgeFor over the whole list, and the
  // single-qemu branch takes segments[0], which is the whole list.
  const bridgedSegments = type === 'lxc' ? segments.slice(0, 1) : segments;
  const known = laneSegmentIds(isV3);
  const unknownSegments = bridgedSegments.filter(s => !known.includes(s));

  // Which segment ip_octet counts FROM. A dual-homed host answers at .240 on
  // BOTH, so it names both.
  // An AD lab host's octet counts from goadSubnetBase, which is the INTERNAL
  // base on v3 and the one flat lane base on v1/v2 (challenge-lane-deployer.js
  // :1358, `isV3 ? net.lanInt.base3 : net.lan.base3`).
  const addressSegment = dualHomed
    ? 'ext+int'
    : (isGoadVm ? (isV3 ? 'int' : 'lan') : (segments[0] || null));

  return {
    segments,
    /** The deployer will treat this as an AD lab host: goadMacs[name] is set. */
    goad_lab_vm: isGoadVm,
    /** The lab's own octet, on the internal base. null when not a lab host. */
    goad_lab_octet: isGoadVm ? goadOctet : null,
    /** The bridge table the deployer will look these up in (mirror of
     *  resolveSegmentBridges), and any segment that is not in it. */
    known_segments: known,
    unknown_segments: unknownSegments,
    segment_for_address: addressSegment,
    /** What the spec asks for — two segments — whether or not it can have them. */
    wants_dual_home: wantsTwo,
    /** canBeDualHomed: may this machine be given the 'pivot' placement at all? */
    can_dual_home: capable,
    /** null, 'container', 'flat_lane' or 'ad_lab_host'. Feeds bridgeBlockText.
     *  In canBeDualHomed's own order, so the reason and the refusal agree. */
    dual_home_blocked_by: capable
      ? null
      : (type === 'lxc' ? 'container' : (!isV3 ? 'flat_lane' : 'ad_lab_host')),
    /** The deployer will really attach two cards AND pin .240 on both. */
    dual_homed: dualHomed,
    pinnable,
    // THE ADDRESS IS THE ONE THE LANE REALLY HAS, OR NONE.
    //   .240        the deployer pins it there (:768-772) — only when dual_homed
    //   band octet  it takes a reservation (:303,310-311) — only when pinnable
    //   null        everything else: a container, or a multi-NIC machine on a
    //               flat lane. profile-to-spec.js:168-172 says this in its own
    //               words — "Pinning an LXC would write an address the deployer
    //               ignores, and the paper would then name an IP nothing lives
    //               at — worse than naming none." NO_HOST_ADDRESSING is the
    //               warn that exists for exactly this, and it can only fire on
    //               a null.
    //   lab octet   goad-deploy.js:310 gave it a MAC-keyed reservation there,
    //               on the INTERNAL base, and :306 skipped the band entirely.
    ip_octet: dualHomed
      ? DUAL_HOMED_OCTET
      : (isGoadVm
        ? goadOctet
        : (pinnable && Number.isInteger(spec.ipOctet) ? spec.ipOctet : null)),
  };
}

/**
 * THE PLACEMENT AN AUTHORED CARD LIST ALREADY DECIDED.
 *
 * RUNG 1 IS ABSOLUTE, AND IT IS ABSOLUTE FOR EVERY ROLE. `explicit.length`
 * returns before role, type, scheme or lab membership is consulted
 * (lane-networking.js resolveVmSegments, rung 1), so a spec that carries a nics
 * array has ALREADY ANSWERED the question this compile would otherwise infer an
 * answer to. The compile may DISAGREE and say so; it may not overwrite.
 *
 * The invariant used to hold for role 'attacker' only, and that is finding N-B:
 * a 'dmz' host authored `nics: [{segment:'int'}]` was stamped 'pivot', handed a
 * two-card list and .240, and printed into the brief as the outward address —
 * while the deployer, reading rung 1, gives it ONE internal card. Which role a
 * special case is written for is not the point; a special case is the defect.
 *
 * @param {string[]} segments the AUTHORED list, in authored order
 * @param {boolean}  capable  canBeDualHomed — a container or a flat lane cannot bridge
 * @returns {'pivot'|'internal'|'public'}
 */
function placementForAuthoredSegments(segments, capable) {
  const segs = asArray(segments);
  if (segs.length > 1) return capable ? 'pivot' : 'public';
  if (segs.length === 1 && segs[0] === 'int') return 'internal';
  return 'public';
}

/** The authored card list, or null when the spec authored none. The ONE reader
 *  of vm.nics outside resolveSpecVmSegments, so "did the spec already answer
 *  this?" has exactly one spelling. */
function authoredSegmentsOf(vm) {
  const spec = isObj(vm) ? vm : {};
  const explicit = asArray(spec.nics).filter(n => isObj(n) && str(n.segment) !== '');
  return explicit.length ? explicit.map(n => str(n.segment)) : null;
}

/**
 * Vocabulary shared with engagement-model.js.
 *
 * engagement-model owns the AUTHORING-time copy (its validateExposurePlan and
 * validateScopeRules). This module prefers that copy when it is exported and
 * otherwise falls back to the same words, because the compile must stay TOTAL:
 * a sibling that has not landed a constant yet must not be able to make this
 * file throw at load, and a vocabulary is not a behaviour worth failing over.
 */
function vocab(name, fallback) {
  const fromModel = M && M[name];
  return Object.freeze(
    Array.isArray(fromModel) && fromModel.length ? fromModel.slice() : fallback.slice()
  );
}

const SCOPE_KINDS = vocab('SCOPE_KINDS',
  ['all', 'vm', 'role', 'cidr', 'url', 'hostname_pattern', 'text']);

/** The kinds that can name a MACHINE. Everything else is brief text — see the
 *  SCOPE_RULE_DOCUMENTARY note on compileEngagementPlan. */
const RESOLVABLE_SCOPE_KINDS = vocab('RESOLVABLE_SCOPE_KINDS', ['all', 'vm', 'role']);

/** Placement, not publishing. See the header. */
const EXPOSURE_PLACEMENTS = vocab('PLACEMENTS', ['pivot', 'public', 'internal']);

const DEFAULT_TYPE_KEY = (M && typeof M.DEFAULT_TYPE_KEY === 'string')
  ? M.DEFAULT_TYPE_KEY
  : 'default';

/**
 * Every code this compile can emit.
 *
 * A code that exists only as a string literal in one branch is a code no caller
 * can handle, so the test asserts that every code emitted over every fixture is
 * a member of this array. Adding a branch means adding a code HERE first.
 *
 * There are deliberately NO port codes. Nothing is published (see the header),
 * so the reserved-port and duplicate-port rules of the earlier draft have no
 * subject at all. What replaces them is EXPOSURE_MULTIPLE_PIVOTS and
 * EXPOSURE_PIVOT_IS_CONSOLE, both of which describe a lane the deployer would
 * refuse or mis-address.
 */
const PLAN_PROBLEM_CODES = Object.freeze([
  'SPEC_EMPTY',                        // error — no spec.vms[] to compile against
  'SCHEME_MISMATCH',                   // warn  — engagement.subnet_scheme !== spec.subnet_scheme
  'SCOPE_RULE_UNRESOLVED',             // warn  — a vm/role rule matched nothing in this spec
  'SCOPE_RULE_DOCUMENTARY',            // info  — a cidr/url/hostname_pattern/text rule; brief only
  'SCOPE_EMPTY',                       // error — nothing left in scope after scope_out
  'NO_HOST_ADDRESSING',                // warn  — an in-scope VM has no ipOctet (LXC / multi-NIC)
  'UNKNOWN_TARGET_VM',                 // error — an exposure/credential entry names a VM not in this spec
  'EXPOSURE_DERIVED',                  // info  — the stored exposure_plan was empty; this is the default
  'EXPOSURE_MULTIPLE_PIVOTS',          // error — the lane defines exactly one dual-homed address
  'EXPOSURE_PIVOT_IS_CONSOLE',         // error — the deployer THROWS on this combination
  'EXPOSURE_PLACEMENT_UNKNOWN',        // warn  — a stored placement outside the vocabulary; read as 'public'
  'EXPOSURE_ROLE_IS_DUAL_HOMED',       // info  — a spec role, not the plan, made this machine the bridge
  'PLACEMENT_OVERRIDES_ROLE',          // warn  — an authored placement demotes a machine its role dual-homes
  'PLACEMENT_REQUIRES_V3',             // warn  — 'pivot'/'internal' on a v1/v2 lane is a fiction
  'EXTERNAL_NO_PIVOT',                 // error — external with nothing bridging ext to int
  'EXTERNAL_NO_SURFACE',               // error — external with no exposed host and no resolvable scope_in
  'EXTERNAL_SYNTHETIC_SURFACE',        // info  — the surface is the synthesizer's appended 'vuln-app' VM
  'EXTERNAL_NEEDS_VULN_APP',           // error — external, no web asset, and no vuln app to append
  'EXTERNAL_SCOPE_WIDE',               // warn  — external with >1 host in scope
  'EXTERNAL_CREDENTIALS_DECLARED',     // warn  — external perspective declaring accounts
  'CREDENTIALS_UNAUTHORED',            // warn  — credential_posture 'credentialed', empty list
  'PROFILE_PUBLIC_IP_NOT_ROUTABLE',    // info  — a per-profile RFC 5737 literal; never a lane address
  'PROFILE_ASSETS_DECLARE_NO_SERVICES',// info  — nothing to infer a service list from but the narrative
  'PROFILE_LAYOUT_UNRECOGNISED',       // warn  — client facts unreadable; the environment still compiles
  'REAL_INTAKE_NO_NETWORK_PLAN',       // warn  — a real-client intake with no segments recorded
  'OVER_PIN_CAPACITY',                 // error — more than SPEC_OCTET_MAX-SPEC_OCTET_MIN+1 pinnable
  'EXPOSURE_ATTACKER_NOT_PLACED',      // warn  — the attack box is placed NOWHERE; the entry is ignored
  'ATTACKER_IS_DUAL_HOMED',            // error — the spec homes the console on both segments, at the bridge's .240
  'PIVOT_NOT_DEPLOYABLE',              // warn  — 'pivot' on a machine canBeDualHomed refuses; read as 'public'
  'ROLE_CASE_MISMATCH',                // warn  — a role that is a known outside role except for its spelling
  'NICS_UNKNOWN_SEGMENT',              // error — a card names a segment this lane has no bridge for: a HARD deploy throw
  'PLACEMENT_CONTRADICTS_NICS',        // warn  — a stored placement disagrees with the card list the spec already carries
  'PLACEMENT_FROM_AUTHORED_NICS',      // info  — the placement was READ off an authored card list, not proposed
  'GOAD_HOST_ADDRESSED_BY_LAB',        // info  — an AD lab host is addressed by the lab, not by this band
  'GOAD_HOST_IS_BRIDGE',               // warn  — an AD lab host given the bridge role is addressed twice over
  'EXPOSURE_DUPLICATE_VM',             // warn  — two exposure entries name one machine; the first wins
  'EXPOSURE_SURFACE_NOT_WEB',          // warn  — the authored surface serves no web site while a web host is unplaced
]);

const PLAN_PROBLEM_CODE_SET = new Set(PLAN_PROBLEM_CODES);

// The pinning band, imported rather than mirrored, so this number cannot drift
// from assignLaneAddressing's own throw (profile-to-spec.js:181-192).
const PIN_CAPACITY = SPEC_OCTET_MAX - SPEC_OCTET_MIN + 1;

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const CIDR_RE = /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/;

// ─── Tiny total helpers ─────────────────────────────────────────────────────
// Every one of these answers "what if the caller handed me garbage?" with a
// value rather than an exception. That is the whole totality contract.

function asArray(v) { return Array.isArray(v) ? v : []; }
function isObj(v) { return !!v && typeof v === 'object' && !Array.isArray(v); }
function str(v) { return v == null ? '' : String(v).trim(); }
function lc(v) { return str(v).toLowerCase(); }
function orNull(v) { const s = str(v); return s === '' ? null : s; }
function intOrNull(v) {
  const n = typeof v === 'number' ? v : parseInt(str(v), 10);
  return Number.isInteger(n) ? n : null;
}

function problem(code, severity, message, ref) {
  return { code, severity, message, ref: ref == null ? null : String(ref) };
}

/**
 * Push a problem, refusing any code that is not registered above.
 *
 * Silently dropping an unregistered code is the lesser evil: the alternative is
 * emitting something no caller can switch on, which is exactly the failure this
 * list exists to prevent. The test that walks every fixture would catch the
 * omission long before a user does.
 */
function emit(list, code, severity, message, ref) {
  if (!PLAN_PROBLEM_CODE_SET.has(code)) return;
  list.push(problem(code, severity, message, ref));
}

/**
 * engagement-model.js is a sibling written to the same plan, but this module's
 * totality contract is stronger than "the sibling behaves". Each of the three
 * calls it makes is wrapped so that a sibling that throws, or that has not
 * landed a function yet, degrades to a documented default instead of taking a
 * 500 out through routes/profile-deploy.js:585-591.
 */
function describeType(engagementType) {
  try {
    const d = M.describeEngagementType(engagementType);
    if (isObj(d)) return d;
  } catch (_err) { /* total by contract */ }
  const key = str(engagementType) || DEFAULT_TYPE_KEY;
  return {
    key,
    known: false,
    label: key.replace(/[_-]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
    perspective: 'internal',
    credential_posture: 'none',
    summary: '',
  };
}

function displayNameFor(engagement, descriptor) {
  try {
    const name = M.engagementDisplayName(engagement);
    if (str(name)) return str(name);
  } catch (_err) { /* total by contract */ }
  return str(descriptor && descriptor.label) || DEFAULT_TYPE_KEY;
}

function liveFor(engagement) {
  try {
    return !!M.isEngagementLive(engagement);
  } catch (_err) {
    return engagement ? engagement.retired_at == null : false;
  }
}

// ─── readClientFacts ────────────────────────────────────────────────────────

const EMPTY_WEAKNESSES = () => ({ governance: [], it: [], network: [], threat: [] });

function normalizeSubnet(s) {
  if (!isObj(s)) return null;
  const name = orNull(s.name || s.label || s.segment_name);
  const cidr = orNull(s.cidr || s.range || s.subnet || s.network);
  if (!name && !cidr) return null;
  return {
    name,
    cidr,
    vlan_id: intOrNull(s.vlan_id != null ? s.vlan_id : s.vlan),
    purpose: orNull(s.purpose || s.description),
    trust_level: orNull(s.trust_level || s.trust),
  };
}

function weaknessList(v) {
  return asArray(v).map(w => (isObj(w) ? w : str(w))).filter(w => (isObj(w) ? true : w !== ''));
}

/**
 * NARRATIVE CLIENT FACTS ONLY. This function NEVER returns a host list.
 *
 * Four profile layouts reach this codebase and all four are live:
 *
 *   canonical    ai/profile/index.js:287-336 — student_view.raw.threats.{...}
 *   real_intake  utils/profile-filler.js:160-180 — the same path, but `network`
 *                carries total_assets/segments and NO subnets
 *   legacy_split student_view.raw.{network, it.it_environment, threat_profile}
 *   flat         routes/profile-deploy.js:95-100's loader shape,
 *                { ...profileRow, assets, json_data }
 *
 * Resolution order, tolerant and never throwing:
 *   1. Array.isArray(p) ? p[0] : p — a real-client profile is WRITTEN as a
 *      one-element array (routes/real-client-intake.js:371), and every loader in
 *      the tree copies that idiom (profile-deploy.js:87, profiles.js:1083).
 *   2. Prefer .json_data when present, because loadProfileForDeploy returns
 *      { ...profileRow, assets, json_data }.
 *   3. Then the four layouts above, in that order.
 *
 * `gaps` is the honesty channel: what could not be read, as codes a caller can
 * switch on rather than prose it has to grep.
 *
 * THE ONE PLACE PROFILE ASSETS ARE TOUCHED is the services check below, and it
 * produces a BOOLEAN, never a host. An AI profile's assets carry no `services`
 * array at all, so a compiler that quietly inferred one would be inventing the
 * environment rather than describing it.
 */
function readClientFacts(profileOrJson) {
  const gaps = [];
  const base = {
    layout: 'empty',
    profile_id: null,
    company_name: null,
    industry: null,
    difficulty: null,
    domain_public: null,
    public_ip: null,
    subnets: [],
    firewall: null,
    stakeholders: [],
    weaknesses: EMPTY_WEAKNESSES(),
    gaps,
  };

  const unwrapped = Array.isArray(profileOrJson) ? profileOrJson[0] : profileOrJson;
  const root = isObj(unwrapped) ? unwrapped : null;
  if (!root) {
    gaps.push({ field: 'profile', code: 'PROFILE_LAYOUT_UNRECOGNISED' });
    return base;
  }

  base.profile_id = root.id != null ? root.id : (root.profile_id != null ? root.profile_id : null);
  base.difficulty = orNull(root.difficulty);

  const jsonRaw = root.json_data != null ? root.json_data : root;
  const json = isObj(Array.isArray(jsonRaw) ? jsonRaw[0] : jsonRaw)
    ? (Array.isArray(jsonRaw) ? jsonRaw[0] : jsonRaw)
    : {};

  const sv = isObj(json.student_view) ? json.student_view : {};
  const raw = isObj(sv.raw) ? sv.raw : {};
  const quick = isObj(sv.quick) ? sv.quick : {};
  const threats = isObj(raw.threats) ? raw.threats : {};

  let org = {};
  let it = {};
  let net = {};
  let tp = {};
  let profiles = {};
  let layout = 'empty';

  if (isObj(threats.organization) || isObj(threats.network) || isObj(threats.it_environment)) {
    org = isObj(threats.organization) ? threats.organization : {};
    it = isObj(threats.it_environment) ? threats.it_environment : {};
    net = isObj(threats.network) ? threats.network : {};
    tp = isObj(threats.threat_profile) ? threats.threat_profile : {};
    profiles = isObj(threats.profiles) ? threats.profiles : {};
    // A real-client intake's network branch counts assets and lists SEGMENTS;
    // an AI profile's lists SUBNETS. The presence of total_assets with no
    // subnets is the only structural tell, and it matters because a real intake
    // with no segments has no network plan to put in the brief at all.
    const realIntake = (net.total_assets != null || Array.isArray(net.segments))
      && !Array.isArray(net.subnets);
    layout = realIntake ? 'real_intake' : 'canonical';
  } else if (isObj(raw.network) || isObj(raw.it) || isObj(raw.threat_profile)) {
    net = isObj(raw.network) ? raw.network : {};
    it = isObj(raw.it) && isObj(raw.it.it_environment) ? raw.it.it_environment : (isObj(raw.it) ? raw.it : {});
    tp = isObj(raw.threat_profile) ? raw.threat_profile : {};
    org = isObj(raw.organization) ? raw.organization : {};
    layout = 'legacy_split';
  } else if (root.company_name != null || Array.isArray(root.assets)) {
    layout = 'flat';
  } else {
    gaps.push({ field: 'profile', code: 'PROFILE_LAYOUT_UNRECOGNISED' });
  }

  base.layout = layout;
  base.company_name = orNull(org.company_name || quick.company_name || root.company_name);
  base.industry = orNull(org.industry || quick.industry || root.industry);
  base.domain_public = orNull(org.domain_public || quick.domain_public);
  base.public_ip = orNull(net.public_ip || quick.public_ip);
  if (!base.difficulty) {
    base.difficulty = orNull((isObj(sv.meta) ? sv.meta.difficulty : null));
  }

  const declaredSubnets = Array.isArray(net.subnets) ? net.subnets
    : (Array.isArray(net.segments) ? net.segments : []);
  base.subnets = declaredSubnets.map(normalizeSubnet).filter(Boolean);

  base.firewall = isObj(net.firewall) ? net.firewall
    : (isObj(it.firewall) ? it.firewall : null);

  // The same three-way fallback utils/answer-key-risk-assessment.js:41 already
  // uses. Kept identical on purpose: two readers of one fact must not disagree
  // about where the fact lives.
  base.stakeholders = asArray(
    Array.isArray(sv.stakeholders) ? sv.stakeholders
      : (Array.isArray(threats.stakeholders) ? threats.stakeholders : root.stakeholders)
  ).filter(isObj);

  base.weaknesses = {
    governance: weaknessList(isObj(profiles.governance_and_policy)
      ? profiles.governance_and_policy.deliberate_weaknesses : null),
    it: weaknessList(it.deliberate_weaknesses),
    network: weaknessList(net.deliberate_weaknesses),
    // Kept SEPARATE from the instructor_view triple above: they are two
    // different sets, and only the threat one is guaranteed to name a real host.
    threat: weaknessList(tp.deliberate_weaknesses),
  };

  if (layout === 'real_intake' && base.subnets.length === 0) {
    gaps.push({ field: 'network.segments', code: 'REAL_INTAKE_NO_NETWORK_PLAN' });
  }

  const profileAssets = Array.isArray(net.assets) ? net.assets
    : (Array.isArray(root.assets) ? root.assets : []);
  const anyServices = profileAssets.some(a => isObj(a) && Array.isArray(a.services) && a.services.length > 0);
  if (profileAssets.length > 0 && !anyServices) {
    gaps.push({ field: 'network.assets[].services', code: 'PROFILE_ASSETS_DECLARE_NO_SERVICES' });
  }

  if (base.public_ip) {
    gaps.push({ field: 'network.public_ip', code: 'PROFILE_PUBLIC_IP_NOT_ROUTABLE' });
  }

  return base;
}

// ─── specFingerprint ────────────────────────────────────────────────────────

/**
 * A stable 16-hex handle for "which environment was this plan compiled
 * against". Deterministic: no clock, no I/O, no ordering surprises — spec order
 * IS the material, because spec order is what assigns the octets.
 *
 * Only the six facts a plan can actually contradict are hashed. A changed
 * post_clone_scripts list does not invalidate a scope decision, and hashing it
 * would make every proposal look stale for no reason.
 */
function specFingerprint(spec) {
  const vms = asArray(spec && spec.vms);
  const material = vms.map((v) => {
    const vm = isObj(v) ? v : {};
    return [
      vm.name == null ? null : String(vm.name),
      vm.hostname == null ? null : String(vm.hostname),
      vm.role == null ? null : String(vm.role),
      Number.isInteger(vm.ipOctet) ? vm.ipOctet : null,
      vm.template_vmid == null ? null : vm.template_vmid,
      !!vm.synthetic,
    ];
  });
  return crypto.createHash('sha256').update(JSON.stringify(material)).digest('hex').slice(0, 16);
}

// ─── Scope rules ────────────────────────────────────────────────────────────

function inferScopeKind(value) {
  const v = str(value);
  if (!v) return 'text';
  if (CIDR_RE.test(v)) return 'cidr';
  if (/^https?:\/\//i.test(v)) return 'url';
  if (v.includes('*')) return 'hostname_pattern';
  return 'vm';
}

/**
 * Read a stored scope list tolerantly.
 *
 * engagement-model.validateScopeRules is the AUTHORING-time normalizer and it
 * writes {kind, value, note}. This reader still lifts a bare string and still
 * infers a kind, because a row can be written by psql and because a plan that
 * throws on a legacy shape is a plan nobody can look at.
 */
function readScopeRules(raw) {
  const out = [];
  const seen = new Set();
  for (const entry of asArray(raw)) {
    let kind;
    let value;
    let note = null;
    if (isObj(entry)) {
      kind = lc(entry.kind);
      value = str(entry.value);
      note = orNull(entry.note);
      if (!SCOPE_KINDS.includes(kind)) kind = inferScopeKind(value);
    } else {
      value = str(entry);
      if (!value) continue;
      kind = inferScopeKind(value);
    }
    if (kind === 'all') value = '';
    else if (!value) continue;
    const dedupe = `${kind}|${value.toLowerCase()}`;
    if (seen.has(dedupe)) continue;
    seen.add(dedupe);
    out.push({ kind, value, note });
  }
  return out;
}

function isResolvableRule(rule) {
  return RESOLVABLE_SCOPE_KINDS.includes(rule.kind);
}

/** Host matching for the RESOLVABLE kinds only. Case-insensitive, trimmed. */
function ruleMatchesHost(rule, host) {
  if (rule.kind === 'all') return true;
  const value = lc(rule.value);
  if (!value) return false;
  if (rule.kind === 'vm') return lc(host.vm_name) === value || lc(host.hostname) === value;
  if (rule.kind === 'role') return lc(host.role) === value;
  return false;
}

// ─── Exposure ───────────────────────────────────────────────────────────────

function nicsForPlacement(placement) {
  // engagement-model.js owns this mapping (its PLACEMENT_SEGMENTS), because the
  // authoring-time validator and the compile must write the SAME nics array or
  // the whole point is lost. Its version wins whenever it is exported; the
  // local table below is the totality fallback and must stay identical to it.
  if (M && typeof M.nicsForPlacement === 'function') {
    try {
      const nics = M.nicsForPlacement(placement);
      if (nics === null || Array.isArray(nics)) return nics;
    } catch (_err) { /* total by contract */ }
  }
  // 'pivot'    — the dual-homed bridge. TWO nics is what makes
  //              assignLaneAddressing's existing filter skip the .80-.99 band
  //              (profile-to-spec.js:176-179) and what makes
  //              resolveVmSegments return two segments
  //              (lane-networking.js:374 — "explicit wins"), so the synthesizer
  //              and the deployer reach the same conclusion from the same data.
  // 'internal' — single-homed on the internal segment; only reachable once the
  //              pivot is owned.
  // 'public'   — null on purpose: single-homed ext is already the v3 default
  //              (lane-networking.js:379-381), so writing it would be a no-op
  //              that also overrides any future default. Leave the spec alone.
  if (placement === 'pivot') return [{ segment: 'ext' }, { segment: 'int' }];
  if (placement === 'internal') return [{ segment: 'int' }];
  return null;
}

/**
 * Read a stored exposure_plan tolerantly.
 *
 * AN UNRECOGNISED PLACEMENT IS REPORTED, NOT SWALLOWED. It still READS as
 * 'public' — the v3 default, which maps to null nics and therefore leaves the
 * spec alone, so the least destructive reading of an unreadable value — but it
 * is announced, because the column's own CHECK constrains SHAPE only (the
 * placement vocabulary is enforced by engagement-model.validateExposurePlan, on
 * the authoring path). A row written by psql, by an import script, or by a
 * future writer that skipped the validator would otherwise silently rehome a
 * machine and nothing anywhere would say so.
 */
function readExposurePlan(raw, problems) {
  const out = [];
  const seen = new Set();
  for (const entry of asArray(raw)) {
    if (!isObj(entry)) continue;
    const vmName = str(entry.vm_name || entry.name || entry.target_vm);
    if (!vmName) continue;
    const key = vmName.toLowerCase();
    // TWO ENTRIES FOR ONE MACHINE ARE TWO CONTRADICTORY STATEMENTS, and
    // collapsing them to the first is a decision, not a no-op. [{b,pivot},
    // {b,internal}] used to yield one entry and ZERO problems — the author said
    // both "this is the bridge" and "this is behind the bridge" about the same
    // host, and nothing anywhere told them which reading survived. It still
    // survives (first wins, so the reading cannot flip on a re-save), but it is
    // announced.
    if (seen.has(key)) {
      const first = out.find(e => e.vm_name.toLowerCase() === key) || null;
      emit(problems, 'EXPOSURE_DUPLICATE_VM', 'warn',
        `The exposure plan places '${vmName}' more than once — first as `
        + `'${first ? first.placement : '(unreadable)'}', then as '${str(entry.placement) || '(empty)'}'. `
        + 'A machine has one placement, so only the FIRST entry is read and the rest are dropped. Delete the '
        + 'entry you did not mean, rather than leaving two statements that disagree.',
        'exposure_plan');
      continue;
    }
    seen.add(key);
    const declared = lc(entry.placement);
    const placement = EXPOSURE_PLACEMENTS.includes(declared) ? declared : 'public';
    if (placement !== declared && problems) {
      emit(problems, 'EXPOSURE_PLACEMENT_UNKNOWN', 'warn',
        `'${vmName}' is stored with the placement '${str(entry.placement) || '(empty)'}', which is not one of `
        + `${EXPOSURE_PLACEMENTS.join(', ')}. It is being read as '${placement}' — single-homed on the outside, `
        + 'which is what an ordinary machine already gets — so re-place it deliberately rather than leaving '
        + 'this reading to stand.',
        'exposure_plan');
    }
    out.push({
      vm_name: vmName,
      placement,
      services: asArray(entry.services).map(str).filter(Boolean),
      note: orNull(entry.note),
    });
  }
  return out;
}

function servicePort(token) {
  const s = str(token);
  const idx = s.indexOf('/');
  const n = parseInt(idx === -1 ? s : s.slice(0, idx), 10);
  return Number.isInteger(n) ? n : null;
}

/** 80 when the host speaks it, else 443, else 80 — the port the brief prints. */
function surfacePort(services) {
  const ports = asArray(services).map(servicePort).filter(p => p != null);
  if (ports.includes(80)) return 80;
  if (ports.includes(443)) return 443;
  return 80;
}

// ─── Techniques ─────────────────────────────────────────────────────────────

/**
 * Rules of engagement, deterministic on (perspective, credential_posture).
 *
 * OWASP classics only, and nothing exotic: this environment is a first
 * engagement for beginners, so a technique list that reads like a red-team
 * scope would be teaching the wrong lesson before the first one has landed.
 *
 * Every REFUSAL carries its own note, because the brief renders refusals as
 * prose and "not allowed" with no reason is the fastest way to get a rule
 * broken by someone who assumed it was boilerplate.
 */
function buildTechniques(perspective, credentialPosture) {
  const allowed = [
    {
      key: 'network_scanning',
      label: 'Network scanning and host discovery',
      allowed: true,
      constraint: 'Only against addresses inside the environment named in scope.',
      note: 'Start here. An inventory you built yourself is worth more than one you were handed.',
    },
    {
      key: 'service_enumeration',
      label: 'Service and version enumeration',
      allowed: true,
      constraint: null,
      note: 'Banner grabbing, version probes and default-page fingerprinting on in-scope hosts.',
    },
    {
      key: 'web_application_testing',
      label: 'Web application testing',
      allowed: true,
      constraint: 'Manual testing and low-rate automated scanning only.',
      note: 'Injection, broken access control, insecure direct object reference, and the rest of the OWASP top ten.',
    },
    {
      key: 'default_credential_testing',
      label: 'Default and weak credential testing',
      allowed: true,
      constraint: 'At most five attempts per account per hour, so nothing gets locked out.',
      note: 'Vendor defaults and obvious reuse. This is testing a control, not running a wordlist.',
    },
    {
      key: 'local_privilege_escalation',
      label: 'Local privilege escalation on a host already accessed',
      allowed: true,
      constraint: 'Only on hosts you reached through an in-scope finding.',
      note: 'Escalation demonstrates impact. Record the exact path you took.',
    },
  ];

  if (perspective === 'external') {
    allowed.push({
      key: 'content_discovery',
      label: 'Content and directory discovery',
      allowed: true,
      constraint: 'Low-rate only; stop if the site degrades.',
      note: 'From the outside, an unlinked path is often the entire finding.',
    });
  }

  if (perspective === 'internal' && credentialPosture === 'credentialed') {
    allowed.push({
      key: 'internal_lateral_movement',
      label: 'Lateral movement using the accounts the client issued',
      allowed: true,
      constraint: 'Only with the accounts listed under WHAT YOU ARE GIVEN.',
      note: 'The point of an issued account is to show what one ordinary user can reach.',
    });
  }

  const refused = [
    {
      key: 'denial_of_service',
      label: 'Denial of service and resource exhaustion',
      allowed: false,
      constraint: null,
      note: 'Availability is the client’s, not yours to spend. A finding you cannot demonstrate twice is not a finding.',
    },
    {
      key: 'social_engineering',
      label: 'Social engineering of staff',
      allowed: false,
      constraint: null,
      note: 'The people in this environment did not consent to being tested. Test the systems.',
    },
    {
      key: 'physical_access',
      label: 'Physical access and on-site entry',
      allowed: false,
      constraint: null,
      note: 'Out of scope for this piece of work, and no authorisation letter exists to cover it.',
    },
    {
      key: 'destructive_exploitation',
      label: 'Destructive exploitation, data deletion and ransomware simulation',
      allowed: false,
      constraint: null,
      note: 'Prove access; never destroy state. A restored backup is not evidence, it is cleanup.',
    },
    {
      key: 'offline_password_cracking',
      label: 'Offline hash cracking',
      allowed: false,
      constraint: null,
      note: 'Dumping a hash is the finding. Cracking it adds nothing the report needs.',
    },
  ];

  return allowed.concat(refused);
}

// ─── Objectives ─────────────────────────────────────────────────────────────

/**
 * Objective DEFINITIONS. Achievement is NOT stored here and never will be.
 *
 * (vm_name, flag_type) is EXACTLY cybercore_lane_flag's unit — its UNIQUE is
 * (lane_id, vm_name, flag_type) and it already carries an unused `points`
 * column (front-end/migrations/023_lane_flags.sql:29-40) — so per-engagement
 * scoring is a VIEW over a table that already exists rather than a fourth
 * progress tracker.
 *
 * LXC machines are skipped because flag-manager skips them, and the attack box
 * is absent because it is not in spec.vms and plantFlagsForLane never plants on
 * it (challenge-lane-deployer.js:1747 filters v.source !== 'instructor').
 */
function buildObjectives(hosts, rawVms) {
  const out = [];
  for (let i = 0; i < hosts.length; i += 1) {
    const type = (rawVms[i] || {}).type || 'qemu';   // verbatim, as the authority reads it
    if (type === 'lxc') continue;
    const host = hosts[i];
    const label = host.hostname || host.vm_name;
    for (const flagType of ['user', 'root']) {
      out.push({
        objective_key: `flag-${host.vm_name}-${flagType}`,
        title: `Recover the ${flagType} flag on ${label}`,
        points: flagType === 'root' ? 20 : 10,
        maps_to: { kind: 'flag', vm_name: host.vm_name, flag_type: flagType },
      });
    }
  }
  return out;
}

// ─── Credentials ────────────────────────────────────────────────────────────

/**
 * ACCOUNT INTENTS ONLY — NEVER a secret.
 *
 * The slots are the AUTHORED issued_credentials, verbatim; they are never
 * derived, because an account the client did not agree to hand over is an
 * account that does not exist. engagement-model.validateIssuedCredentials has
 * already built each entry from a whitelist, so a key like `password` was
 * dropped before the row was written; this reader copies only the same known
 * keys, so a row written by some other writer cannot smuggle one through the
 * compile either.
 */
function readCredentialSlots(raw, knownVmNames) {
  const out = [];
  for (const entry of asArray(raw)) {
    if (!isObj(entry)) continue;
    const slotKey = str(entry.slot_key);
    if (!slotKey) continue;
    const delivery = isObj(entry.delivery) ? entry.delivery : {};
    const targetVm = orNull(entry.target_vm);
    out.push({
      slot_key: slotKey,
      username: orNull(entry.username),
      target_vm: targetVm,
      account_kind: orNull(entry.account_kind) || 'local',
      privilege: orNull(entry.privilege),
      source: orNull(entry.source) || 'cloudinit',
      delivery: {
        target: orNull(delivery.target) || 'console',
        vm_name: orNull(delivery.vm_name),
        dir: orNull(delivery.dir) || '/opt/engagement',
        filename: orNull(delivery.filename) || 'credentials.txt',
        owner: orNull(delivery.owner),
        mode: orNull(delivery.mode) || '600',
      },
      note: orNull(entry.note),
      resolved: targetVm == null ? true : knownVmNames.has(targetVm.toLowerCase()),
    });
  }
  return out;
}

const DELIVERY_NOTE =
  'The per-lane secret is minted at deploy time and delivered as a FILE on the console, never as a '
  + 'script argument: src/utils/password-generator.js:13 guarantees a symbol drawn from !@#$%&*, and '
  + 'script-executor.js interpolates script_args UNQUOTED onto a command line (:249 for PowerShell, '
  + ':624 for sh), where a single & backgrounds the command. Nothing secret is stored on the '
  + 'engagement row itself — this list records WHICH accounts the client agreed to hand over, and '
  + 'nothing more.';

/**
 * A prefill for an engagement that says it is credentialed but lists no
 * accounts. A derived USERNAME and a target machine — and nothing else, ever.
 *
 * The username comes from a NON-EXECUTIVE stakeholder because the account a
 * client actually hands a tester on day one is a rank-and-file one; an
 * executive's account would make the whole engagement a privilege story from
 * the first minute.
 */
function suggestCredentialSlot(facts, hosts, rawVms) {
  const EXEC = /CEO|Owner|President|Principal|Director|Superintendent|CFO|COO|CIO|CISO/i;
  let username = null;
  for (const s of facts.stakeholders) {
    if (EXEC.test(str(s.role))) continue;
    const email = str(s.email);
    const local = email.includes('@') ? email.split('@')[0] : '';
    const cleaned = local.toLowerCase().replace(/[^a-z0-9._-]/g, '');
    if (cleaned) { username = cleaned; break; }
  }
  if (!username) username = 'engagement.user';

  let targetVm = null;
  for (let i = 0; i < hosts.length; i += 1) {
    const vm = rawVms[i] || {};
    if (hosts[i].synthetic) continue;
    if (lc(vm.os_family) !== 'linux') continue;
    targetVm = hosts[i].vm_name;
    break;
  }
  if (!targetVm && hosts.length) targetVm = hosts[0].vm_name;

  return [{
    slot_key: 'client_issued_1',
    username,
    account_kind: 'local',
    target_vm: targetVm,
    privilege: 'standard',
    source: 'cloudinit',
    delivery: {
      target: 'console',
      vm_name: null,
      dir: '/opt/engagement',
      filename: 'credentials.txt',
      owner: null,
      mode: '600',
    },
    note: 'Suggested starting account. Confirm with the client before the engagement opens.',
  }];
}

// ─── asset_selection ────────────────────────────────────────────────────────

/**
 * EXACTLY FOUR KEYS, and rung 3 is byte-identical to
 * routes/profile-deploy.js:108-116 defaultAssetSelection.
 *
 * Rung 2 of the earlier draft — "an external engagement deploys only its public
 * surface" — is DELETED and must not come back. A one-machine external
 * engagement has nothing to pivot INTO, and the whole point of the external
 * exercise is: exploit the exposed host, then pivot to the internal segment.
 * SCOPE and PLACEMENT are different questions from DEPLOYED SET. What
 * perspective changes is (i) what the brief names as in scope and (ii) which
 * host is the bridge — never how many machines come up.
 *
 *   1. a stored asset_selection wins, mapped to the same four keys
 *   2. (deleted — see above)
 *   3. included = role === 'server', byte-identical to defaultAssetSelection
 *   4. AUTHORED scope then constrains it. DERIVED scope never does: derived
 *      scope DESCRIBES the default selection, authored scope CONSTRAINS it, and
 *      that distinction is the only reason rung 3 stays byte-identical for
 *      every engagement that exists today.
 */
function buildAssetSelection({ stored, hosts, rawVms, authoredIn, authoredOut }) {
  if (asArray(stored).length > 0) {
    return asArray(stored).filter(isObj).map(s => ({
      hostname: s.hostname,
      role: s.role,
      os: s.os,
      included: !!s.included,
    }));
  }

  const rows = hosts.map((host, i) => {
    const vm = rawVms[i] || {};
    // The spec carries os_family/os_version, an asset carries a single human
    // `os` string. Prefer the spec's own `os` when it has one so a caller that
    // round-trips assets through the spec gets its string back untouched.
    const os = vm.os !== undefined ? vm.os
      : (vm.os_family !== undefined ? vm.os_family : null);
    return {
      hostname: host.hostname,
      role: host.role,
      os,
      included: String(host.role || '').toLowerCase() === 'server',
    };
  });

  if (authoredIn.length === 0 && authoredOut.length === 0) return rows;

  return rows.map((row, i) => {
    const host = hosts[i];
    let included = row.included;
    for (const rule of authoredIn) {
      if (rule.kind === 'vm' && ruleMatchesHost(rule, host)) included = true;
    }
    for (const rule of authoredOut) {
      if ((rule.kind === 'vm' || rule.kind === 'role') && ruleMatchesHost(rule, host)) included = false;
    }
    return { hostname: row.hostname, role: row.role, os: row.os, included };
  });
}

// ─── The compile ────────────────────────────────────────────────────────────

function emptyPlan({ engagementBlock, clientBlock, synthBlock, fingerprint, problems }) {
  return {
    compile_version: ENGAGEMENT_COMPILE_VERSION,
    engagement: engagementBlock,
    client: clientBlock,
    hosts: [],
    in_scope: [],
    out_of_scope: [],
    scope: { in: [], out: [] },
    declared_only: [],
    public_surface: null,
    start_position: null,
    exposure: [],
    credentials: { slots: [], delivery: 'file', delivery_note: DELIVERY_NOTE },
    techniques: [],
    objectives: [],
    asset_selection: [],
    capacity: { pinnable: 0, pinnable_capacity: PIN_CAPACITY, over_capacity: false },
    brief: { text: null, suggested_text: '', facts: null },
    synth: synthBlock,
    suggestions: null,
    spec_fingerprint: fingerprint,
    problems,
  };
}

/**
 * Compile an engagement.
 *
 * @param {object}  args
 * @param {object}  [args.engagement]  a ciab_engagement row (rowToEngagement's projection is fine)
 * @param {object}  [args.spec]        a synthesized spec — spec.vms[] is the ENTIRE host universe
 * @param {object}  [args.profile]     the client profile, for NARRATIVE facts only
 * @param {object}  [args.options]
 * @param {boolean} [args.options.attackBoxes=true]  reported as a DEPLOY ARGUMENT, not a spec key
 * @param {string}  [args.options.consoleVm]         routes/profile-deploy.js's console_vm override
 * @returns {object} a fully-shaped plan.
 *
 * TOTAL OVER JSON-DERIVED INPUT — the real contract, and not the absolute this
 * line used to claim. An unqualified never-throws-for-anything is literally
 * false for a hand-built object carrying a THROWING ACCESSOR: a vms[] entry
 * whose `name` is
 * a getter that throws propagates straight out of specFingerprint, and out of
 * the host loop after it. Guarding every property read against a hostile getter
 * would cost the readability of the whole file and buy nothing, because every
 * input this module can actually receive is JSON — a jsonb column, a request
 * body, a synthesized spec — and JSON has no getters. For those, and for null,
 * undefined, primitives and arrays in every position, it is total.
 */
function compileEngagementPlan(args) {
  // TOTAL MEANS TOTAL, AND A DEFAULT PARAMETER IS NOT A GUARD. `= {}` fires for
  // `undefined` ONLY, so destructuring the parameter list threw a bare
  // TypeError for compileEngagementPlan(null) — the one input a caller reaches
  // for when it has nothing yet, and precisely the throw the whole module
  // exists to replace with a problem code. Read the argument first, then pull
  // keys off a value that is certainly an object.
  const a = isObj(args) ? args : {};
  const problems = [];
  const eng = isObj(a.engagement) ? a.engagement : {};
  const specObj = isObj(a.spec) ? a.spec : {};
  const opts = isObj(a.options) ? a.options : {};
  const profile = a.profile === undefined ? null : a.profile;

  const descriptor = describeType(eng.engagement_type);
  const perspective = ['internal', 'external'].includes(lc(eng.perspective))
    ? lc(eng.perspective)
    : (['internal', 'external'].includes(lc(descriptor.perspective)) ? lc(descriptor.perspective) : 'internal');
  const credentialPosture = ['none', 'credentialed'].includes(lc(eng.credential_posture))
    ? lc(eng.credential_posture)
    : (['none', 'credentialed'].includes(lc(descriptor.credential_posture)) ? lc(descriptor.credential_posture) : 'none');

  const engagementSubnetScheme = str(eng.subnet_scheme) || 'v2';
  // Resolved HERE, above the host block, because laneAddressing needs it: a
  // machine's segments — and therefore its address — depend on the scheme, so
  // hosts[].ip_octet cannot be filled in before the scheme is known. Only the
  // VALUE moves up; the SCHEME_MISMATCH problem is still emitted at §2, after
  // the SPEC_EMPTY early return, so an engagement with no machines still says
  // ONE thing about its ONE root cause.
  const specScheme = str(specObj.subnet_scheme);
  const isV3 = engagementSubnetScheme === 'v3' || specScheme === 'v3';
  const facts = readClientFacts(profile);
  const fingerprint = specFingerprint(specObj);

  const engagementBlock = {
    engagement_id: eng.engagement_id == null ? null : eng.engagement_id,
    engagement_type: str(eng.engagement_type) || DEFAULT_TYPE_KEY,
    display_name: displayNameFor(eng, descriptor),
    known_type: !!descriptor.known,
    perspective,
    credential_posture: credentialPosture,
    live: liveFor(eng),
    subnet_scheme: engagementSubnetScheme,
    max_students: intOrNull(eng.max_students),
  };

  const clientBlock = {
    profile_id: facts.profile_id,
    company_name: facts.company_name,
    industry: facts.industry,
    domain_public: facts.domain_public,
    // RULE 5. This is the ONLY assignment of the profile's public IP anywhere in
    // a compiled plan. It is a per-PROFILE RFC 5737 literal
    // (ai/profile/index.js:184), so every lane cut from one client would
    // advertise the identical address — which is why start_position is
    // LANE-RELATIVE and why nothing downstream may copy this value. The test
    // pins it: JSON.stringify(plan) must contain this string nowhere else.
    public_ip: facts.public_ip,
    layout: facts.layout,
  };

  const synthBlock = {
    // The ONLY two keys synthesizeSpecFromProfile reads that are not
    // reservation-owned. vxlanBlock is deliberately absent: it belongs to the
    // reservation and adoptedSpec() overwrites it (profile-deploy.js's merge).
    subnetScheme: engagementSubnetScheme,
    attackBoxes: opts.attackBoxes !== false,
  };

  // ── 1. SPEC ───────────────────────────────────────────────────────────────
  const rawVms = asArray(specObj.vms).filter(v => isObj(v) && (str(v.name) || str(v.hostname)));
  if (rawVms.length === 0) {
    // ONE root cause, ONE problem. No SCOPE_EMPTY, no EXTERNAL_NO_SURFACE, no
    // capacity note: they are all restatements of "there is nothing here", and
    // a caller staring at four errors cannot tell which one to fix.
    emit(problems, 'SPEC_EMPTY', 'error',
      'This engagement has no environment to compile against: the synthesized spec contains no machines. '
      + 'Select at least one asset, or synthesize the spec before compiling.',
      'utils/profile-to-spec.js synthesizeSpecFromProfile');
    return emptyPlan({ engagementBlock, clientBlock, synthBlock, fingerprint, problems });
  }

  const hosts = [];
  const knownVmNames = new Set();
  // hosts[i] <-> rawVms[i] <-> addressing[i], all in SPEC ORDER. addressing is
  // the deployer's view of each machine and the ONE answer everything below
  // reads: what segments it lands on, whether that makes it the bridge, whether
  // it can be pinned, and therefore what address it actually has.
  const addressing = [];
  for (const vm of rawVms) {
    const vmName = str(vm.name) || str(vm.hostname);
    const hostname = str(vm.hostname) || vmName;
    const role = vm.role == null ? null : String(vm.role);
    // A spec VM already carries the services the synthesizer resolved scripts
    // from. inferServices is the fallback for a hand-written or legacy spec, and
    // it is the repo's ONLY existing service derivation — a second one would be
    // a second answer to a question that already has one.
    let services = asArray(vm.services).map(str).filter(Boolean);
    if (services.length === 0) {
      try {
        services = asArray(inferServices({
          hostname,
          os: vm.os != null ? vm.os : (vm.os_version || vm.os_family || null),
          function: vm.function,
          role,
        })).map(str).filter(Boolean);
      } catch (_err) {
        services = [];
      }
    }
    let isWeb = false;
    try {
      // EXACTLY ONE ARGUMENT — see the header. vuln-app-generator.js:52 does
      // assets.find(isWebServer), so a second parameter would be the index.
      //
      // A 'dmz' MACHINE IS ASKED THE QUESTION AS A SERVER. isWebServer's first
      // line is `role !== 'server' -> false` (profile-to-spec.js:98-99), and
      // 'dmz' is precisely the role a dual-homed web host carries — the seed
      // emits { name:'web01', role:'dmz', services:['80/HTTP'] }
      // (topology-seed.js:203-208). Asked verbatim, this compile answered "no
      // machine here serves a web site" about the one machine that does, and an
      // external engagement then failed with four errors at once. The coercion
      // happens HERE, on the argument, because profile-to-spec.js is
      // byte-pinned by test/ciab-deploy-parity.test.js and its ARITY is
      // load-bearing — so the predicate itself must not be touched. Everything
      // else about the test (a declared 80/443 service, or a web* hostname
      // token) stays exactly isWebServer's.
      const webRole = role === PIVOT_ROLE ? 'server' : role;
      isWeb = !!isWebServer({ hostname, role: webRole, services });
    } catch (_err) {
      isWeb = false;
    }

    // The RAW name, not the trimmed one: prepareGoadMacs keys on
    // vm.name.toLowerCase() with no trim (goad-deploy.js:297,300).
    const addr = laneAddressing(vm, isV3, goadLabOctet(specObj, vm.name));
    addressing.push(addr);
    knownVmNames.add(vmName.toLowerCase());
    hosts.push({
      vm_name: vmName,
      hostname,
      role,
      synthetic: !!vm.synthetic,
      // The segments the deployer will really attach, in NIC order — all four
      // rungs of resolveVmSegments, including the AD-lab one. Emitted because an
      // octet with no segment beside it is half a fact: .10 on the internal base
      // and .10 on the external base are different addresses.
      segments: addr.segments.slice(),
      segment_for_address: addr.segment_for_address,
      goad_lab_vm: addr.goad_lab_vm,
      // NOT `vm.ipOctet` verbatim. A machine the deployer dual-homes lands on
      // .240 on BOTH segments and never takes a band reservation at all
      // (challenge-lane-deployer.js:310-311 skips it, :768-771 pins it), so a
      // spec-carried .8x on such a host is a true statement about a spec field
      // and a false one about the lane.
      ip_octet: addr.ip_octet,
      dns_alias: (asArray(vm.dns_aliases).map(str).filter(Boolean)[0]) || dnsLabel(hostname) || null,
      is_web: isWeb,
      services,
      placement: null,
      nics: null,
      in_scope: false,
      scope_reason: 'not_selected',
    });
  }

  // A ROLE THAT IS A KNOWN OUTSIDE ROLE EXCEPT FOR ITS SPELLING.
  // topology-editor.js:318 renders Role as a FREE-TEXT input, so 'DMZ' is a
  // plausible thing to type — and lane-networking.js:379 compares with ===, so
  // it is NOT the dual-homing role. The comparison here stays case-SENSITIVE
  // and whitespace-SENSITIVE for exactly that reason (see PIVOT_ROLE); what was
  // missing was anyone TELLING the author. Written 'DMZ', the one web host in an
  // external engagement stops being a web host at all (isWebServer's coercion is
  // keyed on 'dmz' too), and the compile answers with four errors at once —
  // nothing in scope, no web asset, no surface, no bridge — none of which names
  // the real cause. This says the cause, once, before any of them.
  //
  // CASING WAS NEVER THE WHOLE CASE. topology-editor.js:349-352 stores the role
  // input VERBATIM — only `services` and `default_scripts` are trimmed there —
  // so 'dmz ' with a trailing space is a storable, invisible, byte-different
  // role that reproduces the identical four errors. A diagnostic that closed
  // only the casing case left the harder-to-see half open, which is finding N-F.
  // The trigger widens to any role that matches after trimming AND
  // lower-casing; the COMPARISON the environment makes is untouched.
  for (const host of hosts) {
    const role = host.role == null ? '' : String(host.role);
    if (role === '' || isExternalRole(role)) continue;
    const canonical = EXTERNAL_ROLES.find(r => r === role.trim().toLowerCase());
    if (!canonical) continue;
    // NAME THE DIFFERENCE, because a trailing space is invisible in a message
    // that merely quotes both spellings. "'dmz ' is not 'dmz'" reads like a
    // typo in the diagnostic itself unless the reason is spelled out.
    const trimmed = role.trim();
    const spellingNote = trimmed !== role
      ? (trimmed === canonical
        ? `The letters are right; the value carries ${role.startsWith(trimmed) ? 'trailing' : 'leading'} whitespace, which is stored verbatim and is invisible in the editor.`
        : 'It differs both in case and in surrounding whitespace, and whitespace is stored verbatim.')
      : 'It differs only in case.';
    emit(problems, 'ROLE_CASE_MISMATCH', 'warn',
      `'${host.vm_name}' carries the role '${role}', which the environment reads byte for byte: only `
      + `the lower-case '${canonical}', with nothing around it, is recognised, so this machine is treated as `
      + `an ordinary internal server. ${spellingNote} ${canonical === PIVOT_ROLE
        ? 'It is not homed on both segments, it does not answer at .240, and it is not read as the web host.'
        : 'It is not treated as the tester console, so this plan will place it like any other machine.'} `
      + `Change the role to exactly '${canonical}'.`,
      'src/utils/lane-networking.js:379');
  }

  // A CARD NAMING A SEGMENT THIS LANE HAS NO BRIDGE FOR IS A HARD DEPLOY THROW.
  // resolveVmNics' bridgeFor (lane-networking.js) looks every segment up in
  // resolveSegmentBridges' table and throws when it misses — so a spec with
  // nics [{segment:'dmz'}] does not deploy at all. The compile used to emit a
  // healthy-looking plan for it (placement, an octet, one info problem), which
  // is finding N-C: the ONE thing that machine guarantees was the one thing
  // nothing said. The message reproduces the deployer's own wording so the
  // failure a reader eventually sees in a task log is recognisably this.
  for (let i = 0; i < hosts.length; i += 1) {
    const addr = addressing[i];
    if (addr.unknown_segments.length === 0) continue;
    emit(problems, 'NICS_UNKNOWN_SEGMENT', 'error',
      `'${hosts[i].vm_name}' has a network card on the segment `
      + `${addr.unknown_segments.map(s => `'${s}'`).join(', ')}, which this lane does not have — it has `
      + `${addr.known_segments.map(s => `'${s}'`).join(' and ')}. The deploy stops with an error at the moment `
      + 'it builds that card, so nothing in this environment comes up. Point the card at one of the segments '
      + 'this lane really has, or remove it.',
      'src/utils/lane-networking.js resolveVmNics bridgeFor');
  }

  // AN AD LAB HOST IS ADDRESSED BY THE LAB, NOT BY THIS PLAN.
  // goad-deploy.js:286-320 gives every spec VM whose name matches the selected
  // lab a MAC-keyed reservation at the LAB's octet on the INTERNAL base, and
  // challenge-lane-deployer.js:306 then skips it when handing out band octets.
  // The ipOctet such a machine carries in the spec is therefore inert, and a
  // plan that printed it would name an address nothing answers on.
  for (let i = 0; i < hosts.length; i += 1) {
    const addr = addressing[i];
    if (!addr.goad_lab_vm) continue;
    const declared = Number.isInteger(rawVms[i] && rawVms[i].ipOctet) ? rawVms[i].ipOctet : null;
    emit(problems, 'GOAD_HOST_ADDRESSED_BY_LAB', 'info',
      `'${hosts[i].vm_name}' is one of the directory lab's own machines, so the lab addresses it: it lands `
      + `at .${addr.goad_lab_octet} on the INTERNAL segment, and it takes no address from the pinning band.`
      + (declared != null && declared !== addr.goad_lab_octet
        ? ` The spec asks for .${declared}; that value is not used.`
        : ''),
      'utils/goad-deploy.js prepareGoadMacs');
    if (!addr.dual_homed) continue;
    // The bridge role sits ABOVE lab membership in resolveVmSegments, so this
    // machine really is dual-homed and really is pinned to .240 on both
    // segments — while the lab has ALSO reserved it at .<lab octet>. Two
    // addressing mechanisms, one machine, and neither knows about the other.
    emit(problems, 'GOAD_HOST_IS_BRIDGE', 'warn',
      `'${hosts[i].vm_name}' is one of the directory lab's own machines AND carries the bridge role. The `
      + `bridge role wins when the cards are built, so it is pinned to .${DUAL_HOMED_OCTET} on both segments `
      + `— while the lab has separately reserved it at .${addr.goad_lab_octet} on the internal one. Two `
      + 'mechanisms address the same machine and neither knows about the other. Give the bridge role to a '
      + 'machine that is not part of the directory lab.',
      'src/utils/lane-networking.js:374-381');
  }

  // ── 2. SCHEME ─────────────────────────────────────────────────────────────
  // This compile is the FIRST reader of spec.subnet_scheme in the repo. The
  // divergence it surfaces is documented at lane-reservation.js:91-105 —
  // reserve at v2, deploy at v3, and every internal VNet is orphaned forever —
  // and until now it was invisible until the lane was already wrong.
  if (specScheme && specScheme !== engagementSubnetScheme) {
    emit(problems, 'SCHEME_MISMATCH', 'warn',
      `This engagement reserved its network at ${engagementSubnetScheme} but the spec was synthesized at `
      + `${specScheme}. Deploying the two together leaves the segments the reservation carved unused, and the `
      + 'allocator never re-uses a block. Re-synthesize the spec, or reserve again at the scheme you want.',
      'utils/lane-reservation.js:91-105');
  }

  // ── 3. PUBLIC SURFACE — three rungs ───────────────────────────────────────
  // Mirrors profile-to-spec.js:385-461's own targeting order, so the host this
  // plan calls the surface is the host the synthesizer would put the site on.
  const hostByName = new Map(hosts.map(h => [h.vm_name.toLowerCase(), h]));
  const addrByName = new Map(hosts.map((h, i) => [h.vm_name.toLowerCase(), addressing[i]]));
  // WHICH MACHINES HAVE ALREADY ANSWERED. Rung 1 of resolveVmSegments returns
  // before anything else is consulted, so for these hosts the compile is a
  // READER, not an author: it may report a disagreement, never resolve one by
  // overwriting. One map, built once, so every writer below asks the same
  // question in the same words.
  const authoredSegsByName = new Map();
  for (let i = 0; i < hosts.length; i += 1) {
    const segs = authoredSegmentsOf(rawVms[i]);
    if (segs) authoredSegsByName.set(hosts[i].vm_name.toLowerCase(), segs);
  }

  /**
   * ─── THE ATTACK BOX IS PLACED NOWHERE. BY CONSTRUCTION, NOT BY A GUARD. ───
   *
   * THE DECISION, AND WHY. Two readings were open:
   *   (a) an 'attacker' machine can never be given a placement or a card list
   *       by this compile, and an authored entry naming one is reported and
   *       IGNORED;
   *   (b) it can, with its own problem code, as long as its authored card ORDER
   *       is never rewritten.
   * (a) is the honest reading, and it is the one this module already promised
   * further down: "An 'attacker' machine is placed NOWHERE at all: the deploy
   * path owns its addressing, and a proposal that moved it would break the
   * console." (b) would make that sentence false, and would also make this
   * compile a SECOND owner of an address the gateway image already owns: the
   * baked firstboot publishes wan0:3389 -> ext .50 for the per-lane Kali, and
   * its stray-DNAT reaper deletes anything else that appears on 3389. A plan
   * that rehomes the console onto 'int' does not fail loudly; it produces a
   * lane whose one way in is gone.
   *
   * A PROMISE HELD AT ONE CALL SITE IS NOT AN INVARIANT. Three different places
   * can write a placement and a nics array — the derived loop, the appender for
   * machines the spec itself dual-homes, and this authored path — and the guard
   * existed only in the first. So the filter is applied HERE, at the single
   * point the authored plan ENTERS the compile, before anything reads it:
   * surface selection, placement, nics, octets and the pivot count all read
   * `storedExposure`, and none of them can now see an attack box at all.
   */
  const authoredExposure = readExposurePlan(eng.exposure_plan, problems);
  const storedExposure = authoredExposure.filter((entry) => {
    const host = hostByName.get(entry.vm_name.toLowerCase()) || null;
    if (!host || host.role !== ATTACKER_ROLE) return true;
    emit(problems, 'EXPOSURE_ATTACKER_NOT_PLACED', 'warn',
      `The exposure plan places '${entry.vm_name}' — the tester's own console — as '${entry.placement}'. `
      + 'That entry is ignored: the deploy path owns the console’s addressing, and it is reached on the '
      + 'external segment at .50 by a rule the gateway image bakes in. Moving it writes a card list onto the '
      + 'spec that wins over every default, and the console comes up with no way in. Remove the entry, or '
      + 'point it at a machine that is not the console.',
      'exposure_plan');
    return false;
  });

  let publicSurface = null;
  // AN AUTHORED ENTRY IS THE SURFACE ONLY IF IT IS ACTUALLY ON THE OUTSIDE.
  // `storedExposure[0]` used to be the fallback, so an exposure plan whose only
  // entry read {dc01, internal} — a perfectly ordinary thing to author, "put
  // the domain controller behind the bridge" — made dc01 the public surface,
  // and scope follows the surface, so the real web host was excluded from an
  // engagement built entirely around reaching it. A machine placed 'internal'
  // is by definition the one thing nobody outside can see.
  const authoredSurfaceEntry = storedExposure.find(e => e.placement === 'pivot')
    || storedExposure.find(e => e.placement === 'public')
    || null;
  if (authoredSurfaceEntry) {
    const host = hostByName.get(authoredSurfaceEntry.vm_name.toLowerCase()) || null;
    publicSurface = {
      target_vm: authoredSurfaceEntry.vm_name,
      target_port: surfacePort(authoredSurfaceEntry.services.length ? authoredSurfaceEntry.services : (host ? host.services : [])),
      dns_label: dnsLabel(authoredSurfaceEntry.vm_name) || null,
      source: 'authored',
      // Filled in from the RESOLVED exposure entry once §4 has run. It was a
      // literal 'pivot', which put a plan in the position of saying, in two
      // fields at once, that one machine both IS and IS NOT the dual-homed
      // bridge. placement is a fact about a machine's segments; it has exactly
      // one source, and it is not this branch.
      placement: null,
    };
  } else {
    // Rung 2 deliberately ignores the SYNTHETIC machine, even though it is a
    // web server by every test isWebServer applies (role 'server',
    // services ['80/HTTP']). The distinction is not technical, it is editorial:
    // 'asset' means the CLIENT has a web server in its file, 'synthetic' means
    // the environment supplied one. B1 renders those two sentences differently,
    // and collapsing them would make every client look like it runs a web site.
    //
    // A DUAL-HOMED WEB HOST IS PREFERRED OVER A SINGLE-HOMED ONE. Both are
    // 'asset' — the client has a web server in its file either way — but if one
    // of them is the machine the deployer will actually put on both segments,
    // that is the machine the outside can actually reach, and making it the
    // surface is what keeps the derived plan at exactly one bridge.
    const webHosts = hosts.filter(h => h.is_web && !h.synthetic);
    const webHost = webHosts.find(h => (addrByName.get(h.vm_name.toLowerCase()) || {}).dual_homed)
      || webHosts[0] || null;
    if (webHost) {
      publicSurface = {
        target_vm: webHost.vm_name,
        target_port: surfacePort(webHost.services),
        dns_label: webHost.dns_alias || dnsLabel(webHost.vm_name) || null,
        source: 'asset',
        placement: null,
      };
    } else {
      // The synthesizer appends its own 'vuln-app' VM when the profile has no
      // web server (profile-to-spec.js:436-460, template 1005, services
      // ['80/HTTP'], role 'server', synthetic:true). That machine is a real
      // deployable host, so an external engagement built on it is legitimate.
      const syntheticHost = hosts.find(h => h.synthetic && h.is_web) || null;
      const syntheticName = isObj(specObj.vuln_app_install)
        ? (str(specObj.vuln_app_install.target_vm) || 'vuln-app')
        : (syntheticHost ? syntheticHost.vm_name : '');
      if (syntheticName) {
        const host = hostByName.get(syntheticName.toLowerCase()) || null;
        publicSurface = {
          target_vm: syntheticName,
          target_port: surfacePort(host ? host.services : ['80/HTTP']),
          dns_label: (host && host.dns_alias) || dnsLabel(syntheticName) || null,
          source: 'synthetic',
          placement: null,
        };
      }
    }
  }

  // ── 4. EXPOSURE — placement, never publishing ─────────────────────────────
  //
  // THE MACHINES THE SPEC ITSELF ALREADY PLACES. A v3 qemu VM with role 'dmz',
  // and any VM carrying an explicit two-NIC array, is dual-homed by
  // lane-networking.js:374-381 whether or not any exposure plan mentions it —
  // so its placement is a FACT about the environment, not an opinion the plan
  // is free to have or to omit. Reading it from the spec is what stops an
  // authored plan that simply does not name such a machine from leaving it
  // unplaced while the deployer quietly pins it to .240 beside the declared
  // pivot, with nothing anywhere saying two machines now claim one address.
  //
  // `addr.dual_homed` is canBeDualHomed-aware, so a CONTAINER carrying an
  // explicit two-card list is not in this list: the deployer would give it one
  // card on the first segment and no address at all.
  //
  // AND NEITHER IS THE ATTACK BOX — this is the second of the three writers the
  // invariant above has to hold at. An 'attacker' host with an explicit
  // [{int},{ext}] list really IS dual-homed by the environment, so it used to
  // fall straight through to the appender, which stamped it 'pivot' and handed
  // it the CANONICAL [{ext},{int}] — silently reversing the order its author
  // wrote, and taking the console's own address with it. It is reported here
  // and placed nowhere.
  const specDualHomed = [];
  for (let i = 0; i < hosts.length; i += 1) {
    if (!addressing[i].dual_homed) continue;
    if (hosts[i].role === ATTACKER_ROLE) {
      emit(problems, 'ATTACKER_IS_DUAL_HOMED', 'error',
        `'${hosts[i].vm_name}' is the tester's own console, and the network-card list its spec carries homes `
        + `it on BOTH segments — which puts it at .${DUAL_HOMED_OCTET} on each, the same address the bridge `
        + 'takes. This plan proposes no placement and no card list for it, because the deploy path owns the '
        + 'console’s addressing and reaches it on the external segment at .50. Take the card list off that '
        + 'machine in the environment editor, or the bridge and the console will both answer at the same '
        + 'address.',
        'src/utils/lane-networking.js:374-381');
      continue;
    }
    specDualHomed.push({ host: hosts[i], addr: addressing[i] });
  }
  const specDualHomedNames = new Set(specDualHomed.map(x => x.host.vm_name.toLowerCase()));

  let exposureEntries = storedExposure;
  let exposureDerived = false;
  if (exposureEntries.length === 0) {
    if (perspective === 'external' && publicSurface) {
      // The bridge is whatever the SPEC already dual-homes; only when the spec
      // names none does the surface itself become the pivot. Everything else
      // real goes internal, so the estate still deploys in full and the
      // exercise is "find the bridge, cross it", not "here is your one machine".
      const surfaceKey = publicSurface.target_vm.toLowerCase();
      const surfaceAddr = addrByName.get(surfaceKey) || null;
      const surfaceIsSpecPivot = specDualHomedNames.has(surfaceKey);
      // THE CAPABILITY QUESTION IS ASKED BEFORE THE PLACEMENT IS STAMPED, not
      // after. This rung used to read `surfaceIsSpecPivot || nothing else is
      // dual-homed` and nothing more — so when the only web host in the client
      // file was a CONTAINER, or the engagement was scheduled on a flat v1/v2
      // lane, it wrote 'pivot', a two-card list and .240 onto a machine the
      // deployer gives one card and no fixed address. The brief then opened
      // with http://{ext_base}.240/ — an address nothing in that lane lives at.
      // canBeDualHomed is the whole of the difference.
      const surfaceCanBridge = !!(surfaceAddr && surfaceAddr.can_dual_home);
      const surfaceIsBridge = surfaceCanBridge
        && (surfaceIsSpecPivot || specDualHomed.length === 0);
      exposureEntries = [{
        vm_name: publicSurface.target_vm,
        placement: surfaceIsBridge ? 'pivot' : 'public',
        services: (hostByName.get(surfaceKey) || { services: [] }).services,
        // Only ONE pivot note survives, and it names .240 unconditionally,
        // because 'pivot' now implies canBeDualHomed and canBeDualHomed implies
        // v3 — so the case the old isV3 branch existed for can no longer reach
        // this line at all.
        note: surfaceIsBridge
          ? 'Derived: the exposed host, dual-homed on both segments and pinned to .240.'
          : (surfaceCanBridge
            ? 'Derived: reachable from the outside, but not the bridge — another machine is already dual-homed.'
            : `Derived: reachable from the outside, but it cannot be the bridge — ${bridgeBlockText(surfaceAddr ? surfaceAddr.dual_home_blocked_by : null)}.`),
      }];
      for (const host of hosts) {
        if (host.vm_name.toLowerCase() === surfaceKey) continue;
        if (host.synthetic) continue;
        // ROLE IS READ BEFORE ANYTHING IS STAMPED. This loop used to skip only
        // synthetic machines, so it wrote placement 'internal' and an explicit
        // nics [{segment:'int'}] onto EVERY other host — including the per-lane
        // Kali, whose role is 'attacker'. An explicit nics array WINS over every
        // inference (lane-networking.js:374-375), so B2's writeback would have
        // moved the student's console onto the internal segment and broken the
        // baked wan0:3389 -> ext .50 console contract.
        //
        // A 'dmz' machine falls through to the SAME appender that catches one
        // an authored plan omitted, so there is one place that decides a spec
        // pivot's placement. An 'attacker' machine is placed NOWHERE at all:
        // the deploy path owns its addressing, and a proposal that moved it
        // would break the console.
        if (isExternalRole(host.role)) {
          // WRITER ONE OF THREE. See the invariant beside `storedExposure`: the
          // authored path is filtered at entry, the appender skips it, and this
          // loop skips it here. All three, or it is not an invariant.
          if (host.role === ATTACKER_ROLE) continue;
          // The bridge appender below owns every machine the environment really
          // does dual-home, so there is exactly ONE place that decides a spec
          // pivot's placement and its note.
          if (specDualHomedNames.has(host.vm_name.toLowerCase())) continue;
          // A 'dmz' MACHINE THE ENVIRONMENT DOES NOT ACTUALLY DUAL-HOME.
          // resolveVmSegments guards the dual-homing rung with `type !== 'lxc'`
          // (lane-networking.js:379) and with isV3, so a container marked 'dmz'
          // gets ONE external card and on a v1/v2 lane nothing is dual-homed at
          // all. Skipping such a machine outright — which is what a blanket
          // role skip does — left it the ONE machine in a derived plan with no
          // placement, absent from the exposure list entirely, while the
          // EXPOSURE_DERIVED note claimed every other machine sat on the
          // internal segment. Its role still says it belongs outside, so
          // 'internal' would rewrite the author's intent; 'public' is the
          // reading that matches the segments it will really get, and it maps
          // to null nics, so the spec is still left alone.
          exposureEntries.push({
            vm_name: host.vm_name,
            placement: 'public',
            services: host.services,
            note: 'Derived: its role puts it outside, but it cannot be the bridge — '
              + `${bridgeBlockText((addrByName.get(host.vm_name.toLowerCase()) || {}).dual_home_blocked_by)}. `
              + 'It is reachable without bridging anything.',
          });
          continue;
        }
        exposureEntries.push({
          vm_name: host.vm_name,
          placement: 'internal',
          // Empty on purpose: an internal placement exposes NOTHING to the
          // external segment. What the host runs is on hosts[].services.
          services: [],
          note: 'Derived: reachable only after the exposed host is compromised.',
        });
      }
      exposureDerived = true;
    }
    // For perspective 'internal' the derived plan is deliberately EMPTY. An
    // internal engagement is a flat v2 lane with one segment, so it has no
    // placement opinions to express and inventing some would be a fiction.
  }

  // Whatever the plan says or omits, a machine the SPEC dual-homes is placed.
  // Appended rather than substituted: an authored plan is never silently
  // rewritten, so a machine the plan already names keeps the placement it was
  // given and the disagreement is REPORTED below instead.
  const placedNames = new Set(exposureEntries.map(e => e.vm_name.toLowerCase()));
  for (const { host } of specDualHomed) {
    const key = host.vm_name.toLowerCase();
    if (placedNames.has(key)) continue;
    placedNames.add(key);
    exposureEntries = exposureEntries.concat([{
      vm_name: host.vm_name,
      placement: 'pivot',
      services: host.services,
      note: 'From the environment: this machine is dual-homed on both segments by its role, and sits at .240.',
    }]);
    emit(problems, 'EXPOSURE_ROLE_IS_DUAL_HOMED', 'info',
      `'${host.vm_name}' is homed on BOTH segments by the environment itself — by its role, or by the `
      + 'network-card list its spec already carries — not because this plan says so, and it answers at .240 '
      + 'on each of them. It is shown here as the bridge so the paper and the environment describe the same '
      + 'machine.',
      'src/utils/lane-networking.js:374-381');
  }
  // ─── A PLACEMENT IS ONLY REAL IF THE DEPLOYER CAN CARRY IT OUT ─────────────
  //
  // THE LAST GATE, AND THE ONE THAT MAKES canBeDualHomed TOTAL. The derived
  // rung above asks the capability question before it stamps anything, but an
  // AUTHORED plan can still say {ctr, pivot} about a container, or name a
  // bridge on a flat v1/v2 lane. Left alone, such an entry counted toward
  // pivotNames (so EXTERNAL_NO_PIVOT stayed quiet), took .240, and had
  // [{ext},{int}] written onto a spec that cannot use it.
  //
  // It is DEMOTED to 'public' rather than dropped: the author's intent was
  // "this one faces outward", which is true and achievable; only the bridging
  // half is not. And the demotion is REPORTED, never silent — an unresolvable
  // vm_name is left alone here, because UNKNOWN_TARGET_VM already says the one
  // thing worth saying about it.
  //
  // WHAT IS PLACED BEFORE THE CAPABILITY GATE RUNS. PLACEMENT_REQUIRES_V3 below
  // is a statement about what this engagement ASKED FOR, so it must read the
  // pre-demotion list: demoting a v2 'pivot' to 'public' would otherwise delete
  // the very evidence of the mistake the warning exists to report.
  const preCapabilityPlacements = exposureEntries.map(e => e.placement);

  // ─── RUNG 1 IS ABSOLUTE, FOR EVERY ROLE, AT ONE PLACE ─────────────────────
  //
  // WRITER FOUR OF FOUR, and the reason this is a pass rather than a guard
  // inside each writer: three separate rounds of review found three separate
  // places that stamped a placement over something the spec had already said.
  // Every entry, wherever it came from — the authored plan, the derived rung,
  // the bridge appender — passes through here, and any machine whose spec
  // carries a card list has its placement READ off that list rather than
  // proposed. `explicit.length` returns before role, type, scheme or lab
  // membership is consulted (lane-networking.js resolveVmSegments rung 1), so
  // the list is not an opinion this compile is entitled to have a second one
  // about. Authored ORDER is never touched: nothing here writes a nics array at
  // all, and the exposure builder below emits null for these machines.
  //
  // Finding N-B is exactly what this closes: web01, role 'dmz', authored
  // `nics: [{segment:'int'}]`, was stamped 'pivot' with a rewritten two-card
  // list, .240, and a .240 starting URL — for a machine the deployer gives ONE
  // internal card.
  const authoredEntryNames = new Set(storedExposure.map(e => e.vm_name.toLowerCase()));
  exposureEntries = exposureEntries.map((entry) => {
    const key = entry.vm_name.toLowerCase();
    const segs = authoredSegsByName.get(key);
    if (!segs) return entry;
    const addr = addrByName.get(key) || null;
    const truth = placementForAuthoredSegments(segs, !!(addr && addr.can_dual_home));
    const listing = segs.map(s => `'${s}'`).join(', ');
    if (truth === entry.placement) {
      return entry;
    }
    if (authoredEntryNames.has(key)) {
      emit(problems, 'PLACEMENT_CONTRADICTS_NICS', 'warn',
        `'${entry.vm_name}' is placed '${entry.placement}', but its own network-card list — ${listing}, in `
        + 'that order — already decides where it lives, and that list beats every other rule. The placement '
        + `shown is '${truth}', read from the cards. Change the cards in the environment editor if the `
        + 'placement is what was meant; nothing here rewrites them.',
        'exposure_plan');
    } else {
      emit(problems, 'PLACEMENT_FROM_AUTHORED_NICS', 'info',
        `'${entry.vm_name}' already carries its own network-card list — ${listing}, in that order — so its `
        + `placement is READ from it as '${truth}' rather than proposed. Nothing is written onto that `
        + 'machine’s cards.',
        'exposure_plan');
    }
    return {
      vm_name: entry.vm_name,
      placement: truth,
      services: entry.services,
      note: `From the environment: this machine's own network-card list (${listing}) puts it here, and an `
        + 'authored card list beats every other rule.',
    };
  });

  exposureEntries = exposureEntries.map((entry) => {
    if (entry.placement !== 'pivot') return entry;
    const addr = addrByName.get(entry.vm_name.toLowerCase()) || null;
    if (!addr || addr.can_dual_home) return entry;
    // ONE ROOT CAUSE, ONE PROBLEM — the rule this file opens with. The
    // flat-lane half of canBeDualHomed already has an owner two blocks down:
    // PLACEMENT_REQUIRES_V3 names the scheme, explains that one flat lan0 has
    // no boundary to straddle, and offers the fix. A second warning saying the
    // same thing would leave a reader deciding which of two to act on. Every
    // OTHER reason — a container, and an AD lab host the lab itself addresses —
    // has no other owner, so it is reported here. The DEMOTION happens for all
    // of them, because the emitted data may not claim a bridge either way; only
    // the reporting differs.
    if (addr.dual_home_blocked_by === 'flat_lane') {
      return {
        vm_name: entry.vm_name,
        placement: 'public',
        services: entry.services,
        note: `Reachable from the outside, but not the bridge: ${bridgeBlockText(addr.dual_home_blocked_by)}.`,
      };
    }
    emit(problems, 'PIVOT_NOT_DEPLOYABLE', 'warn',
      `'${entry.vm_name}' is placed as the bridge, but ${bridgeBlockText(addr.dual_home_blocked_by)}. `
      + `It is read as reachable from the outside instead, nothing is written onto its card list, and it `
      + `does not answer at .${DUAL_HOMED_OCTET}. `
      + (addr.dual_home_blocked_by === 'container'
        ? 'Use a full virtual machine for the bridge, or place the bridge on one.'
        : (addr.dual_home_blocked_by === 'ad_lab_host'
          ? 'Put the bridge on a machine that is not part of the directory lab — an ordinary web or file '
            + 'server is exactly what the exercise wants there.'
          : 'Reserve this engagement at v3, where the two segments and the .240 pin exist.')),
      'src/utils/challenge-lane-deployer.js:758-772');
    return {
      vm_name: entry.vm_name,
      placement: 'public',
      services: entry.services,
      note: `Reachable from the outside, but not the bridge: ${bridgeBlockText(addr.dual_home_blocked_by)}.`,
    };
  });

  for (const entry of exposureEntries) {
    if (entry.placement === 'pivot') continue;
    if (!specDualHomedNames.has(entry.vm_name.toLowerCase())) continue;
    emit(problems, 'PLACEMENT_OVERRIDES_ROLE', 'warn',
      `'${entry.vm_name}' is placed '${entry.placement}', but the environment homes it on BOTH segments by `
      + 'default — by its role, or by the network-card list its spec already carries. '
      + 'The placement holds only because this plan writes an explicit network-card list onto the '
      + 'environment, which takes precedence — confirm that is what was meant, or place it as the bridge.',
      'src/utils/lane-networking.js:374-381');
  }

  const pivotNames = exposureEntries.filter(e => e.placement === 'pivot').map(e => e.vm_name);
  const consoleOverride = lc(opts.consoleVm);

  const exposure = exposureEntries.map((entry) => {
    const key = entry.vm_name.toLowerCase();
    const host = hostByName.get(key) || null;
    const addr = addrByName.get(key) || null;
    // NEVER REWRITE AN AUTHORED CARD LIST — not its contents, and not its
    // ORDER. `nics` is a PROPOSAL B2 writes onto the spec; for a machine whose
    // spec already carries one, there is nothing to propose, because rung 1 has
    // already decided and this compile has already read the answer off it
    // above. Emitting the canonical [{ext},{int}] here is what silently
    // reversed an authored [{int},{ext}] with no code naming the rewrite.
    const nics = authoredSegsByName.has(key) ? null : nicsForPlacement(entry.placement);
    return {
      vm_name: entry.vm_name,
      placement: entry.placement,
      services: entry.services,
      note: entry.note,
      resolved: !!host,
      // THE ONLY EXPRESSION IN THIS FILE THAT MAY PRODUCE .240, and it asks
      // canBeDualHomed rather than re-deriving the gates. That is where
      // challenge-lane-deployer.js:770-771 really puts a dual-homed host, and
      // both of its conditions are folded into can_dual_home: the type gate
      // (a container gets one card, :465-471, and no reservation, :303) and the
      // isV3 gate (:768). Read the octet off the host otherwise — which is
      // itself null whenever the lane pins nothing for that machine.
      ip_octet: (entry.placement === 'pivot' && host && addr && addr.can_dual_home)
        ? DUAL_HOMED_OCTET
        : (host ? host.ip_octet : null),
      nics,
    };
  });

  for (const entry of exposure) {
    if (entry.resolved) continue;
    emit(problems, 'UNKNOWN_TARGET_VM', 'error',
      `The exposure plan places '${entry.vm_name}', which is not a machine in this environment. `
      + 'Rename the entry to a deployed machine or remove it — a placement the deployer cannot resolve '
      + 'silently does nothing at all.',
      'exposure_plan');
  }

  if (exposureDerived && exposure.length > 0) {
    // "NOTHING WAS AUTHORED" AND "EVERYTHING AUTHORED WAS REJECTED" ARE
    // DIFFERENT FACTS, and this note used to assert the first about both. An
    // exposure plan whose only entry named the attack box is discarded at the
    // filter above, `exposureEntries.length === 0` then takes the derived
    // branch, and the author was told their plan did not exist — while the
    // problem list, two lines up, said the opposite. That is finding N-E: a
    // message that contradicts a message beside it teaches the reader to trust
    // neither.
    const rejected = authoredExposure.length - storedExposure.length;
    emit(problems, 'EXPOSURE_DERIVED', 'info',
      (rejected > 0
        ? `${rejected === 1 ? 'The one entry' : `All ${rejected} entries`} the exposure plan authored `
          + 'could not be used, so this plan was derived instead: '
        : 'No exposure plan was authored, so this one was derived: ')
      + 'the exposed host is the bridge, and every other machine sits on the internal segment unless its own '
      + 'role already puts it outside. Edit it to move the bridge, or to expose more than one host.',
      'exposure_plan');
  }

  // THE AUTHORED SURFACE SERVES NO WEB SITE, AND THE MACHINE THAT DOES IS NOT
  // PLACED AT ALL. An authored plan is never extended — that is deliberate, and
  // it is what keeps an author's list theirs — but the combination is worth one
  // sentence: the brief then opens on a host that answers nothing on port 80
  // (surfacePort falls back to 80 for a machine with no web service at all),
  // while the client's actual web server is absent from the exposure list and
  // therefore from the outside entirely.
  if (publicSurface && publicSurface.source === 'authored') {
    const surfaceHost = hostByName.get(publicSurface.target_vm.toLowerCase()) || null;
    const placedKeys = new Set(exposure.map(e => e.vm_name.toLowerCase()));
    const unplacedWeb = hosts.filter(h => h.is_web && !h.synthetic
      && !placedKeys.has(h.vm_name.toLowerCase()));
    if (surfaceHost && !surfaceHost.is_web && unplacedWeb.length > 0) {
      emit(problems, 'EXPOSURE_SURFACE_NOT_WEB', 'warn',
        `The exposure plan puts '${publicSurface.target_vm}' on the outside, and that machine serves no web `
        + `site — while ${unplacedWeb.map(h => `'${h.vm_name}'`).join(', ')}, which does, is not placed at `
        + `all. The brief will open on '${publicSurface.target_vm}' at port ${publicSurface.target_port}, `
        + 'which is the default rather than a service it was found to run. Place the web host too, or point '
        + 'the entry at it.',
        'exposure_plan');
    }
  }

  if (pivotNames.length > 1) {
    emit(problems, 'EXPOSURE_MULTIPLE_PIVOTS', 'error',
      `${pivotNames.length} machines are marked as the pivot (${pivotNames.join(', ')}), but a lane defines `
      + 'exactly ONE dual-homed address — .240 on each segment — so the second pivot has nowhere to land. '
      + 'Keep one pivot and give the others the \'public\' placement, which is free and makes "which host is '
      + 'the bridge?" a real question.',
      'src/utils/challenge-lane-deployer.js:758-772');
  }

  for (let i = 0; i < exposure.length; i += 1) {
    const entry = exposure[i];
    if (entry.placement !== 'pivot') continue;
    const idx = hosts.findIndex(h => h.vm_name.toLowerCase() === entry.vm_name.toLowerCase());
    const vm = idx === -1 ? {} : (rawVms[idx] || {});
    const isConsole = consoleOverride === entry.vm_name.toLowerCase()
      || ['primary', 'secondary'].includes(lc(vm.console_role));
    if (isConsole) {
      emit(problems, 'EXPOSURE_PIVOT_IS_CONSOLE', 'error',
        `'${entry.vm_name}' is both the pivot and the student console. The deployer THROWS on that `
        + 'combination — a dual-homed machine builds its NICs inline and ignores the console pin, so it would '
        + 'come up with no reservation and a dead console. Point the console at a single-homed machine.',
        'src/utils/challenge-lane-deployer.js:729-735');
    }
  }

  const placementNeedsV3 = preCapabilityPlacements.some(p => p === 'pivot' || p === 'internal')
    || exposure.some(e => e.placement === 'pivot' || e.placement === 'internal');
  if (placementNeedsV3 && !isV3) {
    emit(problems, 'PLACEMENT_REQUIRES_V3', 'warn',
      `This engagement places machines on external and internal segments, but it is scheduled at `
      + `${engagementSubnetScheme}, which is ONE flat lan0. There is no segmentation to place them on, so the `
      + 'pivot is a fiction: everything is an L2 neighbour of everything else. Reserve at v3, or drop the '
      + 'placements.',
      'src/utils/lane-networking.js:374-381');
  }

  // Placement, nics and the pivot's octet land on the hosts themselves, so a
  // reader never has to join two arrays to answer "where does this machine
  // live?" — and so B2 can write hosts[].nics straight onto the spec.
  const exposureByVm = new Map(exposure.map(e => [e.vm_name.toLowerCase(), e]));
  for (const host of hosts) {
    const entry = exposureByVm.get(host.vm_name.toLowerCase());
    if (!entry) continue;
    host.placement = entry.placement;
    host.nics = entry.nics;
    host.ip_octet = entry.ip_octet;
  }

  // The surface's placement is READ, never asserted. It is whatever the
  // resolved exposure gives that machine — and null when nothing places it,
  // which is the honest answer for an internal engagement that expresses no
  // placements at all.
  if (publicSurface) {
    const surfaceEntry = exposureByVm.get(publicSurface.target_vm.toLowerCase()) || null;
    publicSurface.placement = surfaceEntry ? surfaceEntry.placement : null;
  }

  /**
   * IS THE SURFACE REALLY REACHABLE AT .240, IN THIS LANE, ON THIS DAY?
   *
   * Three conditions, and every one of them is load-bearing:
   *   external   — an internal tester is already inside; there is no crossing
   *                to describe and no external segment to name an address on.
   *   v3         — v1/v2 is ONE flat lan0 (lane-networking.js:381). There is no
   *                ext segment for {ext_base} to stand for, and the .240 pin is
   *                gated behind isV3 (challenge-lane-deployer.js:768).
   *   the pivot  — .240 is the DUAL-HOMED address specifically. A single-homed
   *                'public' host takes an ordinary band octet, and a plan with
   *                two declared pivots has no single answer at all.
   *
   * Unguarded, this printed "http://{ext_base}.240/" into the brief of the most
   * ordinary engagement there is — internal, v2, one web asset at a band octet
   * — an address nothing in that lane lives at. The renderer already handles
   * null, and start_position drops the same URL for the same reason.
   */
  const surfaceIsPivot = !!publicSurface
    && publicSurface.placement === 'pivot'
    && pivotNames.length === 1
    && pivotNames[0].toLowerCase() === publicSurface.target_vm.toLowerCase();
  const surfaceUrl = (perspective === 'external' && isV3 && surfaceIsPivot)
    ? `http://{ext_base}.${DUAL_HOMED_OCTET}/`
    : null;

  // ── 5. CREDENTIALS ────────────────────────────────────────────────────────
  const storedCredentials = asArray(eng.issued_credentials);
  const slots = credentialPosture === 'credentialed'
    ? readCredentialSlots(storedCredentials, knownVmNames)
    : [];

  for (const slot of slots) {
    if (slot.resolved) continue;
    emit(problems, 'UNKNOWN_TARGET_VM', 'error',
      `The account '${slot.slot_key}' is issued on '${slot.target_vm}', which is not a machine in this `
      + 'environment. The account would be minted against a host that never deploys.',
      'issued_credentials');
  }

  if (credentialPosture === 'credentialed' && slots.length === 0) {
    emit(problems, 'CREDENTIALS_UNAUTHORED', 'warn',
      'This engagement says the client hands over working accounts, but no account has been recorded yet. '
      + 'An empty list that means "none by design" and one that means "not authored yet" are different facts, '
      + 'and the delivery step cannot tell them apart. A suggested account is offered below.',
      'issued_credentials');
  }

  if (perspective === 'external' && storedCredentials.length > 0) {
    emit(problems, 'EXTERNAL_CREDENTIALS_DECLARED', 'warn',
      'This is an external engagement that declares issued accounts. That is legal — an authenticated web '
      + 'assessment is exactly this shape — but confirm it is intended: a black-box engagement starts with '
      + 'nothing but the exposed site.',
      'issued_credentials');
  }

  // ── 6. SCOPE ──────────────────────────────────────────────────────────────
  const scopeIn = readScopeRules(eng.scope_in);
  const scopeOut = readScopeRules(eng.scope_out);
  const resolvableIn = scopeIn.filter(isResolvableRule);
  const resolvableOut = scopeOut.filter(isResolvableRule);

  for (const host of hosts) {
    let inScope = false;
    let reason = 'not_selected';

    if (resolvableIn.length === 0) {
      if (perspective === 'external') {
        // The default external scope is the exposed surface alone. This is the
        // day-90 property expressed as data: the brief names one host, and
        // everything else is something the tester has to EARN by crossing the
        // pivot — not something the scope handed them.
        if (publicSurface && host.vm_name.toLowerCase() === publicSurface.target_vm.toLowerCase()) {
          inScope = true;
          // 'default_exposed', not 'default_published'. Nothing is published —
          // there is no DNAT and no gateway perimeter publish anywhere in this
          // product — and this was the last word from the cut publish
          // vocabulary still riding in emitted plan DATA, where a later phase
          // would read it as permission to build the path it names.
          reason = 'default_exposed';
        }
      } else {
        // Exactly today's behaviour for every 'default' engagement that exists:
        // the whole environment is in scope, with zero problems.
        inScope = true;
        reason = 'default_all';
      }
    } else {
      for (const rule of resolvableIn) {
        if (!ruleMatchesHost(rule, host)) continue;
        inScope = true;
        reason = rule.kind === 'all' ? 'rule_all' : (rule.kind === 'vm' ? 'rule_vm' : 'rule_role');
        break;
      }
    }

    // scope_out is subtracted last and ALWAYS wins. A deny a reader has to
    // reason about the ordering of is a deny nobody trusts.
    for (const rule of resolvableOut) {
      if (!ruleMatchesHost(rule, host)) continue;
      inScope = false;
      reason = rule.kind === 'all' ? 'excluded_all' : (rule.kind === 'vm' ? 'excluded_vm' : 'excluded_role');
      break;
    }

    host.in_scope = inScope;
    host.scope_reason = reason;
  }

  for (const rule of resolvableIn.concat(resolvableOut)) {
    if (rule.kind === 'all') continue;
    if (hosts.some(h => ruleMatchesHost(rule, h))) continue;
    emit(problems, 'SCOPE_RULE_UNRESOLVED', 'warn',
      `The scope rule ${rule.kind}='${rule.value}' matches no machine in this environment. It has no effect `
      + 'on what is in scope, and it will read to a student as a machine that should exist.',
      `scope_${resolvableIn.includes(rule) ? 'in' : 'out'}`);
  }

  // DOCUMENTARY rules never move a host. A spec VM carries an ipOctet, not an
  // address, and the lane base is per-lane and unknown offline — so a CIDR or a
  // URL cannot be matched here without guessing. Saying so is more honest than
  // a half-working match, and the UI must render these as brief text rather
  // than as scope filters. (isInScope below carries the real matcher for B2,
  // where the lane base is known.)
  const declaredOnly = [];
  for (const [direction, rules] of [['in', scopeIn], ['out', scopeOut]]) {
    for (const rule of rules) {
      if (isResolvableRule(rule)) continue;
      declaredOnly.push({ direction, kind: rule.kind, value: rule.value, note: rule.note });
      emit(problems, 'SCOPE_RULE_DOCUMENTARY', 'info',
        `The ${direction === 'in' ? 'in-scope' : 'out-of-scope'} rule ${rule.kind}='${rule.value}' is carried `
        + 'into the brief as written and matches no machine: the environment knows octets, not addresses.',
        `scope_${direction}`);
    }
  }
  if (!declaredOnly.some(d => d.kind === 'cidr' && d.value === MANAGEMENT_CIDR)) {
    declaredOnly.push({
      direction: 'out',
      kind: 'cidr',
      value: MANAGEMENT_CIDR,
      note: 'Lane transit and management addressing. Never part of the client estate, in any engagement.',
    });
  }

  const inScopeNames = hosts.filter(h => h.in_scope).map(h => h.vm_name);
  const outOfScopeNames = hosts.filter(h => !h.in_scope).map(h => h.vm_name);

  if (inScopeNames.length === 0) {
    emit(problems, 'SCOPE_EMPTY', 'error',
      'Nothing is in scope: every machine in this environment is either unselected or excluded. A student '
      + 'opening this brief has nothing they are allowed to touch.',
      'scope_in / scope_out');
  }

  for (const host of hosts) {
    if (!host.in_scope || host.ip_octet != null) continue;
    emit(problems, 'NO_HOST_ADDRESSING', 'warn',
      `'${host.vm_name}' is in scope but has no fixed address in the spec, so the paper cannot name where it `
      + 'lives. Containers and multi-NIC machines are not pinned; everything else should be.',
      'utils/profile-to-spec.js assignLaneAddressing');
  }

  // ── 7. PERSPECTIVE ────────────────────────────────────────────────────────
  if (perspective === 'external') {
    if (!publicSurface) {
      emit(problems, 'EXTERNAL_NEEDS_VULN_APP', 'error',
        'This is an external engagement, but no machine in this environment serves a web site and no '
        + 'vulnerable application is attached, so there is nothing for the tester to find from the outside. '
        + 'Generate the vulnerable application for this client, or select a web server.',
        'utils/vuln-app-generator.js');
      if (resolvableIn.length === 0) {
        emit(problems, 'EXTERNAL_NO_SURFACE', 'error',
          'This external engagement exposes nothing and names nothing: there is no exposed host and no scope '
          + 'rule pointing at one. The brief would open with no starting point at all.',
          'exposure_plan / scope_in');
      }
    } else if (publicSurface.source === 'synthetic') {
      emit(problems, 'EXTERNAL_SYNTHETIC_SURFACE', 'info',
        `The exposed site is '${publicSurface.target_vm}', the machine the synthesizer adds when a client has `
        + 'no web server of its own. It is a real deployed host cloned from the same web template, so the '
        + 'engagement is sound — the client simply has no on-premises web server in its file.',
        'utils/profile-to-spec.js:436-460');
    }

    if (pivotNames.length === 0) {
      emit(problems, 'EXTERNAL_NO_PIVOT', 'error',
        'This external engagement has no pivot: no machine is dual-homed, so there is no route from the '
        + 'external segment to the internal one. The tester would exploit the exposed host and find that it '
        + 'leads nowhere. Mark exactly one machine as the pivot.',
        'exposure_plan');
    }

    if (inScopeNames.length > 1) {
      emit(problems, 'EXTERNAL_SCOPE_WIDE', 'warn',
        `${inScopeNames.length} machines are in scope for an external engagement. That is allowed, but from `
        + 'the outside a tester can only see what is exposed — confirm the scope matches what they can '
        + 'actually reach on day one.',
        'scope_in');
    }
  }

  // ── 8. CAPACITY ───────────────────────────────────────────────────────────
  // Computed from the IMPORTED band, and from the same nics rule
  // assignLaneAddressing uses (profile-to-spec.js:176-179), so a pivot's two
  // NICs take it out of the count here exactly as they will there.
  // A ROLE TAKES A MACHINE OUT OF THE BAND EXACTLY AS AN EXPLICIT NIC LIST
  // DOES. Counting vm.nics alone counted a role 'dmz' host as pinnable, so the
  // ceiling this check exists to enforce was over-stated by one for every
  // dual-homed machine — and the deployer, which asks resolveVmSegments, would
  // never have written that reservation. addressing[i] is that same question,
  // asked once, at the top.
  let pinnable = 0;
  for (let i = 0; i < hosts.length; i += 1) {
    if (!addressing[i].pinnable) continue;
    if (asArray(hosts[i].nics).length > 1) continue;
    pinnable += 1;
  }
  const overCapacity = pinnable > PIN_CAPACITY;
  if (overCapacity) {
    emit(problems, 'OVER_PIN_CAPACITY', 'error',
      `This engagement selects ${pinnable} deployable machines, but a lane can pin only ${PIN_CAPACITY} `
      + `(the .${SPEC_OCTET_MIN}-.${SPEC_OCTET_MAX} band). Deselect assets until at most ${PIN_CAPACITY} `
      + 'remain, or split the profile across two engagements.',
      'utils/profile-to-spec.js:181-192');
  }

  // ── 9. CLIENT-FACT GAPS ───────────────────────────────────────────────────
  // Last, and in readClientFacts' own order, so the environment's problems are
  // never buried under the client file's.
  for (const gap of facts.gaps) {
    if (gap.code === 'PROFILE_PUBLIC_IP_NOT_ROUTABLE') {
      emit(problems, gap.code, 'info',
        'The client file records a public IP from the RFC 5737 documentation range. It is a per-client '
        + 'literal, identical for every lane cut from this client, so nothing in this plan uses it as an '
        + 'address: the starting point is the lane’s own external segment.',
        gap.field);
    } else if (gap.code === 'PROFILE_ASSETS_DECLARE_NO_SERVICES') {
      emit(problems, gap.code, 'info',
        'No asset in the client file declares a service list, so services shown against a machine are '
        + 'inferred from its name and stated function rather than read from the file.',
        gap.field);
    } else if (gap.code === 'REAL_INTAKE_NO_NETWORK_PLAN') {
      emit(problems, gap.code, 'warn',
        'This client came from a real intake that records no network segments, so the brief cannot describe '
        + 'the client’s own addressing — only the environment as deployed.',
        gap.field);
    } else if (gap.code === 'PROFILE_LAYOUT_UNRECOGNISED') {
      emit(problems, gap.code, 'warn',
        'The client file is not in a shape this compile recognises, so the brief has no company name, '
        + 'industry or stakeholders to draw on. The environment itself still compiles.',
        gap.field);
    }
  }

  // ── 10. THE REST ──────────────────────────────────────────────────────────
  const techniques = buildTechniques(perspective, credentialPosture);
  const objectives = asArray(eng.objectives).length > 0
    ? asArray(eng.objectives).filter(isObj).map(o => ({
      objective_key: str(o.objective_key),
      title: str(o.title),
      points: intOrNull(o.points) == null ? 10 : intOrNull(o.points),
      maps_to: isObj(o.maps_to) ? o.maps_to : { kind: 'manual' },
    }))
    : buildObjectives(hosts, rawVms);

  const assetSelection = buildAssetSelection({
    stored: eng.asset_selection,
    hosts,
    rawVms,
    authoredIn: scopeIn.filter(isResolvableRule),
    authoredOut: scopeOut.filter(isResolvableRule),
  });

  const startPosition = {
    perspective,
    credentialed: credentialPosture === 'credentialed',
    // BOTH perspectives start on the attack box. Nothing is published at the
    // perimeter, so there is no service to start "at"; what the perspective
    // changes is what is REACHABLE from the external segment, not where the
    // tester sits. On an external engagement Kali (.50) and the exposed host
    // (.240) are L2 neighbours on ext — no DNAT, no port, no rule ordering.
    // ONE computation, shared with brief.facts.surface_url, so the two can
    // never say different things about the same address.
    entry: { kind: 'attack_box', value: 'kali', url_template: surfaceUrl },
    // Reported as a DEPLOY ARGUMENT, not a spec key: spec.attack_boxes has zero
    // readers in this repo. The live value travels as runProfileDeploy's own
    // attackBoxes argument (profile-deploy.js:369,419 -> lane-provision.js:316,448).
    attack_box_required: true,
    // The .240 sentence is bound to the SAME condition as the address itself:
    // prose that names an address the plan does not emit is the same defect as
    // emitting the wrong one, one layer up.
    note: perspective !== 'external'
      ? 'The tester works from the Kali console inside the environment, alongside the machines in scope.'
      : (surfaceUrl
        ? 'The tester works from the Kali console on the external segment. The exposed host answers on that '
          + 'segment at .240; the internal segment is reachable only through it. {ext_base} is the lane’s own '
          + 'external /24 and is filled in per lane at deploy time.'
        : 'The tester works from the Kali console on the external segment. Nothing in this environment is '
          + 'placed at a fixed outward-facing address yet, so there is no starting URL to hand over.'),
  };

  const briefFacts = {
    company_name: facts.company_name,
    industry: facts.industry,
    domain_public: facts.domain_public,
    layout: facts.layout,
    difficulty: facts.difficulty,
    engagement_name: engagementBlock.display_name,
    engagement_summary: str(descriptor.summary) || null,
    perspective,
    credentialed: credentialPosture === 'credentialed',
    stakeholder_count: facts.stakeholders.length,
    declared_subnets: facts.subnets.map(s => (s.cidr ? `${s.name || s.cidr} (${s.cidr})` : String(s.name))),
    in_scope: inScopeNames.slice(),
    // ONLY the machines an AUTHORED rule excluded. A derived non-selection —
    // every internal machine on a black-box engagement — is deliberately NOT
    // named: "do not touch the payroll server" is a rule the tester must know,
    // while "dc01 exists" is the thing they are being asked to find out. The
    // full list is still on plan.out_of_scope for the instructor's screen; the
    // brief is what the student reads.
    out_of_scope: hosts
      .filter(h => !h.in_scope && h.scope_reason.indexOf('excluded_') === 0)
      .map(h => h.vm_name),
    pivot: pivotNames.length === 1 ? pivotNames[0] : null,
    exposed: exposure.filter(e => e.placement === 'pivot' || e.placement === 'public').map(e => e.vm_name),
    // See surfaceIsPivot: an address only when the tester is outside, the lane
    // has an outside, and the surface really is the one machine that bridges it.
    surface_url: surfaceUrl,
    surface_vm: publicSurface ? publicSurface.target_vm : null,
    // Documentary rules, split by direction so each is rendered under the
    // heading it belongs to. They name addresses and URLs, which the compile
    // cannot match to a machine offline — the brief is exactly where they are
    // useful and the only place they are honest.
    declared_in: declaredOnly.filter(d => d.direction === 'in')
      .map(d => `${d.value}${d.note ? ` — ${d.note}` : ''}`),
    declared_out: declaredOnly.filter(d => d.direction === 'out')
      .map(d => `${d.value}${d.note ? ` — ${d.note}` : ''}`),
    techniques_allowed: techniques.filter(t => t.allowed).map(t => t.label),
    techniques_refused: techniques.filter(t => !t.allowed).map(t => t.label),
    objective_count: objectives.length,
    objective_points: objectives.reduce((sum, o) => sum + (Number.isInteger(o.points) ? o.points : 0), 0),
    credential_slots: slots.map(s => `${s.username || s.slot_key}${s.target_vm ? ` on ${s.target_vm}` : ''}`),
    start_note: startPosition.note,
  };

  const suggestedText = renderBriefText({ brief: { facts: briefFacts } });
  const storedBrief = orNull(eng.brief);

  const suggestions = {
    display_name: engagementBlock.display_name,
    asset_selection: assetSelection,
    scope_in: perspective === 'external' && publicSurface
      ? [{ kind: 'vm', value: publicSurface.target_vm, note: 'The exposed host, and the only thing visible from outside on day one.' }]
      : [{ kind: 'all', value: '', note: 'The whole environment.' }],
    scope_out: [{
      kind: 'cidr',
      value: MANAGEMENT_CIDR,
      note: 'Lane transit and management addressing. Never part of the client estate.',
    }],
    allowed_techniques: techniques,
    exposure_plan: exposure.map(e => ({
      vm_name: e.vm_name, placement: e.placement, services: e.services, note: e.note,
    })),
    objectives,
    brief: suggestedText,
  };
  if (credentialPosture === 'credentialed' && slots.length === 0) {
    suggestions.issued_credentials = suggestCredentialSlot(facts, hosts, rawVms);
  }

  return {
    compile_version: ENGAGEMENT_COMPILE_VERSION,
    engagement: engagementBlock,
    client: clientBlock,
    hosts,
    in_scope: inScopeNames,
    out_of_scope: outOfScopeNames,
    // The normalized rules, so isInScope(plan, target) can answer a question
    // about an address the compile itself could not resolve offline.
    scope: { in: scopeIn, out: scopeOut },
    declared_only: declaredOnly,
    public_surface: publicSurface,
    start_position: startPosition,
    exposure,
    credentials: { slots, delivery: 'file', delivery_note: DELIVERY_NOTE },
    techniques,
    objectives,
    asset_selection: assetSelection,
    capacity: { pinnable, pinnable_capacity: PIN_CAPACITY, over_capacity: overCapacity },
    brief: { text: storedBrief, suggested_text: suggestedText, facts: briefFacts },
    synth: synthBlock,
    suggestions,
    spec_fingerprint: fingerprint,
    problems,
  };
}

// ─── hasBlockingProblem ─────────────────────────────────────────────────────

/**
 * True iff some problem is an error.
 *
 * This module never decides what blocking MEANS — a route may refuse to save, a
 * screen may show a banner, a preview may show everything anyway. That decision
 * belongs to the caller, which is precisely the property assignLaneAddressing's
 * bare throw takes away from it.
 */
function hasBlockingProblem(plan) {
  return asArray(plan && plan.problems).some(p => isObj(p) && p.severity === 'error');
}

// ─── isInScope ──────────────────────────────────────────────────────────────

function globToRegExp(glob) {
  const escaped = String(glob).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const body = escaped.replace(/\\\*/g, '.*').replace(/\\\?/g, '.');
  try {
    return new RegExp(`^${body}$`, 'i');
  } catch (_err) {
    return null;
  }
}

function ruleMatchesTarget(rule, target) {
  if (rule.kind === 'all') return true;
  const value = str(rule.value);
  if (!value) return false;

  if (rule.kind === 'vm') {
    const v = value.toLowerCase();
    return lc(target.hostname) === v || lc(target.name) === v || lc(target.vm_name) === v;
  }
  if (rule.kind === 'role') return lc(target.role) === value.toLowerCase();
  if (rule.kind === 'cidr') {
    const ip = str(target.ip);
    // BOTH pre-tests are load-bearing: ipInCidr('10.0.0.5','Servers') THROWS
    // `Not a CIDR block`, and a profile's asset.subnet is heterogeneous — a
    // subnet NAME on LLM-authored servers, a CIDR STRING on assets rebuilt by
    // reconcile-workstations — so a stored rule really can carry 'Servers'.
    if (!ip || !IPV4_RE.test(ip) || !CIDR_RE.test(value)) return false;
    try {
      return !!ipInCidr(ip, value);
    } catch (_err) {
      return false;
    }
  }
  if (rule.kind === 'hostname_pattern') {
    const hostname = str(target.hostname);
    if (!hostname) return false;
    const re = globToRegExp(value);
    return re ? re.test(hostname) : false;
  }
  if (rule.kind === 'url') {
    const url = lc(target.url);
    return url !== '' && url === value.toLowerCase();
  }
  // 'text' — and anything unrecognised — never matches. A prose rule is for the
  // brief; deciding scope from it would be guessing.
  return false;
}

/**
 * Answer "is this thing in scope?" for a target the compile could not resolve
 * offline — an address, a URL, a hostname a scan turned up.
 *
 * DENY BEATS ALLOW, and an unmatched target is default_deny. Both halves are
 * deliberate: a tester who has to reason about rule ORDER to know whether they
 * are allowed to touch something will eventually reason wrong, and the failure
 * mode of guessing wrong is testing someone else's machine.
 *
 * Accepts either a compiled plan (it reads plan.scope) or a bare
 * { scope_in, scope_out } — an engagement row is exactly that shape, so a
 * caller with a row and no spec can still ask.
 *
 * @returns {{in_scope:boolean, decision:'allow'|'deny'|'default_deny', rule:object|null}}
 */
function isInScope(planOrScope, target) {
  const src = isObj(planOrScope) ? planOrScope : {};
  const scope = isObj(src.scope) ? src.scope : null;
  const inRules = readScopeRules(scope ? scope.in : src.scope_in);
  const outRules = readScopeRules(scope ? scope.out : src.scope_out);
  const t = isObj(target) ? target : {};

  for (const rule of outRules) {
    if (ruleMatchesTarget(rule, t)) return { in_scope: false, decision: 'deny', rule };
  }
  for (const rule of inRules) {
    if (ruleMatchesTarget(rule, t)) return { in_scope: true, decision: 'allow', rule };
  }
  return { in_scope: false, decision: 'default_deny', rule: null };
}

// ─── renderBriefText ────────────────────────────────────────────────────────

function bullet(lines, text) {
  lines.push(`  - ${text}`);
}

/**
 * The brief, as deterministic prose from plan.brief.facts.
 *
 * No LLM, no network, no clock: the same plan renders the same words, forever,
 * which is what makes it safe to hand a class and diff against later.
 *
 * VOCABULARY IS FIXED — Section, Module, Client, Engagement, Environment,
 * Objectives, console, tester. The words course, material and challenge must
 * never appear here; a test scans this output for them.
 */
function renderBriefText(plan) {
  const facts = isObj(plan) && isObj(plan.brief) && isObj(plan.brief.facts) ? plan.brief.facts : null;
  if (!facts) return '';

  const client = facts.company_name || 'the client';
  const lines = [];

  lines.push('THE CLIENT');
  lines.push('');
  bullet(lines, `Name: ${client}`);
  if (facts.industry) bullet(lines, `Sector: ${facts.industry}`);
  if (facts.domain_public) bullet(lines, `Public domain: ${facts.domain_public}`);
  if (facts.stakeholder_count) {
    bullet(lines, `People you can talk to: ${facts.stakeholder_count} named contacts on the client side.`);
  }
  if (asArray(facts.declared_subnets).length) {
    bullet(lines, `Addressing the client claims to use: ${facts.declared_subnets.join('; ')}.`);
  }
  lines.push('');

  lines.push('THE ENGAGEMENT');
  lines.push('');
  bullet(lines, `${facts.engagement_name}${facts.engagement_summary ? ` — ${facts.engagement_summary}` : ''}`);
  bullet(lines, facts.perspective === 'external'
    ? 'You are working from outside the client’s perimeter.'
    : 'You are working from inside the client’s environment.');
  bullet(lines, facts.credentialed
    ? 'The client has agreed to issue you working accounts. They are listed below.'
    : 'The client is issuing you no accounts. Anything you get, you earn.');
  if (facts.start_note) bullet(lines, facts.start_note);
  if (facts.surface_vm) {
    bullet(lines, `The site the client puts in front of the world runs on ${facts.surface_vm}`
      + `${facts.surface_url ? ` (${facts.surface_url})` : ''}.`);
  }
  if (facts.pivot) {
    bullet(lines, `One machine sits on both sides of the perimeter. Finding out which, and what that means, `
      + 'is part of the work.');
  }
  lines.push('');

  lines.push('IN SCOPE');
  lines.push('');
  if (asArray(facts.in_scope).length) {
    for (const name of facts.in_scope) bullet(lines, name);
  } else if (!asArray(facts.declared_in).length) {
    bullet(lines, 'Nothing has been placed in scope yet.');
  }
  for (const entry of asArray(facts.declared_in)) bullet(lines, entry);
  lines.push('');

  lines.push('OUT OF SCOPE');
  lines.push('');
  for (const name of asArray(facts.out_of_scope)) bullet(lines, name);
  for (const entry of asArray(facts.declared_out)) bullet(lines, entry);
  bullet(lines, 'Anything not named under IN SCOPE is outside this piece of work until the client '
    + 'agrees otherwise in writing. If a finding leads somewhere you were not given, stop and say so — '
    + 'that sentence is itself one of the most valuable things in the report.');
  lines.push('');

  lines.push('RULES OF ENGAGEMENT');
  lines.push('');
  bullet(lines, 'Permitted:');
  for (const label of asArray(facts.techniques_allowed)) lines.push(`      * ${label}`);
  bullet(lines, 'Not permitted:');
  for (const label of asArray(facts.techniques_refused)) lines.push(`      * ${label}`);
  lines.push('');

  lines.push('WHAT YOU ARE GIVEN');
  lines.push('');
  bullet(lines, 'A console inside the lane, and the tools on it.');
  if (asArray(facts.credential_slots).length) {
    for (const slot of facts.credential_slots) bullet(lines, `An account: ${slot}.`);
    bullet(lines, 'The secrets themselves are delivered to your console as a file, not printed here.');
  } else {
    bullet(lines, 'No accounts. Everything you authenticate as, you will have obtained yourself.');
  }
  lines.push('');

  lines.push('DELIVERABLES');
  lines.push('');
  bullet(lines, `${facts.objective_count} objectives are defined for this engagement, worth `
    + `${facts.objective_points} points in total.`);
  bullet(lines, 'A written report: what you found, how severe it is, how you proved it, and what '
    + `${client} should do about it.`);
  bullet(lines, 'Evidence for every finding — commands, output, timestamps — good enough that someone '
    + 'else could repeat it.');
  bullet(lines, 'An out-brief the client can act on without a technical translator in the room.');

  return lines.join('\n');
}

module.exports = {
  compileEngagementPlan,
  hasBlockingProblem,
  isInScope,
  renderBriefText,
  readClientFacts,
  specFingerprint,
  PLAN_PROBLEM_CODES,
  ENGAGEMENT_COMPILE_VERSION,
  MANAGEMENT_CIDR,
  DUAL_HOMED_OCTET,
  // THE capability predicate, exported so a test can pin the rule itself rather
  // than infer it from a fixture that happens to exercise it.
  canBeDualHomed,
  // ─── THE MIRROR, EXPORTED SO ITS COMPLETENESS IS TESTABLE ────────────────
  // A source scan can prove a rung is WRITTEN. Only calling the function can
  // prove it is REACHED, in the right order, with the right answer. Three
  // rounds of review found three incomplete-mirror bugs, so the mirror is
  // exercised directly against the authority's rungs rather than inferred from
  // whichever fixture happens to reach it.
  resolveSpecVmSegments,
  placementForAuthoredSegments,
  authoredSegmentsOf,
  laneSegmentIds,
  goadLabOctet,
  GOAD_LAB_VMS,
  GOAD_DEFAULT_LAB,
  // Exported so the source-scan guard can compare this mirror with
  // src/utils/topology-validate.js:25-26 without importing that file.
  EXTERNAL_ROLES,
};
