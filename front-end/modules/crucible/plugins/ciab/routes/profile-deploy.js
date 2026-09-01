/*
 * ============================================================================
 * Profile-Deploy Routes — admin deploys N cybercore lanes from one CIAB profile
 * ============================================================================
 * All endpoints are admin-only. Three intake paths into /deploy:
 *   (a) profile_id from CIAB profiles table (most common)
 *   (b) profile_id from a previously uploaded JSON  → /api/profiles/upload
 *   (c) one-step generate + deploy                  → /api/profiles/generate-and-deploy
 *
 * Lane deployment goes through ../utils/lane-provision.js, a thin wrapper over
 * the shared spec deployer (src/utils/challenge-lane-deployer.js). This file
 * owns intake, validation and bookkeeping only — it clones nothing. The VXLAN
 * reservation lives in ../utils/lane-reservation.js.
 *
 * Default subnet_scheme = DEFAULT_SUBNET_SCHEME ('v3' — two segments behind one
 * gateway, ext0/int0 DROPped in FORWARD, the company web host dual-homed at
 * .240). v2 — one flat 10.x.x.x segment — stays fully selectable and an explicit
 * subnet_scheme always wins over the default. No GOAD provisioning happens here
 * under either scheme.
 *
 * THE SCHEME AN ENGAGEMENT WAS CARVED AT BEATS THE REQUEST, on every path that
 * touches the network. A block reserved as v2 holds ONE VNet per lane; a v3
 * block holds two. Building at the request's scheme when the engagement row
 * says otherwise cables lanes onto bridges that were never created — see
 * `carvedScheme` in runProfileDeploy.
 */

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const { pool, query } = require('../utils/db');
const { authenticateToken, requireRole } = require('../../../../../src/middleware/auth');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { claimsSql } = require('../../../../../src/utils/lane-claims');
const laneDeployer = require('../../../../../src/utils/lane-deployer');
const { proxmoxAPI } = require('../../../../../src/utils/proxmox');
const { buildDeployPreview } = require('../../../../../src/middleware/deployment-guards');
const audit = require('../../../../../src/utils/audit');

// DEFAULT_SUBNET_SCHEME is imported, never re-spelled. R1's finding was that the
// constant existed, said 'v3', and reached nothing: every call site here wrote a
// bare `|| 'v2'`, so the flip was inert. profile-to-spec.js is its one owner.
// buildSpecDns comes along for C1b. Its AD branch reads spec.goad.domain and its
// own comment says a later wave stamps that key — this is that wave, so the
// lane's conditional forwarder has to be recomputed once the bake's forest is on
// the spec. Without it every AD tool a student is taught to invoke by NAME
// (`nxc smb dc01.corp.local`, `bloodhound-python -d corp.local`) fails at
// resolution on a lane whose directory is right there.
//
// synthesizeSpecFromProfile and resolveDmzVm are BOTH read by the bake as well
// as by the deploy, and that is X1's whole point: the bake's company web host
// has to be the machine a deploy of this client would put in the DMZ, down to
// its name, or the golden template capture makes for it matches nothing and the
// deploy refuses with BAKE_GOLDEN_UNMATCHED ninety minutes later. See
// bakeWebMachine — the answer is ASKED of these two, never re-derived here.
const {
  synthesizeSpecFromProfile, buildSpecDns, resolveDmzVm, DEFAULT_SUBNET_SCHEME,
} = require('../utils/profile-to-spec');
const { getOrGenerateVulnApp } = require('../utils/vuln-app-generator');
const { resolveImageFile } = require('../utils/vuln-app-builder');
const { estimateDeployCost, DEFAULT_MODEL } = require('../utils/cost-estimator');
// Student accounts for profile lanes. Extracted in Track A3 — the identical
// loop existed at both call sites below and had already begun to drift. It
// still mints through src/utils/account-provisioning, so the create-or-rotate
// semantics this path depends on are unchanged; see profile-students.js.
const { provisionLaneStudents, slugForGroup } = require('../utils/profile-students');
const laneProvision = require('../utils/lane-provision');
const engagementProvision = require('../utils/engagement-provision');
// G5. startBake() and buildBakeSteps() had no caller at all before the bake
// routes below; the gate at the end of runProfileDeploy is the other half.
const bakeOrchestrator = require('../utils/bake-orchestrator');
// C1. The two phases that touch the cluster, required here for their PURE
// guards only. The pre-flight below runs assertBakeableSpec and
// assertFixedSubnet — the REAL functions the provision and capture phases call
// — rather than a second copy of the same rules: a pre-flight that could
// disagree with the consumer is a pre-flight that passes a bake the consumer
// then refuses ninety minutes later. bake-staging has no top-level requires of
// its own (every cluster edge is behind defaultDeps), so this costs nothing.
const bakeStaging = require('../utils/bake-staging');

const { guacAPI } = require('../../../../../src/utils/guacamole');
const {
  teardownLane,
  getOrCreateProfileChallenge,
  deleteProfileChallenge,
  findProfileChallenge,
  getProfileChallengeById,
  listProfileChallenges,
  DEFAULT_ENGAGEMENT_TYPE,
  sanitizeEngagementType,
  VXLAN_SEARCH_MIN,
  VXLAN_SEARCH_MAX
} = require('../utils/lane-reservation');

const adminOnly = requireRole('admin');

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Load profile row + JSON file, normalize to a flat asset list.
 * Returns { profile, assets } or throws on not-found.
 */
async function loadProfileForDeploy(profileId) {
  const result = await pool.query(
    // employee_count is here for the vuln-app concept prompt, not for the
    // deploy: ai/vuln-app/prompts.js:253 reads it straight off the object this
    // function returns. It is NULL on every real-client intake
    // (real-client-intake.js inserts null), which is why the JSON fallbacks
    // below exist as well.
    `SELECT id, user_id, company_name, industry, difficulty, client_type,
            employee_count, json_file_path, html_file_path, run_id, generation_status
       FROM profiles
      WHERE id = $1`,
    [profileId]
  );
  if (result.rows.length === 0) {
    throw Object.assign(new Error('Profile not found'), { statusCode: 404 });
  }
  const profile = result.rows[0];

  // Load JSON from disk
  let json = null;
  if (profile.json_file_path) {
    const resolvedPath = path.join(process.cwd(), profile.json_file_path.replace(/^\//, ''));
    if (fs.existsSync(resolvedPath)) {
      const parsed = JSON.parse(fs.readFileSync(resolvedPath, 'utf-8'));
      json = Array.isArray(parsed) ? parsed[0] : parsed;
    }
  }
  if (!json) {
    throw Object.assign(new Error('Profile JSON file missing'), { statusCode: 422 });
  }

  // Normalize asset array out of the student_view.raw.threats.network.assets shape
  const assets = (json.student_view?.raw?.threats?.network?.assets) || json.assets || [];

  // The generated company website is seeded from the REAL roster — employee
  // names in the app's seed data, headcount in the design brief. The concept
  // prompt reads profile.stakeholders and profile.employee_count/employees_total
  // (ai/vuln-app/prompts.js:253-261) off the object returned here, so a field
  // left off this spread is not a degraded prompt, it is a silently generic one:
  // "Size: ? employees" and "(no stakeholder data in profile — invent plausible
  // names)" while the whole roster sits unread in json_data.
  //
  // Two live layouts put the roster in two different places — an AI profile at
  // student_view.stakeholders (ai/profile/index.js), a real-client intake at
  // student_view.raw.threats.stakeholders (utils/profile-filler.js) — so this is
  // the same three-way fallback utils/answer-key-risk-assessment.js:41 and
  // utils/engagement-plan.js:947 already use. Three readers of one fact must not
  // disagree about where the fact lives.
  const roster = json.student_view?.stakeholders
    || json.student_view?.raw?.threats?.stakeholders
    || json.stakeholders;
  const stakeholders = Array.isArray(roster) ? roster : [];

  // Headcount fallback chain, only consulted when the employee_count column is
  // NULL. employees_band ("51-100") is last because it is a band rather than a
  // number — but it is the ONLY headcount a real-client intake carries, and the
  // prompt interpolates it into "Size: <n> employees", where a band still reads
  // correctly. Kept as its own key instead of backfilling employee_count: the
  // prompt already spells the precedence as `employee_count || employees_total`,
  // and overwriting the column would erase which source the number came from.
  const org = json.student_view?.raw?.threats?.organization;
  const employeesTotal = org?.employees_total
    || json.student_view?.quick?.employees_total
    || org?.employees_band
    || null;

  return {
    profile: { ...profile, assets, stakeholders, employees_total: employeesTotal, json_data: json },
    assets
  };
}

// (createEphemeralChallenge removed — challenges are now per-profile, managed
//  by getOrCreateProfileChallenge() in utils/lane-reservation.js)

/**
 * Build the default asset_selection from a list of assets: tick role==='server'.
 */
function defaultAssetSelection(assets) {
  return (Array.isArray(assets) ? assets : []).map(a => ({
    hostname: a.hostname,
    role: a.role,
    os: a.os,
    included: String(a.role || '').toLowerCase() === 'server'
  }));
}

/**
 * Merge a freshly synthesized spec onto a reservation, for the UPDATE that
 * replaces crucible_challenge.spec wholesale.
 *
 * vxlan_block and zone are RESERVATION-owned, not synthesizer-owned:
 * reserveLabNetwork writes both, and teardownLabNetwork reads spec.zone.abbrev to
 * decide which Proxmox SDN zone to remove. profile-to-spec emits neither, so
 * spreading rawSpec alone blanks the abbrev out on the first deploy of every
 * reservation — after which teardownSdnForBlock's `if (zone)` guard skips zone
 * deletion in silence and the zone can never be found again.
 *
 * src/routes/lab-templates.js:355-363 defends the same invariant on the admin
 * edit path, by name: PROTECTED_SPEC_KEYS = ['vxlan_block','zone','cle','course_id'].
 * This is that rule, on the deploy path.
 *
 * Pure and exported so ciab-reservation.test.js can assert the behaviour rather
 * than grep the source for the word "zone" — the comment above would satisfy
 * a source-text check while the code did the wrong thing.
 */
function adoptedSpec(rawSpec, reservation) {
  const zone = (reservation && reservation.spec && reservation.spec.zone)
    || (reservation && reservation.zone_abbrev ? { abbrev: reservation.zone_abbrev } : null);
  return {
    ...rawSpec,
    vxlan_block: reservation ? reservation.vxlan_block : undefined,
    ...(zone ? { zone } : {})
  };
}

// ─── G5: the per-profile bake ───────────────────────────────────────────────
/*
 * WHY ANY OF THIS IS IN A ROUTE FILE
 * utils/bake-orchestrator.js owns sequencing, durable status, boot recovery and
 * refusal. It deliberately owns neither the compiler nor an HTTP surface —
 * buildBakeSteps() binds the five phases to the code that performs them, and
 * startBake() had NO CALLER AT ALL before this block. A bake was a library with
 * a green test suite and no way to run, which is the same silent-success shape
 * the whole track exists to eliminate, one level up.
 *
 * So this file supplies the two halves a route has to supply: the IDENTITY of
 * the environment being baked, and the words an operator reads when it refuses.
 */

// ─── C1a: the network a staging lane borrows ────────────────────────────────
/**
 * WHICH RESERVED BLOCK A BAKE BORROWS, AND WHY IT IS NOT THE CLASS'S.
 *
 * A staging lane is a lane: it needs a VXLAN id out of a carved block, with its
 * SDN zone and its VNets already on every node. Reservations are keyed on
 * (profile, engagement) — lane-reservation.js's own header says one client can
 * be the subject of several — so the question is only WHICH engagement's block,
 * and there are exactly three answers. Two of them are wrong:
 *
 *   the client's student block   The block is sized EXACTLY to max_students
 *                               (getOrCreateProfileChallenge passes it straight
 *                               to reserveLabNetwork as maxLanes), and the
 *                               staging lane is never torn down — its VMs ARE
 *                               the golden templates, which is why captureGolden
 *                               says so out loud. So an id borrowed from there
 *                               is gone for the life of the environment, and a
 *                               class of max_students permanently loses a seat.
 *                               Worse, and this is the decisive half: the
 *                               deployer allocates whichever id in the block is
 *                               FREE, so nothing can say in advance which one
 *                               the staging lane will get — and fixed_subnet is
 *                               derived from that id. captureGolden's
 *                               assertSubnetMatch compares the declared bases
 *                               against the ones the lane actually came up on
 *                               and refuses when they disagree, ninety minutes
 *                               in. A multi-id block makes that refusal a
 *                               coin-flip.
 *   a block of its own, carved  reserveLabNetwork here means a cluster-wide SDN
 *   inline on the bake path     apply inside an HTTP request. runProfileDeploy's
 *                               A8a note is the standing rule: reserving "just
 *                               this once" on a request path is exactly how the
 *                               cost became invisible the first time.
 *
 * So: a DEDICATED one-slot engagement, 'bake', created through the same
 * engagementProvision machinery every other reservation goes through and
 * provisioned in the background exactly as createEngagement already does it. It
 * costs one VXLAN id (two VNets under v3) instead of a student's seat; because
 * the block holds exactly one id, that id — and therefore the pair of /24 bases
 * every lane of this client will be pinned to — is KNOWN before the lane exists;
 * and because it is keyed on its own engagement type, the student engagement's
 * resize path (which teardownLabNetworks the whole block) can never reach it,
 * which is the hazard bake-staging.resolveVxlanBlock's header warns about.
 *
 * The SDN zone is not duplicated either: CIAB_ZONE_ABBREV is a constant, so a
 * second CIAB reservation lands in the one zone every CIAB VNet already lives
 * in.
 */
const BAKE_ENGAGEMENT_TYPE = 'bake';

/**
 * The pair of /24 bases every lane cloned from this bake is pinned to.
 *
 * DERIVED, from the one id the staging block holds, through the SAME two
 * functions the deployer uses to address a lane — never re-spelled here.
 * lane-networking.js's header is about precisely this: the last time these four
 * lines of arithmetic were copied, the copy drifted and minted addresses that
 * collided with the shared allocator's, cross-module and invisible. The bases
 * are what the golden images write into their AD-integrated DNS zone, their
 * SYSVOL referrals and every SPN, so a base derived one way at bake time and
 * another way at deploy time is a forest that names addresses no lane owns.
 *
 * BOTH SEGMENTS, because assertFixedSubnet requires both: `int` is where the
 * baked AD lives, `ext` is where Kali, the DMZ pivot and every published console
 * live on a v3 lane.
 *
 * Lazily required for the same reason the compiler is: this file is loaded by
 * tests that want a router and nothing else.
 */
function bakeFixedSubnetFor(vxlanBlock) {
  // eslint-disable-next-line global-require
  const laneNetworking = require('../utils/lane-networking');
  const id = Number(vxlanBlock && vxlanBlock.start);
  return {
    int: laneNetworking.v3InternalSubnet(id).base3,
    ext: laneNetworking.v2LaneSubnet(id).base3,
  };
}

/** A refusal a bake operator can act on, in the shape every renderer here reads. */
function refuseBake(message, code, status = 409) {
  return Object.assign(new Error(message), { code, status, statusCode: status });
}

/**
 * The staging engagement's block, or a refusal naming what to do about it.
 *
 * CREATES THE ENGAGEMENT AND THEN REFUSES, rather than waiting for it. Carving
 * even a one-lane block is a cluster-wide `PUT /cluster/sdn` plus a wait for the
 * bridges on every node; createEngagement's whole contract is that it returns as
 * soon as the row exists and the UI polls. So the first Bake on a client sets
 * the reservation going and says so — which is a button an operator presses
 * again in a minute, not a request that hangs for one.
 *
 * @returns {Promise<{engagement:object, vxlanBlock:{start:number,end:number}, fixedSubnet:{int:string,ext:string}}>}
 */
async function resolveBakeNetwork({ profileId, companyName, subnetScheme, actingUserId }) {
  let engagement = await engagementProvision.resolveEngagement(profileId, BAKE_ENGAGEMENT_TYPE);

  if (!engagement) {
    engagement = await engagementProvision.createEngagement({
      profileId,
      engagementType: BAKE_ENGAGEMENT_TYPE,
      subnetScheme,
      // ONE. See BAKE_ENGAGEMENT_TYPE: a block of one is what makes the staging
      // lane's id — and therefore the bases the golden images bake into
      // themselves — knowable before the lane exists.
      maxStudents: 1,
      companyName,
      actingUserId,
    });
    throw refuseBake(
      `This client had no staging network yet, so one is being carved now (a single-lane block for `
      + `the bake, separate from the class's so it cannot eat a student's seat). It takes a couple of `
      + `minutes — the SDN zone, the VNets and the wait for the bridges on every node. Press Bake `
      + `again when the reservation panel reads Ready.`,
      'BAKE_NETWORK_PROVISIONING');
  }

  if (engagement.provision_status !== 'ready') {
    // assertEngagementDeployable already words every one of these — still
    // provisioning, failed, ready-but-inconsistent — and re-wording them here
    // would be a second vocabulary for one fact. Only the CODE is re-stamped, so
    // the bake panel can tell an engagement problem from a compile problem.
    try {
      engagementProvision.assertEngagementDeployable(engagement, {
        profileId, engagementType: BAKE_ENGAGEMENT_TYPE,
      });
    } catch (err) {
      throw refuseBake(err.message, 'BAKE_NETWORK_NOT_READY', err.status || 409);
    }
  }

  const reservation = await findProfileChallenge(profileId, BAKE_ENGAGEMENT_TYPE);
  const block = reservation && reservation.vxlan_block;
  if (!block || !Number.isInteger(Number(block.start)) || !Number.isInteger(Number(block.end))) {
    throw refuseBake(
      `This client's '${BAKE_ENGAGEMENT_TYPE}' engagement reads ready but its reservation carries no `
      + 'VXLAN block, so the staging lane has no id to allocate and no SDN zone to attach to. '
      + 'Re-provision the staging reservation before baking.',
      'BAKE_NETWORK_NO_BLOCK');
  }

  if (Number(block.end) !== Number(block.start)) {
    throw refuseBake(
      `This client's staging reservation holds ${Number(block.end) - Number(block.start) + 1} VXLAN `
      + `ids (${block.start}-${block.end}), and a bake needs exactly one. The block size is not `
      + 'bookkeeping: the pair of /24 bases the golden images write into their DNS zone, their SYSVOL '
      + 'referrals and every SPN is derived from the id the staging lane takes, and with more than '
      + 'one id in the block nothing can say which id that will be — so the capture phase would '
      + 'compare the declared bases against different ones and refuse, ninety minutes in. Retire the '
      + `'${BAKE_ENGAGEMENT_TYPE}' engagement and let Bake re-create it at one slot.`,
      'BAKE_NETWORK_BLOCK_TOO_BIG');
  }

  const vxlanBlock = { start: Number(block.start), end: Number(block.end) };
  let fixedSubnet;
  try {
    fixedSubnet = bakeFixedSubnetFor(vxlanBlock);
  } catch (err) {
    // v3InternalSubnet refuses above 32767: the high-bit scheme that keeps the
    // internal /24 from ever colliding with an external one overflows the second
    // octet there. That is a cluster-wide condition rather than anything about
    // this client — the block allocator only ever climbs — so it is reported as
    // itself instead of as a stack trace out of a lazy require.
    throw refuseBake(
      `This client's staging block (VXLAN ${vxlanBlock.start}) has no usable /24 pair: ${err.message} `
      + 'Every v3 lane on the cluster is in the same position, so this is range exhaustion rather '
      + 'than a problem with this client. Retire finished labs to reclaim the top of the range.',
      'BAKE_NETWORK_NO_SUBNET');
  }
  return { engagement, vxlanBlock, fixedSubnet };
}

/**
 * THE PRE-FLIGHT. Everything the provision and capture phases will refuse on,
 * asked BEFORE a row exists.
 *
 * Not a re-implementation of those rules — the actual functions, imported from
 * the module that owns them. That is the whole point: a pre-flight built out of
 * a second copy of the rules is a pre-flight that can pass a spec the consumer
 * then rejects, and the consumer here rejects at the far end of a ninety-minute
 * ansible run. `fixed_subnet` in particular is read by captureGolden, which is
 * the LAST thing a bake does; discovering it there costs the whole run.
 *
 * vxlan_block is checked here and nowhere else in this file, because
 * bake-staging's own resolveVxlanBlock falls back to the client's default
 * reservation when the spec carries none — a fallback that is right for a spec
 * written by hand and wrong for one this route emitted, where a missing block
 * means resolveBakeNetwork was skipped and the staging lane would quietly draw
 * from the CLASS's block instead.
 */
function assertBakeSpecProvisionable(spec) {
  bakeStaging.assertBakeableSpec(spec);
  bakeStaging.assertFixedSubnet(spec);
  const block = spec && spec.vxlan_block;
  if (!block || !Number.isInteger(Number(block.start)) || !Number.isInteger(Number(block.end))) {
    throw refuseBake(
      'this bake carries no spec.vxlan_block, so its staging lane would fall back to whatever block '
      + "the client's default engagement reserved — the class's own, sized exactly to max_students "
      + 'and never freed again, because a staging lane is not torn down. Resolve the staging '
      + 'engagement first.',
      'BAKE_PROVISION_NO_VXLAN_BLOCK');
  }
  return spec;
}

// ─── B1: the machines a bake is actually made of ────────────────────────────
/*
 * A BAKE SPEC WITH NO MACHINES IN IT IS A BAKE THAT CANNOT PRODUCE ANYTHING.
 *
 * bake-staging.stagingChallenge hands the bake's spec STRAIGHT to
 * deployChallengeLanes — it adds a challenge key, a name and the vxlan block and
 * changes nothing else — so `spec.vms` is the entire answer to "which machines
 * does the staging lane clone". Emitting a spec without it stood a lane holding
 * a gateway and a Kali, ran the chain against an empty inventory, and left
 * captureGolden with nothing to convert: BAKE_CAPTURE_NO_TARGETS at the far end
 * of the run, if it got that far.
 *
 * The machines are DERIVED FROM THE COMPILED LAB, in the deployer's vocabulary,
 * and nothing about them is chosen here:
 *
 *   name      ir.hosts[].hostname — which, since the compiler now takes its
 *             hostnames from the client's own asset register, is the SAME name
 *             profile-to-spec gives the machine on a student's lane. That
 *             correspondence is what makes a golden template match a deploy
 *             machine at all; see the compiler's "WHICH SIDE OWNS A FOREST
 *             HOSTNAME" note.
 *   ipOctet   ir.hosts[].ipOctet — the octet the emitted providers/proxmox
 *             inventory addresses the host at. It is not a preference: the
 *             chain runs over that inventory, so a machine placed anywhere else
 *             is unreachable to every playbook.
 *   template  the Windows Server base image the shipped GOAD labs clone, read
 *             through goad-deploy's own catalog reader rather than re-spelled
 *             as a number here — the staging machines have to start from the
 *             image the pinned chain is proven against.
 */

/** dc | member, as goad-deploy's ROLE_RESOURCES spells it. */
function goadRoleForHostType(type) {
  return String(type || '').toLowerCase() === 'dc' ? 'dc' : 'member';
}

/**
 * The forest root, from whichever spelling the compiled lab used.
 *
 * foothold_credential.domain first: it is the one field the chain contract
 * guarantees is a real, created domain (assertFootholdContract), rather than a
 * list entry that may be a string or an object. Shared by the bake's own lab
 * definition and the deploy's, so the two cannot name different forests.
 */
function forestRootOf(ir, fallback) {
  const domains = Array.isArray(ir && ir.domains) ? ir.domains : [];
  const firstDomain = domains
    .map((d) => (typeof d === 'string' ? d : (d && d.fqdn)))
    .find((d) => typeof d === 'string' && d.trim());
  return String(
    ((ir && ir.foothold_credential && ir.foothold_credential.domain))
    || firstDomain
    || fallback
    || ''
  ).trim();
}

/**
 * The forest, as machines: one entry per compiled host, in deployer shape.
 *
 * @returns {Array<{name,role,os,template_vmid,ipOctet,nic_model}>}
 */
function forestMachinesFromIr(ir) {
  // eslint-disable-next-line global-require
  const goadDeploy = require('../../../../../src/utils/goad-deploy');
  // THE IMAGE THE PINNED CHAIN IS PROVEN AGAINST, read through goad-deploy's own
  // catalog reader ("what does CyberCore ship?") rather than re-spelled here.
  // GOAD-Mini is the one-host Windows Server lab, so its controller IS that
  // image — and its os/template_vmid/nic_model come along together, because they
  // describe one machine. e1000 in particular is load-bearing: upstream GOAD
  // documents that an AD-joining Windows guest must use it, since a stock
  // Windows image has no virtio-net driver, never DHCPs, and comes up
  // unreachable while the lane reports active.
  const winServer = goadDeploy.getLab('GOAD-Mini').vms[0];
  return (Array.isArray(ir && ir.hosts) ? ir.hosts : []).map((h) => ({
    name: String((h && h.hostname) || '').trim(),
    role: goadRoleForHostType(h && h.type),
    os: winServer.os,
    template_vmid: winServer.template_vmid,
    ipOctet: Number(h && h.ipOctet),
    nic_model: winServer.nic_model,
  }));
}

/**
 * The bake's spec.vms — the staging lane's machines — from those forest hosts.
 *
 * vm_offset follows admin's canonical convention (600000 + idx * 10000), the
 * same formula profile-to-spec uses, because the deployer derives each clone's
 * VMID from it and two machines sharing an offset clone to one VMID.
 *
 * NO `nics`. On a v3 lane the GOAD layer places a lab host on the internal
 * segment itself (lane-networking resolveVmSegments rung 3), and an explicit
 * segment here would be read by isGoadManagedVm as "placed by hand, not a lab
 * host" — which drops the machine out of the roster the chain is checked
 * against. See stripInferredForestNics below for the same rule on the deploy
 * side, where profile-to-spec has already stamped one.
 */
function bakeSpecVmsFromMachines(machines) {
  return machines.map((m, i) => ({
    name: m.name,
    hostname: m.name,
    template_vmid: m.template_vmid,
    type: 'qemu',
    vm_offset: 600000 + i * 10000,
    role: 'server',
    os_family: 'windows_server',
    services: [],
    post_clone_scripts: [],
    ipOctet: m.ipOctet,
    nic_model: m.nic_model,
  }));
}

// ─── X1: the company web host, which is not a forest machine ────────────────
/*
 * WHY A BAKE WITHOUT ONE CANNOT RUN AT ALL
 *
 * bake-staging's provision phase installs this client's website on the staging
 * lane's dual-homed DMZ host, and it does that BEFORE the capture — its own
 * header says so, and it has to be that way round: the golden image is what
 * every student lane clones, so a site installed after the capture exists on
 * nothing. With only the Windows forest on the spec the staging lane had no
 * dual-homed machine at all: resolveDmzHost found none and refused with
 * BAKE_PROVISION_NO_DMZ_HOST before the chain had even started. Every real bake
 * died there, which is why this machine genuinely belongs on the bake spec
 * rather than on the deploy alone.
 *
 * WHY ITS NAME IS ASKED OF THE SYNTHESIZER INSTEAD OF BEING WRITTEN HERE
 *
 * captureGolden names each golden template after the staging machine it
 * converted, and prebakedSpecFromBake refuses a golden template that no machine
 * in the deploy can be cloned onto (BAKE_GOLDEN_UNMATCHED). That refusal lands
 * ninety minutes after Bake was pressed, and it leaves a client that cannot be
 * deployed at all — so a bake and a deploy that spell this machine's name
 * differently is the most expensive mistake available on this path, and the
 * previous wave deferred the work rather than risk it.
 *
 * The deploy's name has exactly one author: profile-to-spec, which puts the
 * CLIENT'S OWN web asset in the DMZ when the register has one (WEB-01) and
 * appends its own standalone machine when it does not. So the derivation is
 * ASKED rather than copied — the synthesizer is run over this profile and the
 * machine it placed in the DMZ is read back off the spec it produced. Its name,
 * its template, its two NICs and its .240 octet all come back with it, and
 * nothing here re-decides any of them. A second spelling of any one of those
 * four is exactly the drift this arrangement exists to make impossible.
 *
 * ONE CASE THIS DELIBERATELY LEAVES LOUD. A client whose register names no web
 * server at all gets the synthesizer's standalone machine here, and a deploy of
 * that client gets the same machine — unless the deploy turns the vuln-app off,
 * in which case the synthesizer appends nothing and the golden template for it
 * matches no deploy machine. That refuses by name (BAKE_GOLDEN_UNMATCHED,
 * naming the machine), which is the right outcome: deploying a baked
 * environment with its public surface switched off is an exercise whose whole
 * way in is missing, and it must not pass quietly.
 */

/**
 * A vuln-app row shaped ONLY to make the synthesizer answer the question.
 *
 * `vuln_app_install` is emitted only for a row that carries an install script,
 * and resolveDmzVm derives the DMZ host from exactly that field — so a probe
 * without one would report "this client has no DMZ host" for every client alive.
 *
 * The script is never delivered anywhere: the bake spec below carries NO
 * vuln_app_install, deliberately. A staging lane that ran a per-lane app install
 * would bake that install into the golden image, and the real site arrives the
 * other way — bake-staging's cc_web phase, from the compiled lab, before capture.
 */
const BAKE_WEB_PROBE_APP = Object.freeze({
  install_script: '# bake web-host probe — never delivered, see BAKE_WEB_PROBE_APP',
  delivery_mode: 'docker',
});

/**
 * One synthesizer run, in the shape a DEPLOY of this client would make.
 *
 * assetSelection is NULL rather than a hand-built list: isIncluded's own default
 * (role === 'server') is what a deploy with no admin selection uses, and
 * defaultAssetSelection above builds precisely that. One rule, asked of the
 * module that owns it.
 *
 * vulnScriptCatalog is empty because a probe exists to NAME a machine — every
 * entry it could match is a vulnerable-service installer, and the bake spec
 * carries no post_clone_scripts for the same reason it carries no app install.
 */
function bakeWebProbe({ profile, vmTemplateCatalog, subnetScheme }) {
  return synthesizeSpecFromProfile({
    profile,
    assetSelection: null,
    vmTemplateCatalog,
    vulnScriptCatalog: [],
    vulnApp: BAKE_WEB_PROBE_APP,
    options: { subnetScheme, attackBoxes: false },
  }).spec;
}

/** The machine THAT spec puts in the DMZ, by the synthesizer's own rule. */
function dmzMachineOf(spec, subnetScheme) {
  const name = resolveDmzVm({
    subnetScheme,
    vms: spec.vms,
    vulnAppInstall: spec.vuln_app_install,
  });
  if (!name) return null;
  return (Array.isArray(spec.vms) ? spec.vms : []).find((vm) => vm.name === name) || null;
}

/**
 * The bake's web host: the DMZ machine profile-to-spec would give this client.
 *
 * TWO PROBES, because the two facts have two different owners and neither is
 * exported:
 *
 *   1. the baked web template's VMID. It is a function-local const inside the
 *      synthesizer (WEB_TEMPLATE_VMID = 1005) and is exported nowhere, so it is
 *      read back off the standalone machine the synthesizer appends for a client
 *      with no web server — probe 1 is exactly that client. Re-typing the number
 *      here would make this file its fourth copy, which is how the earlier drift
 *      started.
 *   2. the NAME, which depends on this client's own asset register: the first
 *      web server on it, or that same standalone machine when there is none.
 *
 * @param {object} profile   the client, with .assets, as loadProfileForDeploy returns it
 * @param {object} opts
 * @param {string} opts.subnetScheme  the scheme the golden images are addressed at
 * @param {number} opts.vmOffset      this machine's slot in the bake's own spec.vms
 * @returns {object|null} a spec VM, or null when the layout has no DMZ host at all
 */
function bakeWebMachine(profile, { subnetScheme, vmOffset }) {
  // eslint-disable-next-line global-require
  const goadDeploy = require('../../../../../src/utils/goad-deploy');

  let chosen;
  try {
    // PROBE 1 — a client with no register at all, against an EMPTY catalog.
    // Both rungs that could name a machine of the client's own fall through and
    // the synthesizer appends the standalone web VM it keeps for that case.
    const synthetic = dmzMachineOf(bakeWebProbe({
      profile: { assets: [] }, vmTemplateCatalog: [], subnetScheme,
    }), subnetScheme);
    // No DMZ host in this layout at all — v2 is one flat segment, so nothing is
    // dual-homed and there is no .240 for the website to be installed at. Said
    // by returning nothing rather than by inventing a machine the deployer would
    // not place: the provision phase then refuses by name, which is a true
    // sentence about a v2 bake.
    if (!synthetic) return null;

    // PROBE 2 — this client's REAL register, against a catalog holding exactly
    // the two images the answer can turn on: the web template probe 1 just
    // named, and the Windows Server image the forest machines already clone.
    // This is not a claim about the cluster's catalog; it is the smallest one
    // under which every asset a deploy would keep still resolves, so the machine
    // that comes back is the machine a deploy would place in the DMZ. What a
    // Windows asset resolves to here is never read — those machines come from
    // the compiled forest above — and `node` is spelled so the resolver never
    // reaches site-config, which reads a file this pure path must not need.
    const winServer = goadDeploy.getLab('GOAD-Mini').vms[0];
    chosen = dmzMachineOf(bakeWebProbe({
      profile,
      vmTemplateCatalog: [
        {
          id: 'bake-probe-web', os_family: 'linux', os_version: null, os_name: 'web',
          template_vmid: synthetic.template_vmid, node: 'bake-probe',
          role_hints: ['web'], is_active: true, preferred: true,
        },
        {
          id: 'bake-probe-windows', os_family: 'windows_server', os_version: null,
          os_name: 'windows_server', template_vmid: winServer.template_vmid,
          node: 'bake-probe', role_hints: [], is_active: true, preferred: true,
        },
      ],
      subnetScheme,
    }), subnetScheme);
  } catch (err) {
    // The synthesizer refuses a register it cannot turn into a lane at all — a
    // client with more selected machines than the pinning band holds is the live
    // case. A DEPLOY of that client refuses identically, so this is a true
    // answer about the client rather than a crash, and saying it here costs
    // nothing: no row, no staging lane, no chain.
    throw refuseBake(
      `this client's asset register cannot be synthesized into a lane, so nothing can say which `
      + `machine the company website would be installed on: ${err.message} A bake has to name that `
      + 'machine before it starts, because the golden template it captures is matched to a deploy '
      + 'machine BY NAME. Fix the register — a deploy of this client refuses the same way.',
      'BAKE_WEB_HOST_UNSYNTHESIZABLE', 422);
  }
  if (!chosen) return null;

  return {
    name: chosen.name,
    hostname: chosen.hostname || chosen.name,
    // 1005 by way of probe 1: the baked web image (Debian + Docker + Apache),
    // which is what a deploy clones for this machine too.
    template_vmid: chosen.template_vmid,
    type: chosen.type || 'qemu',
    // The bake's own slot, NOT the probe's: spec.vms here is the forest plus
    // this machine, and the deployer derives each clone's VMID from the offset,
    // so two machines sharing one would clone to a single VMID.
    vm_offset: vmOffset,
    role: chosen.role,
    os_family: chosen.os_family,
    services: Array.isArray(chosen.services) ? chosen.services.slice() : [],
    // EMPTY whatever a deploy would run: a post-clone script is a vulnerable
    // service installer, and per-lane content has no business inside a golden
    // image. See BAKE_WEB_PROBE_APP.
    post_clone_scripts: [],
    // BOTH STRAIGHT OFF THE SYNTHESIZED MACHINE. .240 on both segments is where
    // the deployer pins a dual-homed guest (DUAL_HOMED_OCTET) and where
    // bake-staging goes looking for the web host (CC_WEB_DMZ_OCTET) — this file
    // does not get a vote, and does not spell either the octet or the segments.
    ipOctet: chosen.ipOctet,
    nics: chosen.nics,
  };
}

/**
 * What this client currently compiles to — the identity of one bake.
 *
 * lab_hash is the content hash of the compiled IR (migration 015), and it — not
 * a timestamp, not the row's own id — is what "this environment" means. The
 * same profile compiles to the same hash and finds the same row (re-baking
 * identical content is a no-op); an edited profile compiles to a different one
 * and gets a NEW row with its own gates and its own golden templates. It is
 * also what assertBakeDeployable measures drift against, which is why it is
 * derived in exactly ONE place and both callers — the bake route and the deploy
 * gate — read it from here. Two derivations would mean a deploy that silently
 * believed it was current.
 *
 * THE IR AND THE CONTENT, NOT THE EMITTED CHASSIS FILES. Those three carry a
 * provenance banner naming the chassis and the GOAD ref, so hashing them would
 * turn a comment change into a new environment and a ninety-minute re-bake. The
 * IR and the content tree carry no banner and no timestamp; JSON.stringify is
 * deterministic over the IR because every choice in it is seeded off the
 * profile's run_id — the property goad-lab-compile refuses to compile without —
 * and the content tree is hashed path-by-path in sorted order for the same
 * reason. See "WHAT THE IDENTITY HAS TO COVER" below.
 *
 * LAZY REQUIRE, on the one path that needs it. goad-lab-compile reads the
 * chassis library off disk and pulls the validator, the pre-flight and the
 * attack-chain designer in behind it; goad-lab-content pulls the designer's
 * password pools. A top-level require would put all of that into the load graph
 * of every test that requires this router for something else entirely — the
 * same reasoning bake-orchestrator.js gives for lane-deployer.
 */
function bakeIdentityForProfile(profile, opts = {}) {
  // eslint-disable-next-line global-require
  const compiler = require('../utils/goad-lab-compile');
  // eslint-disable-next-line global-require
  const labContent = require('../utils/goad-lab-content');
  // eslint-disable-next-line global-require
  const { toStrictJson } = require('../utils/goad-lab-validate');
  // eslint-disable-next-line global-require
  const roleManifest = require('../utils/goad-role-manifest');

  // ── compileLabWithChain, NEVER compileLab ────────────────────────────────
  //
  // compileLab LOWERS a chain it is handed; called with no opts — which is what
  // this function used to do — it emits a lab whose `acls` is {} and whose
  // `ir.chain` is all-null. That is a forest with a roster, a payload and NO
  // ATTACK PATH, and it is invisible: assertLabCompiles checks AD semantics and
  // assertGoadLabPreflight checks the dereferences the playbooks actually
  // perform, and neither has an opinion about whether the exercise is solvable.
  // So the lab passed both checkers, pushed clean and deployed green with
  // nothing anywhere reporting a problem — a silent success, which is the one
  // outcome this pipeline treats as worse than a crash.
  //
  // compileLabWithChain is the composer/designer negotiation in one call: the
  // composer emits and DECLARES every privileged principal, the designer designs
  // a chain over that lab and proves no declared admin short-circuits it, and
  // the composer demotes and re-emits when one does. It is bounded
  // (MAX_NEGOTIATION_ROUNDS) and deterministic under a fixed run_id, and it
  // REFUSES rather than emit an unproven chain — those refusals are the whole
  // subject of COMPILE_REFUSALS below.
  const compiled = compiler.compileLabWithChain(profile);

  // ── the per-lab files/ and scripts/, which is where the originality is ────
  //
  // The composer emits three chassis-derived text files and no payload of its
  // own, and it cannot: GOAD's two escape hatches (vulns/files' win_copy and
  // roles/ps' static .ps1) take NO parameters, so per-client content has to be
  // EMITTED rather than templated. goad-lab-content is that emitter, and until
  // this call site existed nothing in the tree called it — every bake shipped
  // the same three files, and the web-app config that is the seam between the
  // website and the forest, the planted credentials the chain's entry technique
  // depends on, and the six technique scripts were all simply absent.
  //
  // generateLabContent wants the compiled `lab` DICT and the composer returns
  // the emitted tree rather than the dict it emitted from, so it is read back
  // out of config.json — the same route ciab-goad-lab-content.test.js takes.
  // mergeLabContent then WIRES the artifacts in (vulns_vars.files entries,
  // hosts[].scripts) and re-sorts `vulns` so `files` runs before anything that
  // consumes what it copied.
  const lab = JSON.parse(compiled.files['data/config.json']).lab;
  const content = labContent.generateLabContent(compiled.ir, {
    runId: compiled.run_id,
    lab,
  });
  const mergedLab = labContent.mergeLabContent(lab, content);

  // A content path that collided with a chassis file would replace it in
  // silence. It cannot today — every content member is under files/ or
  // scripts/ — so this guards a future writer rather than a live case, and it is
  // cheap enough to keep the impossible case impossible.
  const collision = Object.keys(content.tree)
    .find((p) => Object.prototype.hasOwnProperty.call(compiled.files, p));
  if (collision) {
    throw Object.assign(
      new Error(`The generated lab content wants '${collision}', which the compiler already emits. `
        + 'One of the two would silently win and the lab would ship the wrong bytes.'),
      { code: 'CIAB_LAB_TREE_COLLISION', status: 500, statusCode: 500 });
  }

  // config.json is REPLACED by the merged one, not merely accompanied by the
  // new members: an artifact is only reachable if a host dict references it, so
  // a tree that carried files/ without the vulns_vars.files entries would copy
  // nothing and report success.
  const files = Object.assign({}, compiled.files, content.tree, {
    'data/config.json': `${toStrictJson(mergedLab, { wrap: true, indent: 2 })}\n`,
  });

  // ── the compiler's contract, asserted where it ships ─────────────────────
  // Not defensive decoration: a chain-less compile is EXACTLY what this call
  // site used to produce, and it is undetectable downstream. Asserting it here
  // makes the regression impossible to reintroduce quietly. It is a 500 and NOT
  // one of the named refusals below, deliberately — the three refusals are the
  // compiler correctly declining to build a broken environment; this one is the
  // compiler breaking its own contract, which is a bug in us.
  const aclCount = Object.values(compiled.ir.acls || {})
    .reduce((n, block) => n + Object.keys(block || {}).length, 0);
  const edgeCount = ((compiled.ir.chain || {}).edges || []).length;
  if (aclCount === 0 || edgeCount === 0) {
    throw Object.assign(
      new Error(`${compiled.ir.lab_name} compiled with ${edgeCount} chain edge(s) and ${aclCount} `
        + 'ACL(s) — an environment with a roster and no attack path. Both checkers pass such a lab '
        + 'and it deploys green, so this refuses instead: compileLabWithChain must have designed a '
        + 'chain, and a compile that returns one without is a defect in the compiler rather than a '
        + 'client that cannot host an engagement.'),
      { code: 'CIAB_BAKE_CHAINLESS_COMPILE', status: 500, statusCode: 500 });
  }

  const vendored = roleManifest.loadManifest();

  // The FILE's digest, not vendored.goad_ref. Two re-vendors at one pin are two
  // different role libraries, and a bake validated against one and run against
  // the other is precisely the failure the vendored manifest exists to prevent —
  // quietly, because GOAD roles report success whether or not they planted
  // anything.
  const manifestSha = crypto.createHash('sha256')
    .update(fs.readFileSync(roleManifest.MANIFEST_PATH))
    .digest('hex');

  // ── WHAT THE IDENTITY HAS TO COVER ───────────────────────────────────────
  //
  // The IR carries the attack chain (ir.chain) and the planted ACLs (ir.acls),
  // so hashing it makes an edit that moves ONLY the attack path — same company,
  // same roster, same hosts — a different environment. Which is what it is: the
  // golden templates were built with the old edges planted in AD, and a deploy
  // that reused them would hand students a forest whose graph does not match the
  // answer key their instructor is holding.
  //
  // The content tree is hashed SEPARATELY rather than trusted to follow. It is
  // derived from the IR, so in practice a chain change moves it too — but the
  // implication only runs one way. A change to goad-lab-content itself (a new
  // artifact writer, a different plant for the same entry kind) rewrites the
  // bytes on the guest while leaving the IR byte-identical, and a hash covering
  // only the IR would call that the same environment and deploy last week's
  // golden templates against this week's planted files. Path-by-path in sorted
  // order, because an object's key order is not part of what was built.
  // Serialised as sorted [path, body] PAIRS rather than joined with a separator:
  // JSON quoting does the framing, so no choice of delimiter can make two
  // different trees hash alike — a separator byte that can appear in a path or
  // in a file body is a collision waiting for the one client whose filename
  // contains it.
  // ── the machines, before the spec is written ─────────────────────────────
  // Derived here so the two emissions cannot disagree: spec.vms is what the
  // staging lane clones, and spec.goad.lab.vms is what the deployer reconciles
  // that lane against (assertGoadRoster requires them to be the same set in both
  // directions, and prepareGoadMacs refuses a lab definition that is not in
  // deploy shape at all — which the bare IR is not).
  const forestMachines = forestMachinesFromIr(compiled.ir);
  if (forestMachines.length === 0) {
    throw Object.assign(
      new Error(`${compiled.ir.lab_name} compiled a forest with no hosts in it, so a bake of it `
        + 'would stand a staging lane holding nothing and capture no golden templates. A compile '
        + 'that returns a lab with an empty roster is a defect in the compiler rather than a client '
        + 'that cannot host an engagement.'),
      { code: 'CIAB_BAKE_HOSTLESS_COMPILE', status: 500, statusCode: 500 });
  }
  // Every one of them addressed, or none of them baked. The octet is the last
  // byte of the machine's deterministic MAC and the address the emitted ansible
  // inventory reaches it at, so an unaddressed host is a staging lane whose
  // chain connects to nothing — discovered an hour in, as unreachable hosts.
  const unaddressed = forestMachines.filter(
    (m) => !m.name || !Number.isInteger(m.ipOctet) || m.ipOctet < 2 || m.ipOctet > 254);
  if (unaddressed.length > 0) {
    throw Object.assign(
      new Error(`${compiled.ir.lab_name} compiled ${unaddressed.length} forest host(s) with no name `
        + `or no pinned octet (${unaddressed.map((m) => `${m.name || '(unnamed)'}=${m.ipOctet}`).join(', ')}). `
        + 'The octet is what providers/proxmox/inventory addresses the host at and the last byte of '
        + 'its deterministic MAC, so a bake of this lab would run its chain against machines nothing '
        + 'can reach. A compile that returns a host without one is a defect in the compiler.'),
      { code: 'CIAB_BAKE_UNADDRESSED_HOST', status: 500, statusCode: 500 });
  }

  // ── the machine the company's website lives on ───────────────────────────
  // Derived HERE rather than in the spec literal below because it needs the
  // forest's size: it is appended after the forest, and vm_offset continues the
  // same 600000 + idx * 10000 walk bakeSpecVmsFromMachines uses — two machines
  // sharing an offset clone to one VMID.
  //
  // The scheme is resolved once and read twice (here and in `subnet_scheme`
  // below), because it decides BOTH the addressing the golden images are baked
  // at and whether this client's layout has a DMZ host at all. Two spellings of
  // it could disagree, and the disagreement would be a bake whose declared
  // scheme has no dual-homed machine in it.
  const subnetScheme = opts.subnetScheme || DEFAULT_SUBNET_SCHEME;
  const webMachine = bakeWebMachine(profile, {
    subnetScheme,
    vmOffset: 600000 + forestMachines.length * 10000,
  });

  const contentSha = crypto.createHash('sha256')
    .update(JSON.stringify(
      Object.keys(content.tree).sort().map((p) => [p, content.tree[p]])))
    .digest('hex');
  const labHash = crypto.createHash('sha256')
    .update(JSON.stringify({ ir: compiled.ir, content: contentSha }))
    .digest('hex');

  // Both producers' warnings, in one shape. Every warning on either side is by
  // definition a silent no-op on the lane — an ACL edge no principal can
  // exercise, a chain-declared file copy the emitter has no writer for — and
  // dropping the content half because it arrives as a bare string would lose
  // exactly the ones nothing else can report.
  const warnings = (compiled.warnings || []).concat(
    (content.warnings || []).map((message) => ({ code: 'CIAB_CONTENT_WARNING', message })));

  return {
    labHash,
    goadRef: vendored.goad_ref,
    manifestSha,
    tier: compiled.tier,
    warnings,
    spec: {
      // The scheme the golden templates are addressed at. A lane cloned from
      // this bake has to be built the same way, so it travels WITH the
      // environment rather than being taken from whatever a later deploy asked
      // for.
      subnet_scheme: subnetScheme,
      // THE STAGING LANE'S MACHINES. bake-staging passes this spec straight to
      // deployChallengeLanes, so without them the lane comes up empty and the
      // capture phase has nothing to convert. See "A BAKE SPEC WITH NO MACHINES
      // IN IT" above.
      //
      // THE FOREST PLUS THE COMPANY WEB HOST, and the web host is LAST and
      // OUTSIDE spec.goad.lab below. It is on this list because the staging
      // lane has to actually stand it up — the provision phase installs the
      // site on it before the capture, and without it resolveDmzHost refuses
      // with BAKE_PROVISION_NO_DMZ_HOST — and it is out of the lab definition
      // because the compiled forest never contained it: deployPrebakedGoadLane
      // skips role 'linux', so a Linux member inside the lab definition gets no
      // heal and no restart while the lane reports active. See bakeWebMachine.
      vms: bakeSpecVmsFromMachines(forestMachines)
        .concat(webMachine ? [webMachine] : []),
      // The spec is NOT complete here. spec.vxlan_block and
      // spec.goad.fixed_subnet are the other half of it, and they are applied by
      // withBakeNetwork below — they need a database round trip, and this
      // function is called on three paths of which only one is starting a bake.
      // The other two (GET /bake and the deploy gate) compile purely to compare
      // hashes, and labHash covers the IR and the content tree ONLY, so an
      // identity with no network is the same ENVIRONMENT as one with it. What it
      // is not is bakeable, which is what the pre-flight is for.
      goad: {
        enabled: true,
        version: compiled.ir.lab_name,
        // validateBakeIdentity's one hard requirement. Without the compiled lab
        // definition the lanes cloned from this bake resolve a DIFFERENT forest
        // than the templates were built with, and nothing throws. It carries the
        // chain and the ACLs now, so an answer key generated off this row
        // describes the path the lane actually has.
        //
        // IN DEPLOY SHAPE AS WELL AS IR SHAPE, and both halves are load-bearing.
        // bake-staging reads the IR out of here to author the company website
        // (hasCompiledLab wants domains + principals) and the deploy gate reads
        // the chain and the foothold out of it — while the DEPLOYER, which the
        // staging lane goes through like any other lane, calls resolveGoadLab on
        // this exact key and runs assertValidLabDef over it before a single
        // clone. A bare IR fails that check on `forestRoot`, so every bake died
        // in the provision phase with a message about a spec nobody hand-wrote.
        // The two shapes are one object because there is only one lab.
        lab: {
          ...compiled.ir,
          forestRoot: forestRootOf(compiled.ir),
          vms: forestMachines,
        },
        // The tree the bake's compile phase picks up. buildBakeSteps()'s
        // default compile step has no chassis composer to call, but it does
        // take a tree already compiled onto the spec — a real source, not a
        // silent success: it is named, it is refused by the push phase on
        // exactly what pushLabTree would refuse it on, and it is delivered byte
        // for byte. `chain` here is the PLAYBOOK chain — pushLabTree renders
        // playbooks.yml from it and refuses a tree that ships its own — not the
        // attack chain, which travels inside `lab` above.
        generated_lab: {
          name: compiled.ir.lab_name,
          files,
          chain: compiled.chain,
        },
      },
    },
  };
}

/**
 * The half of a bake's spec that needs the database: where its staging lane
 * lives, and the two /24 bases its golden images will bake into themselves.
 *
 * SEPARATE FROM THE COMPILE, AND AFTER IT, for a reason that is about cost
 * rather than tidiness. resolveBakeNetwork CREATES a reservation when the client
 * has none — a VXLAN id, an SDN carve and a wait for bridges — and three of the
 * clients that reach POST /bake cannot be baked at all (below the domain floor,
 * an unrepairable chain, an admin negotiation that fails). Compiling first means
 * those three are refused for what they are, before anything is carved for a
 * client that can never use it.
 *
 * PURE and separate from bakeIdentityForProfile so the two emissions have one
 * owner each and neither can quietly stop happening: this is the ONLY place
 * spec.vxlan_block and spec.goad.fixed_subnet are written, and
 * assertBakeSpecProvisionable is the only place their absence is judged.
 */
function withBakeNetwork(identity, network) {
  return {
    ...identity,
    spec: {
      ...identity.spec,
      // The block bake-staging.resolveVxlanBlock reads FIRST, ahead of its
      // fallback to the client's default reservation — which is the class's
      // block, and the thing this whole arrangement exists to keep out of.
      vxlan_block: network.vxlanBlock,
      goad: {
        ...identity.spec.goad,
        // captureGolden's hard requirement, and the reason a bake that omits it
        // dies at the LAST phase: a provisioned forest writes its own addresses
        // into its DNS zone, its SYSVOL referrals and every SPN, so every lane
        // cloned from these templates has to stand on the same base per segment.
        fixed_subnet: network.fixedSubnet,
      },
    },
  };
}

/**
 * THE COMPILER'S LEGITIMATE REFUSALS, AND WHY NONE OF THEM IS A 500.
 *
 * compileLabWithChain declines to produce three kinds of broken environment,
 * and every one of them is a correct answer about this CLIENT rather than a
 * fault in the server:
 *
 *   CIAB_NO_AD_TO_COMPILE          org-sizing says a company this size, in this
 *                                  sector, with this delivery posture does not
 *                                  run Active Directory. Emitting a forest would
 *                                  contradict the paper profile the student
 *                                  reads — validators.js/S-01 strips the domain
 *                                  controllers off exactly this org.
 *   CHAIN_UNREPAIRABLE             the designer could not produce a path its own
 *                                  solvability proof accepts. Shipping the chain
 *                                  anyway means a lab with a second solution
 *                                  nobody wrote down.
 *   CIAB_ADMIN_NEGOTIATION_FAILED  a roster Domain Admin stays reachable more
 *                                  cheaply than the designed chain however many
 *                                  times the composer demotes them and re-emits.
 *
 * "The bake crashed" and "this profile cannot host an AD engagement" send an
 * operator to completely different places — one to the cluster, one to the
 * client's intake — so they must not render as the same 500 with different
 * prose. Each gets its own STATE in the vocabulary bakeStateOf already speaks,
 * its own 422 (the request is well-formed; the thing it describes is not — the
 * same reading assertLabCompiles and assertGoadLabPreflight take), and a REMEDY,
 * because a refusal an operator cannot act on is only marginally better than a
 * crash.
 *
 * WHERE THE STATE LANDS. A refusal happens BEFORE any bake row exists, and not
 * by accident: lab_hash is the row's identity and a refused compile has no hash,
 * so there is nothing to key a row on. The state therefore travels on the route
 * response — POST /bake renders it directly, and GET /bake reports it as the
 * profile's state in place of 'not_built', because telling an operator "not
 * built yet" about a client that can NEVER be built is the same silent-success
 * shape one level up: they press Bake, and it refuses again, forever.
 */
const COMPILE_REFUSALS = Object.freeze({
  CIAB_NO_AD_TO_COMPILE: {
    state: 'no_ad_to_compile',
    status: 422,
    remedy: "This client is below org-sizing's first-domain floor, so there is no forest to build. "
      + 'Deploy it without a GOAD tier — the lanes, the vuln-app and the roster are unaffected. If '
      + 'the client really does run AD, the headcount, sector or delivery posture on the intake is '
      + 'what says otherwise; fix the profile and bake again.',
  },
  CHAIN_UNREPAIRABLE: {
    state: 'chain_unrepairable',
    status: 422,
    remedy: 'The attack-chain designer ran out of repairs before it could prove a path no student '
      + 'can short-circuit. Re-baking runs the identical deterministic design and refuses '
      + 'identically. Change the client — a larger roster, more hosts or a different difficulty '
      + 'gives the designer material to work with — or deploy this one without a GOAD tier.',
  },
  CIAB_ADMIN_NEGOTIATION_FAILED: {
    state: 'admin_negotiation_failed',
    status: 422,
    remedy: 'A roster Domain Admin stays reachable in fewer hops than the intended chain even after '
      + 'the composer demoted them and re-emitted. Re-baking is deterministic and will refuse the '
      + 'same way. The named principal is the lead: an org chart with fewer privileged stakeholders, '
      + 'or a longer chain from a larger client, is what resolves it.',
  },
});

/**
 * A compiler refusal, as the thing an operator reads — or null when this error
 * is not one.
 *
 * Keyed on `.code` and nothing else. Matching prose would turn every reworded
 * message into a silent reclassification back to "the bake crashed", and the
 * codes are already the compiler's own machine-routable contract.
 */
function compileRefusalOf(err) {
  const known = err && err.code ? COMPILE_REFUSALS[err.code] : null;
  if (!known) return null;
  return {
    code: err.code,
    state: known.state,
    reason: err.message,
    remedy: known.remedy,
  };
}

/**
 * Stamp a compiler refusal so it renders as itself all the way out.
 *
 * `status` AND `statusCode`: LabCompileError sets only the former, ChainCompileError
 * likewise, and the renderers on this router read one or the other — so a
 * refusal carrying a single name renders as a bare 500 somewhere, which is the
 * same defect ciab-engagement-routes.test.js records against
 * assertEngagementDeployable's 409. Anything that is NOT a known refusal is
 * returned untouched, because inventing a state for an unrecognised failure is
 * how a cluster outage starts reading as a client that cannot host AD.
 */
function refineCompileRefusal(err) {
  const refusal = compileRefusalOf(err);
  if (!refusal) return err;
  err.status = COMPILE_REFUSALS[err.code].status;
  err.statusCode = err.status;
  err.bake_state = refusal.state;
  err.compile_refusal = refusal;
  return err;
}

/**
 * "This part of the feature is not built yet" vs "this bake ran and failed".
 *
 * Two of the five phases REFUSE by construction (see buildBakeSteps): nothing
 * builds a single staging lane for a bake — provisionProfileLanes deploys one
 * lane per STUDENT and tears the batch down together, which is a different
 * resource — and nothing converts a staging lane's VMs into golden templates.
 * Both raise BakeStepNotImplemented, and both reach the row the only way
 * anything reaches a detached worker's row: as status='failed' plus a message.
 *
 * That is right for the orchestrator and useless for an operator, who cannot
 * act on "failed" and CAN act on "that phase does not exist in this build".
 * There is no sixth status to write — migration 015's CHECK constraint is the
 * vocabulary, and an off-vocabulary value raises 23514 on every bake — so the
 * distinction is drawn HERE, on the way out, off the recorded message.
 *
 * Matching prose is fragile, so the coupling is PINNED rather than assumed:
 * test/ciab-bake-route.test.js runs the REAL buildBakeSteps() and asserts this
 * regex classifies what those steps actually throw, in both flavours — the step
 * that refuses by name and the orchestrator's own missing-key guard.
 */
const BAKE_STEP_MISSING_RE = /the '([a-z_]+)' phase has no implementation/i;

function notImplementedPhase(bake) {
  if (!bake || bake.status !== 'failed') return null;
  const m = BAKE_STEP_MISSING_RE.exec(String(bake.error || ''));
  return m ? m[1] : null;
}

/**
 * One word for what an operator is looking at.
 *
 * Not a rename of `status`: it collapses the five in-flight statuses into
 * 'building' (which is what a panel renders) and splits the two terminal ones
 * that a bare status conflates — a bake that stopped because a phase does not
 * exist is 'not_implemented', and a bake that finished but has no sign-off is
 * 'awaiting_signoff' rather than 'ready', because the three gates are the only
 * evidence anyone looked at what the playbooks claim they built.
 */
function bakeStateOf(bake, refusal) {
  // A profile the compiler REFUSES is not 'not_built'. 'not_built' means "press
  // Bake"; this client's Bake will refuse again, deterministically, forever —
  // and there is no row to say so on, because lab_hash IS the row's identity and
  // a refused compile has no hash. The refusal only wins when there is no row:
  // an environment that already exists is still described by its own row, and
  // the refusal then surfaces beside it as the reason drift cannot be checked.
  if (!bake && refusal) return refusal.state;
  if (!bake) return 'not_built';
  if (notImplementedPhase(bake)) return 'not_implemented';
  if (bakeOrchestrator.ACTIVE_STATUSES.includes(bake.status)) return 'building';
  if (bake.status === 'ready') return bake.gates_approved_at ? 'ready' : 'awaiting_signoff';
  return bake.status;
}

/**
 * The projection a panel gets.
 *
 * rowToBake already whitelists the row, but `spec` on a baked AD environment
 * carries the compiled IR AND the emitted lab tree — hundreds of kilobytes that
 * no panel renders and that a two-second status poll would ship every time. So
 * the spec is SUMMARISED rather than sent, and summarised by naming what it
 * holds (the lab, its playbook chain, its file list) rather than by dropping it
 * silently: an operator who cannot see the chain cannot tell a lab that will
 * run four playbooks from one that will run sixteen.
 */
function bakeView(bake) {
  if (!bake) return null;
  const spec = (bake.spec && typeof bake.spec === 'object') ? bake.spec : {};
  const goad = (spec.goad && typeof spec.goad === 'object') ? spec.goad : {};
  const tree = (goad.generated_lab && typeof goad.generated_lab === 'object') ? goad.generated_lab : null;
  const step = notImplementedPhase(bake);
  return {
    bake_id: bake.bake_id,
    profile_id: bake.profile_id,
    lab_name: bake.lab_name,
    lab_hash: bake.lab_hash,
    goad_ref: bake.goad_ref,
    manifest_sha: bake.manifest_sha,
    status: bake.status,
    state: bakeStateOf(bake),
    phase_detail: bake.phase_detail,
    error: bake.error,
    // Named, so the UI can say "not built yet" without parsing an error string
    // of its own — the classification happens once, here.
    not_implemented: step ? { step, detail: bake.error } : null,
    staging_lane_id: bake.staging_lane_id,
    staging_vxlan_id: bake.staging_vxlan_id,
    controller_vmid: bake.controller_vmid,
    verify_report: bake.verify_report,
    golden_vmids: bake.golden_vmids,
    gate_solvable: bake.gate_solvable,
    gate_paper: bake.gate_paper,
    gate_no_unintended: bake.gate_no_unintended,
    gates_approved_at: bake.gates_approved_at,
    started_at: bake.started_at,
    finished_at: bake.finished_at,
    created_at: bake.created_at,
    updated_at: bake.updated_at,
    lab: {
      subnet_scheme: spec.subnet_scheme || null,
      version: goad.version || null,
      chain: (tree && Array.isArray(tree.chain)) ? tree.chain.slice() : null,
      files: (tree && tree.files && typeof tree.files === 'object') ? Object.keys(tree.files) : null,
    },
  };
}

/**
 * Re-render a bake refusal so it reaches the client intact. TWO REPAIRS, both
 * mechanical, both about a refusal arriving as something an operator can act on.
 *
 *  1. assertBakeDeployable stamps `status`; every OTHER producer runProfileDeploy
 *     reads stamps `statusCode`, and POST /deploy's renderer reads
 *     `err.statusCode || 500`. A refusal carrying only `status` would render as
 *     a bare 500 — the same defect ciab-engagement-routes.test.js records
 *     against assertEngagementDeployable's 409 on this exact path. Both names
 *     are stamped here rather than rewriting the renderer, because the renderer
 *     is shared with a dozen statusCode-only throws above.
 *
 *  2. A bake that stopped on a phase with no implementation is NOT a failed
 *     bake. 'BAKE_FAILED' with "use Re-bake" tells an operator to press a button
 *     that will stop in the same place forever. It becomes 501
 *     BAKE_STEP_NOT_IMPLEMENTED, naming the phase and the remedy.
 */
function refineBakeRefusal(err, bake, refusal) {
  const step = notImplementedPhase(bake);
  if (step && err.code === 'BAKE_FAILED') {
    const refined = new Error(
      `This client's environment cannot be built in this release: the '${step}' phase of the bake `
      + `has no implementation yet (${bake.error}). That is a missing feature, not a failed run — `
      + 'Re-bake will stop in the same place. Deploy this client without an AD lab until the phase '
      + 'lands.');
    refined.code = 'BAKE_STEP_NOT_IMPLEMENTED';
    refined.status = 501;
    refined.statusCode = 501;
    refined.bake_state = 'not_implemented';
    refined.not_implemented = { step, detail: bake.error };
    if (refusal) refined.compile_refusal = refusal;
    return refined;
  }
  err.status = err.status || err.statusCode || 500;
  err.statusCode = err.statusCode || err.status;
  err.bake_state = bakeStateOf(bake, refusal);
  // BAKE_DRIFT_UNKNOWN stays the gate's answer — the bake genuinely cannot be
  // compared with a compile that refused — but the REASON rides along, so an
  // operator reading "could not check" is told in the same breath that this
  // client is below the domain floor rather than that the compiler fell over.
  if (refusal) err.compile_refusal = refusal;
  return err;
}

/**
 * Does this deploy need a baked environment?
 *
 * TWO LIVE ANSWERS, deliberately. `spec.goad.enabled` is the plan's own
 * statement that these lanes carry an AD lab, and it is the condition that
 * becomes the whole rule the moment profile-to-spec emits it (its own comment
 * at :355 says a later wave stamps spec.goad). Nothing writes it TODAY, so a
 * gate resting on that alone would be a constant that reaches nothing — which
 * is exactly the defect R1 found in DEFAULT_SUBNET_SCHEME, on this same path,
 * where every call site wrote a bare literal and the flip was inert.
 *
 * So the second answer is the one that is live now: a client that HAS a bake has
 * a baked environment, and a deploy that ignored it would hand students machines
 * built from something else. A client with no bake row at all has no AD lab and
 * deploys exactly as it did before any of this existed.
 */
function deployNeedsBake(spec, bakes) {
  if (spec && spec.goad && spec.goad.enabled) return true;
  return Array.isArray(bakes) && bakes.length > 0;
}

/**
 * THE DEPLOY GATE. It refuses; it never bakes.
 *
 * NO INLINE FALLBACK, for a stronger reason than the engagement gate a few lines
 * below it has. Reserving a VXLAN block "just this once" on the deploy path is
 * merely slow; baking inline is ninety minutes inside an HTTP request, so nobody
 * would ever write that one. The fallback that WOULD get written is the quiet
 * one — deploy from the newest ready bake and say nothing about the profile
 * having been edited since — and that produces a class of lanes whose machines
 * do not match the client the students were briefed on, with nothing anywhere
 * reporting a problem.
 *
 * Which is why the drift arguments are computed even on the path where computing
 * them FAILS: assertBakeDeployable refuses on a hash it was not given rather
 * than assuming, so a compile that throws arrives as null and produces
 * BAKE_DRIFT_UNKNOWN. "I could not check" and "there is no drift" must never be
 * the same answer.
 */
async function assertProfileBakeDeployable({ profileId, profile, spec }) {
  let bakes;
  try {
    bakes = await bakeOrchestrator.listBakes(profileId);
  } catch (err) {
    // The table may not exist on this deployment yet — plugin migrations are
    // ordered within a plugin, not across a boot. A client with no table has no
    // bake, which is the pre-existing behaviour; it is LOGGED, never swallowed,
    // because the same catch would otherwise hide a real outage as "no bake".
    console.warn(`[CIAB Bake] deploy gate could not read bakes for ${String(profileId).slice(0, 8)}: ${err.message}`);
    return null;
  }

  if (!deployNeedsBake(spec, bakes)) return null;

  // The bake a deploy would USE, and — when there is no ready one — the most
  // recent attempt, so the refusal names the state that row is actually in.
  // getLatestReadyBake alone reports "has not been baked yet" for a client whose
  // bake failed an hour ago, which sends an operator to the wrong button.
  const bake = (await bakeOrchestrator.getLatestReadyBake(profileId)) || bakes[0] || null;

  let identity = null;
  let refusal = null;
  try {
    identity = bakeIdentityForProfile(profile);
  } catch (err) {
    // A NAMED refusal is not the same fact as "the compile blew up", and the
    // difference decides where an operator goes next. Both still produce
    // BAKE_DRIFT_UNKNOWN below — a bake that cannot be compared is a bake that
    // cannot be deployed either way — but only one of them can say why.
    refusal = compileRefusalOf(err);
    console.warn(`[CIAB Bake] could not compile ${String(profileId).slice(0, 8)} to compare with its bake`
      + ` (${refusal ? refusal.code : 'unclassified'}): ${err.message}`);
  }

  try {
    bakeOrchestrator.assertBakeDeployable(bake, {
      currentGoadRef: identity ? identity.goadRef : null,
      currentLabHash: identity ? identity.labHash : null,
      profileId,
    });
  } catch (err) {
    throw refineBakeRefusal(err, bake, refusal);
  }
  return bake;
}

// ─── C1b: the bake's golden templates, on the deploy spec ───────────────────
/*
 * THE GAP THIS CLOSES, IN ONE SENTENCE: a bake built golden templates and
 * nothing ever cloned them.
 *
 * assertProfileBakeDeployable already refuses a deploy whose environment was
 * never built, is still building, was never signed off or has drifted. What it
 * did NOT do is USE the bake it just validated — it returned the row and the
 * caller dropped it. So a client with a perfect, signed-off, ninety-minute bake
 * deployed exactly like a client with none: every lane cloned the ORIGINAL
 * catalog templates, spec.goad.prebaked was never set, challenge-lane-deployer
 * took the deployGoadLane branch, and every student's lane stood up its own
 * ansible controller and re-ran the whole chain. That is not a slow path, it is
 * the entire thing the golden-image design exists to avoid, and it reported
 * success the whole way.
 *
 * Everything below is one pure function so that "what a bake changes about a
 * deploy" is assertable without a cluster, and so the NO-BAKE case is provably
 * unchanged: with no bake the caller gets back the SAME OBJECT it passed in
 * (`===`), not a reconstruction that happens to look equal.
 */

/**
 * golden_vmids, normalised to a name → { name, vmid, node } map.
 *
 * Tolerant of the two shapes for the same reason bake-orchestrator's
 * vmidsFromGolden is: capture writes the rich entry, and a hand-repaired row may
 * carry a bare number.
 */
function goldenTemplatesOf(bake) {
  const raw = (bake && bake.golden_vmids && typeof bake.golden_vmids === 'object')
    ? bake.golden_vmids : null;
  const out = new Map();
  for (const [key, entry] of Object.entries(raw || {})) {
    const rich = (entry && typeof entry === 'object') ? entry : {};
    const vmid = Number(rich.vmid != null ? rich.vmid : entry);
    if (!Number.isInteger(vmid) || vmid <= 0) continue;
    const name = String(rich.name || key);
    out.set(name.toLowerCase(), { name, vmid, node: rich.node || null });
  }
  return out;
}

/**
 * WHO IS IN THE FOREST THIS BAKE BUILT, by name.
 *
 * Both spellings a bake row can carry are read: `vms[]` when the lab is in
 * deploy shape (which is what this route emits, because the staging lane goes
 * through the same deployer as every other lane and resolveGoadLab validates
 * exactly that shape) and `hosts[]` for a bare IR, which is what rows written
 * before that carry. `type: 'dc'` on a host and `role: 'dc'` on a deploy-shaped
 * entry are the same fact: deployPrebakedGoadLane heals a controller and a
 * member differently, and a role it does not recognise is a machine it silently
 * skips.
 *
 * @returns {Map<string, {name:string, isDc:boolean}>} keyed by lower-case name
 */
function forestOfBake(bake) {
  const ir = ((bake && bake.spec && bake.spec.goad) || {}).lab || {};
  const forest = new Map();
  for (const h of (Array.isArray(ir.hosts) ? ir.hosts : [])) {
    const name = String((h && h.hostname) || '').trim();
    if (name) forest.set(name.toLowerCase(), { name, isDc: goadRoleForHostType(h.type) === 'dc' });
  }
  for (const v of (Array.isArray(ir.vms) ? ir.vms : [])) {
    const name = String((v && v.name) || '').trim();
    if (name) forest.set(name.toLowerCase(), { name, isDc: String(v.role || '').toLowerCase() === 'dc' });
  }
  return forest;
}

/**
 * A forest machine's placement, with profile-to-spec's INFERENCE taken back off.
 *
 * THE COLLISION THIS RESOLVES, stated once. applyV3Topology stamps
 * `nics: [{segment:'int'}]` on every non-DMZ machine of a v3 lane, and its own
 * comment says why it leaves an existing nics[] alone: an explicit array "is the
 * topology canvas's or an instructor's authored answer". But for a machine the
 * baked lab declares, that stamp is not an authored answer — it is an inference
 * of the SAME placement the GOAD layer derives for itself (lane-networking
 * resolveVmSegments rung 3 puts a lab host on 'int'), made by a synthesizer that
 * had no forest to consult.
 *
 * Downstream, `isGoadManagedVm` reads any explicit segment as "placed by hand,
 * not a lab host". So the inference told the GOAD layer to keep its hands off
 * every machine in the forest, and the consequences were all silent:
 * prepareGoadMacs returned nothing, so no machine got a deterministic MAC or a
 * DHCP reservation; the pre-baked cloud-init strip (which is keyed on the same
 * flag) never ran, so cloudbase-init renamed each clone and broke the secure
 * channel its baked AD account depends on; and assertGoadRoster then failed the
 * whole lane over hosts it had just been told were not lab hosts.
 *
 * Removing the stamp is not a placement change — the machine lands on 'int'
 * either way — it is deleting a claim about WHO decided, and for a forest host
 * the answer is the lab. A machine whose placement genuinely disagrees with
 * that (dual-homed, or on the external segment) is refused rather than
 * rewritten: cabling a baked DC to the attacker's own segment is not something
 * to fix silently.
 */
function stripInferredForestNics(vm, bakeLabName) {
  const nics = Array.isArray(vm.nics) ? vm.nics.filter((n) => n && n.segment) : [];
  if (nics.length === 0) return vm;
  const segments = [...new Set(nics.map((n) => String(n.segment)))];
  if (segments.length !== 1 || segments[0] !== 'int') {
    throw refuseBake(
      `'${vm.name}' is one of the machines this client's bake (${bakeLabName}) built into its `
      + `forest, but this deploy places it on ${segments.map((s) => `'${s}'`).join(' + ')}. A baked `
      + 'AD host lives on the internal segment: that is where its golden image was addressed, where '
      + 'the lane reserves its address, and what the FORWARD drop is protecting. A dual-homed one '
      + 'also gets no pinned MAC at all (the deployer builds multi-NIC configs inline), so it would '
      + 'come up on a pool lease with a forest that names a different address. Remove the explicit '
      + 'nics[] from this machine, or re-bake with it outside the forest.',
      'BAKE_LAB_VM_MISPLACED');
  }
  const next = { ...vm };
  delete next.nics;
  return next;
}

/**
 * The lab definition a PRE-BAKED lane is deployed against.
 *
 * WHY THIS IS NOT JUST `bake.spec.goad.lab`. The bake stamps the COMPILER's IR
 * there — `{ run_id, tier, lab_name, domains, hosts, principals, chain, acls,
 * foothold_credential }` — because that is what the answer key and the drift
 * check need. goad-deploy wants something else entirely: `{ forestRoot, vms: [{
 * name, role, os, template_vmid, ipOctet }] }`, and it VALIDATES it
 * (assertValidLabDef) before a single clone. Handing it the IR is not a slow
 * failure, it is prepareGoadMacs throwing before the lane starts.
 *
 * So the deploy-shaped definition is DERIVED, and each of its three parts comes
 * from the side that actually owns that fact:
 *   the BAKE         WHO IS IN THE FOREST, and which of them are domain
 *                    controllers. The bake built the directory; nothing on the
 *                    deploy side gets a vote about which machines have an
 *                    account in it.
 *   the deploy spec  the ADDRESS each of those machines is pinned to. The scan
 *                    report, the asset register and the topology diagram are
 *                    written from this spec, and a student nmaps what they say
 *                    — so the octet the paper prints is the octet the lane
 *                    reserves, not the one the staging lane happened to use.
 *   the golden set   the TEMPLATE each machine clones from.
 *
 * WHY MEMBERSHIP IS NOT `isGoadManagedVm`, WHICH IS WHAT THIS USED TO ASK.
 * That predicate answers "is this machine one the GOAD layer should place", and
 * it says no to anything carrying an explicit nics[] segment — correctly, since
 * an authored placement must win over an inferred one. But it is NOT the same
 * question as "is this machine part of the forest", and profile-to-spec's
 * applyV3Topology stamps nics[] on EVERY machine of a v3 lane the moment the
 * lane has a dual-homed DMZ host, which is the default shape of every CIAB
 * profile lane. So a correct selection of Windows servers arrived here with all
 * of them exempt, the roster came out empty, and the deploy refused with
 * BAKE_LAB_NO_MEMBERS naming an asset selection that was never wrong.
 *
 * The forest is a fact the bake already recorded, so it is READ rather than
 * inferred: a spec machine is in the forest iff the bake's lab names it. The
 * DMZ web host stays out because the compiled forest never contained it (the
 * synthesizer forces every web asset onto Linux and the compiler skips them),
 * which is the right reason — deployPrebakedGoadLane skips role 'linux', so a
 * Linux member in this list would be a machine nothing heals.
 */
function deployLabDefFromBake(vms, bake, golden) {
  const ir = ((bake.spec || {}).goad || {}).lab || {};

  const forestRoot = forestRootOf(ir, ((bake.spec || {}).goad || {}).domain);
  if (!forestRoot) {
    throw refuseBake(
      `This client's bake (${bake.lab_name}) names no forest root, so the lanes cloned from it have `
      + 'no domain to be healed against — the pre-baked path resolves the lab by forestRoot before it '
      + 'touches a machine. Re-bake this client; a bake whose compiled lab carries no domain cannot '
      + 'have produced a forest worth cloning.',
      'BAKE_LAB_NO_FOREST_ROOT');
  }

  const forest = forestOfBake(bake);

  const labVms = [];
  for (const vm of vms) {
    // IS THIS MACHINE IN THE FOREST THE BAKE BUILT? Nothing else — not its
    // nics, not its role. See the note above: asking isGoadManagedVm here
    // conflated "placed by hand" with "not a lab host", and on the default v3
    // topology that emptied the roster completely.
    const member = forest.get(String(vm.name || '').toLowerCase());
    if (!member) continue;
    // A container can never BE a lab host: every one is a full QEMU clone of a
    // Windows image, and an LXC takes net1 with its template owning net0 — so it
    // could not carry the pinned MAC the baked forest's address depends on.
    // Named here rather than skipped, because skipping it is what the old
    // predicate did: the machine would drop out of the roster, its golden
    // template would go unmatched, and the reason would be a name nobody printed.
    if ((vm.type || 'qemu') === 'lxc') {
      throw refuseBake(
        `'${vm.name}' is one of the machines this client's bake (${bake.lab_name}) built into its `
        + 'forest, but this deploy declares it a container. A baked AD host is a full QEMU clone of '
        + 'a Windows image; a container cannot take the golden template, cannot carry the pinned MAC '
        + 'the forest was addressed on, and would join nothing while the lane reported active. '
        + 'Deploy this machine as a VM, or re-bake with it outside the forest.',
        'BAKE_LAB_VM_MISPLACED');
    }
    const isDc = member.isDc || String(vm.role || '').toLowerCase() === 'dc';
    const isLinux = String(vm.os_family || vm.os || '').toLowerCase().includes('linux');
    if (!Number.isInteger(vm.ipOctet) || vm.ipOctet < 2 || vm.ipOctet > 254) {
      throw refuseBake(
        `'${vm.name}' is part of this client's baked forest but its spec carries no pinned octet `
        + `(ipOctet=${JSON.stringify(vm.ipOctet)}). The octet is both the host's address and the last `
        + 'byte of its deterministic MAC, so without it the machine takes a random pool lease, the '
        + 'golden image answers on an address nothing reserved, and the lane still reports active. '
        + 'Re-synthesize this deploy so every machine is addressed.',
        'BAKE_LAB_VM_UNADDRESSED');
    }
    const g = golden.get(String(vm.name || '').toLowerCase());
    // The other direction of the same check BAKE_GOLDEN_UNMATCHED makes. A
    // machine inside the forest roster that the capture never produced would
    // clone the STOCK catalog image: it has no account in the baked directory,
    // so the pre-baked heal restarts Netlogon at it six times, warns, and gives
    // up — in a log nobody is reading — while the lane reports active and the
    // student finds a Windows box that is a member of nothing.
    if (!g) {
      throw refuseBake(
        `'${vm.name}' is inside the forest this deploy would build, but this client's bake `
        + `(${bake.lab_name}) captured no golden template for it — it captured `
        + `${[...golden.values()].map((x) => x.name).join(', ')}. It would clone the stock catalog `
        + 'image instead, which has no account in the baked directory: the heal would retry its '
        + 'secure channel, warn, and give up, and the lane would still report active. Re-bake this '
        + 'client against the asset selection you are deploying.',
        'BAKE_GOLDEN_MISSING');
    }
    labVms.push({
      name: vm.name,
      role: isDc ? 'dc' : (isLinux ? 'linux' : 'member'),
      os: isLinux ? 'linux' : 'windows',
      template_vmid: g.vmid,
      ipOctet: vm.ipOctet,
    });
  }

  if (labVms.length === 0) {
    // WHAT THIS MEANS NOW THAT MEMBERSHIP IS A NAME MATCH: not one machine in
    // this deploy is called what the bake's forest calls its hosts. That is a
    // NAMING failure, not an exemption one — the two lists are printed so an
    // operator can see the difference at a glance, because the cause is almost
    // always that the bake predates the client's asset register (or the register
    // was edited after it), and the fix is a re-bake rather than an edit to a
    // selection that was never wrong.
    const forestNames = [...forest.values()].map((f) => f.name).join(', ') || 'nothing';
    throw refuseBake(
      `None of this deploy's ${vms.length} machine(s) is in the forest this client's bake `
      + `(${bake.lab_name}) built. The bake's forest is ${forestNames}; this deploy carries `
      + `${vms.map((v) => v.name).join(', ') || 'nothing'}. A machine is inside the forest when the `
      + 'baked lab names it, and none of these are — so the golden templates would be cloned onto a '
      + 'lane with no directory in it, and the lane would still report active. Re-bake this client '
      + 'against the asset register you are deploying: the forest takes its hostnames from that '
      + 'register, so a bake made before it was edited names machines this deploy no longer has.',
      'BAKE_LAB_NO_MEMBERS');
  }
  return { forestRoot, vms: labVms };
}

// ─── C1c: WHAT THE PER-LANE RESEED MAY ROTATE, AND WHAT IT MUST NOT ─────────
/*
 * THREE SILENT DEFECTS LIVED IN THE TWO LINES THIS SECTION REPLACES, and every
 * one of them ended as a green lane whose exercise does not work.
 *
 * 1. IT ROTATED THE WRONG ACCOUNT. The overlay took the account off
 *    labIR.foothold_credential, which is where the CHAIN starts. The account the
 *    WEBSITE publishes is a different one on most clients: goad-lab-content puts
 *    the foothold on the site only when the chain plants it web-side
 *    (SITE_WEB_PLANT_FORMATS — 'web_app_credential' and
 *    'ad_description_mirrored_on_web'). For an AS-REP, a null-session, an
 *    open-share or a password-equals-username entry it DELIBERATELY publishes an
 *    inert bind account instead, so that reading a public page does not hand the
 *    student the entry they were meant to earn — assertSiteSound refuses a site
 *    that leaks the foothold any other way. Over a spread of compiled clients
 *    that is most of them. So the reseed rotated one account while every
 *    publisher on the box advertised another, and nothing reported it: AD
 *    returned 0, the file write returned 0, and the credential on the page was
 *    simply not a credential.
 *
 * 2. IT TOOK THE DOMAIN FROM THE WRONG FIELD. site.reseed.domain is
 *    `bindNetbios` — the NetBIOS SHORT name (CLINIC, not clinic.local) — because
 *    that is what the settings page prints beside the account.
 *    Set-ADAccountPassword -Server and PrincipalContext('Domain', …) both want a
 *    DNS domain, so a short name is a credential nothing can set and nothing can
 *    validate. The FQDN is a fact about the PRINCIPAL, so it is read off
 *    labIR.principals.users — the roster that actually creates the account, and
 *    the only list that is still right when the account is in a child domain.
 *
 * 3. AND site.reseed NEVER REACHED THE SPEC AT ALL. lane-reseed's consumer half
 *    is complete — it rewrites an ini, a PHP array, a JSON document, an XML
 *    element and an HTML slot in place, all-or-none, with a read-back — and it
 *    had nothing to consume, so every lane took its "declares NO site plants"
 *    branch and the website kept the baked password for the life of the section.
 *
 * WHERE THE PLANTS COME FROM. goad-lab-content emits them while the site is
 * being authored, which is the only moment anything knows that this client's
 * config is an ini at /var/www/cc-web/config/settings.ini whose password is the
 * `password` key of its [directory] section. The bake row does not persist that
 * block, so this function RE-DERIVES it from the IR the row does carry, with the
 * same run id bake-staging used. A second derivation of one fact is not
 * something this pipeline does on trust: it is CHECKED against what the staging
 * lane actually installed (verify_report.cc_web.pivot_path / .pivot_account),
 * and a disagreement is a named refusal rather than a section full of
 * descriptors addressing files the golden image does not have.
 */

/**
 * Where the chain's entry credential is published, and therefore whether a
 * per-lane rotation can reach every copy of it.
 *
 * Keyed on labIR.foothold_credential.planted_at.format — the DESIGNER'S OWN
 * declaration of what it did — never on anything inferred from the password
 * string. "That looks like a wordlist entry" is a guess; "the chain says this
 * entry is an AS-REP roast" is a fact, and it is the fact that decides whether
 * rotating the value deletes the exercise.
 */
const FIXED_ENTRY_FORMATS = Object.freeze({
  password_equals_samaccountname:
    'the password IS the sAMAccountName, and that equality is the technique (chain entry '
    + "'user_equals_password'); a 20-character random value deletes the entry outright",
  asrep_roastable:
    'the password is drawn from the crackable wordlist on purpose so the AS-REP hash falls to an '
    + "offline crack (chain entry 'asrep'); a CSPRNG value makes the hash uncrackable and the lab "
    + 'has no entrance',
  ad_description_via_anonymous:
    "the password is planted in the account's AD description, which is what the null session reads; "
    + 'nothing on the web box publishes it, so a rotation cannot reach that copy and the student '
    + 'would read a password the directory no longer honours',
  smb_share_file:
    'the password is planted in an IT handover note on an anonymous SMB share, which is the artifact '
    + 'the student is meant to find; a rotation cannot rewrite a file on a Windows share host',
});

/** The edge declaration that makes an account's password a CRACK TARGET. A
 *  roasted account's password is a wordlist value by construction — see
 *  goad-attack-chain's CRACKABLE_PASSWORDS and addCrackablePrerequisite. */
const KERBEROAST_EDGE_TYPE = 'kerberoast';

/** `CLINIC\svc.webapp` / `svc.webapp@clinic.local` → `svc.webapp`. The chain and
 *  the roster spell principals both ways; goad-lab-content's own bareSam exists
 *  for the same reason. */
function bareSamOf(v) {
  const s = String(v == null ? '' : v).trim();
  const back = s.lastIndexOf('\\');
  if (back !== -1) return s.slice(back + 1).trim();
  const at = s.indexOf('@');
  return (at !== -1 ? s.slice(0, at) : s).trim();
}

/**
 * The DNS domain an account really lives in, off the roster that creates it.
 *
 * NOT site.reseed.domain (the NetBIOS short name) and NOT spec.goad.domain (the
 * forest root, which is the wrong answer for any account in a child domain, and
 * a multi-domain client is the common case above tier S).
 *
 * @returns {string|null} the FQDN, or null when the roster does not name them
 */
function principalDomainOf(ir, sam) {
  const want = bareSamOf(sam).toLowerCase();
  if (!want) return null;
  const users = (ir && ir.principals && Array.isArray(ir.principals.users))
    ? ir.principals.users : [];
  const hit = users.find((u) => bareSamOf(u && u.sam).toLowerCase() === want);
  const fqdn = hit ? String(hit.domain || '').trim() : '';
  return fqdn || null;
}

/**
 * Every credential in this lab whose VALUE or PROPERTY carries the exercise.
 *
 * THE RULE THIS ENCODES. Per-lane uniqueness exists for secrets whose only job
 * is to differ between students. It must NEVER be applied to a credential the
 * exercise is ABOUT — a password that is deliberately crackable, a password that
 * equals the account name, a password planted in a share file or a description
 * the student is meant to find and reuse. Rotating one of those reports
 * `credential: ok` and leaves a chain nobody can walk, which is the worst
 * outcome this pipeline recognises: a silent success.
 *
 * Every entry comes from a DECLARATION the designer wrote:
 *   - foothold_credential.planted_at.format          → FIXED_ENTRY_FORMATS
 *   - chain.edges[] / chain.decoys[] edge_type       → the roasted account
 *   - edge.prerequisites[] that set a password       → the targeted-roast plant
 * Decoys count, because a decoy has to be WALKABLE to teach anything: one that
 * dead-ends at the crack instead of at its destination teaches the wrong lesson.
 *
 * A FORMAT NOBODY HAS CLASSIFIED IS TREATED AS FIXED. The failure modes are not
 * symmetric — not rotating loses per-lane uniqueness LOUDLY (it is named in the
 * plan and on the lane row), while rotating a credential whose publishers we
 * cannot enumerate breaks the exercise silently.
 *
 * @returns {Array<{sam:string, domain:string|null, technique:string, why:string}>}
 */
function fixedCredentialsFromIr(ir) {
  // eslint-disable-next-line global-require
  const { SITE_WEB_PLANT_FORMATS } = require('../utils/goad-lab-content');
  const lab = (ir && typeof ir === 'object') ? ir : {};
  const chain = (lab.chain && typeof lab.chain === 'object') ? lab.chain : {};
  const out = [];
  const seen = new Set();

  const add = (rawSam, technique, why) => {
    const sam = bareSamOf(rawSam);
    if (!sam) return;
    const key = sam.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ sam, domain: principalDomainOf(lab, sam), technique, why });
  };

  // ── the entry credential ─────────────────────────────────────────────────
  const foothold = (lab.foothold_credential && typeof lab.foothold_credential === 'object')
    ? lab.foothold_credential : {};
  const plantedAt = (foothold.planted_at && typeof foothold.planted_at === 'object')
    ? foothold.planted_at : {};
  const format = String(plantedAt.format || '').trim();
  const entryKind = String((chain.start && chain.start.kind) || '').trim();
  if (foothold.sam) {
    if (Object.prototype.hasOwnProperty.call(FIXED_ENTRY_FORMATS, format)) {
      add(foothold.sam, `chain entry '${entryKind || format}'`, FIXED_ENTRY_FORMATS[format]);
    } else if (SITE_WEB_PLANT_FORMATS.indexOf(format) === -1) {
      add(foothold.sam, `chain entry planted as '${format || '(unrecorded)'}'`,
        `nothing classifies where a '${format || '(unrecorded)'}' plant publishes this password, so a `
        + 'per-lane rotation cannot be shown to reach every copy of it. Classify the format in '
        + 'FIXED_ENTRY_FORMATS, or as a web-side plant in goad-lab-content.SITE_WEB_PLANT_FORMATS, '
        + 'before rotating it');
    }
    // else: a web-side plant. Every copy of it is a file on the web box, which
    // is exactly what lane-reseed rewrites — rotatable, nothing to record.
  }

  // ── the accounts the graph expects to be CRACKED ─────────────────────────
  const edges = []
    .concat(Array.isArray(chain.edges) ? chain.edges : [])
    .concat(Array.isArray(chain.decoys) ? chain.decoys : []);
  for (const edge of edges) {
    if (!edge || typeof edge !== 'object') continue;
    if (String(edge.edge_type || '') === KERBEROAST_EDGE_TYPE) {
      add(edge.to, `chain edge '${edge.id || KERBEROAST_EDGE_TYPE}' (kerberoast)`,
        'the roasted account carries an SPN and a wordlist password so its service ticket cracks '
        + 'offline; a CSPRNG value turns an edge BloodHound still draws into a dead end');
    }
    for (const pre of (Array.isArray(edge.prerequisites) ? edge.prerequisites : [])) {
      if (pre && pre.item_vars && typeof pre.item_vars.password === 'string') {
        add(pre.item, `prerequisite of chain edge '${edge.id || '(unnamed)'}'`,
          'the edge writes an SPN onto this account for a targeted roast and the designer planted a '
          + 'crackable password so the roast is walkable; rotating it dead-ends the edge at the '
          + 'crack rather than at its destination');
      }
    }
  }

  return out;
}

/**
 * The website's own reseed descriptor for this bake, re-derived and CHECKED.
 *
 * @param {object} bake  the validated bake row
 * @param {object} ir    the compiled lab on it (bake.spec.goad.lab)
 * @returns {{plan:object|null, where:string}}  `plan` is null only when the
 *   environment declares itself AD-only, and `where` says which case it is.
 */
function siteReseedForBake(bake, ir) {
  const bakeSpec = (bake && bake.spec && typeof bake.spec === 'object') ? bake.spec : {};
  const cc = (bakeSpec.cc_web && typeof bakeSpec.cc_web === 'object') ? bakeSpec.cc_web : {};
  const web = (bake && bake.verify_report && bake.verify_report.cc_web) || null;

  // A DECLARATION, NOT A SILENCE — the same reading installCompanyWebsite takes.
  // "This environment has no website" and "we could not find the website" must
  // never produce the same spec.
  if (cc.enabled === false || (web && web.applicable === false)) {
    return {
      plan: null,
      where: 'this environment declares itself AD-only (spec.cc_web.enabled is false), so no company '
        + 'website publishes the credential and there is nothing on the web side to rewrite',
    };
  }

  // eslint-disable-next-line global-require
  const labContent = require('../utils/goad-lab-content');
  let site;
  try {
    site = labContent.generateSiteContent(ir, { runId: ir.run_id || ir.lab_name });
  } catch (err) {
    throw refuseBake(
      `This client's environment (${bake.lab_name}) carries a company website, and the website its `
      + 'compiled lab describes could not be re-derived to find out WHERE that website publishes the '
      + `pivot credential: ${err.message}. Deploying anyway would give every lane a rotated account `
      + 'in Active Directory and a website still serving the BAKED password out of its own config '
      + 'file and off its integration-settings page — a green lane whose pivot does not work, which '
      + 'nothing downstream can detect. Re-bake this client.',
      'BAKE_SITE_RESEED_UNRESOLVED');
  }

  const plan = (site && site.reseed && typeof site.reseed === 'object') ? site.reseed : null;
  if (!plan || !Array.isArray(plan.plants) || plan.plants.length === 0 || !plan.username) {
    throw refuseBake(
      `This client's environment (${bake.lab_name}) has a company website that publishes a pivot `
      + 'credential and records nowhere for a per-lane reseed to rewrite it, so every lane in the '
      + 'section would advertise the one password baked into the golden image. Re-bake this client.',
      'BAKE_SITE_RESEED_UNRESOLVED');
  }

  // ── the derivation, checked against what was actually installed ──────────
  // The staging lane's web report is the only witness to what cc_web really
  // wrote. If this re-derivation and that witness disagree, the descriptors
  // address files the golden image does not have — and lane-reseed would fail
  // every lane in the section on a path nobody could explain from the spec.
  const installedPath = web ? String(web.pivot_path || '') : '';
  if (installedPath && installedPath !== String(site.pivot.path)) {
    throw refuseBake(
      `This client's environment (${bake.lab_name}) installed its pivot credential at `
      + `'${installedPath}', and the same compiled lab now re-derives it at '${site.pivot.path}'. The `
      + 'per-lane reseed addresses the website BY PATH, so it would rewrite a file the golden image '
      + 'does not have and leave the one it does have serving the baked password. Re-bake this client.',
      'BAKE_SITE_RESEED_DRIFT');
  }
  const installedAccount = web ? String(web.pivot_account || '') : '';
  const derivedAccount = `${plan.domain}\\${plan.username}`;
  if (installedAccount && installedAccount !== derivedAccount) {
    throw refuseBake(
      `This client's environment (${bake.lab_name}) published '${installedAccount}' on its company `
      + `website, and the same compiled lab now re-derives '${derivedAccount}'. The reseed would `
      + 'rotate one account while every page on the box advertised the other, which is a pivot that '
      + 'silently does not work. Re-bake this client.',
      'BAKE_SITE_RESEED_DRIFT');
  }

  return {
    plan,
    where: `the website publishes it in ${site.pivot.path} (${site.pivot.format}) and on ${site.admin_path}`,
  };
}

/**
 * The whole `spec.reseed` block: what rotates per lane, what deliberately does
 * not, and where per-lane uniqueness comes from in each case.
 *
 * SAYING "NOT ROTATED" OUT LOUD IS HALF THE JOB. An operator reading a reseed
 * report has to be able to tell "deliberately not rotated, because the password
 * IS the exercise" from "forgotten". So a credential that must stay fixed is
 * named here with the declaration that fixed it, travels onto the spec, and is
 * echoed onto the lane row by lane-reseed — instead of being quietly skipped.
 *
 * @returns {object} the value for spec.reseed
 */
function reseedBlockForBake({ spec, bake, ir, foothold }) {
  const site = siteReseedForBake(bake, ir);
  const fixed = fixedCredentialsFromIr(ir);
  const fixedBySam = new Map(fixed.map((f) => [f.sam.toLowerCase(), f]));

  // ── the account the WEBSITE publishes, which is the one to rotate ────────
  const published = site.plan ? bareSamOf(site.plan.username) : bareSamOf(foothold.sam);
  const domain = principalDomainOf(ir, published);
  if (!domain) {
    throw refuseBake(
      `This client's environment (${bake.lab_name}) publishes the account '${published}' as its pivot `
      + 'credential, and its compiled roster (labIR.principals.users) creates no such user, so '
      + 'nothing names the DNS domain to reset the password in. The NetBIOS short name the website '
      + 'prints beside the account is not a domain Set-ADAccountPassword or ValidateCredentials will '
      + 'accept. Re-bake this client.',
      'BAKE_PIVOT_DOMAIN_UNRESOLVED');
  }
  // THE SHORT-NAME CHECK, MADE MECHANICAL. This is the field the old overlay got
  // wrong by reading site.reseed.domain, and a single label reaches the DC and
  // fails there — on every lane in the section at once, after the staged
  // rewrites are already sitting on the web box. A DNS domain has a dot, and it
  // is one this forest actually builds.
  const forestDomains = (Array.isArray(ir.domains) ? ir.domains : [])
    .map((d) => String((d && d.fqdn) || d || '').trim()).filter(Boolean);
  if (domain.indexOf('.') === -1 || (forestDomains.length > 0 && forestDomains.indexOf(domain) === -1)) {
    throw refuseBake(
      `This client's environment (${bake.lab_name}) would have each lane's pivot credential reset in `
      + `'${domain}', which is not one of the DNS domains this forest builds `
      + `(${forestDomains.join(', ') || 'none recorded'}). Set-ADAccountPassword -Server and `
      + 'PrincipalContext take a DNS domain, so this is a credential nothing could set and nothing '
      + 'could validate — on every lane at once. Re-bake this client.',
      'BAKE_PIVOT_DOMAIN_UNRESOLVED');
  }

  const blocked = fixedBySam.get(published.toLowerCase()) || null;
  const rotate = Boolean(site.plan) && !blocked;
  const fixedReason = blocked
    ? `${blocked.technique}: ${blocked.why}`
    : (site.plan ? null : site.where);

  const pivot = {
    ...((spec.reseed || {}).pivot || {}),
    sam: published,
    domain,
    // Recorded because the report and the settings page both print it, and
    // NEVER used to authenticate — see the header of this section.
    netbios: site.plan ? String(site.plan.domain || '') : null,
    rotate,
    fixed_reason: fixedReason,
  };
  if (site.plan) pivot.site = site.plan;

  // ── where uniqueness is, and where it is not ─────────────────────────────
  // Stated in both directions on purpose. A per-lane guarantee that quietly
  // stops applying to one value is the same class of defect as a rotation that
  // quietly breaks a chain.
  const perLane = [
    'the application flag, minted per lane from cybercore_lane_flag (CSPRNG) and written where the '
    + 'app exposes it',
    'the seeded record identifiers on the web box (order number, patient id and invoice bases), so '
    + 'two students cannot compare answers about the records the site displays',
    "the web box's SSH host keys and machine-id, so the cohort does not share one host fingerprint",
  ];
  if (rotate) {
    perLane.push(
      `the pivot credential ${domain}\\${published}, rotated in the directory and on every publisher `
      + 'the website carries, in one all-or-none step');
  }
  const baked = fixed.map((f) => `${f.domain || '(domain unknown)'}\\${f.sam} — ${f.technique}: ${f.why}`);
  if (!rotate) {
    baked.push(
      `${domain}\\${published} is the account the website publishes and it is NOT rotated per lane: `
      + `${fixedReason}. Every lane in this section serves the same value for it, so the per-lane `
      + 'uniqueness of this engagement rests entirely on the flag and the seeded data above');
  }

  return {
    ...(spec.reseed || {}),
    pivot,
    fixed,
    uniqueness: { per_lane: perLane, baked },
  };
}

/**
 * The deploy spec, with this client's baked environment on it.
 *
 * Returns its INPUT unchanged (identity-equal) when no bake applies, which is
 * how "an existing non-bake deploy is byte-identical to today" is proved rather
 * than asserted.
 *
 * Three things change when one does apply, and each of them is a downstream
 * consumer that had no producer:
 *
 *   vms[].template_vmid   the machine clones the GOLDEN template instead of the
 *                         catalog one. This is the whole point of a bake.
 *   goad.prebaked         challenge-lane-deployer branches on exactly this to
 *                         call deployPrebakedGoadLane (clone + heal, minutes)
 *                         instead of deployGoadLane (controller + the full
 *                         ansible chain, ~90 minutes). Without it a lane cloned
 *                         from golden AD images ALSO stands up a controller and
 *                         re-provisions a forest that is already there.
 *   reseed.pivot          the account lane-reseed rotates per lane. Named
 *                         rather than guessed — resolveReseedPlan skips the
 *                         credential phase entirely when the spec names none,
 *                         which leaves every lane in a section holding the ONE
 *                         password baked into the golden image.
 *
 * @param {object} spec  the synthesized (or stored) deploy spec
 * @param {?object} bake the row assertProfileBakeDeployable validated, or null
 * @param {object} [opts]
 * @param {string} [opts.subnetScheme]  the scheme the lanes will actually be built at
 * @param {object} [opts.profile]         the client, for buildSpecDns's public web name
 * @param {string} [opts.engagementType]  which engagement — it decides whether the
 *   AD forwarder is published at all
 * @returns {object} a NEW spec, or `spec` itself when nothing applies
 */
function prebakedSpecFromBake(spec, bake, opts = {}) {
  if (!spec || !bake || bake.status !== 'ready') return spec;

  const bakeSpec = (bake.spec && typeof bake.spec === 'object') ? bake.spec : {};
  const bakeGoad = (bakeSpec.goad && typeof bakeSpec.goad === 'object') ? bakeSpec.goad : {};
  const golden = goldenTemplatesOf(bake);

  // A signed-off bake with nothing to clone from. This is a refusal and not a
  // fall-through to the live path on purpose: the gates say a human walked this
  // environment, so silently re-running the chain would hand students a forest
  // nobody reviewed while the panel reads 'ready'.
  if (golden.size === 0) {
    throw refuseBake(
      `This client's environment (${bake.lab_name}) is signed off but recorded no golden templates, `
      + 'so there is nothing for a lane to clone. The capture phase never ran or never recorded what '
      + 'it converted. Re-bake this client — deploying now would re-run the ninety-minute chain on '
      + 'every lane and produce an environment nobody signed off.',
      'BAKE_NO_GOLDEN_TEMPLATES');
  }

  // The pin the images were built around. A bake row written before this route
  // emitted one carries no fixed_subnet at all, and stamping `prebaked` without
  // it would reach applyPrebakedFixedSubnet — which throws, killing the whole
  // lane deploy with a message about a spec nobody hand-wrote. Refusing here
  // names the bake instead, which is the thing an operator has to act on.
  const bakedFixed = bakeGoad.fixed_subnet || {};
  const missingPin = ['int', 'ext']
    .filter((k) => !String(bakedFixed[k] == null ? '' : bakedFixed[k]).trim())
    .map((k) => `fixed_subnet.${k}`);
  if (missingPin.length > 0) {
    throw refuseBake(
      `This client's environment (${bake.lab_name}) declares no ${missingPin.join(' and no ')}, so `
      + 'nothing records which /24 its golden images were built on. A provisioned forest writes its '
      + 'own addresses into its DNS zone, its SYSVOL referrals and every SPN, so lanes cloned from '
      + 'it would come up healthy and resolve nothing. Re-bake this client — a bake started now '
      + 'records the pin.',
      'BAKE_NO_FIXED_SUBNET');
  }

  // The scheme the images were baked at has to be the scheme the lanes are
  // built at. fixed_subnet declares one base PER SEGMENT and a v2 lane has one
  // segment: cloning a v3-baked forest onto a v2 lane puts the AD machines and
  // the attack path on one /24 that only the internal base names, so half the
  // baked addresses are wrong — and the lane still comes up.
  const bakedScheme = bakeSpec.subnet_scheme || null;
  if (opts.subnetScheme && bakedScheme && opts.subnetScheme !== bakedScheme) {
    throw refuseBake(
      `This client's environment was baked as ${bakedScheme} and these lanes would be built as `
      + `${opts.subnetScheme}. The golden images wrote the ${bakedScheme} addressing into their DNS `
      + 'zone, their SYSVOL referrals and every SPN, and a lane built on a different segment layout '
      + 'resolves none of it while still reporting active. Re-carve the engagement at '
      + `${bakedScheme}, or re-bake this client at ${opts.subnetScheme}.`,
      'BAKE_SCHEME_MISMATCH');
  }

  // ── the templates ────────────────────────────────────────────────────────
  const forest = forestOfBake(bake);
  const matched = new Set();
  const vms = (Array.isArray(spec.vms) ? spec.vms : []).map((raw) => {
    const key = String((raw && raw.name) || '').toLowerCase();
    // A forest machine's placement belongs to the lab, not to the synthesizer's
    // inference — see stripInferredForestNics. Done BEFORE the template repoint
    // so the object handed to deployLabDefFromBake and the one the deployer
    // clones are the same object.
    const vm = forest.has(key) ? stripInferredForestNics(raw, bake.lab_name) : raw;
    const g = golden.get(key);
    if (!g) return vm;
    matched.add(key);
    // template_node too: a golden template lives on the node the staging lane
    // was placed on, which is not the catalog node the synthesizer wrote.
    return { ...vm, template_vmid: g.vmid, template_node: g.node || vm.template_node };
  });

  const unmatched = [...golden.values()].filter((g) => !matched.has(g.name.toLowerCase()));
  if (unmatched.length > 0) {
    throw refuseBake(
      `This client's bake produced golden templates for ${unmatched.map((g) => g.name).join(', ')}, `
      + 'which this deploy has no machine for '
      + `(it deploys ${vms.map((v) => v.name).join(', ') || 'nothing'}). A lane built now would be `
      + 'missing a machine the forest was provisioned with — its AD account, its SPNs and its DNS '
      + 'records would all still be there, pointing at a host that does not exist, and the lane would '
      + 'report active. Either restore the asset selection the bake was built from, or re-bake this '
      + 'client against the selection you want.',
      'BAKE_GOLDEN_UNMATCHED');
  }

  // ── the pivot credential ─────────────────────────────────────────────────
  // The seam between the website and the forest: the account whose password the
  // student finds on the web app and sprays at the DC. lane-reseed rotates it
  // per lane, and it REFUSES TO GUESS the name — resetting an account we
  // invented fails on every lane at once, and resetting the wrong real one
  // breaks the forest. So the name has to be emitted, and it can only be
  // emitted from here: it is a fact about the compiled lab.
  //
  // THE FOOTHOLD IS THE GATE, NOT THE ANSWER. Its presence is what proves the
  // bake recorded a lab with an entrance at all; WHICH account gets rotated is
  // decided by reseedBlockForBake, because on most clients the account the
  // website publishes is deliberately not this one. See the C1c section header.
  const lab = (bakeGoad.lab && typeof bakeGoad.lab === 'object') ? bakeGoad.lab : {};
  const foothold = lab.foothold_credential || {};
  const pivotSam = String(foothold.sam || '').trim();
  const pivotDomain = String(foothold.domain || bakeGoad.domain || '').trim();
  if (!pivotSam || !pivotDomain) {
    throw refuseBake(
      `This client's environment (${bake.lab_name}) records no foothold credential, so nothing names `
      + 'the account each lane must be given its OWN password for. Deploying anyway would hand every '
      + 'student in the section the single password baked into the golden image — one student pastes '
      + 'it into the group chat and the cohort is finished — and nothing would report a problem. '
      + 'Re-bake this client.',
      'BAKE_NO_PIVOT_CREDENTIAL');
  }

  const next = {
    ...spec,
    vms,
    goad: {
      ...(spec.goad || {}),
      enabled: true,
      // THE BRANCH. challenge-lane-deployer reads this and nothing else to
      // choose deployPrebakedGoadLane over deployGoadLane.
      prebaked: true,
      version: bakeGoad.version || bake.lab_name,
      domain: pivotDomain,
      fixed_subnet: bakeGoad.fixed_subnet,
      lab: deployLabDefFromBake(vms, bake, golden),
    },
    // WHAT ROTATES PER LANE, WHAT DELIBERATELY DOES NOT, AND WHERE THE
    // WEBSITE PUBLISHES IT. All three, or a lane is green and its pivot is
    // fiction — see the C1c section header.
    reseed: reseedBlockForBake({ spec, bake, ir: lab, foothold }),
  };

  // ── the lane's own resolver, recomputed ──────────────────────────────────
  // buildSpecDns's AD branch is keyed on spec.goad.domain, and its comment says
  // so: "a later wave stamps spec.goad and the forwarder starts being emitted
  // here with no change to this function". Nothing stamped it, so the branch had
  // never once fired. Re-running it on the FINISHED spec is what fires it — and
  // it is re-run rather than patched by hand because the rule that decides
  // whether the forwarder is published at all (withheld on an EXTERNAL
  // engagement, where enumerating AD through the pivot IS the exercise) lives in
  // there and must not acquire a second implementation.
  //
  // Merged onto whatever was already there: the web-name half depends on `vms`
  // and `vuln_app_install`, which this overlay does not touch, so the only thing
  // that can newly appear is the AD pair.
  const dns = buildSpecDns({ spec: next, profile: opts.profile, engagementType: opts.engagementType });
  const mergedDns = { ...(spec.dns || {}), ...(dns || {}) };
  if (Object.keys(mergedDns).length > 0) next.dns = mergedDns;

  // generated_lab is DELIBERATELY not carried across. It is the ansible tree the
  // push phase delivered to the staging lane's controller — hundreds of
  // kilobytes — and a pre-baked lane has no controller and runs no playbook. It
  // would be copied into crucible_challenge.spec and re-read on every add-lanes
  // and every retry for the rest of the engagement's life.
  return next;
}

// ─── Core: runProfileDeploy — invoked by /deploy AND generate-and-deploy ──
/**
 * Synthesizes spec, allocates VXLAN IDs, creates DB rows, kicks off background
 * deploy. Returns the group_id immediately (deployment runs async).
 *
 * @param {object} opts
 * @param {string} opts.profileId
 * @param {string} opts.userId             admin user_id
 * @param {number} opts.numLanes
 * @param {string} [opts.groupName]
 * @param {boolean}[opts.attackBoxes=true]
 * @param {string} [opts.subnetScheme]  defaults to DEFAULT_SUBNET_SCHEME ('v3');
 *   an explicit value wins, and the ENGAGEMENT's own scheme wins over both
 *   wherever the network is touched (see carvedScheme below)
 * @param {Array}  [opts.assetSelection]   if omitted → default-server-only
 * @param {object} [opts.vulnAppOpts]      { enabled, delivery_mode, use_dedicated_vm, llm_model }
 * @param {string} [opts.engagementType]   which engagement against this client
 *   these lanes are for. Reservations are keyed on (profile, engagement), so an
 *   external and an internal engagement against one company get separate VXLAN
 *   blocks instead of aliasing onto each other. Track B turns this into a row in
 *   ciab_engagement; until then it is a free slug defaulting to 'default'.
 * @returns {Promise<{group_id, profile_id, lanes:[...], service_gaps, template_misses}>}
 */
async function runProfileDeploy(opts) {
  const {
    profileId, userId, numLanes,
    maxStudents,                                           // ← NEW: total reservation size; defaults to numLanes
    groupName, attackBoxes = true, subnetScheme = DEFAULT_SUBNET_SCHEME,
    assetSelection: providedSelection, vulnAppOpts = {},
    engagementType
  } = opts;
  const engagement = sanitizeEngagementType(engagementType);

  if (!profileId) throw Object.assign(new Error('profile_id required'), { statusCode: 400 });
  if (!Number.isFinite(numLanes) || numLanes < 1 || numLanes > 100) {
    throw Object.assign(new Error('num_lanes must be 1..100'), { statusCode: 400 });
  }
  if (!['v1', 'v2', 'v3'].includes(subnetScheme)) {
    throw Object.assign(
      new Error(`subnet_scheme must be v1|v2|v3 (default ${DEFAULT_SUBNET_SCHEME})`),
      { statusCode: 400 });
  }
  // max_students reserves a VXLAN slice for future additions. Defaults to numLanes
  // (no headroom) for backward compatibility. Must be >= numLanes.
  const effectiveMaxStudents = Number.isFinite(maxStudents) && maxStudents > 0
    ? maxStudents
    : numLanes;
  if (effectiveMaxStudents < numLanes) {
    throw Object.assign(new Error(`max_students (${effectiveMaxStudents}) must be >= num_lanes (${numLanes})`), { statusCode: 400 });
  }
  if (effectiveMaxStudents > 200) {
    throw Object.assign(new Error('max_students cap is 200 per group'), { statusCode: 400 });
  }

  // 1. Load profile
  const { profile, assets } = await loadProfileForDeploy(profileId);

  // 2. Build asset selection
  const assetSelection = Array.isArray(providedSelection) && providedSelection.length > 0
    ? providedSelection
    : defaultAssetSelection(assets);

  // 3. Fetch catalogs. vm catalog lives in cybercore_db; vuln scripts in clinic_db.
  const [vmCatalogRes, vulnCatalogRes] = await Promise.all([
    cybercoreQuery(`SELECT id, os_family, os_version, os_name, template_vmid, node, role_hints, is_active, preferred, created_at
                    FROM cybercore_template_catalog WHERE is_active = true AND template_type = 'os_template'`),
    query(`SELECT id, slug, name, os_target, category, script_type, services_exposed, is_active FROM vuln_scripts WHERE is_active = true`)
  ]);
  const vmTemplateCatalog = vmCatalogRes.rows;
  const vulnScriptCatalog = vulnCatalogRes.rows;

  // 4 + 6 in parallel. Vuln-app LLM generation can take ~4min on a fresh
  // profile, and SDN provisioning for a 25-slot reservation takes ~45s.
  // They're independent — kick both off, await both before continuing.
  //   - vulnApp generation needs: profile + assets
  //   - reservation+SDN needs: profileId + max + company name + subnetScheme
  //                            (spec is stored but not used for VNet creation;
  //                            we update it after synthesis via the "adopt
  //                            fresh spec" branch below)
  console.log(`[CIAB ProfileDeploy] Profile ${profileId.slice(0,8)}: starting vuln-app generation + reservation in parallel`);
  const vulnAppPromise = vulnAppOpts.enabled === false
    ? Promise.resolve(null)
    : getOrGenerateVulnApp({
        profile: { ...profile, assets },
        llmModel: vulnAppOpts.llm_model,
        preferMode: vulnAppOpts.delivery_mode || 'docker',
        // Per-deploy difficulty (easy|medium|hard) from the admin UI radio.
        // Drives the LLM prompt's vuln-pool selection. Defaults to easy so
        // existing callers (without the field) get the beginner-friendly
        // chain that the rest of the prompt now assumes.
        difficulty: vulnAppOpts.difficulty || 'easy'
      }).catch(err => {
        console.warn(`[CIAB ProfileDeploy] vuln app generation failed (continuing): ${err.message}`);
        return null;
      });

  // A8a: the reservation is NOT carved here any more.
  //
  // Carving it means 25-50 serial VNet POSTs, a CLUSTER-WIDE `PUT /cluster/sdn`
  // apply (which commits every pending SDN change on the cluster, not just
  // ours), up to three reconcile passes each with another apply, and then a wait
  // for the bridges to materialize on every node. Doing that here put all of it
  // in front of the lanes an instructor is waiting on — partly hidden behind the
  // vuln-app LLM call on a first deploy, and fully exposed on any deploy where
  // the app is a cache hit.
  //
  // It now happens when the ENGAGEMENT is created, usually days earlier. There
  // is deliberately NO inline fallback: reserving "just this once" here is
  // exactly how the cost became invisible in the first place.
  const engagementRow = await engagementProvision.resolveEngagement(profileId, engagement);
  engagementProvision.assertEngagementDeployable(engagementRow, {
    profileId, engagementType: engagement,
  });

  // ── THE SCHEME THE BLOCK WAS ACTUALLY CARVED AT ──────────────────────────
  //
  // R1 made this load-bearing. The reservation and the synthesizer already
  // preferred engagementRow.subnet_scheme over the request (B0, two lines
  // below), but the BUILD did not: it passed the request's `subnetScheme`
  // straight through to the group row and to the deployer, which reads it as
  // `challenge.subnet_scheme` (challenge-lane-deployer.js:2247). While the
  // default was 'v2' that divergence was mostly harmless — a v2 build on a v3
  // carve uses the external half of a block that exists. With the default at
  // 'v3' it inverts into a live outage: an engagement deliberately created as
  // v2 holds ONE VNet per lane, and a deploy that omits subnet_scheme would
  // build v3 against it and cable every lane onto an int-segment bridge that
  // was never created. "v2 stays fully selectable" is only true if selecting it
  // at creation also survives to the build.
  //
  // engagementRow is non-null here — assertEngagementDeployable throws
  // otherwise — and subnet_scheme is NOT NULL on the table, so in practice this
  // IS the engagement's scheme; the fallback covers only a hand-edited row.
  //
  // Written into ciab_profile_lane_groups.subnet_scheme as well, because
  // add-lanes and retry-lane rebuild their challenge object from
  // `group.subnet_scheme` and would otherwise re-introduce the same divergence
  // days later, on a path nobody is watching.
  const carvedScheme = engagementRow.subnet_scheme || subnetScheme;

  // Idempotent read of the block the engagement already reserved. requestedMax
  // is the engagement's own size, not the caller's — max_students locks with the
  // reservation, and passing a different number here would ask the resize path
  // to re-carve a block that lanes may already be sitting in.
  const reservationPromise = getOrCreateProfileChallenge({
    profileId,
    engagementType: engagement,
    requestedMax: engagementRow.max_students,
    companyName: profile.company_name,
    spec: {},                            // synthesized spec filled in below
    subnetScheme: engagementRow.subnet_scheme || subnetScheme
  });

  const [vulnApp, reservation] = await Promise.all([vulnAppPromise, reservationPromise]);

  // 5. Synthesize the deploy spec (vxlan_block gets filled in by step 6 below)
  const { spec: rawSpec, service_gaps, template_misses } = synthesizeSpecFromProfile({
    profile: { ...profile, assets },
    assetSelection,
    vmTemplateCatalog,
    vulnScriptCatalog,
    vulnApp,
    options: {
      // B0: the ENGAGEMENT's scheme, not the request body's. The block was
      // carved at engagementRow.subnet_scheme — the same expression this file
      // already uses at line 267 for the reservation — and spec.subnet_scheme is
      // the value engagement-plan.js reads to raise SCHEME_MISMATCH. Reserving
      // at v2 and building at v3 creates internal VNets at
      // tag+V3_INTERNAL_TAG_OFFSET that the teardown sweep can never name again;
      // lane-reservation.js:91-105 has the full account.
      //
      // IT HAS EXACTLY ONE READER, AND THIS CHANGE SET ADDED IT.
      // engagement-plan.js's compile reads spec.subnet_scheme and compares it
      // with the engagement row's, raising SCHEME_MISMATCH when they disagree —
      // which is the whole reason the field has to be honest here. Before that
      // reader existed the field was decorative; it is not any more, and a
      // refactor that reverted this expression to the request body's value
      // would make the compile agree with a carve that never happened.
      //
      // INERT ON THE DEPLOY PATH, though: nothing in the BUILD reads it — the
      // deployer takes the scheme from the challenge row
      // (challenge-lane-deployer.js:1990) — so this makes the persisted spec
      // honest about the carve without changing what gets built. Lines 383 and
      // 430 still carry the request's value; closing that divergence needs a
      // 400 on the mismatch and belongs to B2.
      subnetScheme: engagementRow.subnet_scheme || subnetScheme,
      attackBoxes,
      vxlanBlock: { start: VXLAN_SEARCH_MIN, end: VXLAN_SEARCH_MAX }  // placeholder, replaced by reservation
    }
  });
  if (rawSpec.vms.length === 0) {
    throw Object.assign(
      new Error('No deployable VMs after asset filter — every included asset failed template resolution'),
      { statusCode: 400, template_misses, service_gaps }
    );
  }

  // ── THE BAKE GATE ────────────────────────────────────────────────────────
  // The engagement gate above refuses a deploy whose NETWORK was never carved.
  // This refuses one whose ENVIRONMENT was never built, or was built from
  // content this client no longer has. Same doctrine, one resource up, and the
  // same absence of an inline fallback — see assertProfileBakeDeployable.
  //
  // Placed after synthesis because the spec is what says whether these lanes
  // carry an AD lab at all, and before anything is written: the reservation
  // read above is idempotent, so a refusal here costs nothing.
  //
  // C1b: the row it returns is USED, not discarded. A gate that validated a
  // bake and then let the deploy ignore it is the exact shape this track exists
  // to remove — the environment was built, signed off, and never cloned.
  const readyBake = await assertProfileBakeDeployable({ profileId, profile, spec: rawSpec });

  console.log(`[CIAB ProfileDeploy] Profile ${profileId.slice(0,8)} → challenge ${reservation.challenge_id.slice(0,8)} (${reservation.was_existing ? 'existing' : 'newly created'}), VXLAN ${reservation.vxlan_block.start}-${reservation.vxlan_block.end}, max_students=${reservation.max_students}`);

  // Spec selection:
  //   - New reservation → stored spec is the rawSpec we just wrote, same thing.
  //   - New reservation (was_existing=false) → reservation was created with
  //     an empty stub spec (so SDN provision could run in parallel with the
  //     vuln-app LLM). Now that synthesis is done, persist the real spec.
  //   - Existing reservation with 0 live lanes → admin may have changed the
  //     asset selection since the prior (failed) attempt. Adopt the fresh spec
  //     and update the stored one so retry/add-lanes stay consistent.
  //   - Existing reservation with live lanes → must keep stored spec; changing
  //     VM offsets/templates now would collide with running lanes.
  let spec = reservation.spec;
  let shouldAdoptFreshSpec = !reservation.was_existing;   // always for new reservations
  const storedHasVms = Array.isArray(spec && spec.vms) && spec.vms.length > 0;

  if (reservation.was_existing) {
    const liveLanesRes = await cybercoreQuery(
      `SELECT COUNT(*)::int AS n FROM cybercore_lane
        WHERE vxlan_id BETWEEN $1 AND $2 AND ${claimsSql()}`,
      [reservation.vxlan_block.start, reservation.vxlan_block.end]
    );
    const liveCount = liveLanesRes.rows[0]?.n || 0;

    if (!storedHasVms) {
      // Stored spec is empty/missing (e.g. created from the empty-stub during
      // the parallelized first deploy, or the previous deploy crashed before
      // synthesis). MUST adopt fresh regardless of live-lane count — keeping
      // an empty spec would just re-produce a broken deploy.
      shouldAdoptFreshSpec = true;
      console.log(`[CIAB ProfileDeploy] Stored spec is empty (${liveCount} live lane(s) ignored) — adopting fresh spec (${rawSpec.vms.length} VMs)`);
    } else if (liveCount === 0) {
      shouldAdoptFreshSpec = true;
      console.log(`[CIAB ProfileDeploy] Reservation has no live lanes — adopting fresh spec (${rawSpec.vms.length} VMs) from current asset selection`);
    } else {
      console.log(`[CIAB ProfileDeploy] Reservation has ${liveCount} live lane(s) — keeping stored spec (${spec.vms.length} VMs) to avoid collision`);
    }
  } else {
    console.log(`[CIAB ProfileDeploy] New reservation — persisting fresh spec (${rawSpec.vms.length} VMs)`);
  }

  if (shouldAdoptFreshSpec) {
    spec = adoptedSpec(rawSpec, reservation);
  }

  // ── C1b: THE GOLDEN TEMPLATES, ON WHICHEVER SPEC WON ─────────────────────
  //
  // AFTER the adopt decision and not instead of it: the two questions are
  // independent. Adoption is about whether the asset selection may move under
  // running lanes; this is about which TEMPLATE each of those machines clones
  // from, which is safe to change either way because it moves no address and no
  // offset — a lane that is already built is already built.
  //
  // PERSISTED, and that is the half that makes this reach production. add-lanes
  // and retry-lane rebuild their challenge object from the STORED reservation
  // spec (`reservation.spec`, through the group's ephemeral_challenge_id), so an
  // overlay applied only in memory here would give the first deploy golden
  // clones and hand every later lane of the same engagement the catalog
  // templates and a ninety-minute chain — the same defect, one route over, on a
  // path nobody watches. Writing it once here is what makes them all agree.
  const bakedSpec = prebakedSpecFromBake(spec, readyBake, {
    subnetScheme: carvedScheme, profile, engagementType: engagement,
  });
  const bakeChangedSpec = bakedSpec !== spec;
  spec = bakedSpec;

  if (shouldAdoptFreshSpec || bakeChangedSpec) {
    await cybercoreQuery(
      `UPDATE crucible_challenge SET spec = $1::jsonb WHERE challenge_id = $2`,
      [JSON.stringify(spec), reservation.challenge_id]
    );
  }

  if (bakeChangedSpec) {
    console.log(
      `[CIAB ProfileDeploy] Profile ${profileId.slice(0, 8)} deploys PRE-BAKED from ${readyBake.lab_name}: `
      + `${Object.keys(readyBake.golden_vmids || {}).length} golden template(s), pinned to `
      + `${spec.goad.fixed_subnet.int}.0/24 internal — no controller, no ansible chain`);
  }

  if (numLanes > reservation.max_students) {
    throw Object.assign(
      new Error(`num_lanes (${numLanes}) exceeds this profile's max_students (${reservation.max_students}). ` +
                `The reservation was locked on first deploy. To grow it, delete the profile and re-create with a larger max_students.`),
      { statusCode: 400 }
    );
  }

  // NOTE: there is deliberately no VXLAN allocation here. deployChallengeLanes
  // allocates from the challenge's own vxlan_block and releases what it does not
  // use. Allocating here as well would hand the same ids out twice — the
  // in-process reservation set is per-caller, so the deployer's allocator cannot
  // see ours, and the second INSERT dies on ux_cybercore_lane_vxlan_active.

  // 8. Insert group row
  const finalGroupName = groupName || `${profile.company_name || 'profile'}-${new Date().toISOString().slice(0, 10)}`;
  const groupInsert = await query(
    `INSERT INTO ciab_profile_lane_groups
       (profile_id, group_name, created_by, num_lanes,
        asset_selection, service_gaps, template_misses, profile_snapshot, subnet_scheme,
        attack_boxes, vuln_app_id, ephemeral_challenge_id, engagement_type, status)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb, $9, $10, $11, $12, $13, 'deploying')
     RETURNING id`,
    [
      profileId, finalGroupName, userId, numLanes,
      JSON.stringify(assetSelection),
      JSON.stringify(service_gaps),
      JSON.stringify(template_misses),
      JSON.stringify(assets),
      // carvedScheme, not the request's: add-lanes and retry-lane rebuild the
      // deployer's challenge object from this column, so it has to describe the
      // block rather than the button that was pressed.
      carvedScheme, attackBoxes,
      vulnApp ? vulnApp.id : null,
      // The group's pointer at its reservation. Add-lanes and retry resolve the
      // reservation through THIS id rather than re-deriving a key — one profile
      // can now own several, so re-deriving would be a guess.
      reservation.challenge_id,
      engagement
    ]
  );
  const groupId = groupInsert.rows[0].id;
  const challengeId = reservation.challenge_id;
  const challengeKey = reservation.challenge_key;

  // 8b. Auto-create student accounts (one per lane) + Guac users so each lane
  // appears in its owner's "My Workspaces" page: that page filters on
  // cybercore_lane.user_id, so a lane owned by the deploying admin shows up in
  // nobody's workspace list.
  //
  // Shared with the add-lanes route below — see utils/profile-students.js for
  // why this is create-or-rotate rather than an insert, and why the slug has to
  // have exactly one owner.
  const { groupSlug, students, credentials } = await provisionLaneStudents({
    groupName: finalGroupName,
    groupId,
    indices: Array.from({ length: numLanes }, (_, i) => i + 1),
    // `userId` is the acting admin, passed in by the route — runProfileDeploy
    // has no req of its own.
    actingUserId: userId,
  });

  // ── Hand over to the shared deployer ─────────────────────────────────────
  // VXLAN allocation, gateway WAN addresses, cybercore_lane rows, the clone
  // sequence, Guacamole, DHCP reservations — deployChallengeLanes does all of
  // it. CIAB doing any of it a second time is what W1-W7 were, so this function
  // stops as soon as the students exist.
  {
    const spawnedAt = new Date().toISOString();
    setImmediate(() => {
      laneProvision.provisionProfileLanes({
        groupId,
        groupName: finalGroupName,
        groupSlug,
        challenge: {
          challenge_id: reservation.challenge_id,
          challenge_key: reservation.challenge_key,
          name: finalGroupName,
          spec,
          // THE BUILD SCHEME. deployChallengeLanes reads exactly this key
          // (challenge-lane-deployer.js:2247) and cables every lane from it, so
          // it must name the scheme the VNets were created at — not the one the
          // request asked for.
          subnet_scheme: carvedScheme,
        },
        students,
        attackBoxes,
        vulnAppInstall: spec.vuln_app_install,
      }).catch(err => {
        console.error(`[CIAB ProfileDeploy] V2 batch ${groupId} crashed:`, err);
        query(`UPDATE ciab_profile_lane_groups SET status='error', updated_at=NOW() WHERE id=$1`, [groupId])
          .catch(() => {});
      });
    });

    return {
      group_id: groupId,
      profile_id: profileId,
      num_lanes: numLanes,
      // What is being BUILT, so the UI cannot report a scheme the lanes do not
      // have. (deploy_path is unrelated — it names the shared-deployer pipeline,
      // not a subnet scheme.)
      subnet_scheme: carvedScheme,
      deploy_path: 'v2',
      // Deliberately empty: under V2 the lane rows do not exist yet — the shared
      // deployer creates them as it goes. The admin UI follows the deploy through
      // GET /groups/:groupId/progress, which reads the shared registry, and the
      // per-lane rows appear in ciab_profile_lane_jobs as each lane lands.
      lanes: [],
      progress_id: laneProvision.progressIdForGroup(groupId),
      started_at: spawnedAt,
      service_gaps,
      template_misses,
      vuln_app_id: vulnApp ? vulnApp.id : null,
      credentials,
      students: students.map(s => ({ email: s.email, name: s.name, index: s.index })),
    };
  }

}

// ─── Routes ─────────────────────────────────────────────────────────────────

// Lab-internal source check for the unauthenticated image pull. The token is
// the real gate (24 random bytes); this is defense-in-depth so the endpoint
// can't be probed from the public internet. Lane egress SNATs to the gateway
// WAN IP (100.64.0.0/10 CGNAT) — same source lane-bootstrap trusts.
function isLabSourceIp(ip) {
  if (!ip) return false;
  if (/^127\./.test(ip) || ip === '::1') return true;            // loopback (local test)
  if (/^10\./.test(ip)) return true;                              // RFC1918
  if (/^192\.168\./.test(ip)) return true;                        // RFC1918
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;         // RFC1918 + docker bridge
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip)) return true; // 100.64/10 CGNAT (lab/Tailscale)
  return false;
}

// GET /api/profile-deploy/image/:token — UNAUTHENTICATED, token-gated.
// Lane web VMs pull their prebuilt vuln-app image tarball here (they have no
// JWT). Streamed gzip'd `docker save` output. See utils/vuln-app-builder.js.
router.get('/image/:token', (req, res) => {
  const ip = String(req.ip || req.socket?.remoteAddress || '').replace(/^::ffff:/, '');
  if (!isLabSourceIp(ip)) {
    console.warn(`[CIAB ProfileDeploy] image pull rejected from non-lab source ${ip}`);
    return res.status(403).end();
  }
  const entry = resolveImageFile(req.params.token);
  if (!entry) return res.status(404).end();

  res.setHeader('Content-Type', 'application/gzip');
  const safeName = entry.imageTag.replace(/[^a-z0-9._-]/gi, '_');
  res.setHeader('Content-Disposition', `attachment; filename="${safeName}.tar.gz"`);
  const stream = fs.createReadStream(entry.filePath);
  stream.on('error', err => {
    console.error(`[CIAB ProfileDeploy] image stream error for ${req.params.token.slice(0, 8)}…: ${err.message}`);
    if (!res.headersSent) res.status(500).end(); else res.destroy();
  });
  stream.pipe(res);
});

// POST /api/profile-deploy/preview — pre-flight resource estimate
router.post('/preview', authenticateToken, adminOnly, async (req, res) => {
  try {
    const {
      profile_id, num_lanes = 1, attack_boxes = true,
      vuln_app_enabled = true,
      model_id = DEFAULT_MODEL
    } = req.body;
    if (!profile_id) return res.status(400).json({ error: 'profile_id required' });

    const { assets } = await loadProfileForDeploy(profile_id);
    const serverCount = assets.filter(a => String(a.role || '').toLowerCase() === 'server').length;

    const preview = await buildDeployPreview({
      numLanes: parseInt(num_lanes) || 1,
      attackBoxes: !!attack_boxes,
      challengeVmCount: Math.max(serverCount, 1),
      proxmoxAPI,
      cybercoreQuery
    });

    // Has this profile's vuln-app already been generated? If so, the deploy
    // won't re-run the LLM pipeline — cost is just infra.
    let vulnAppCached = false;
    try {
      const cached = await query(
        `SELECT 1 FROM ciab_profile_vuln_apps WHERE profile_id = $1 LIMIT 1`,
        [profile_id]
      );
      vulnAppCached = cached.rowCount > 0;
    } catch (_) { /* table missing in test envs — assume not cached */ }

    const cost = estimateDeployCost({
      modelId: model_id,
      vulnAppEnabled: !!vuln_app_enabled,
      vulnAppAlreadyCached: vulnAppCached,
      numLanes: parseInt(num_lanes) || 1,
      vmsPerLane: Math.max(serverCount, 1),
      attackBoxes: !!attack_boxes
    });

    res.json({
      ...preview,
      profile_asset_summary: {
        total: assets.length,
        servers: serverCount,
        will_deploy: serverCount
      },
      cost_estimate: cost
    });
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

// POST /api/profile-deploy/deploy — the headline endpoint
router.post('/deploy', authenticateToken, adminOnly, async (req, res) => {
  try {
    const {
      profile_id,
      num_lanes,
      max_students,
      group_name,
      attack_boxes,
      subnet_scheme,
      asset_selection,
      vuln_app,
      engagement_type
    } = req.body;

    const result = await runProfileDeploy({
      profileId: profile_id,
      userId: req.user.userId,
      numLanes: parseInt(num_lanes, 10),
      maxStudents: max_students != null ? parseInt(max_students, 10) : undefined,
      groupName: group_name,
      attackBoxes: attack_boxes !== false,
      // Explicit wins; omitted means the default. runProfileDeploy then lets the
      // ENGAGEMENT's carved scheme override both wherever the network is real.
      subnetScheme: subnet_scheme || DEFAULT_SUBNET_SCHEME,
      assetSelection: asset_selection,
      vulnAppOpts: vuln_app || {},
      engagementType: engagement_type
    });
    audit.log({
      req,
      action: 'profile_lane.deployed',
      source: 'ciab',
      target: { type: 'group', id: result.group_id, label: group_name },
      metadata: {
        profile_id, num_lanes: parseInt(num_lanes, 10),
        max_students: max_students != null ? parseInt(max_students, 10) : null,
        attack_boxes: attack_boxes !== false,
        // The scheme the lanes are actually BUILT at, which is the engagement's
        // carve — not `subnet_scheme || DEFAULT_SUBNET_SCHEME`, which is only
        // what was asked for and can legitimately differ from what happened.
        subnet_scheme: result.subnet_scheme,
      },
    });
    res.status(202).json({ success: true, ...result });
  } catch (err) {
    const status = err.statusCode || 500;
    const body = { error: err.message };
    if (err.template_misses) body.template_misses = err.template_misses;
    if (err.service_gaps) body.service_gaps = err.service_gaps;
    // A refusal an operator can act on has to name itself. Both gates on this
    // path throw a coded error; without these two lines the UI sees prose it
    // cannot switch on, and a bake blocked on an unbuilt phase is
    // indistinguishable from one that ran and failed.
    if (err.code) body.code = err.code;
    if (err.bake_state) body.state = err.bake_state;
    // Which refusal, and what to do about it. Without this a deploy blocked
    // because the client is below the domain floor and a deploy blocked because
    // the compiler crashed both render as BAKE_DRIFT_UNKNOWN and nothing else.
    if (err.compile_refusal) body.compile_refusal = err.compile_refusal;
    res.status(status).json(body);
  }
});

// GET /api/profile-deploy/profiles/:profileId/reservation — show the VXLAN
// reservation status for a profile. Lets the UI display "12/25 slots used"
// and decide whether to enable the "Add lanes" button. Reservation lives
// entirely in cybercore_db; lookup by deterministic challenge_key.
router.get('/profiles/:profileId/reservation', authenticateToken, adminOnly, async (req, res) => {
  try {
    const pr = await query(`SELECT id, company_name FROM profiles WHERE id = $1`, [req.params.profileId]);
    if (pr.rows.length === 0) return res.status(404).json({ error: 'Profile not found' });
    const p = pr.rows[0];

    // One profile can hold a reservation per engagement. Absent a query param
    // this reports the default engagement's, which is also the one a
    // pre-engagement reservation is adopted into.
    const engagement = sanitizeEngagementType(req.query.engagement_type);
    const ch = await findProfileChallenge(p.id, engagement);
    // Split on the exact prefix, not on '-': an engagement slug may itself
    // contain hyphens (sanitizeEngagementType permits them), so indexing into
    // challenge_key.split('-') would truncate 'external-blackbox' to 'external'.
    const keyPrefix = `ciab-profile-${String(p.id).slice(0, 8)}-`;
    const allReservations = (await listProfileChallenges(p.id)).map(row => ({
      challenge_id: row.challenge_id,
      challenge_key: row.challenge_key,
      // null marks a not-yet-adopted pre-engagement row; it belongs to the
      // default engagement and is renamed on its next deploy.
      engagement_type: row.challenge_key.startsWith(keyPrefix)
        ? row.challenge_key.slice(keyPrefix.length)
        : null,
    }));
    if (!ch) {
      return res.json({
        reserved: false,
        profile_id: p.id,
        company_name: p.company_name,
        engagement_type: engagement,
        engagements: allReservations,
        search_window: { min: VXLAN_SEARCH_MIN, max: VXLAN_SEARCH_MAX }
      });
    }

    const usedRes = await cybercoreQuery(
      `SELECT COUNT(DISTINCT vxlan_id) AS used
         FROM cybercore_lane
        WHERE vxlan_id BETWEEN $1 AND $2
          AND ${claimsSql()}`,
      [ch.vxlan_block.start, ch.vxlan_block.end]
    );
    const used = parseInt(usedRes.rows[0].used, 10) || 0;
    res.json({
      reserved: true,
      profile_id: p.id,
      company_name: p.company_name,
      challenge_id: ch.challenge_id,
      challenge_key: ch.challenge_key,
      engagement_type: engagement,
      // Every reservation this profile holds, not just the one asked about. A
      // profile can now own one per engagement, and nothing else on the CIAB
      // surface can see them — without this an engagement other than the default
      // is invisible, and its VXLAN block and pre-created VNets look like a leak.
      // Releasing one individually is still only possible by deleting the profile;
      // a per-engagement teardown belongs with the Environments tab.
      engagements: allReservations,
      max_students: ch.max_students,
      vxlan_range_start: ch.vxlan_block.start,
      vxlan_range_end: ch.vxlan_block.end,
      reserved_at: ch.created_at,
      slots_used: used,
      slots_free: ch.max_students - used,
      search_window: { min: VXLAN_SEARCH_MIN, max: VXLAN_SEARCH_MAX }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── A8: engagements — reserve the VXLAN block ahead of deploy day ──────────
// Carving a block is 25-50 serial VNet POSTs plus a CLUSTER-WIDE SDN apply plus
// a per-node bridge wait. These endpoints move that off the deploy path.

// GET /api/profile-deploy/profiles/:profileId/engagements — status per engagement
router.get('/profiles/:profileId/engagements', authenticateToken, adminOnly, async (req, res) => {
  try {
    const rows = await engagementProvision.listEngagements(req.params.profileId);
    // Nothing recorded yet may still mean a pre-A8 reservation exists — adopt it
    // so the UI shows the truth rather than offering to reserve a second block.
    if (rows.length === 0) {
      const adopted = await engagementProvision.resolveEngagement(
        req.params.profileId, DEFAULT_ENGAGEMENT_TYPE);
      return res.json({ engagements: adopted ? [adopted] : [] });
    }
    res.json({ engagements: rows });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/profile-deploy/engagements — create one and start carving in the background
router.post('/engagements', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { profile_id, engagement_type, subnet_scheme, max_students } = req.body || {};
    const profRes = await query(`SELECT id, company_name FROM profiles WHERE id = $1`, [profile_id]);
    if (profRes.rows.length === 0) return res.status(404).json({ error: 'Profile not found' });

    const engagement = await engagementProvision.createEngagement({
      profileId: profile_id,
      engagementType: engagement_type || DEFAULT_ENGAGEMENT_TYPE,
      // Explicit wins; omitted means the default. This is the moment the block
      // is carved, so it is also the moment the scheme is decided for good —
      // nothing afterwards may rewrite it (migration 016 has the account).
      subnetScheme: subnet_scheme || DEFAULT_SUBNET_SCHEME,
      maxStudents: max_students,
      companyName: profRes.rows[0].company_name,
      actingUserId: req.user.userId,
    });

    audit.log({
      req,
      action: 'profile_engagement.created',
      source: 'ciab',
      target: { type: 'engagement', id: engagement.engagement_id },
      metadata: {
        profile_id, engagement_type: engagement.engagement_type,
        max_students: engagement.max_students, subnet_scheme: engagement.subnet_scheme,
      },
    });

    // 202: the row exists, the network does not yet. The UI polls the GET above.
    res.status(202).json({ success: true, engagement });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/profile-deploy/engagements/:id/reprovision — retry a failed reservation
router.post('/engagements/:engagementId/reprovision', authenticateToken, adminOnly, async (req, res) => {
  try {
    const existing = await engagementProvision.getEngagementById(req.params.engagementId);
    if (!existing) return res.status(404).json({ error: 'Engagement not found' });

    const profRes = await query(`SELECT company_name FROM profiles WHERE id = $1`, [existing.profile_id]);
    const engagement = await engagementProvision.reprovisionEngagement(req.params.engagementId, {
      companyName: profRes.rows[0] && profRes.rows[0].company_name,
      // Guarded on purpose: re-provisioning a HEALTHY block carves a second one,
      // because the allocator only ever climbs and never re-uses range.
      force: req.body && req.body.force === true,
    });

    audit.log({
      req,
      action: 'profile_engagement.reprovisioned',
      source: 'ciab',
      target: { type: 'engagement', id: req.params.engagementId },
      metadata: { profile_id: existing.profile_id, previous_status: existing.provision_status },
    });

    res.status(202).json({ success: true, engagement });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ─── G5: the bake — build the environment once, ahead of deploy day ────────
// Same shape and the same reasons as the engagement endpoints above: the
// expensive thing is moved OFF the deploy path, started detached, and reported
// through a row the UI polls. The resource is bigger — a bake is ~90 minutes, a
// whole staging lane and a controller VM against an engagement's VXLAN block —
// so the concurrency guard is stricter and the refusals are louder.

/** JSON on every failure path, carrying the code the UI switches on. */
function bakeErrorBody(err) {
  const body = { error: err.message };
  if (err.code) body.code = err.code;
  if (err.bake_state) body.state = err.bake_state;
  if (err.not_implemented) body.not_implemented = err.not_implemented;
  // The compiler declining to build a broken environment, named and with a
  // remedy — the one thing that distinguishes it from the cluster falling over.
  if (err.compile_refusal) body.compile_refusal = err.compile_refusal;
  return body;
}

// POST /api/profile-deploy/profiles/:profileId/bake — start one, return at once
router.post('/profiles/:profileId/bake', authenticateToken, adminOnly, async (req, res) => {
  try {
    const profileId = req.params.profileId;
    const { profile } = await loadProfileForDeploy(profileId);

    // REFUSED BEFORE ANYTHING IS CREATED, and per CLIENT rather than per row.
    // bake-orchestrator's own mutex is keyed on bake_id, which is the right
    // guard for a double-click on one environment; it does not cover the case
    // that costs a cluster — an edited profile compiles to a DIFFERENT hash, so
    // a second Bake while the first is running is a second row, a SECOND
    // staging lane and a SECOND controller VM, with whichever loses unfindable
    // forever.
    const existing = await bakeOrchestrator.listBakes(profileId);
    const running = existing.find(b => b.status === 'pending'
      || bakeOrchestrator.ACTIVE_STATUSES.includes(b.status));
    if (running) {
      return res.status(409).json({
        error: `This client is already baking (${running.lab_name}): ${running.phase_detail || running.status}. `
          + 'A bake builds one staging lane and one controller VM; a second one now would build a '
          + 'second set that nothing could find afterwards. Wait for it to finish, or re-bake it.',
        code: 'BAKE_IN_PROGRESS',
        state: bakeStateOf(running),
        bake: bakeView(running),
      });
    }

    // THE THREE REFUSALS ARE ANSWERS, NOT FAILURES — see COMPILE_REFUSALS.
    // compileLabWithChain declines when the client is below the first-domain
    // floor, when the designer cannot prove a chain nobody can short-circuit,
    // and when a roster Domain Admin stays cheaper than the intended path. Each
    // becomes its own 422 with its own state and its own remedy here; anything
    // else falls through untouched and renders as the 500 it is.
    let identity;
    try {
      identity = bakeIdentityForProfile(profile, {
        subnetScheme: req.body && req.body.subnet_scheme,
      });
    } catch (err) {
      throw refineCompileRefusal(err);
    }

    // C1a. The staging network, after the compile and long before the row. This
    // is what puts spec.vxlan_block and spec.goad.fixed_subnet on the identity
    // at all — and the pre-flight under it is what stops a bake that cannot be
    // provisioned from ever being started, instead of discovering it at the
    // provision phase or, for fixed_subnet, at CAPTURE, which is on the far side
    // of the ninety-minute chain.
    identity = withBakeNetwork(identity, await resolveBakeNetwork({
      profileId,
      companyName: profile.company_name,
      subnetScheme: identity.spec.subnet_scheme,
      actingUserId: req.user.userId,
    }));

    // THE PRE-FLIGHT, run against the REAL guards the two cluster phases use.
    // A refusal here costs nothing: no row, no lane, no controller, no chain.
    assertBakeSpecProvisionable(identity.spec);

    const { bake, created, started } = await bakeOrchestrator.startBake({
      profileId,
      labHash: identity.labHash,
      goadRef: identity.goadRef,
      manifestSha: identity.manifestSha,
      spec: identity.spec,
      actingUserId: req.user.userId,
      // buildBakeSteps() and never a hand-rolled object: it is the ONE place the
      // five phases are bound to the code that performs them, and a steps set
      // assembled here could silently omit one. bakeProfile fails a bake whose
      // phase is missing rather than skipping it, but only this call guarantees
      // the set is the shipped one.
      steps: bakeOrchestrator.buildBakeSteps(),
    });

    // startBake NEVER restarts an existing row, whatever state it is in — see
    // its header. Re-baking on a repeated press would throw away golden
    // templates lanes may be cloning from and re-run ninety minutes because
    // somebody double-clicked, so a second press of identical content is
    // answered with what already exists and the button that would redo it.
    if (!created) {
      const state = bakeStateOf(bake);
      const ready = state === 'ready' || state === 'awaiting_signoff';
      return res.status(409).json({
        error: ready
          ? `This exact environment is already baked (${bake.lab_name}). Editing the client produces a `
            + 'new version to bake; re-baking this one rebuilds identical content and destroys the '
            + 'golden templates lanes clone from.'
          : `This exact environment already has a bake (${bake.lab_name}, ${state}): `
            + `${bake.error || bake.phase_detail || 'no detail recorded'}. Use Re-bake to run it again.`,
        code: ready ? 'BAKE_ALREADY_READY' : 'BAKE_ALREADY_EXISTS',
        state,
        bake: bakeView(bake),
      });
    }

    audit.log({
      req,
      action: 'profile_bake.started',
      source: 'ciab',
      target: { type: 'bake', id: bake.bake_id, label: bake.lab_name },
      metadata: {
        profile_id: profileId,
        lab_name: bake.lab_name,
        // NOT lab_hash: audit.js's SECRET_KEY_RE matches the substring `hash`
        // and would store the version identity as "[redacted]", which is worse
        // than not recording it — it reads as a credential that was scrubbed.
        lab_version: String(identity.labHash).slice(0, 12),
        goad_ref: identity.goadRef,
        tier: identity.tier,
        compile_warnings: (identity.warnings || []).length,
        // The staging block and the bases every lane of this client will be
        // pinned to. Recorded because they are the two facts a later
        // "why does this lane resolve nothing" investigation starts from.
        staging_vxlan: identity.spec.vxlan_block.start,
        fixed_subnet_int: identity.spec.goad.fixed_subnet.int,
        fixed_subnet_ext: identity.spec.goad.fixed_subnet.ext,
      },
    });

    // 202: the row exists, the environment does not yet. The UI polls the GET
    // below, exactly as it polls the engagement it was modelled on.
    res.status(202).json({
      success: true,
      started,
      state: bakeStateOf(bake),
      bake: bakeView(bake),
      // Warnings from the compiler travel with the response rather than being
      // dropped: every one of them is by definition a silent no-op on the lane.
      compile_warnings: identity.warnings || [],
    });
  } catch (err) {
    res.status(err.status || err.statusCode || 500).json(bakeErrorBody(err));
  }
});

// GET /api/profile-deploy/profiles/:profileId/bake — status, and why a deploy
// would be refused right now.
router.get('/profiles/:profileId/bake', authenticateToken, adminOnly, async (req, res) => {
  try {
    const profileId = req.params.profileId;
    const bakes = await bakeOrchestrator.listBakes(profileId);
    const bake = (await bakeOrchestrator.getLatestReadyBake(profileId)) || bakes[0] || null;

    // The panel's whole job is to answer "can I deploy this, and if not why" —
    // so it compiles the client and asks the SAME function the deploy path asks.
    // A status view that reported drift by a different rule than the gate
    // enforces would be a second thing to keep true, and the one that is wrong
    // is always the one nobody deploys against.
    //
    // The compile is repeated per poll rather than cached, deliberately: a
    // cached hash cannot notice the edit it exists to notice. It is pure CPU
    // over files already on disk, and it is the ONLY thing that can say "this
    // client has been edited since the environment was baked".
    let current = { goad_ref: null, lab_hash: null, error: null, refusal: null };
    try {
      const { profile } = await loadProfileForDeploy(profileId);
      const identity = bakeIdentityForProfile(profile);
      current = {
        goad_ref: identity.goadRef, lab_hash: identity.labHash, error: null, refusal: null,
      };
    } catch (err) {
      // TWO DIFFERENT FACTS, and the panel must not merge them. A profile JSON
      // that has gone missing is an incident; the compiler declining to build a
      // forest for a nine-person cloud-first consultancy is the correct answer
      // about that client and comes with a remedy. Reported, not thrown: the
      // bake rows are still worth showing either way.
      current = {
        goad_ref: null, lab_hash: null, error: err.message, refusal: compileRefusalOf(err),
      };
    }

    let blocked = null;
    try {
      bakeOrchestrator.assertBakeDeployable(bake, {
        currentGoadRef: current.goad_ref, currentLabHash: current.lab_hash, profileId,
      });
    } catch (err) {
      const refined = refineBakeRefusal(err, bake, current.refusal);
      blocked = { code: refined.code, reason: refined.message };
      if (refined.compile_refusal) blocked.compile_refusal = refined.compile_refusal;
    }

    const step = notImplementedPhase(bake);
    res.json({
      profile_id: profileId,
      // 'not_built' would send an operator to a Bake button that refuses every
      // time. When this client cannot compile and has no row, the state IS the
      // refusal.
      state: bakeStateOf(bake, current.refusal),
      compile_refusal: current.refusal,
      // Same column name, same job and same renderer as
      // ciab_profile_lane_jobs.phase_detail — hoisted to the top of the body
      // because it is the one field a panel polls for.
      phase_detail: bake ? bake.phase_detail : null,
      not_implemented: step ? { step, detail: bake.error } : null,
      deployable: blocked === null,
      blocked,
      current,
      bake: bakeView(bake),
      bakes: bakes.map(bakeView),
    });
  } catch (err) {
    res.status(err.status || err.statusCode || 500).json(bakeErrorBody(err));
  }
});

// POST /api/profile-deploy/bakes/:bakeId/rebake — run it again from scratch
router.post('/bakes/:bakeId/rebake', authenticateToken, adminOnly, async (req, res) => {
  try {
    const before = await bakeOrchestrator.getBakeById(req.params.bakeId);
    const bake = await bakeOrchestrator.restartBake(req.params.bakeId, {
      steps: bakeOrchestrator.buildBakeSteps(),
      // A literal true, never a truthy string: force means "throw away golden
      // templates lanes may be cloning from right now".
      force: !!(req.body && req.body.force === true),
    });

    audit.log({
      req,
      action: 'profile_bake.restarted',
      source: 'ciab',
      target: { type: 'bake', id: bake.bake_id, label: bake.lab_name },
      metadata: {
        profile_id: bake.profile_id,
        previous_status: before ? before.status : null,
        forced: !!(req.body && req.body.force === true),
      },
    });

    res.status(202).json({ success: true, state: bakeStateOf(bake), bake: bakeView(bake) });
  } catch (err) {
    res.status(err.status || err.statusCode || 500).json(bakeErrorBody(err));
  }
});

// POST /api/profile-deploy/bakes/:bakeId/gates — record a human's review
router.post('/bakes/:bakeId/gates', authenticateToken, adminOnly, async (req, res) => {
  try {
    const body = req.body || {};
    // Three states, kept apart: TRUE reviewed and passed, FALSE reviewed and
    // did not, null never looked at. Coercing an absent field to false would
    // record a rejection nobody made.
    const tri = (v) => (v === true ? true : (v === false ? false : null));

    const bake = await bakeOrchestrator.approveBakeGates(req.params.bakeId, {
      gateSolvable: tri(body.gate_solvable),
      gatePaper: tri(body.gate_paper),
      gateNoUnintended: tri(body.gate_no_unintended),
      actingUserId: req.user.userId,
    });

    audit.log({
      req,
      action: 'profile_bake.gates_recorded',
      source: 'ciab',
      target: { type: 'bake', id: bake.bake_id, label: bake.lab_name },
      metadata: {
        profile_id: bake.profile_id,
        gate_solvable: bake.gate_solvable,
        gate_paper: bake.gate_paper,
        gate_no_unintended: bake.gate_no_unintended,
        approved: !!bake.gates_approved_at,
      },
    });

    res.json({ success: true, state: bakeStateOf(bake), bake: bakeView(bake) });
  } catch (err) {
    res.status(err.status || err.statusCode || 500).json(bakeErrorBody(err));
  }
});

// POST /api/profile-deploy/groups/:groupId/add-lanes — deploy additional lanes
// to an existing group, pulling from the profile's VXLAN reservation.
router.post('/groups/:groupId/add-lanes', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { groupId } = req.params;
    const count = parseInt(req.body?.count, 10);
    if (!Number.isFinite(count) || count < 1 || count > 50) {
      return res.status(400).json({ error: 'count must be 1..50' });
    }

    const grpRes = await query(`SELECT * FROM ciab_profile_lane_groups WHERE id=$1`, [groupId]);
    if (grpRes.rows.length === 0) return res.status(404).json({ error: 'Group not found' });
    const group = grpRes.rows[0];
    if (group.status === 'deleted') return res.status(409).json({ error: 'Group is deleted' });

    // Through the group's own pointer, NOT by re-deriving a key from the
    // profile: reservations are keyed on (profile, engagement) now, and this
    // group's lanes belong to exactly one of them.
    const reservation = await getProfileChallengeById(group.ephemeral_challenge_id);
    if (!reservation) {
      return res.status(409).json({ error: 'Group has no reservation — tear down everything and re-deploy' });
    }

    // Continue the lane_index sequence. The index is the student's identity
    // within the group (`<slug>-studentN@clinic.local`), so restarting it would
    // hand a new lane to an existing student and rotate their password.
    const idxRes = await query(
      `SELECT COALESCE(MAX(lane_index), 0) AS m FROM ciab_profile_lane_jobs WHERE group_id=$1`,
      [groupId]
    );
    const startIndex = parseInt(idxRes.rows[0].m, 10);
    const indices = Array.from({ length: count }, (_, i) => startIndex + i + 1);

    const { groupSlug, students, credentials } = await provisionLaneStudents({
      groupName: group.group_name,
      groupId,
      indices,
      actingUserId: req.user.userId,
    });

    audit.log({
      req,
      action: 'profile_lane.lanes_added',
      source: 'ciab',
      target: { type: 'group', id: groupId },
      metadata: { count, first_index: indices[0], last_index: indices[indices.length - 1] },
    });

    res.status(202).json({
      success: true,
      group_id: groupId,
      added: count,
      lane_indices: indices,
      progress_id: laneProvision.progressIdForGroup(groupId),
      // One-time display, exactly as the first deploy does it: the cleartext
      // password exists nowhere else after this response.
      credentials,
      students: students.map(s => ({ email: s.email, name: s.name, index: s.index })),
    });

    // Background. Same wrapper as the first deploy — add-lanes was a second,
    // drifting copy of that pipeline before A7, and the group's VXLAN block,
    // spec and reservation are identical either way.
    setImmediate(() => {
      laneProvision.provisionProfileLanes({
        groupId,
        groupName: group.group_name,
        groupSlug,
        challenge: {
          challenge_id: reservation.challenge_id,
          challenge_key: reservation.challenge_key,
          name: group.group_name,
          spec: reservation.spec,
          subnet_scheme: group.subnet_scheme,
        },
        students,
        attackBoxes: group.attack_boxes,
        vulnAppInstall: (reservation.spec && reservation.spec.vuln_app_install) || null,
      }).catch(err => {
        console.error(`[CIAB AddLanes] group ${groupId} add-lanes crashed: ${err.message}`);
      });
    });
  } catch (err) {
    res.status(err.status || err.statusCode || 500).json({ error: err.message });
  }
});

// GET /api/profile-deploy/groups — list groups created by the admin
router.get('/groups', authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await query(
      `SELECT g.id, g.profile_id, g.group_name, g.num_lanes, g.status,
              g.subnet_scheme, g.attack_boxes, g.created_at, g.updated_at,
              jsonb_array_length(COALESCE(g.service_gaps,'[]'::jsonb))   AS gap_count,
              jsonb_array_length(COALESCE(g.template_misses,'[]'::jsonb)) AS miss_count,
              p.company_name AS profile_company
         FROM ciab_profile_lane_groups g
         LEFT JOIN profiles p ON p.id = g.profile_id
        WHERE g.status != 'deleted'
        ORDER BY g.created_at DESC
        LIMIT 100`
    );
    res.json({ groups: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/profile-deploy/groups/:groupId — full group detail
router.get('/groups/:groupId', authenticateToken, adminOnly, async (req, res) => {
  try {
    const groupRes = await query(
      `SELECT * FROM ciab_profile_lane_groups WHERE id = $1`,
      [req.params.groupId]
    );
    if (groupRes.rows.length === 0) return res.status(404).json({ error: 'Group not found' });

    const jobsRes = await query(
      `SELECT id, lane_id, vxlan_id, lane_index, status, phase_detail, error_msg,
              vm_ids, target_node, started_at, finished_at
         FROM ciab_profile_lane_jobs
        WHERE group_id = $1
        ORDER BY lane_index`,
      [req.params.groupId]
    );
    res.json({ group: groupRes.rows[0], jobs: jobsRes.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/profile-deploy/groups/:groupId/progress — UI polling endpoint
router.get('/groups/:groupId/progress', authenticateToken, adminOnly, async (req, res) => {
  // The SHARED progress registry — the one with a heartbeat and staleness
  // fields, and the one that doubles as this app's only mutex. CIAB's private
  // registry had neither and was deleted with the fourth copy in A7.
  const shared = laneProvision.readGroupProgress(req.params.groupId);
  if (shared) return res.json({ group_id: req.params.groupId, ...shared });

  // No in-process progress (server restart or already-finalized) — fall back to DB
  try {
    const groupRes = await query(
      `SELECT id, group_name, num_lanes, status FROM ciab_profile_lane_groups WHERE id = $1`,
      [req.params.groupId]
    );
    if (groupRes.rows.length === 0) return res.status(404).json({ error: 'Group not found' });
    const jobs = await query(
      `SELECT status FROM ciab_profile_lane_jobs WHERE group_id = $1`,
      [req.params.groupId]
    );
    const counts = jobs.rows.reduce((acc, j) => { acc[j.status] = (acc[j.status] || 0) + 1; return acc; }, {});
    res.json({
      group_id: req.params.groupId,
      group_name: groupRes.rows[0].group_name,
      total: groupRes.rows[0].num_lanes,
      succeeded: counts.active || 0,
      failed: counts.error || 0,
      completed: (counts.active || 0) + (counts.error || 0),
      phase: groupRes.rows[0].status === 'deploying' ? 'in_progress' : 'complete',
      from_db: true
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/profile-deploy/groups/:groupId/retry/:laneId — re-deploy a failed lane
router.post('/groups/:groupId/retry/:laneId', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { groupId, laneId } = req.params;
    const groupRes = await query(`SELECT * FROM ciab_profile_lane_groups WHERE id=$1`, [groupId]);
    if (groupRes.rows.length === 0) return res.status(404).json({ error: 'Group not found' });
    const group = groupRes.rows[0];

    const jobRes = await query(
      `SELECT * FROM ciab_profile_lane_jobs WHERE group_id=$1 AND lane_id=$2`,
      [groupId, laneId]
    );
    if (jobRes.rows.length === 0) return res.status(404).json({ error: 'Lane job not found' });
    const job = jobRes.rows[0];

    const reservation = await getProfileChallengeById(group.ephemeral_challenge_id);
    if (!reservation) {
      return res.status(409).json({ error: 'Reservation missing — cannot retry' });
    }

    // The student who owns the failed lane, read from the lane row rather than
    // re-derived from the group slug. Re-deploying a group rotates the student's
    // password but keeps the user id, so the lane is the only record of WHICH
    // account this particular lane belongs to.
    const ownerRes = await cybercoreQuery(
      `SELECT l.user_id, u.email
         FROM cybercore_lane l
         LEFT JOIN cybercore_user u ON u.user_id = l.user_id
        WHERE l.lane_id = $1`,
      [laneId]
    );
    const owner = ownerRes.rows[0];
    if (!owner || !owner.user_id || !owner.email) {
      return res.status(409).json({
        error: 'That lane has no owning student account, so a retry would deploy it to nobody.'
      });
    }

    audit.log({
      req,
      action: 'profile_lane.retried',
      source: 'ciab',
      target: { type: 'lane', id: laneId },
      metadata: { group_id: groupId, job_id: job.id },
    });
    res.status(202).json({ success: true, message: 'Retry started', lane_id: laneId, job_id: job.id });

    // Background. The lane is destroyed and rebuilt, so it comes back under a
    // NEW lane_id — the job mirror re-keys on (group_id, lane_index).
    setImmediate(() => {
      laneProvision.retryProfileLane({
        groupId,
        groupName: group.group_name,
        groupSlug: slugForGroup(group.group_name),
        challenge: {
          challenge_id: reservation.challenge_id,
          challenge_key: reservation.challenge_key,
          name: group.group_name,
          spec: reservation.spec,
          subnet_scheme: group.subnet_scheme,
        },
        laneId,
        user: { id: owner.user_id, email: owner.email },
        laneIndex: job.lane_index,
        attackBoxes: group.attack_boxes,
        vulnAppInstall: (reservation.spec && reservation.spec.vuln_app_install) || null,
        // Machines whose lane-config write never landed are recorded nowhere
        // else. They go through teardownLanes' contested and ownership checks.
        extraVmIds: Array.isArray(job.vm_ids) ? job.vm_ids : [],
      }).catch(err => {
        console.error(`[CIAB ProfileDeploy] Retry of lane ${laneId} failed: ${err.message}`);
        query(`UPDATE ciab_profile_lane_jobs SET status='error', error_msg=$2 WHERE id=$1`,
              [job.id, err.message]).catch(() => {});
      });
    });
  } catch (err) {
    res.status(err.status || err.statusCode || 500).json({ error: err.message });
  }
});

// DELETE /api/profile-deploy/groups/:groupId — tear down all lanes in the group
router.delete('/groups/:groupId', authenticateToken, adminOnly, async (req, res) => {
  try {
    const groupRes = await query(
      `SELECT id, group_name, ephemeral_challenge_id FROM ciab_profile_lane_groups WHERE id=$1`,
      [req.params.groupId]
    );
    if (groupRes.rows.length === 0) return res.status(404).json({ error: 'Group not found' });
    const group = groupRes.rows[0];

    // Refuse to tear down a group that is still deploying. The first thing a
    // teardown does is snapshot the lane rows, and a deploy in flight is still
    // creating them — so the lanes that appear after the snapshot are destroyed
    // by nothing and belong to no one. 409 rather than queueing: there is no job
    // queue, and the admin can simply wait.
    laneProvision.assertNoConflictingProfileOperation({ groupId: req.params.groupId });

    const jobsRes = await query(
      `SELECT lane_id, vxlan_id, vm_ids FROM ciab_profile_lane_jobs WHERE group_id=$1`,
      [req.params.groupId]
    );

    // Collect the auto-provisioned student accounts BEFORE tearing lanes down
    // (teardownLane deletes the cybercore_lane rows we'd otherwise read them
    // from). Two sources, deduped:
    //   1. cybercore_lane.user_id where the lane config marks it a
    //      profile-lane-group lane with a student_email — the normal case.
    //   2. cybercore_user rows whose organization is this group and whose
    //      username matches the @clinic.local pattern — catches students whose
    //      lane was already deleted individually via the admin Lanes tab.
    // Only @clinic.local accounts are ever deleted, so a lane assigned to a
    // real user can never take that user's account down with it.
    const studentUsers = new Map();   // user_id -> username/email
    const laneIds = jobsRes.rows.map(j => j.lane_id).filter(Boolean);
    if (laneIds.length > 0) {
      try {
        const laneRows = await cybercoreQuery(
          `SELECT l.user_id, l.config, u.username
             FROM cybercore_lane l
             JOIN cybercore_user u ON u.user_id = l.user_id
            WHERE l.lane_id = ANY($1::uuid[])`,
          [laneIds]
        );
        for (const row of laneRows.rows) {
          const cfg = typeof row.config === 'string' ? JSON.parse(row.config || '{}') : (row.config || {});
          if (cfg.profile_lane_group && /@clinic\.local$/i.test(row.username || '')) {
            studentUsers.set(row.user_id, row.username);
          }
        }
      } catch (e) {
        console.warn(`[CIAB Teardown] lane->student lookup failed: ${e.message}`);
      }
    }
    try {
      const orgRows = await cybercoreQuery(
        `SELECT user_id, username FROM cybercore_user
          WHERE role = 'student' AND organization = $1 AND username LIKE '%@clinic.local'`,
        [group.group_name]
      );
      for (const row of orgRows.rows) studentUsers.set(row.user_id, row.username);
    } catch (e) {
      console.warn(`[CIAB Teardown] org->student lookup failed: ${e.message}`);
    }

    const errors = [];
    // Populated by the cybercore_user DELETE further down — the only point at
    // which these auto-provisioned accounts still have names.
    let deletedStudents = [];
    let lanesKeptForRetry = 0;
    for (const job of jobsRes.rows) {
      const result = await teardownLane({ laneId: job.lane_id, vmIds: job.vm_ids || [] });
      if (result.errors && result.errors.length > 0) errors.push(...result.errors);
      if (result.keptForRetry) lanesKeptForRetry += 1;
    }

    // ── Delete the auto-provisioned students + their Guacamole artifacts ──
    //
    // Gated on every lane having actually gone. cybercore_lane.user_id is
    // ON DELETE CASCADE (config/postgres/001_init_db.sql), so deleting these
    // accounts would erase the very rows teardownLane just kept on purpose —
    // with no Proxmox interaction at all, orphaning every survivor permanently
    // and releasing its vxlan_id for the next deploy to collide with.
    const studentIds = [...studentUsers.keys()];
    const studentEmails = [...studentUsers.values()];
    if (lanesKeptForRetry > 0) {
      const msg =
        `${lanesKeptForRetry} lane(s) kept because machines survived the teardown — ` +
        `the auto-provisioned student accounts were NOT deleted, because removing them ` +
        `would cascade those rows away and orphan the survivors. Re-run once cleared.`;
      console.warn(`[CIAB Teardown] ${msg}`);
      errors.push(msg);
    }
    if (lanesKeptForRetry === 0 && studentIds.length > 0) {
      // cybercore_allocation has CHECK (user_id IS NOT NULL OR group_key IS NOT NULL)
      // and its user FK is ON DELETE SET NULL — deleting a user with allocations
      // would violate the check and roll the user delete back. Purge first
      // (same ordering as the group teardown in src/routes/admin/groups.js).
      try {
        await cybercoreQuery(
          `DELETE FROM cybercore_allocation WHERE user_id = ANY($1::uuid[])`, [studentIds]
        );
      } catch (e) {
        errors.push(`allocation cleanup: ${e.message}`);
      }
      try {
        const r = await cybercoreQuery(
          `DELETE FROM cybercore_user WHERE user_id = ANY($1::uuid[]) AND username LIKE '%@clinic.local'
           RETURNING user_id, email`,
          [studentIds]
        );
        // Captured here because this DELETE is the last moment these accounts
        // exist; afterwards there is nothing left to name in the audit row.
        deletedStudents = r.rows || [];
        console.log(`[CIAB Teardown] ${group.group_name}: deleted ${r.rowCount}/${studentIds.length} auto-provisioned student account(s)`);
        if (r.rowCount < studentIds.length) {
          errors.push(`only ${r.rowCount}/${studentIds.length} student accounts deleted — check FK constraints`);
        }
      } catch (e) {
        errors.push(`student account cleanup: ${e.message}`);
      }
      // Guacamole accounts are keyed by email; best-effort.
      for (const email of studentEmails) {
        await guacAPI('DELETE', `/users/${encodeURIComponent(email)}`).catch(() => {});
      }
    }

    // Guacamole Kali console connections are named "<group> - lane<vxlan> - Kali"
    // (see lane-provision.js). Delete every connection carrying this group's prefix.
    try {
      const conns = await guacAPI('GET', '/connections');
      const prefix = `${group.group_name} - lane`;
      for (const [id, conn] of Object.entries(conns || {})) {
        if (conn && typeof conn.name === 'string' && conn.name.startsWith(prefix)) {
          await guacAPI('DELETE', `/connections/${encodeURIComponent(id)}`).catch(e =>
            errors.push(`guac connection ${conn.name}: ${e.message}`));
        }
      }
    } catch (e) {
      errors.push(`guac connection sweep: ${e.message}`);
    }

    // NOTE: we DO NOT delete the crucible_challenge here. Challenges are now
    // per-PROFILE (managed by getOrCreateProfileChallenge / deleteProfileChallenge),
    // so other groups from the same profile may still reference it. The
    // challenge is only deleted when the profile itself is deleted — that
    // path lives in profiles.js's DELETE /api/profiles/:id handler, which
    // calls deleteProfileChallenge() from utils/lane-reservation.js.

    // 'deleted' only when the cluster is actually clear. Tombstoning a group whose
    // machines are still running hides the survivors behind a row that reads as
    // finished — the same mistake the lane teardowns made, one level up.
    await query(
      `UPDATE ciab_profile_lane_groups SET status=$2, updated_at=NOW() WHERE id=$1`,
      [req.params.groupId, lanesKeptForRetry > 0 ? 'error' : 'deleted']
    );

    audit.batch({
      req,
      source: 'ciab',
      action: 'profile_lane.group_destroyed',
      targetAction: 'user.deleted',
      target: { type: 'group', id: req.params.groupId, label: group.group_name },
      metadata: { group_name: group.group_name, reason: 'profile_lane_teardown', errors: errors.length },
      targets: deletedStudents.map(u => ({
        id: u.user_id, label: u.email,
        metadata: { group_name: group.group_name, auto_provisioned: true },
      })),
    });

    // 207 when machines survived: the lane rows, the student accounts and the
    // group row have all deliberately been kept so a retry can still find them.
    res.status(lanesKeptForRetry === 0 ? 200 : 207).json({
      success: lanesKeptForRetry === 0,
      group_id: req.params.groupId,
      students_deleted: deletedStudents.length,
      lanes_kept_for_retry: lanesKeptForRetry,
      errors: errors.length ? errors : undefined
    });
  } catch (err) {
    // assertNoConflictingProfileOperation throws a 409. Flattening it to 500
    // would tell the admin the teardown broke, when in fact it was correctly
    // refused and retrying in a minute is the answer.
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
module.exports.runProfileDeploy = runProfileDeploy;
module.exports.adoptedSpec = adoptedSpec;
module.exports.loadProfileForDeploy = loadProfileForDeploy;
module.exports.defaultAssetSelection = defaultAssetSelection;

// G5. Exported so test/ciab-bake-route.test.js can pin the classification and
// the identity derivation directly, rather than inferring either from a route
// response that happens to exercise it.
module.exports.bakeIdentityForProfile = bakeIdentityForProfile;
module.exports.COMPILE_REFUSALS = COMPILE_REFUSALS;
module.exports.compileRefusalOf = compileRefusalOf;
module.exports.refineCompileRefusal = refineCompileRefusal;
module.exports.notImplementedPhase = notImplementedPhase;
module.exports.bakeStateOf = bakeStateOf;
module.exports.bakeView = bakeView;
module.exports.deployNeedsBake = deployNeedsBake;
module.exports.assertProfileBakeDeployable = assertProfileBakeDeployable;

// C1. The bake-to-deploy loop. Every one of these is a producer for a consumer
// that already existed and had nothing feeding it, so each is exported to be
// driven directly as well as through its route: a golden template set that is
// built and never cloned looks identical, from the outside, to one that is.
module.exports.BAKE_ENGAGEMENT_TYPE = BAKE_ENGAGEMENT_TYPE;
module.exports.bakeFixedSubnetFor = bakeFixedSubnetFor;
module.exports.resolveBakeNetwork = resolveBakeNetwork;
module.exports.withBakeNetwork = withBakeNetwork;
module.exports.assertBakeSpecProvisionable = assertBakeSpecProvisionable;
module.exports.goldenTemplatesOf = goldenTemplatesOf;
module.exports.deployLabDefFromBake = deployLabDefFromBake;
module.exports.prebakedSpecFromBake = prebakedSpecFromBake;
// The reseed producer's pure halves, exported so a test can ask the REAL
// compiler's output "which account does the website publish, in which domain,
// and which credentials must never be rotated" without standing up a route.
module.exports.FIXED_ENTRY_FORMATS = FIXED_ENTRY_FORMATS;
module.exports.bareSamOf = bareSamOf;
module.exports.principalDomainOf = principalDomainOf;
module.exports.fixedCredentialsFromIr = fixedCredentialsFromIr;
module.exports.siteReseedForBake = siteReseedForBake;
module.exports.reseedBlockForBake = reseedBlockForBake;
