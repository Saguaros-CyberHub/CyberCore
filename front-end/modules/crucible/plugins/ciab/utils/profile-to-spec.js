/**
 * profile-to-spec.js — Pure synthesizer
 * ============================================================================
 * Turn an AI-generated CIAB profile into a deployable challenge `spec`,
 * plus a service-gaps report and template-misses report so the admin can
 * see what won't deploy and why.
 *
 * No DB calls — callers pre-fetch cybercore_template_catalog and vuln_scripts and
 * pass them in. This keeps the function unit-testable and lets the route
 * handler control caching/concurrency.
 *
 * Output `spec` shape matches what the cybercore_lane deploy orchestrator
 * already consumes (admin.js /deploy-lane and /deploy-group are the
 * reference): { vxlan_block, template_node, vms: [...], vuln_app_install }.
 */

const { resolveTemplate } = require('../../../../../src/utils/vm-template-resolver');
const { findScript, familyToOsTarget } = require('../../../../../src/utils/vuln-script-resolver');
// engagement-model.js imports NOTHING (test/ciab-engagement-model.test.js B0-1
// pins that), so this cannot pull a cluster, a DB handle or site-config.js into
// the synthesizer's load path — which is the property that makes this file
// unit-testable with no config at all. It is also not a cycle: engagement-plan
// imports BOTH this file and engagement-model; engagement-model imports neither.
//
// Imported rather than re-spelled because all three are facts about the lane
// that already have exactly one authority, and a second spelling of any of them
// is the drift this plugin has been closing all program long:
//   DUAL_HOMED_OCTET      .240, where challenge-lane-deployer.js actually pins a
//                         dual-homed host (its own comment forbids re-spelling 240)
//   nicsForPlacement      the {segment} array a placement implies
//   describeEngagementType the ONLY authority on an engagement slug's perspective
const {
  DUAL_HOMED_OCTET, nicsForPlacement, describeEngagementType,
} = require('./engagement-model');

// ─── OS string parser ───────────────────────────────────────────────────────
// Profile assets carry `os` as a single human string (e.g. "Windows Server 2022",
// "Ubuntu Server 22.04 LTS"). The template resolver wants {os_family, os_version}.
function parseOs(osString) {
  const s = String(osString || '').trim();
  if (!s) return { os_family: null, os_version: null };

  const lower = s.toLowerCase();

  // Windows
  if (lower.startsWith('windows server')) {
    const m = lower.match(/windows server\s+(\d{4}(?:\s*r2)?)/);
    return { os_family: 'windows_server', os_version: m ? m[1].replace(/\s+/g, '') : null };
  }
  if (lower.startsWith('windows')) {
    const m = lower.match(/windows\s+(\d+|xp|vista|7|8|10|11)/);
    return { os_family: 'windows_client', os_version: m ? m[1] : null };
  }

  // Linux distros (parse before generic "linux")
  if (lower.includes('ubuntu')) {
    const m = lower.match(/ubuntu(?:\s+server)?\s+(\d+\.\d+)/);
    return { os_family: 'linux', os_version: m ? `ubuntu-${m[1]}` : 'ubuntu' };
  }
  if (lower.includes('debian')) {
    const m = lower.match(/debian\s+(\d+)/);
    return { os_family: 'linux', os_version: m ? `debian-${m[1]}` : 'debian' };
  }
  if (lower.includes('rocky') || lower.includes('rhel') || lower.includes('centos') || lower.includes('alma')) {
    const m = lower.match(/(\d+)/);
    return { os_family: 'linux', os_version: m ? `rhel-${m[1]}` : 'rhel' };
  }
  if (lower.includes('linux')) {
    return { os_family: 'linux', os_version: null };
  }

  // macOS / iOS / embedded — return family, version optional. Resolver will
  // typically miss these (no template), they fall into template_misses.
  if (lower.startsWith('macos') || lower.startsWith('mac os')) {
    return { os_family: 'macos', os_version: null };
  }
  if (lower.includes('embedded')) {
    return { os_family: 'embedded', os_version: null };
  }

  return { os_family: null, os_version: null };
}

// ─── Service token parser ───────────────────────────────────────────────────
// Profile services are "port/Service" strings (e.g. "445/SMB", "80/HTTP").
function parseService(token) {
  const str = String(token || '').trim();
  if (!str) return null;
  const idx = str.indexOf('/');
  if (idx === -1) return { port: null, service: str.toLowerCase() };
  const port = parseInt(str.slice(0, idx), 10);
  return {
    port: Number.isFinite(port) ? port : null,
    service: str.slice(idx + 1).trim().toLowerCase()
  };
}

// ─── Asset filter ───────────────────────────────────────────────────────────
function isIncluded(asset, assetSelection) {
  if (!Array.isArray(assetSelection) || assetSelection.length === 0) {
    // Default: only servers
    return String(asset.role || '').toLowerCase() === 'server';
  }
  const sel = assetSelection.find(s => s.hostname === asset.hostname);
  return sel ? !!sel.included : false;
}

// ─── Detect web-server asset (for vuln-app placement) ──────────────────────
// Matches by either: (a) declared HTTP/HTTPS service, OR (b) hostname pattern
// (any token that is exactly 'web' or 'web<digits>'). The hostname check covers
// AI-generated profiles where the services array is sometimes empty/missing
// but the hostname clearly marks a web server (e.g. 'mercury-web-01', 'web01',
// 'intranet-web'). Per the user's "every company has WEB01" convention.
function isWebServer(asset) {
  if (String(asset.role || '').toLowerCase() !== 'server') return false;

  const svcs = Array.isArray(asset.services) ? asset.services : [];
  const hasHttpService = svcs.some(s => {
    const p = parseService(s);
    return p && (p.port === 80 || p.port === 443 || /^https?$/i.test(p.service));
  });
  if (hasHttpService) return true;

  const hostname = String(asset.hostname || '').toLowerCase();
  const tokens = hostname.split(/[-_.]/);
  return tokens.some(t => /^web\d*$/.test(t));
}

// ─── VM type heuristic ──────────────────────────────────────────────────────
// QEMU for everything by default; LXC only when a template explicitly says so.
// The four-rung resolver doesn't return a type — we infer from os_family.
function inferVmType(matchedRow) {
  // If the catalog row has an explicit hint, honor it
  if (matchedRow && matchedRow.row && matchedRow.row.vm_type) return matchedRow.row.vm_type;
  return 'qemu';
}

// ─── Lane addressing (A4) ───────────────────────────────────────────────────
/**
 * The band the shared deployer hands out to ordinary (non-console, non-GOAD)
 * spec machines under `pinAllVms`.
 *
 * MIRRORED, not imported: challenge-lane-deployer.js pulls site-config at module
 * load (via batch-deployer), which reads a gitignored config/site.json — and
 * this file's whole point is being a pure synthesizer that unit tests can load
 * with no cluster, no DB and no config. test/ciab-deploy-parity.test.js asserts
 * the two agree, so a change to the band there fails here rather than silently
 * handing out addresses the deployer will reject.
 *
 * Authority: src/utils/challenge-lane-deployer.js SPEC_OCTET_MIN / SPEC_OCTET_MAX.
 */
const SPEC_OCTET_MIN = 80;
const SPEC_OCTET_MAX = 99;

/**
 * Where E3's SIEM machines live, and the short names they answer to.
 *
 * MIRRORED, not imported — the same trade SPEC_OCTET_MIN/MAX above makes, and
 * for the same reason. The authority is src/utils/goad-deploy.js
 * GOAD_EXTENSIONS.elk.ipOctet / .wazuh.ipOctet, which also carries the
 * load-time guard that refuses an extension octet colliding with lane
 * infrastructure. That module requires script-executor -> proxmox + db, so
 * importing it here would end this file's one non-negotiable property: it loads
 * with no cluster, no database and no config/site.json, which is what lets
 * test/ciab-engagement-model.test.js require it BARE as its purity assertion.
 * test/ciab-blueteam.test.js asserts the two agree, so a change there fails a
 * test here rather than silently handing out an address something else owns.
 *
 * WHY THESE TWO NUMBERS, SPECIFICALLY.
 *   elk .24   NOT the .50 upstream's extensions/elk/inventory pins. On v3, .50
 *             was free because Kali lives on the EXTERNAL segment and a SIEM
 *             sits internally. A defensive engagement is v2 — ONE flat lan0 —
 *             where .50 is INFRA_IP_OCTETS.Kali. Two dhcp-host lines claiming
 *             one address make dnsmasq refuse to START, which takes DHCP down
 *             for the whole lane, not just for the SIEM.
 *   wazuh .51 Upstream's own octet, and free on v2 — so nothing has to be
 *             edited in the inventory the golden image was built from.
 *
 * Both are OUTSIDE the .80-.99 band on purpose. A band octet is invented by
 * this walk and moves when the asset list changes; these two are baked into
 * images and into a sensor's ELK_HOST, so they must not move at all.
 */
const SIEM_OCTETS = Object.freeze({ elk: 24, wazuh: 51 });

/**
 * Which SIEM machines each telemetry stack stands up.
 *
 * Deliberately data rather than an if/else: 'both' is a real, supported choice
 * (comparing two consoles against one incident is a skill), and spelling it as
 * a union of the other two makes it impossible for the three modes to disagree
 * about what a SIEM is.
 */
const SIEM_MACHINES_FOR_STACK = Object.freeze({
  elastic: Object.freeze(['elk']),
  wazuh: Object.freeze(['wazuh']),
  both: Object.freeze(['elk', 'wazuh']),
});

/** The sensor's spec name, hostname and DNS label — one string, one place.
 *  'sensor' is in the incident engine's LOGGEN_ROLES set already, so emitting
 *  role:'sensor' makes the spec_role rung of its target ladder fire with no
 *  change on that side. */
const SENSOR_VM_NAME = 'sensor';

/**
 * The subnet scheme a profile lane gets when the caller names none.
 *
 * WAS 'v2', AND THE FLIP IS THE POINT. v2 is one flat segment: Kali, the web
 * host and the domain controller all share a broadcast domain, so "pivot
 * through the web server to reach AD" is a CONVENTION a student can simply
 * decline to follow — nmap the /24, find the DC, attack it directly, and the
 * exercise the engagement was built around never happens.
 *
 * v3 is two segments behind one gateway (ext0 / int0) with ext0<->int0 DROPped
 * in FORWARD. Kali sits on ext at .50, the company web host is DUAL-HOMED at
 * .240 on both, and everything else is internal. Reaching AD then REQUIRES
 * compromising the web host, because the network enforces it rather than the
 * worksheet asking for it.
 *
 * v2 STAYS SELECTABLE, per engagement: an engagement row carries subnet_scheme
 * and both live callers pass it through (routes/profile-deploy.js and
 * routes/engagements.js each send `engagementRow.subnet_scheme || …`), so an
 * explicit 'v2' still synthesizes exactly what it synthesized before this
 * change — see the v2 snapshot in test/ciab-spec-dns-topology.test.js.
 */
const DEFAULT_SUBNET_SCHEME = 'v3';

/**
 * A profile hostname reduced to something dnsmasq will accept as a host-record.
 *
 * Only the FIRST label survives: a profile may name an asset `web01.corp.local`,
 * but `resolveDnsAliases` validates against a single DNS label and drops
 * anything with a dot — and a dropped alias is invisible until a student
 * discovers `ping web01` does not work. Taking the label ourselves keeps the
 * name the paper uses.
 *
 * Returns null when nothing usable survives, so the caller omits the key rather
 * than publishing an empty alias.
 */
function dnsLabel(hostname) {
  const first = String(hostname == null ? '' : hostname).trim().toLowerCase().split('.')[0];
  const cleaned = first.replace(/[^a-z0-9-]/g, '-').replace(/^-+/, '').replace(/-+$/, '');
  if (!cleaned || cleaned.length > 63) return null;
  return cleaned;
}

/**
 * A DOTTED DNS name, normalised — or null when the input is not one.
 *
 * dnsLabel's sibling, and deliberately a different function: a label is one
 * component (`web01`) and this is a whole name (`www.acme-clinic.com`). Passing
 * a public domain through dnsLabel would keep only `www`.
 *
 * MIRRORED from challenge-lane-deployer.js's DNS_NAME_RE / dnsNameOrEmpty, for
 * the same reason SPEC_OCTET_MIN/MAX above is mirrored: that module pulls
 * site-config at load (via batch-deployer) and this one's whole value is being
 * loadable with no cluster, no DB and no config. The agreement is asserted
 * end-to-end instead of by copying the regex around —
 * test/ciab-spec-dns-topology.test.js feeds what this emits through the REAL
 * resolveLaneDnsExtras and checks the dnsmasq lines that come out, which is a
 * stronger check than two regexes matching, because it also proves the field
 * names match.
 *
 * WHY IT REFUSES RATHER THAN REPAIRS. domain_public is LLM-authored, so it
 * arrives as anything: 'N/A', 'acme clinic dot com', ''. The line built from it
 * lands in the SAME dnsmasq file as the lane's DHCP reservations, and dnsmasq
 * refuses to START on one malformed directive — so a single bad character here
 * does not produce a missing web name, it takes DHCP down for every machine on
 * the lane and the whole environment comes up unreachable.
 *
 * The two repairs it DOES make are the two shapes an author writes on purpose:
 * a URL (`https://acme-clinic.com/`) and a root-form FQDN (`acme-clinic.com.`).
 * The scheme/path pair is exactly the normalization utils/profile-to-intake.js
 * already applies to this same field at :319 and :425 — a third reading of one
 * value is how the paper and the lane end up naming different sites.
 */
const DNS_NAME_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

function dnsName(value) {
  const name = String(value == null ? '' : value)
    .trim()
    .toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')   // scheme, as profile-to-intake.js:319 strips it
    .replace(/\/.*$/, '')                     // path
    .replace(/\.$/, '');                      // root-form trailing dot; dnsmasq wants it gone
  if (!name || name.length > 253 || !DNS_NAME_RE.test(name)) return null;
  return name;
}

/**
 * The client's public domain, wherever this profile happens to keep it.
 *
 * THREE LAYOUTS, ONE FACT. An AI profile stores it at
 * student_view.raw.threats.organization.domain_public, the quick-view copy at
 * student_view.quick.domain_public, and an uploaded/flat profile at the root.
 * routes/profile-deploy.js's loadProfileForDeploy hands this function the DB row
 * spread over `json_data`, so the nested forms are the ones that actually arrive
 * in production.
 *
 * engagement-plan.js's readClientFacts is the fuller reader of the same fact and
 * would be the right thing to import — except that engagement-plan imports THIS
 * file (for isWebServer, dnsLabel and the octet band), so importing it back is a
 * require cycle. The chain below is deliberately the same order readClientFacts
 * uses at :931, so the brief and the lane name the same domain.
 *
 * Total: any shape, including null and a string where an object belongs.
 */
function resolvePublicDomain(profile) {
  const obj = (v) => (v && typeof v === 'object' ? v : {});
  const p = obj(profile);
  const sv = obj(obj(p.json_data).student_view);
  const org = obj(obj(obj(sv.raw).threats).organization);
  const quick = obj(sv.quick);
  return org.domain_public
    || quick.domain_public
    || obj(p.organization).domain_public
    || p.domain_public
    || null;
}

/**
 * The lane's own DNS answers, as `spec.dns` — or null when there is nothing
 * worth publishing.
 *
 * OPT-IN AT THE OTHER END TOO. challenge-lane-deployer.resolveLaneDnsExtras
 * reads exactly this block and nothing else, and returns [] when it is absent —
 * so a spec that gets null back here produces the byte-identical reservations
 * file it produced before this function existed.
 *
 * The shape is that function's, verbatim:
 *   { ad_domain, ad_dc, web_name, web_vm }
 * Machines are named by SPEC NAME, never by address: the lane subnet is
 * allocated per lane (10.<vxh>.<vxl>), so an IP literal in a spec is right for
 * at most one student and silently wrong for every other one.
 *
 * ── THE ENGAGEMENT DECIDES WHETHER AD IS RESOLVABLE ─────────────────────────
 *
 * This is a deliberate design decision, not an oversight, and it is the reason
 * this function needs to know the engagement type at all.
 *
 * The gateway's dnsmasq serves BOTH v3 segments — Kali on ext0 and the corp
 * machines on int0 use the same resolver. `server=/<forest>/<dc-ip>` is
 * therefore published to Kali as well, and ext0<->int0 is DROPped in FORWARD, so
 * Kali can RESOLVE `dc01.corp.acme.local` and every `_msdcs`/`_tcp` SRV under it
 * while being unable to send a single packet there. That is a topology leak: the
 * forest name, the DC's hostname and its internal address are the first three
 * things an external test is supposed to have to EARN, and a resolver that
 * answers hands over all three before the student has touched the target.
 *
 * So for an EXTERNAL engagement the forwarder is WITHHELD. Enumerating AD
 * through the compromised pivot IS the exercise; publishing it lane-wide would
 * delete the middle of the engagement. For an INTERNAL engagement it is
 * published, because there the tester is legitimately inside and every AD tool
 * invoked the way a student is taught to invoke it — `nxc smb dc01.corp.local`,
 * `bloodhound-python -d corp.local`, `GetUserSPNs.py corp.local/user` with no
 * `-dc-ip` — otherwise fails at name resolution before it has touched anything.
 *
 * Keyed on the REGISTRY's perspective, not on the slug: describeEngagementType
 * is the one authority on what a slug means, it is total, and an unknown slug
 * yields the conservative (internal) posture — the same value the ciab_engagement
 * columns DEFAULT to, so a locally-defined type behaves like the internal case
 * rather than silently losing its forwarder.
 *
 * THE COMPANY WEB NAME IS PUBLISHED EITHER WAY. It is the client's forward-facing
 * site: an external engagement is defined as starting with nothing BUT that site,
 * so withholding its name would leave the tester with no starting point at all.
 *
 * @param {object}  a
 * @param {object}  a.spec            the spec under construction — read for
 *                                    `vuln_app_install.target_vm`, `vms` and
 *                                    (once an AD compiler exists) `goad`
 * @param {object}  [a.profile]       the client profile, for domain_public
 * @param {string}  [a.engagementType] slug; falls back to spec.engagement_type
 * @returns {{ad_domain?:string, ad_dc?:string, web_name?:string, web_vm?:string}|null}
 */
function buildSpecDns({ spec = {}, profile = null, engagementType = null } = {}) {
  const s = spec && typeof spec === 'object' ? spec : {};
  const dns = {};

  // ── the company's public web name ────────────────────────────────────────
  // A PUBLIC domain has a dot in it, and requiring one is not pedantry — it is
  // the check that catches what this field actually arrives as when the model
  // had nothing to say. 'N/A' survives the URL-path strip above as the label
  // `n`, and 'TBD', 'none' and 'unknown' are valid DNS labels on their own, so
  // every one of them would otherwise be published lane-wide as the client's web
  // site and answer for a real name. dnsName's job is "is this a DNS name";
  // this is the separate question "is this plausibly a company's public domain",
  // and only the second one can reject `n`.
  const candidate = dnsName(resolvePublicDomain(profile));
  const webName = candidate && candidate.includes('.') ? candidate : null;
  const install = s.vuln_app_install && typeof s.vuln_app_install === 'object'
    ? s.vuln_app_install : {};
  const webVm = String(install.target_vm == null ? '' : install.target_vm).trim();
  const vms = Array.isArray(s.vms) ? s.vms : [];
  // Both keys or neither. web_name without a machine, or naming a machine that
  // is not in this spec, reaches the deployer as a warning and a dropped record
  // — a name the paper promises and the lane never answers.
  if (webName && webVm && vms.some(vm => vm && vm.name === webVm)) {
    dns.web_name = webName;
    dns.web_vm = webVm;
  }

  // ── the AD forest's conditional forwarder ────────────────────────────────
  // Read from the SPEC, because that is where the AD compiler will put it: a
  // later wave stamps spec.goad and the forwarder starts being emitted here with
  // no change to this function. Nothing writes spec.goad today, so `dns.ad_*` is
  // absent from every spec this synthesizer currently produces.
  const goad = s.goad && typeof s.goad === 'object' ? s.goad : {};
  const adDomain = dnsName(goad.domain);
  const external = describeEngagementType(
    engagementType || s.engagement_type || null
  ).perspective === 'external';

  if (adDomain && !external) {
    dns.ad_domain = adDomain;
    // ad_dc is emitted only when the lab NAMES its answering DC. Omitted, the
    // deployer takes the first goadMacs host with role 'dc' and its already
    // resolved static IP — which is the right host for every stock lab, and the
    // only one that stays right when the lab version changes underneath us.
    const adDc = String(goad.dc == null ? '' : goad.dc).trim();
    if (adDc) dns.ad_dc = adDc;
  }

  return Object.keys(dns).length ? dns : null;
}

/**
 * Give every pinnable machine a fixed address and a stable in-lane name.
 *
 * This is the contract between a profile's generated paper and its lane's real
 * addresses: the scan documents can only claim `10.x.y.83` for `web01` if the
 * deploy actually puts it there. `ipOctet` is the EXISTING key the shared
 * deployer honours (challenge-lane-deployer.js resolveSpecAddressing PASS 1,
 * src/utils/attached-modules.js allocateIpOctets) — this does not invent a
 * second spelling.
 *
 * Only QEMU single-homed machines are pinned, because those are exactly the ones
 * `resolveSpecAddressing` treats as eligible. Pinning an LXC would write an
 * address the deployer ignores, and the paper would then name an IP nothing
 * lives at — worse than naming none.
 *
 * THE DUAL-HOMED DMZ HOST IS THE ONE EXCEPTION, and it is an exception with an
 * address rather than without one. `opts.dmzVmName` names the machine the v3
 * layout puts on BOTH segments; it is excluded from the band by the same
 * `nics.length > 1` filter as everything else multi-homed, and then given
 * DUAL_HOMED_OCTET explicitly, because .240 is where challenge-lane-deployer.js
 * actually pins it (ipconfig0/ipconfig1, above the gateway's .10-.200 DHCP
 * pool). Leaving its ipOctet undefined would be just as wrong as a band octet:
 * the scan report, the asset register and the brief all read the spec, and
 * "no address" for the one machine the whole external exercise points at is a
 * document that cannot be written. A band octet would be worse still — a true
 * statement about a spec field and a false one about the lane.
 *
 * A MACHINE THAT ALREADY NAMES ITS OWN OCTET IS THE SECOND EXCEPTION, and it
 * costs no band slot. E3's SIEM machines arrive here with `ipOctet` already set
 * (elk .24, wazuh .51 — see SIEM_OCTETS), because those addresses are fixed by
 * what the golden images were baked against rather than by this walk. That is
 * not a special case invented here: resolveSpecAddressing does exactly the same
 * thing in two passes, claiming every EXPLICIT ipOctet before handing out a
 * single automatic one, and its own comment explains why one cursor is not
 * enough (a late explicit .85 would otherwise be told its own address is taken,
 * naming a conflict the author cannot see anywhere in their spec). This
 * function mirrors that shape so the two cannot disagree about who owns .24.
 *
 * Omit `dmzVmName` and pass no pre-set `ipOctet` (every caller before v3 and
 * before E3 did) and this behaves EXACTLY as it always has, down to which
 * machine wins a contested alias.
 *
 * Mutates `vms` in place and returns it.
 *
 * @param {Array} vms
 * @param {object} [opts]
 * @param {string|null} [opts.dmzVmName] spec name of the dual-homed DMZ host
 */
function hasExplicitOctet(vm) {
  return !!vm && vm.ipOctet !== undefined && vm.ipOctet !== null;
}

function assignLaneAddressing(vms, { dmzVmName = null } = {}) {
  const pinnable = vms.filter(vm =>
    (vm.type || 'qemu') !== 'lxc'
    && !(Array.isArray(vm.nics) && vm.nics.length > 1)
  );

  // Only the machines that need an address INVENTED spend the band. A machine
  // carrying its own ipOctet is pinned out of band (resolveSpecAddressing PASS 1
  // range-checks it 2-254 and claims it before the cursor starts), so counting
  // it here would refuse a lane the deployer can build perfectly well.
  const explicit = pinnable.filter(hasExplicitOctet);
  const bandBound = pinnable.filter(vm => !hasExplicitOctet(vm));

  const capacity = SPEC_OCTET_MAX - SPEC_OCTET_MIN + 1;
  if (bandBound.length > capacity) {
    // Fail here rather than let the deployer fail later, or — far worse — let a
    // partially-pinned lane deploy. Half the hosts on their documented address
    // and half on a pool lease is an environment whose own scan report is wrong
    // about it, which is the one outcome this whole synthesizer exists to avoid.
    //
    // THE MESSAGE NAMES THE RESERVED SLOTS ON PURPOSE. An instructor who
    // selected twenty assets and is told "a lane can pin only 20" has been
    // handed a contradiction. The band is spent by machines this synthesizer
    // APPENDS as well as by the ones they picked: the standalone vuln-app host
    // when the client has no web server of its own, and — on a defensive
    // engagement — the telemetry sensor. The two SIEMs cost nothing here,
    // because each names its own address. Saying which is which is the
    // difference between "deselect an asset" and "why is this number wrong".
    const appended = bandBound.filter(vm => vm.synthetic).map(vm => vm.name);
    throw new Error(
      `This profile selects ${bandBound.length} deployable machines, but a lane can pin only ` +
      `${capacity} (the .${SPEC_OCTET_MIN}-.${SPEC_OCTET_MAX} band)` +
      (appended.length
        ? `, and ${appended.length} of those ${appended.length === 1 ? 'is a machine' : 'are machines'} ` +
          `this environment adds for you (${appended.join(', ')}) rather than one you selected`
        : '') +
      `. Deselect assets until at most ${capacity} remain, or split the profile across two ` +
      `engagements.`
    );
  }

  const claimedAlias = new Map();
  // The deployer THROWS when two machines claim one alias, which would fail the
  // whole batch over a convenience name. First claimant wins; the loser keeps
  // its pinned address and simply has no short name.
  const claimAlias = (vm) => {
    const alias = dnsLabel(vm.hostname || vm.name);
    if (!alias) return;
    if (claimedAlias.has(alias)) {
      console.warn(
        `[profile-to-spec] '${vm.name}' wanted DNS alias '${alias}' but '${claimedAlias.get(alias)}' ` +
        `already claimed it — deploying without a short name for this host`
      );
      return;
    }
    claimedAlias.set(alias, vm.name);
    vm.dns_aliases = [alias];
  };

  // PASS 1 — machines that name their own address, claiming their aliases
  // FIRST. The order is not cosmetic: the sensor's baked agent hard-codes
  // ELK_HOST=elk.cybercore.lan, so if a selected client asset happened to be
  // called `elk` and claimed the name ahead of the SIEM, the agent would ship
  // nowhere — healthy process, no error, no events. Losing a short name is
  // survivable for a client asset and fatal for the SIEM, so the SIEM wins.
  // (synthesizeSpecFromProfile refuses that collision outright before it gets
  // here; this ordering is the second line of defence, for a hand-built spec
  // that never went through it.)
  for (const vm of explicit) claimAlias(vm);

  // PASS 2 — walked in SPEC ORDER over every machine rather than over
  // `bandBound`, so the DMZ host takes its turn at claiming a short name in the
  // same position it occupies in the spec. With no dmzVmName and no explicit
  // octets the two walks are indistinguishable from the single walk this
  // replaced: a machine that is not band-bound `continue`s before it can claim
  // anything, and the cursor advances only for band-bound machines, in order.
  const bandSet = new Set(bandBound);
  let octet = SPEC_OCTET_MIN;
  for (const vm of vms) {
    if (hasExplicitOctet(vm)) continue;          // addressed and claimed in PASS 1
    if (dmzVmName && vm.name === dmzVmName) vm.ipOctet = DUAL_HOMED_OCTET;
    else if (bandSet.has(vm)) vm.ipOctet = octet++;
    else continue;

    claimAlias(vm);
  }

  return vms;
}

// ─── v3 topology (the enforced pivot) ───────────────────────────────────────
/**
 * Which single machine is the lane's dual-homed DMZ host — or null.
 *
 * ONE PER LANE, AND THAT IS PHYSICAL, NOT EDITORIAL. The deployer defines
 * exactly ONE dual-homed address (.240 on both segments), so a second dual-homed
 * machine would be handed the same address as the first and the lane would come
 * up with an IP conflict on its most important host. Deriving the answer from
 * `vuln_app_install.target_vm` makes "exactly one" structural: that field holds
 * one name by construction, so there is no list to pick from and no tie to break
 * — every other public-facing asset stays an ordinary internal host.
 *
 * WHY THE VULN-APP TARGET IS THE RIGHT MACHINE. The DMZ host exists to serve the
 * client's forward-facing site, and on a CIAB profile lane the generated
 * vuln-app IS that site. The target is already resolved deterministically above
 * (cached target_hostname, else the first web-server asset, else the appended
 * synthetic 'vuln-app' VM), and engagement-plan.js's derivePublicSurface walks
 * the same three rungs in the same order — so the compile's `public_surface` and
 * the lane's bridge are the same machine without either file consulting the
 * other.
 *
 * NO SITE MEANS NO BRIDGE, deliberately. A profile with no generated app has
 * nothing public-facing to put in a DMZ, and inventing a bridge out of some
 * arbitrary server would be a lane that disagrees with its own paper. The
 * compile already reports that state honestly (EXTERNAL_NO_SURFACE /
 * EXTERNAL_NO_PIVOT), which is a far better outcome than a silent guess.
 *
 * An LXC can never be it: resolveVmNics gives a container ONE card no matter how
 * many segments it asks for (lane-networking.js's `segments.slice(0, 1)`), so a
 * "dual-homed" container is a claim the deploy cannot honour — and it would then
 * be stamped .240 while sitting on a DHCP lease.
 */
function resolveDmzVm({ subnetScheme, vms, vulnAppInstall }) {
  if (subnetScheme !== 'v3') return null;
  if (!vulnAppInstall || !vulnAppInstall.target_vm) return null;

  const vm = vms.find(v => v.name === vulnAppInstall.target_vm);
  if (!vm) return null;
  if ((vm.type || 'qemu') === 'lxc') {
    console.warn(
      `[profile-to-spec] '${vm.name}' serves the company site but is an LXC, which the deployer can ` +
      `only give one NIC — leaving this lane with no dual-homed DMZ host. Every machine stays on the ` +
      `external segment.`
    );
    return null;
  }
  return vm.name;
}

/**
 * Place every machine on a segment, now that the lane has a bridge.
 *
 * The DMZ host gets [{ext},{int}] and everything else gets [{int}]. Both come
 * from engagement-model's nicsForPlacement so the segment names have one source.
 *
 * WHY EVERYTHING ELSE MOVES TO int. The v3 default for an ordinary spec VM is a
 * single EXTERNAL NIC (lane-networking.js resolveVmSegments' last line), which
 * would leave the domain controller, the file server and the attack box all on
 * ext0 together. The FORWARD drop would then be protecting nothing but a GOAD
 * lab that a profile-derived lane does not even have, Kali would reach every
 * company machine directly, and the dual-homed host would be a decoration
 * instead of the only way in. Putting the rest on int0 is what makes the
 * sentence "reaching AD requires pivoting through the web host" a fact about
 * the network rather than an instruction on a worksheet.
 *
 * An explicit `nics` already on a VM is left alone: it is the topology canvas's
 * or an instructor's authored answer, and it wins over every inference
 * (lane-networking.js honours explicit nics before role and before GOAD).
 *
 * ROLE IS NOT TOUCHED. It is tempting to stamp role 'dmz' on the bridge — that
 * is the other way lane-networking.js reaches the same two segments — but the
 * explicit nics array already wins over role, and role is load-bearing here for
 * two other readers: 'server' + an HTTP service is what registers this host for
 * the company domain, and isWebServer returns FALSE for any role that is not
 * 'server' (which is the exact bug engagement-plan.js:B0-86 documents).
 */
function applyV3Topology(vms, dmzVmName) {
  for (const vm of vms) {
    if (Array.isArray(vm.nics) && vm.nics.length) continue;
    vm.nics = nicsForPlacement(vm.name === dmzVmName ? 'pivot' : 'internal');
  }
  return vms;
}

// ─── E3: telemetry machines ──────────────────────────────────────
/**
 * Refuse a spec whose client assets already occupy a telemetry machine's name.
 *
 * A spec is a set of machines keyed by `name`, and two machines with one name
 * is not a naming preference — the deployer matches deployedVMs by name in the
 * postDeploy hook, the vuln-app installer targets by name, and the incident
 * engine's sensor stamp finds its VM by name. A duplicate silently makes all
 * three point at whichever one they saw first.
 *
 * A THROW HERE IS THE GOOD OUTCOME. runProfileDeploy calls this before anything
 * is written, so an instructor gets a message naming the asset to rename or
 * deselect, on a screen, before a single clone. The alternative is a lane that
 * deploys, reports active, and has a SIEM the sensor cannot find.
 */
function assertTelemetryNamesFree(vms, wanted) {
  const taken = new Map();
  for (const vm of vms) taken.set(String(vm.name || '').toLowerCase(), vm.name);
  for (const name of wanted) {
    const hit = taken.get(name.toLowerCase());
    if (hit !== undefined) {
      throw new Error(
        `This environment stands up a machine called '${name}', but the client's selected assets ` +
        `already include one named '${hit}'. Two machines cannot share a name: the deploy matches ` +
        `by name when it installs content and when it records where the sensor landed, so one of ` +
        `them would silently be used for both. Rename or deselect that asset.`
      );
    }
  }
}

/**
 * Append the sensor and the SIEM(s) a defensive engagement runs on.
 *
 * CALLED AFTER THE VULN-APP VM AND BEFORE assignLaneAddressing, which is what
 * gives the sensor a band octet and its `sensor` short name for free, and lets
 * the two SIEMs claim their own aliases in PASS 1.
 *
 * ── THE SENSOR HAS NO console_role, AND THAT IS THE POINT ──────────────────
 * Nothing logs into the sensor. It runs the synthetic emitter, which means it
 * holds the playbook the whole exercise is about finding. Designating it a
 * console would put a Guacamole session on the one machine carrying the answer
 * key, and the student would not even have to cheat on purpose to see it —
 * resolveConsolePlan would simply open it for them. Omitting the key is the
 * whole control; there is nothing else stopping this.
 *
 * ── THE SIEMs ARE ORDINARY SPEC VMs, AND THEY STAY OUT OF GOAD_LABS ────────
 * Being ABSENT from goadMacs is exactly what keeps them inside
 * resolveSpecAddressing, and resolveSpecAddressing is the only source of the
 * `host-record` line that makes `elk.cybercore.lan` resolve inside the lane
 * (challenge-lane-deployer.js). Adding either machine to a GOAD lab roster
 * would give it a deterministic MAC and a dhcp-host line and take its
 * host-record away — after which the sensor's baked ELK_HOST resolves to
 * nothing, ships nowhere, and reports itself perfectly healthy.
 *
 * Mutates `vms` in place. Returns the names it appended, in spec order.
 *
 * @param {Array} vms                    the spec's machines, so far
 * @param {object} telemetry             see synthesizeSpecFromProfile options
 * @param {object} opts
 * @param {string} opts.templateNode     fallback node for a catalog row with none
 */
function appendTelemetryMachines(vms, telemetry, { templateNode }) {
  const stack = String((telemetry && telemetry.stack) || '').trim().toLowerCase();
  const siemKeys = SIEM_MACHINES_FOR_STACK[stack] || [];
  // `sensor` is DERIVED on the engagement (stack !== 'wazuh'), never authored —
  // engagement-model.js validateTelemetryPlan owns that derivation. Here we only
  // ask whether a resolved template came with it: blueteam-templates.js returns
  // null for a stack that does not run one, and a NAMED 400 rather than null
  // when it should have run one and the catalog row is missing.
  const wantSensor = !!(telemetry && telemetry.sensor);

  const appended = [];
  const wantedNames = [];
  if (wantSensor) wantedNames.push(SENSOR_VM_NAME);
  for (const key of siemKeys) wantedNames.push(key);
  if (wantedNames.length === 0) return appended;

  assertTelemetryNamesFree(vms, wantedNames);

  const push = (vm) => {
    // The canonical offset formula, computed from the CURRENT length exactly as
    // every other push in this file does, so appending a telemetry machine
    // cannot renumber one that is already there.
    vms.push({ ...vm, vm_offset: 600000 + vms.length * 10000 });
    appended.push(vm.name);
  };

  if (wantSensor) {
    const t = telemetry.sensor;
    push({
      name: SENSOR_VM_NAME,
      hostname: SENSOR_VM_NAME,
      template_vmid: t.template_vmid,
      template_node: t.template_node || templateNode,
      type: 'qemu',
      role: 'sensor',
      os_family: 'linux',
      os_version: null,
      services: [],
      post_clone_scripts: [],
      // Not one of the client's assets. The asset register, the scan report and
      // the risk assessment all read the spec, and a machine the CLIENT does
      // not own must not appear in a document describing the client.
      synthetic: true,
      // NO console_role. See the header.
    });
  }

  for (const key of siemKeys) {
    const t = telemetry[key];
    if (!t) continue;                 // resolver refuses rather than returns null
    push({
      name: key,
      hostname: key,
      template_vmid: t.template_vmid,
      template_node: t.template_node || templateNode,
      type: 'qemu',
      // 'siem' matches GOAD_EXTENSIONS' own role for these two machines, so the
      // Designer's topology view and this synthesizer describe one thing.
      role: 'siem',
      os_family: 'linux',
      os_version: null,
      services: [],
      post_clone_scripts: [],
      synthetic: true,
      // Explicit and out of band: honoured by resolveSpecAddressing PASS 1,
      // which range-checks it 2-254. See SIEM_OCTETS for why these two numbers.
      ipOctet: SIEM_OCTETS[key],
    });
  }

  return appended;
}

// ─── Main synthesizer ──────────────────────────────────────────────────────
/**
 * @param {object} args
 * @param {object} args.profile               profiles row + loaded JSON. Expects
 *                                            profile.assets to be the asset array
 *                                            (callers normalize from student_view.raw.threats.network.assets).
 * @param {Array}  args.assetSelection        [{hostname, included:bool}]; falsy → default server-only.
 * @param {Array}  args.vmTemplateCatalog     cybercore_template_catalog rows.
 * @param {Array}  args.vulnScriptCatalog     vuln_scripts rows.
 * @param {object} [args.vulnApp]             ciab_profile_vuln_apps row (or null).
 * @param {object} [args.options]
 * @param {string} [args.options.subnetScheme='v3']   see DEFAULT_SUBNET_SCHEME
 * @param {object} [args.options.vxlanBlock]   {start, end} — defaults to {10000, 10009}
 * @param {boolean}[args.options.attackBoxes=true]
 * @param {string} [args.options.templateNode='cyberhub-node-5']
 * @param {string} [args.options.engagementType]  slug; decides only whether the
 *                                            AD forwarder is published (buildSpecDns)
 * @param {object} [args.options.telemetry]   E3. Absent on every engagement that
 *   is not defensive_monitoring, and absent is the ONLY thing that keeps a lane
 *   byte-identical to what it was before Track E. Shape, all resolved by
 *   utils/blueteam-templates.js from cybercore_template_catalog:
 *     { stack:'elastic'|'wazuh'|'both',
 *       sensor: {template_vmid, template_node}|null,   // null unless the plan
 *                                                      // derived sensor:true
 *       elk:    {template_vmid, template_node}|null,
 *       wazuh:  {template_vmid, template_node}|null }
 *   The machines are appended AFTER the vuln-app VM and BEFORE addressing, so
 *   the sensor takes a band octet and its own short name exactly like any other
 *   machine, and the two SIEMs keep the fixed octets their images were baked
 *   against.
 * @returns {{
 *   spec: {
 *     vxlan_block: {start, end},
 *     subnet_scheme: string,
 *     template_node: string,
 *     vms: Array<{name, hostname, template_vmid, type, vm_offset, role, os_family, services, post_clone_scripts, nics?}>,
 *     vuln_app_install: {target_vm, mode, install_script}|null,
 *     dns?: {ad_domain?, ad_dc?, web_name?, web_vm?}
 *   },
 *   service_gaps: Array<{vm, service, port, reason}>,
 *   template_misses: Array<{hostname, os, reason}>
 * }}
 */
function synthesizeSpecFromProfile({
  profile,
  assetSelection,
  vmTemplateCatalog,
  vulnScriptCatalog,
  vulnApp = null,
  options = {}
}) {
  const subnetScheme = options.subnetScheme || DEFAULT_SUBNET_SCHEME;
  const vxlanBlock = options.vxlanBlock || { start: 10000, end: 10009 };
  const attackBoxes = options.attackBoxes !== false;
  const templateNode = options.templateNode || 'cyberhub-node-5';
  // Decides ONLY whether the AD conditional forwarder is published — see
  // buildSpecDns. Nothing threads it in yet, and the default ('default' →
  // internal) is the publishing branch, so today it changes nothing: no spec
  // carries an AD domain for it to withhold.
  const engagementType = options.engagementType || null;
  // E3. Null on every other engagement type, and that is what makes this whole
  // change inert for them: appendTelemetryMachines is never called, no machine
  // is added, and the octet walk is the walk it always was.
  const telemetry = options.telemetry || null;

  const assets = Array.isArray(profile && profile.assets) ? profile.assets : [];
  const selected = assets.filter(a => isIncluded(a, assetSelection));

  const vms = [];
  const serviceGaps = [];
  const templateMisses = [];
  let webServerVmName = null;

  // Per-VM offsets follow admin's canonical convention: 600000 + idx * 10000.
  // See front-end/public/admin.html:4275, front-end/migrations/009_multi_vm_support.sql,
  // and modules/.../real-client-intake.js:512 — they all use this formula.
  for (const asset of selected) {
    let { os_family, os_version } = parseOs(asset.os);

    // Force web-server hosts to Linux. The vuln-app generator emits Docker /
    // apt install scripts that only run on Linux; if the AI profile gave us a
    // Windows web-01, override the OS to Linux so the bake scripts work and
    // we don't end up with a redundant standalone vuln-app VM. See user's
    // "every company has a WEB01 server" rule.
    if (isWebServer(asset)) {
      if (os_family !== 'linux') {
        console.log(`[profile-to-spec] Forcing ${asset.hostname} to Linux (was ${os_family}) — web servers must be Linux for vuln-app installability`);
      }
      os_family = 'linux';
      os_version = null;
    }

    if (!os_family) {
      templateMisses.push({
        hostname: asset.hostname,
        os: asset.os || null,
        reason: 'unparseable_os'
      });
      continue;
    }

    // For web servers, pass role='web' so the resolver picks a template whose
    // role_hints contains 'web' (e.g. 1005 Debian-web) deterministically,
    // instead of falling back to the most-recent generic Linux template.
    const resolverRole = isWebServer(asset) ? 'web' : asset.role;
    const match = resolveTemplate({ os_family, os_version, role: resolverRole }, vmTemplateCatalog);
    if (!match) {
      console.warn(`[profile-to-spec] No template match for ${asset.hostname} (os_family=${os_family} os_version=${os_version} role=${resolverRole}). Catalog had ${vmTemplateCatalog.filter(r => r.os_family === os_family).length} ${os_family} row(s).`);
      templateMisses.push({
        hostname: asset.hostname,
        os: asset.os || null,
        reason: 'no_family_match'
      });
      continue;
    }
    console.log(`[profile-to-spec] ${asset.hostname} → template_vmid=${match.template_vmid} (${match.os_name}, match=${match.match_type}, role=${resolverRole})`);

    // Resolve post-clone scripts for each declared service. Include the
    // 'init-setup' bootstrap only if its os_target covers the VM's os_family
    // (init-setup is currently Windows-only PowerShell; running it on a Linux
    // VM 596's on every agent/exec call because powershell doesn't exist).
    //
    // os_family and os_target are DIFFERENT namespaces: parseOs() emits
    // 'windows_server' / 'windows_client' / 'linux', while vuln_scripts.os_target
    // stores 'windows' / 'linux'. Comparing them raw made 'windows' !==
    // 'windows_server' and silently excluded init-setup from every host it was
    // meant for — so the bootstrap ran nowhere at all. familyToOsTarget() is the
    // same normalization findScript() already applies to service scripts below.
    const postCloneScripts = [];
    const seenSlugs = new Set();

    const lc = s => String(s || '').trim().toLowerCase();
    const vmOsTarget = familyToOsTarget(os_family);
    const bootstrap = vulnScriptCatalog.find(r =>
      r.slug === 'init-setup'
      && r.is_active !== false
      && (!r.os_target || lc(r.os_target) === vmOsTarget || lc(r.os_target) === 'any')
    );
    if (bootstrap) {
      postCloneScripts.push(bootstrap.slug);
      seenSlugs.add(bootstrap.slug);
    }

    const services = Array.isArray(asset.services) ? asset.services : [];
    for (const token of services) {
      const parsed = parseService(token);
      if (!parsed || !parsed.service) continue;

      const script = findScript({
        service: parsed.service,
        os_family,
        role: asset.role,
        prefer_type: 'vulnerable'   // for CIAB labs we want real findings
      }, vulnScriptCatalog);

      if (script) {
        if (!seenSlugs.has(script.slug)) {
          postCloneScripts.push(script.slug);
          seenSlugs.add(script.slug);
        }
      } else {
        serviceGaps.push({
          vm: asset.hostname,
          service: parsed.service,
          port: parsed.port,
          reason: 'no_installer'
        });
      }
    }

    const vmName = asset.hostname;
    vms.push({
      name: vmName,
      hostname: vmName,
      template_vmid: match.template_vmid,
      template_node: match.node || templateNode,
      type: inferVmType(match),
      vm_offset: 600000 + vms.length * 10000,
      role: asset.role,
      os_family,
      os_version,
      services,
      post_clone_scripts: postCloneScripts,
      template_match_type: match.match_type
    });

    // Remember the first web server for vuln-app placement
    if (!webServerVmName && isWebServer(asset)) {
      webServerVmName = vmName;
    }
  }

  // ─── Vuln-app install plan ────────────────────────────────────────────────
  // Targeting order:
  //   1. The cached vulnApp.target_hostname (if that exact host is in vms)
  //   2. Any web-server in this lane's vms (covers asset-selection changes
  //      between profile generation and deploy — the cached target_hostname
  //      may not match the currently-selected web server hostname)
  //   3. Append a DEDICATED standalone vuln-app VM. Most realistic profiles
  //      have NO on-prem web server (small/cloud-first orgs), so this is the
  //      common case, not a rare last resort. The standalone VM is cloned from
  //      the SAME Linux web template a real web server would use, so Docker is
  //      present and the install path is identical. The orchestrator registers
  //      it in the lane's /etc/hosts so students reach the site by URL.
  // Common payload shared by both the on-host and standalone install plans.
  const vulnAppPayload = vulnApp ? {
    install_script: vulnApp.install_script,
    source_tree: vulnApp.source_tree || null,
    dockerfile: vulnApp.dockerfile || null,
    // Color palette lives in the generation_meta JSONB (no dedicated DB
    // column). Read from there with a fallback to a top-level field for
    // any in-memory callers that don't go through the DB round-trip.
    color_palette: (vulnApp.generation_meta && vulnApp.generation_meta.color_palette)
      || vulnApp.color_palette || null,
    // LLM-authored stylesheet (same JSONB round-trip as color_palette).
    // The orchestrator inlines it into every page; null falls back to the
    // themed buildBaseCss().
    app_stylesheet: (vulnApp.generation_meta && vulnApp.generation_meta.app_stylesheet)
      || vulnApp.app_stylesheet || null
  } : null;

  let vulnAppInstall = null;
  if (vulnApp && vulnApp.install_script) {
    let targetVm = vulnApp.target_hostname
      && vms.find(v => v.name === vulnApp.target_hostname);
    if (!targetVm && webServerVmName) {
      targetVm = vms.find(v => v.name === webServerVmName);
    }

    if (targetVm) {
      vulnAppInstall = {
        target_vm: targetVm.name,
        mode: vulnApp.delivery_mode || 'docker',
        ...vulnAppPayload
      };
    } else {
      // No web-server asset in this profile → give the app its own dedicated
      // VM cloned from template 1005, the canonical baked "web-01" template
      // (Debian 13 + Docker + Apache + PHP + SQLite + QEMU guest agent — see
      // infrastructure/proxmox-templates/vm-templates/bake-web-template.sh). Docker is pre-baked, so the image
      // build/run install path is identical to deploying onto a real web
      // server. 1005 is baked directly on the Proxmox node, so it's always
      // available even if the template catalog row isn't present.
      const WEB_TEMPLATE_VMID = 1005;
      const webTplRow = vmTemplateCatalog.find(t => Number(t.template_vmid) === WEB_TEMPLATE_VMID);
      vms.push({
        name: 'vuln-app',
        hostname: 'vuln-app',
        template_vmid: WEB_TEMPLATE_VMID,
        template_node: (webTplRow && webTplRow.node) || templateNode,
        type: 'qemu',
        vm_offset: 600000 + vms.length * 10000,
        // role 'server' (not 'web') so the lane's /etc/hosts builder, which
        // keys the company-domain alias off role==='server' + an HTTP service,
        // registers this VM's hostname for the company domain.
        role: 'server',
        os_family: 'linux',
        os_version: null,
        services: ['80/HTTP'],
        post_clone_scripts: [],
        synthetic: true
      });
      vulnAppInstall = {
        target_vm: 'vuln-app',
        mode: vulnApp.delivery_mode || 'docker',
        ...vulnAppPayload
      };
    }
  }

  // ─── E3: the telemetry machines ────────────────────────────────
  // AFTER the vuln-app VM so the environment's own content is placed first and
  // the sensor lands after it in the band, and BEFORE addressing so the sensor
  // is addressed like any other machine rather than by a second rule.
  //
  // Not gated on engagementType. The decision "does this engagement carry
  // telemetry" is made once, on the engagement's telemetry_plan, and arrives
  // here already resolved down to template ids — so this file never has to know
  // which slug means blue team, and a locally defined slug that wants a SIEM
  // gets one by passing the option.
  if (telemetry) appendTelemetryMachines(vms, telemetry, { templateNode });

  // ─── v3 topology ──────────────────────────────────────────────────────────
  // Before addressing, because it is what DECIDES the addressing: the machine
  // that gets two NICs is the machine assignLaneAddressing must keep out of the
  // .80-.99 band (the deployer skips a multi-segment VM before it ever looks at
  // an ipOctet, so a band octet on it would be a number nothing honours).
  const dmzVmName = resolveDmzVm({ subnetScheme, vms, vulnAppInstall });
  if (dmzVmName) applyV3Topology(vms, dmzVmName);

  // ─── Lane addressing ──────────────────────────────────────────────────────
  // Last, so the synthetic vuln-app VM (appended above when the profile has no
  // web server) is addressed like any other machine. Order is the contract: the
  // octets follow spec order, so adding an asset must not silently move an
  // existing one and invalidate paper that has already been handed out.
  assignLaneAddressing(vms, { dmzVmName });

  const spec = {
    vxlan_block: vxlanBlock,
    subnet_scheme: subnetScheme,
    template_node: templateNode,
    attack_boxes: attackBoxes,
    vms,
    vuln_app_install: vulnAppInstall
  };

  // ─── The lane's own DNS ───────────────────────────────────────────────────
  // Built from the finished spec, so it can only ever name a machine that is
  // actually in it. Omitted entirely — not written as null — when there is
  // nothing to publish, because `spec.dns` is read as "did the author declare
  // one at all", and an empty object is a declaration.
  const dns = buildSpecDns({ spec, profile, engagementType });
  if (dns) spec.dns = dns;

  return {
    spec,
    service_gaps: serviceGaps,
    template_misses: templateMisses
  };
}

module.exports = {
  synthesizeSpecFromProfile,
  parseOs,
  parseService,
  isWebServer,
  // Exported for the addressing tests, and so the band stays checkable against
  // challenge-lane-deployer's own constants rather than by reading source text.
  assignLaneAddressing,
  dnsLabel,
  SPEC_OCTET_MIN,
  SPEC_OCTET_MAX,
  // E3. Exported for the same reason the band is: each is MIRRORED from an
  // authority this file cannot import without losing its load-with-nothing
  // property, so the agreement is asserted by a test that can afford to load
  // both. SIEM_OCTETS mirrors src/utils/goad-deploy.js GOAD_EXTENSIONS.
  SIEM_OCTETS,
  SIEM_MACHINES_FOR_STACK,
  SENSOR_VM_NAME,
  appendTelemetryMachines,
  assertTelemetryNamesFree,
  // Exported for the same reason resolveSpecAddressing and resolveLaneDnsExtras
  // are exported from the deployer: each encodes a rule whose failure mode is a
  // lane that deploys, reports active and is silently wrong — a dropped web
  // name, a forest leaked to the attacker's own resolver, a bridge that is not
  // there — and none of those can be reached through the deploy path in a test.
  buildSpecDns,
  dnsName,
  resolvePublicDomain,
  resolveDmzVm,
  applyV3Topology,
  DEFAULT_SUBNET_SCHEME
};
