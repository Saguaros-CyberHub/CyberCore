/**
 * ciab-spec-dns-topology.test.js — the two things the synthesizer had stopped
 * short of: the lane's own DNS, and the v3 topology that enforces the pivot.
 *
 * WHY THIS FILE EXISTS
 *
 * Two capabilities existed at the CONSUMING end and had no producer:
 *
 *   1. challenge-lane-deployer.resolveLaneDnsExtras reads an optional
 *      `spec.dns` block and writes the lane's AD conditional forwarder and its
 *      company web name into the gateway's dnsmasq. Nothing in the tree wrote
 *      that block, so the function returned [] on every lane it ever ran on.
 *
 *   2. lane-networking.resolveVmNics has always honoured an explicit
 *      `nics: [{segment}]` array, and challenge-lane-deployer pins a dual-homed
 *      machine to .240 on BOTH v3 segments. Nothing emitted `nics` either, so
 *      every profile lane came up flat (v2) and "pivot through the web host to
 *      reach AD" was a convention a student could simply decline to follow.
 *
 * profile-to-spec.js now produces both. The assertions below are about the
 * FAILURE MODES that make each one worth testing at all — every one of them
 * produces a lane that deploys, reports active, and is silently wrong:
 *
 *   * a malformed dnsmasq directive does not drop a DNS name, it stops dnsmasq
 *     STARTING, which takes DHCP down for every machine on the lane;
 *   * an AD forwarder published on a lane whose gateway serves BOTH segments
 *     hands the attacker's own resolver the forest name, the DC's hostname and
 *     its internal address — the first three things an external engagement is
 *     supposed to make the student earn;
 *   * a band octet (.80-.99) on a machine the deployer actually pins to .240 is
 *     a true statement about a spec field and a false one about the lane, and
 *     the scan report, the asset register and the brief all read the spec.
 *
 * WHY IT LOADS THE REAL DEPLOYER. Asserting that the synthesizer emits a field
 * called `web_name` proves nothing: the value has to reach a function that
 * spells it the same way. So the emitted block is fed through the REAL
 * resolveLaneDnsExtras and the assertions are on the dnsmasq LINES that come
 * out. challenge-lane-deployer pulls site-config at module load (via
 * batch-deployer), which reads a gitignored config/site.json — same require.cache
 * stub test/ciab-lane-provision.test.js uses.
 *
 * Run: node --test front-end/test/ciab-spec-dns-topology.test.js  (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const UTILS = path.join(ROOT, 'src', 'utils');

require.cache[require.resolve(path.join(UTILS, 'site-config.js'))] = {
  id: 'site-config', filename: 'site-config', loaded: true,
  exports: {
    getSchedulingConfig: () => ({
      min_free_mem_gb: 8, min_free_disk_gb: 20,
      max_concurrent_lanes: 5, max_concurrent_clones: 4,
      node_score_weights: { cpu: 0.35, mem: 0.55, disk: 0.10 },
    }),
    getDefaultTemplateNode: () => 'node-1',
  },
};

const SYNTH = require(path.join(
  ROOT, 'modules/crucible/plugins/ciab/utils/profile-to-spec.js'));
const MODEL = require(path.join(
  ROOT, 'modules/crucible/plugins/ciab/utils/engagement-model.js'));
const deployer = require(path.join(UTILS, 'challenge-lane-deployer.js'));
const laneNet = require(path.join(UTILS, 'lane-networking.js'));

// ── Fixtures ────────────────────────────────────────────────────────────────
// Deliberately the same shapes the plugin's own test/profile-to-spec.test.js
// uses, plus template 1005 — the baked Debian web template the synthesizer
// falls back to when a profile has no web server of its own.

const VM_CATALOG = [
  { id: 'tpl-win2022', template_vmid: 1000, node: 'cyberhub-node-5',
    os_family: 'windows_server', os_version: '2022', os_name: 'Windows Server 2022',
    role_hints: ['dc', 'file'], is_active: true, preferred: true },
  { id: 'tpl-ubuntu2204', template_vmid: 1001, node: 'cyberhub-node-5',
    os_family: 'linux', os_version: 'ubuntu-22.04', os_name: 'Ubuntu Server 22.04',
    role_hints: ['db'], is_active: true, preferred: true },
  { id: 'tpl-debian-web', template_vmid: 1005, node: 'cyberhub-node-5',
    os_family: 'linux', os_version: 'debian-13', os_name: 'Debian 13 web',
    role_hints: ['web'], is_active: true, preferred: true },
];

const VULN_SCRIPTS = [
  { id: 'sc-init', slug: 'init-setup', os_target: 'windows',
    services_exposed: [], category: 'initial setup', script_type: 'baseline', is_active: true },
  { id: 'sc-smb', slug: 'win-smb-vuln', os_target: 'windows',
    services_exposed: ['445/SMB'], category: 'lateral movement', script_type: 'vulnerable', is_active: true },
  { id: 'sc-http', slug: 'lin-apache-2449', os_target: 'linux',
    services_exposed: ['80/HTTP'], category: 'web', script_type: 'vulnerable', is_active: true },
];

const ASSETS = [
  { hostname: 'DC-01',  role: 'server', os: 'Windows Server 2022', services: ['445/SMB', '389/LDAP'] },
  { hostname: 'WEB-01', role: 'server', os: 'Ubuntu Server 22.04', services: ['80/HTTP'] },
  { hostname: 'FS-01',  role: 'server', os: 'Ubuntu Server 22.04', services: ['22/SSH'] },
  { hostname: 'WS-01',  role: 'workstation', os: 'Windows 11', services: [] },
];

const VULN_APP = { install_script: 'echo install', delivery_mode: 'docker', target_hostname: null };

/** A profile in the layout loadProfileForDeploy actually returns: the DB row,
 *  the normalized asset array, and the whole JSON under `json_data`. */
function profileWith(domainPublic, assets = ASSETS) {
  return {
    id: 'profile-1', company_name: 'Acme Clinic', assets,
    json_data: domainPublic === undefined ? {} : {
      student_view: { raw: { threats: { organization: { domain_public: domainPublic } } } },
    },
  };
}

/** Synthesize with the noise suppressed. The synthesizer logs a line per VM and
 *  warns loudly on every value it refuses, which is the correct behaviour in
 *  production and would bury the test output here. */
function synth({ profile, vulnApp = VULN_APP, options = {} }) {
  const log = console.log;
  const warn = console.warn;
  console.log = () => {};
  console.warn = () => {};
  try {
    return SYNTH.synthesizeSpecFromProfile({
      profile,
      assetSelection: null,
      vmTemplateCatalog: VM_CATALOG,
      vulnScriptCatalog: VULN_SCRIPTS,
      vulnApp,
      options: { vxlanBlock: { start: 10000, end: 10009 }, templateNode: 'cyberhub-node-5', ...options },
    });
  } finally {
    console.log = log;
    console.warn = warn;
  }
}

/** The dnsmasq lines the REAL deployer would write for a spec, given which
 *  machines this lane can name an address for. Quiet for the same reason. */
function dnsLinesFor(spec, { pinnedHosts = [], goadMacs = {}, consoleOctets = {} } = {}) {
  const warn = console.warn;
  console.warn = () => {};
  try {
    return deployer.resolveLaneDnsExtras({
      spec, goadMacs, consoleOctets, pinnedHosts, extSubnetBase: '10.39.0',
    });
  } finally {
    console.warn = warn;
  }
}

const EXT_BASE = '10.39.0';
const INT_BASE = '10.39.1';

// ════════════════════════════════════════════════════════════════════════════
// §1 — spec.dns: the company's public web name
// ════════════════════════════════════════════════════════════════════════════

test('a valid domain_public becomes spec.dns, naming the machine that serves the site', () => {
  const { spec } = synth({ profile: profileWith('acme-clinic.com'), options: { subnetScheme: 'v2' } });

  assert.deepStrictEqual(spec.dns, { web_name: 'acme-clinic.com', web_vm: 'WEB-01' },
    'The shape is challenge-lane-deployer.resolveLaneDnsExtras\'s, verbatim. A field spelled any other '
    + 'way is read as absent and the record is silently never written.');

  // The machine is named, never an address: the lane subnet is allocated per
  // lane (10.<vxh>.<vxl>), so an IP literal in a spec is right for at most one
  // student and silently wrong for every other one.
  assert.ok(spec.vms.some(vm => vm.name === spec.dns.web_vm),
    'web_vm must name a machine that is actually in this spec');
  assert.strictEqual(spec.dns.web_vm, spec.vuln_app_install.target_vm,
    'The site the name points at and the machine the app installs on are one machine by construction');
});

test('the emitted block survives the deployer and becomes a real host-record', () => {
  // The whole point of §1. Asserting on spec.dns alone would pass just as
  // happily if resolveLaneDnsExtras spelled the field `webName`.
  const { spec } = synth({ profile: profileWith('acme-clinic.com'), options: { subnetScheme: 'v2' } });
  const web = spec.vms.find(vm => vm.name === spec.dns.web_vm);

  const lines = dnsLinesFor(spec, {
    pinnedHosts: [{ name: web.name, octet: web.ipOctet, subnetBase: EXT_BASE }],
  });
  assert.deepStrictEqual(lines, [`host-record=acme-clinic.com,${EXT_BASE}.${web.ipOctet}`],
    'A dotted public name takes the two-field host-record form. It must NOT go through hostRecordLine, '
    + 'which appends the lane search domain and would publish acme-clinic.com.cybercore.lan while '
    + 'leaving the name the student was actually given unresolvable.');
});

test('an absent domain_public omits spec.dns entirely rather than writing an empty block', () => {
  for (const profile of [
    profileWith(undefined),          // no organization block at all
    profileWith(null),
    profileWith(''),
    { id: 'p', company_name: 'X', assets: ASSETS },   // flat profile, no json_data
  ]) {
    const { spec } = synth({ profile, options: { subnetScheme: 'v2' } });
    assert.ok(!('dns' in spec),
      'The key must be ABSENT, not null and not {}. resolveLaneDnsExtras reads spec.dns as "did the '
      + 'author declare one at all", so an empty object is a declaration and would start producing '
      + 'warnings on lanes that never asked for a name.');
    assert.deepStrictEqual(dnsLinesFor(spec), [],
      'and the reservations file is then byte-identical to what it was before spec.dns existed');
  }
});

test('a malformed domain_public is skipped, not written through', () => {
  // domain_public is LLM-authored. Every one of these has appeared in a
  // generated profile in some form, and each would land in the SAME dnsmasq
  // file as the lane's DHCP reservations — where one bad directive stops the
  // service and takes DHCP down for the WHOLE lane.
  const GARBAGE = [
    'N/A',                        // survives the URL-path strip as the label `n`
    'TBD',                        // a perfectly valid DNS label, and not a domain
    'unknown',
    'localhost',
    'not applicable',
    'acme clinic dot com',
    'acme_clinic.com',            // underscore is not a hostname character
    '-acme.com',                  // label may not start with a hyphen
    'acme..com',                  // empty label
    'acme.com;server=/evil/1.2.3.4',   // directive injection
    'acme.com\nserver=/evil/1.2.3.4',
    `${'a'.repeat(64)}.com`,      // label over 63 octets
    `${'a.'.repeat(130)}com`,     // name over 253 octets
    { not: 'a string' },
    42,
  ];
  for (const bad of GARBAGE) {
    const { spec } = synth({ profile: profileWith(bad), options: { subnetScheme: 'v2' } });
    assert.ok(!('dns' in spec), `domain_public ${JSON.stringify(bad)} must not reach the spec`);
  }
});

test('everything the synthesizer DOES publish is a name the deployer accepts', () => {
  // The containment that matters runs one way: this file's validator is a
  // MIRROR of challenge-lane-deployer's DNS_NAME_RE, and a mirror can drift.
  // Stricter here is safe — nothing malformed can reach dnsmasq. LAXER here is
  // the failure: the synthesizer would emit a name the deployer silently drops,
  // and the generated paper would promise a site that never resolves.
  for (const authored of [
    'acme-clinic.com', 'https://acme-clinic.com/', 'www.acme-clinic.com.',
    'shop.eu.acme-clinic.co.uk', 'a1.io',
  ]) {
    const { spec } = synth({ profile: profileWith(authored), options: { subnetScheme: 'v2' } });
    assert.ok(spec.dns, `${authored} should have been published`);
    const lines = dnsLinesFor(spec, {
      pinnedHosts: [{ name: spec.dns.web_vm, octet: 81, subnetBase: EXT_BASE }],
    });
    assert.deepStrictEqual(lines, [`host-record=${spec.dns.web_name},${EXT_BASE}.81`],
      `the deployer must accept ${spec.dns.web_name}`);
  }
});

test('the two shapes an author writes on purpose are normalised, not refused', () => {
  // A URL and a root-form FQDN are how a human (and an LLM imitating one) types
  // this field. The scheme/path strip is the same normalization
  // utils/profile-to-intake.js:319 already applies to this exact value.
  const cases = [
    ['https://acme-clinic.com/', 'acme-clinic.com'],
    ['http://www.acme-clinic.com', 'www.acme-clinic.com'],
    ['acme-clinic.com.', 'acme-clinic.com'],
    ['  ACME-Clinic.COM  ', 'acme-clinic.com'],
  ];
  for (const [authored, expected] of cases) {
    const { spec } = synth({ profile: profileWith(authored), options: { subnetScheme: 'v2' } });
    assert.strictEqual(spec.dns.web_name, expected, `${authored} → ${expected}`);
  }
  // dnsName itself answers only "is this a DNS name", which is why it is not the
  // whole rule: 'N/A' normalises to the label `n`, and rejecting that takes the
  // second question — "is this plausibly a PUBLIC domain" — which buildSpecDns
  // asks and the loop above proves.
  assert.strictEqual(SYNTH.dnsName('https://acme-clinic.com/'), 'acme-clinic.com');
  assert.strictEqual(SYNTH.dnsName('N/A'), 'n');
  assert.strictEqual(SYNTH.dnsName('acme clinic'), null);
});

test('a profile with a domain but nothing to serve it publishes no name', () => {
  // No vuln-app means no generated site, so there is no machine to point the
  // name at. Naming one anyway would promise a site the lane does not host.
  const { spec } = synth({
    profile: profileWith('acme-clinic.com'), vulnApp: null, options: { subnetScheme: 'v2' },
  });
  assert.ok(!('dns' in spec));
});

// ════════════════════════════════════════════════════════════════════════════
// §2 — the AD forwarder is SCOPED TO THE ENGAGEMENT
//
// The gateway's dnsmasq serves BOTH v3 segments. `server=/<forest>/<dc-ip>` is
// therefore answered for Kali on ext0 too, even though ext0<->int0 is DROPped in
// FORWARD — so an external tester can RESOLVE the whole forest, including every
// _msdcs/_tcp SRV record, while being unable to send it a packet. That is a
// topology leak, and it deletes the middle of the exercise.
// ════════════════════════════════════════════════════════════════════════════

/** A spec carrying what a future AD compiler will put on it. buildSpecDns reads
 *  spec.goad, so this is exactly the input that wave produces. */
function specWithForest(extra = {}) {
  return {
    subnet_scheme: 'v3',
    goad: { enabled: true, domain: 'corp.acme-clinic.local' },
    vms: [{ name: 'WEB-01' }, { name: 'DC01' }],
    vuln_app_install: { target_vm: 'WEB-01' },
    ...extra,
  };
}

const GOAD_MACS = { DC01: { mac: 'aa:bb:cc:00:00:0a', static_ip: `${INT_BASE}.10`, role: 'dc' } };

test('an external engagement gets NO AD forwarder — enumerating the forest is the exercise', () => {
  const dns = SYNTH.buildSpecDns({
    spec: specWithForest(),
    profile: profileWith('acme-clinic.com'),
    engagementType: 'external_blackbox',
  });
  assert.ok(!('ad_domain' in dns) && !('ad_dc' in dns),
    'Publishing it would hand the attacker box the forest name and the DC\'s internal address before '
    + 'the student has touched a single target. The pivot is what is supposed to reveal them.');

  const lines = dnsLinesFor(specWithForest({ dns }), { goadMacs: GOAD_MACS, pinnedHosts: [] });
  assert.ok(!lines.some(l => l.startsWith('server=/')),
    'and nothing anywhere else re-derives one');
});

test('an internal engagement DOES get it — every AD tool fails at name resolution without it', () => {
  const dns = SYNTH.buildSpecDns({
    spec: specWithForest(),
    profile: profileWith('acme-clinic.com'),
    engagementType: 'internal_credentialed',
  });
  assert.strictEqual(dns.ad_domain, 'corp.acme-clinic.local');

  const lines = dnsLinesFor(specWithForest({ dns }), { goadMacs: GOAD_MACS });
  assert.ok(lines.includes(`server=/corp.acme-clinic.local/${INT_BASE}.10`),
    'One line covers the domain AND every subdomain, so the _msdcs/_tcp SRV records Kerberos and the '
    + 'DC-locator actually look up are covered too. `nxc smb dc01.corp.acme-clinic.local` and '
    + '`bloodhound-python -d corp.acme-clinic.local` fail before touching the target without it.');
  assert.ok(!('ad_dc' in dns),
    'ad_dc is omitted when the lab does not name one, so the deployer takes the first goadMacs host '
    + 'with role dc — right for every stock lab, and it stays right when the lab version changes');
});

test('the split is keyed on the registry\'s perspective, not on the literal slug', () => {
  const args = { spec: specWithForest(), profile: profileWith('acme-clinic.com') };

  // Unknown and absent types take describeEngagementType's conservative
  // (internal) posture — the same value the ciab_engagement columns DEFAULT to,
  // so a locally defined type behaves like the internal case rather than
  // silently losing its forwarder.
  for (const type of [null, undefined, '', 'default', 'a-locally-defined-type']) {
    const dns = SYNTH.buildSpecDns({ ...args, engagementType: type });
    assert.strictEqual(dns.ad_domain, 'corp.acme-clinic.local', `${type} is an internal posture`);
  }
  assert.strictEqual(MODEL.describeEngagementType('external_blackbox').perspective, 'external',
    'and this is the registry fact the whole split rests on');

  // The type may also arrive ON the spec, which is where a later wave will put
  // it once the compile writes back.
  const carried = SYNTH.buildSpecDns({
    spec: specWithForest({ engagement_type: 'external_blackbox' }),
    profile: profileWith('acme-clinic.com'),
  });
  assert.ok(!('ad_domain' in carried));
});

test('the company web name is published to BOTH postures', () => {
  // An external engagement is DEFINED as starting with nothing but the
  // forward-facing site. Withholding its name would leave the tester with no
  // starting point at all.
  for (const type of ['external_blackbox', 'internal_credentialed']) {
    const dns = SYNTH.buildSpecDns({
      spec: specWithForest(), profile: profileWith('acme-clinic.com'), engagementType: type,
    });
    assert.strictEqual(dns.web_name, 'acme-clinic.com', type);
    assert.strictEqual(dns.web_vm, 'WEB-01', type);
  }
});

test('no forest in the spec means no ad_* keys, whatever the engagement is', () => {
  // Nothing writes spec.goad today, so this is the state of every spec the
  // synthesizer currently produces — and the reason the AD half of spec.dns is
  // inert rather than half-written.
  const { spec } = synth({ profile: profileWith('acme-clinic.com'), options: { engagementType: 'internal_credentialed' } });
  assert.deepStrictEqual(Object.keys(spec.dns).sort(), ['web_name', 'web_vm']);
});

// ════════════════════════════════════════════════════════════════════════════
// §3 — v3 by default, with the web host as the dual-homed DMZ
// ════════════════════════════════════════════════════════════════════════════

test('a profile lane defaults to v3', () => {
  const { spec } = synth({ profile: profileWith('acme-clinic.com') });
  assert.strictEqual(spec.subnet_scheme, 'v3');
  assert.strictEqual(SYNTH.DEFAULT_SUBNET_SCHEME, 'v3');
  // v2 stays selectable per engagement — both live callers pass the engagement
  // row's scheme through, so an engagement carved at v2 still builds at v2.
  assert.strictEqual(synth({ profile: profileWith('acme-clinic.com'), options: { subnetScheme: 'v2' } })
    .spec.subnet_scheme, 'v2');
});

test('the web host is dual-homed and everything else is internal', () => {
  const { spec } = synth({ profile: profileWith('acme-clinic.com') });
  const byName = Object.fromEntries(spec.vms.map(vm => [vm.name, vm]));

  assert.deepStrictEqual(byName['WEB-01'].nics, [{ segment: 'ext' }, { segment: 'int' }],
    'This is the shape resolveVmNics consumes and the topology canvas emits. Kali is on ext, so it '
    + 'reaches the site as an L2 neighbour with no DNAT and no gateway change at all.');
  assert.deepStrictEqual(byName['DC-01'].nics, [{ segment: 'int' }]);
  assert.deepStrictEqual(byName['FS-01'].nics, [{ segment: 'int' }],
    'The v3 default for an ordinary VM is a single EXTERNAL nic, which would put the DC and the file '
    + 'server on the attacker\'s own segment and make the bridge decorative.');

  // The deployer must agree, through its own resolver rather than by inspection.
  assert.deepStrictEqual(
    laneNet.resolveVmSegments(byName['WEB-01'], { subnetScheme: 'v3' }), ['ext', 'int']);
  assert.strictEqual(
    laneNet.resolveVmNics(byName['WEB-01'], { subnetScheme: 'v3', bridges: { ext: 'vnetE', int: 'vnetI' } })
      .dualHomed, true);
});

test('the dual-homed host leaves the .80-.99 band and lands on .240 instead', () => {
  const { spec } = synth({ profile: profileWith('acme-clinic.com') });
  const web = spec.vms.find(vm => vm.name === 'WEB-01');

  assert.strictEqual(web.ipOctet, MODEL.DUAL_HOMED_OCTET,
    '.240 is where challenge-lane-deployer actually pins a dual-homed host — above the gateway DHCP '
    + 'pool (.10-.200), so no lease can claim it. The paper reads the spec, so the spec has to say '
    + 'where the machine really lands.');
  assert.ok(web.ipOctet < SYNTH.SPEC_OCTET_MIN || web.ipOctet > SYNTH.SPEC_OCTET_MAX,
    'and it must not be holding a band octet as well');

  // The rest still take the band, in spec order, with no gap left where the
  // web host used to be — an octet that moves invalidates paper already handed
  // to a student.
  assert.deepStrictEqual(
    spec.vms.filter(vm => vm.name !== 'WEB-01').map(vm => [vm.name, vm.ipOctet]),
    [['DC-01', SYNTH.SPEC_OCTET_MIN], ['FS-01', SYNTH.SPEC_OCTET_MIN + 1]]);

  // THE DEPLOYER'S OWN RULE, not a restatement of it. resolveSpecAddressing
  // skips a multi-segment VM before it ever looks at an ipOctet, so the two
  // must agree about which machines take band addresses or the spec names an
  // address nothing lives at.
  const { pinnedHosts } = deployer.resolveSpecAddressing({
    specVms: spec.vms, subnetScheme: 'v3',
    laneSubnetBase: EXT_BASE, goadSubnetBase: INT_BASE, pinAllVms: true,
  });
  const dmzPin = pinnedHosts.find(h => h.name === 'WEB-01');
  assert.ok(!dmzPin || dmzPin.octet === MODEL.DUAL_HOMED_OCTET,
    'The deployer must never hand the DMZ host a band octet. It skips it entirely today; a later wave '
    + `that starts naming it must name it at .${MODEL.DUAL_HOMED_OCTET}.`);
  assert.deepStrictEqual(pinnedHosts.filter(h => h.name !== 'WEB-01'),
    [{ name: 'DC-01', octet: 80, subnetBase: INT_BASE },
      { name: 'FS-01', octet: 81, subnetBase: INT_BASE }],
    'and an internal machine draws the INTERNAL subnet base, which is chosen by WHICH segment it is '
    + 'on rather than by how many it has');
});

test('the DMZ host\'s web record is correct once the lane can name its address', () => {
  // KNOWN GAP IN THE DEPLOYER, RECORDED HERE BECAUSE THIS IS WHERE IT SHOWS.
  // resolveLaneDnsExtras builds its address table from three sources —
  // goadMacs, pinnedHosts and consoleOctets — and a dual-homed host is in NONE
  // of them: resolveSpecAddressing skips a multi-segment VM before it can reach
  // pinnedHosts, the bridge is deliberately not a GOAD lab host, and it cannot
  // be a console (the deployer throws on that combination outright). So on a v3
  // lane the company web name is currently dropped with
  // "web_vm '<name>' has no address on this lane", even though the spec names
  // the right machine and the machine really is at .240.
  //
  // The fix is one entry in that table — a dual-homed spec VM contributes
  // `<extSubnetBase>.${DUAL_HOMED_OCTET}` — and it belongs in
  // challenge-lane-deployer.js, not here. This test asserts what the
  // SYNTHESIZER is responsible for: that the block it emits produces the right
  // line the moment the address is knowable. It stays green either way.
  const { spec } = synth({ profile: profileWith('acme-clinic.com') });
  const web = spec.vms.find(vm => vm.name === spec.dns.web_vm);
  assert.strictEqual(web.ipOctet, MODEL.DUAL_HOMED_OCTET);

  const lines = dnsLinesFor(spec, {
    pinnedHosts: [{ name: web.name, octet: web.ipOctet, subnetBase: EXT_BASE }],
  });
  assert.deepStrictEqual(lines, [`host-record=acme-clinic.com,${EXT_BASE}.${MODEL.DUAL_HOMED_OCTET}`],
    'The name must resolve to the EXTERNAL .240, because that is the segment Kali is on and the '
    + 'side of the bridge an external tester can reach.');
});

test('exactly one machine is dual-homed, however many public-facing assets a profile has', () => {
  // .240 is a single address on each segment: a second dual-homed machine would
  // be handed the address the first one already has, and the lane would come up
  // with an IP conflict on its most important host.
  const manyWeb = [
    { hostname: 'WEB-01',    role: 'server', os: 'Ubuntu Server 22.04', services: ['80/HTTP'] },
    { hostname: 'WEB-02',    role: 'server', os: 'Ubuntu Server 22.04', services: ['443/HTTPS'] },
    { hostname: 'intranet',  role: 'server', os: 'Ubuntu Server 22.04', services: ['80/HTTP'] },
    { hostname: 'DC-01',     role: 'server', os: 'Windows Server 2022', services: ['445/SMB'] },
  ];
  const { spec } = synth({ profile: profileWith('acme-clinic.com', manyWeb) });

  const dual = spec.vms.filter(vm => Array.isArray(vm.nics) && vm.nics.length > 1);
  assert.deepStrictEqual(dual.map(vm => vm.name), ['WEB-01'],
    'The bridge is the machine serving the generated site — the same rung order engagement-plan\'s '
    + 'derivePublicSurface walks, so the compile and the lane agree without consulting each other.');
  for (const vm of spec.vms.filter(v => v.name !== 'WEB-01')) {
    assert.deepStrictEqual(vm.nics, [{ segment: 'int' }],
      `${vm.name} is a surplus public-facing asset and becomes an ordinary internal host`);
    assert.ok(vm.ipOctet >= SYNTH.SPEC_OCTET_MIN && vm.ipOctet <= SYNTH.SPEC_OCTET_MAX,
      `${vm.name} keeps a band address`);
  }
  assert.strictEqual(spec.dns.web_vm, 'WEB-01', 'and the published name points at the bridge');
});

test('the choice is deterministic — synthesizing twice picks the same bridge', () => {
  const p = () => profileWith('acme-clinic.com', [
    { hostname: 'shop', role: 'server', os: 'Ubuntu Server 22.04', services: ['80/HTTP'] },
    { hostname: 'portal', role: 'server', os: 'Ubuntu Server 22.04', services: ['80/HTTP'] },
  ]);
  const a = synth({ profile: p() }).spec;
  const b = synth({ profile: p() }).spec;
  assert.deepStrictEqual(a.vms.map(vm => [vm.name, vm.nics, vm.ipOctet]),
    b.vms.map(vm => [vm.name, vm.nics, vm.ipOctet]));
});

test('a profile with no web server of its own bridges through the synthetic vuln-app VM', () => {
  const { spec } = synth({
    profile: profileWith('acme-clinic.com', ASSETS.filter(a => a.hostname !== 'WEB-01')),
  });
  const app = spec.vms.find(vm => vm.synthetic);
  assert.deepStrictEqual(app.nics, [{ segment: 'ext' }, { segment: 'int' }]);
  assert.strictEqual(app.ipOctet, MODEL.DUAL_HOMED_OCTET);
  assert.deepStrictEqual(app.dns_aliases, ['vuln-app'],
    'It still gets a short name: it is excluded from the BAND, not from the lane');
  assert.strictEqual(spec.dns.web_vm, 'vuln-app');
});

test('no generated site means no bridge, rather than a bridge invented from some other server', () => {
  // A lane with nothing public-facing is a real state, and the compile already
  // reports it honestly (EXTERNAL_NO_SURFACE / EXTERNAL_NO_PIVOT). Promoting an
  // arbitrary machine would produce a lane that disagrees with its own paper.
  const { spec } = synth({ profile: profileWith('acme-clinic.com'), vulnApp: null });
  assert.strictEqual(spec.subnet_scheme, 'v3');
  assert.ok(spec.vms.every(vm => !vm.nics),
    'and with no bridge nothing is forced internal either — every machine keeps the v3 default');
  assert.deepStrictEqual(spec.vms.map(vm => vm.ipOctet),
    [SYNTH.SPEC_OCTET_MIN, SYNTH.SPEC_OCTET_MIN + 1, SYNTH.SPEC_OCTET_MIN + 2]);
});

test('the web host is never part of the GOAD lab definition', () => {
  // deployPrebakedGoadLane filters role !== 'linux', so a Linux member inside
  // spec.goad.lab.vms gets no secure-channel heal and no restart — it is simply
  // skipped, silently, on the one machine the whole engagement points at.
  const { spec } = synth({ profile: profileWith('acme-clinic.com') });
  const labVms = ((spec.goad || {}).lab || {}).vms || [];
  assert.ok(!labVms.some(vm => vm && vm.name === spec.dns.web_vm),
    'The bridge stays an ordinary spec.vms machine. This synthesizer emits no spec.goad at all today; '
    + 'the assertion is here so the wave that adds one cannot put the web host inside it.');
  assert.ok(spec.vms.some(vm => vm.name === spec.dns.web_vm),
    'and it is in spec.vms, where the deploy actually builds it');
});

test('the dual-homed host is never the student console', () => {
  // challenge-lane-deployer throws on that combination outright: a dual-homed
  // machine is pinned to .240 by the v3 layout, which the console's MAC-keyed
  // reservation cannot override, so the console would open on a dead address.
  const { spec } = synth({ profile: profileWith('acme-clinic.com') });
  assert.ok(spec.vms.every(vm => !vm.console_role),
    'The synthesizer designates no spec console, so Kali stays the console it has always been');

  const plan = deployer.resolveConsolePlan({ specVms: spec.vms, attackBoxes: true });
  assert.strictEqual(plan.primary.kind, 'kali');
  assert.ok(!plan.consoles.some(c => c.kind === 'spec'),
    'and no spec machine — dual-homed or not — is handed a console connection');
});

test('a container is never made the bridge', () => {
  // resolveVmNics gives an LXC ONE card no matter how many segments it asks for
  // (the template owns net0), so a "dual-homed" container is a claim the deploy
  // cannot honour — and it would then carry .240 while sitting on a DHCP lease.
  const vms = [
    { name: 'ct-web', hostname: 'ct-web', type: 'lxc' },
    { name: 'srv', hostname: 'srv', type: 'qemu' },
  ];
  const warn = console.warn;
  console.warn = () => {};
  try {
    assert.strictEqual(
      SYNTH.resolveDmzVm({ subnetScheme: 'v3', vms, vulnAppInstall: { target_vm: 'ct-web' } }), null);
  } finally { console.warn = warn; }
  assert.strictEqual(
    SYNTH.resolveDmzVm({ subnetScheme: 'v3', vms, vulnAppInstall: { target_vm: 'srv' } }), 'srv');
  assert.strictEqual(
    SYNTH.resolveDmzVm({ subnetScheme: 'v2', vms, vulnAppInstall: { target_vm: 'srv' } }), null,
    'and v2 has one segment, so it has no bridge to be');
  assert.strictEqual(
    SYNTH.resolveDmzVm({ subnetScheme: 'v3', vms, vulnAppInstall: null }), null);
});

test('an authored nics array wins over the derived placement', () => {
  // Explicit nics is the topology canvas's (or an instructor's) answer, and
  // lane-networking honours it before role and before GOAD. Overwriting it here
  // would silently move a machine an author deliberately placed.
  const vms = [
    { name: 'web', nics: [{ segment: 'int' }] },
    { name: 'srv' },
  ];
  SYNTH.applyV3Topology(vms, 'web');
  assert.deepStrictEqual(vms[0].nics, [{ segment: 'int' }]);
  assert.deepStrictEqual(vms[1].nics, [{ segment: 'int' }]);
});

// ════════════════════════════════════════════════════════════════════════════
// §4 — v2 IS UNCHANGED
//
// The literals below were captured from the synthesizer BEFORE any of this
// change set existed, by running these exact fixtures through it. They are not
// a description of what the code does now; they are a record of what it did
// then, which is the only thing that makes the comparison worth anything.
// ════════════════════════════════════════════════════════════════════════════

const V2_SNAPSHOT = {
  vxlan_block: { start: 10000, end: 10009 },
  subnet_scheme: 'v2',
  template_node: 'cyberhub-node-5',
  attack_boxes: true,
  vms: [
    {
      name: 'DC-01', hostname: 'DC-01', template_vmid: 1000, template_node: 'cyberhub-node-5',
      type: 'qemu', vm_offset: 600000, role: 'server', os_family: 'windows_server',
      os_version: '2022', services: ['445/SMB', '389/LDAP'],
      post_clone_scripts: ['init-setup', 'win-smb-vuln'], template_match_type: 'exact',
      ipOctet: 80, dns_aliases: ['dc-01'],
    },
    {
      name: 'WEB-01', hostname: 'WEB-01', template_vmid: 1005, template_node: 'cyberhub-node-5',
      type: 'qemu', vm_offset: 610000, role: 'server', os_family: 'linux',
      os_version: null, services: ['80/HTTP'],
      post_clone_scripts: ['lin-apache-2449'], template_match_type: 'family_only',
      ipOctet: 81, dns_aliases: ['web-01'],
    },
    {
      name: 'FS-01', hostname: 'FS-01', template_vmid: 1001, template_node: 'cyberhub-node-5',
      type: 'qemu', vm_offset: 620000, role: 'server', os_family: 'linux',
      os_version: 'ubuntu-22.04', services: ['22/SSH'],
      post_clone_scripts: [], template_match_type: 'exact',
      ipOctet: 82, dns_aliases: ['fs-01'],
    },
  ],
  vuln_app_install: null,
};

test('a v2 profile lane with nothing to publish synthesizes byte-identically to before', () => {
  const result = synth({ profile: profileWith(undefined), vulnApp: null, options: { subnetScheme: 'v2' } });
  assert.deepStrictEqual(result.spec, V2_SNAPSHOT,
    'Every stored engagement carved at v2 re-synthesizes on every deploy. A machine whose octet or '
    + 'template moved would collide with lanes already running out of the same reservation.');
  assert.deepStrictEqual(result.service_gaps, [
    { vm: 'DC-01', service: 'ldap', port: 389, reason: 'no_installer' },
    { vm: 'FS-01', service: 'ssh', port: 22, reason: 'no_installer' },
  ]);
  assert.deepStrictEqual(result.template_misses, []);
});

test('on v2 the only thing that can differ is the additive dns block', () => {
  const { spec } = synth({ profile: profileWith('acme-clinic.com'), options: { subnetScheme: 'v2' } });
  const { dns, ...rest } = spec;
  assert.deepStrictEqual(rest, {
    ...V2_SNAPSHOT,
    vuln_app_install: {
      target_vm: 'WEB-01', mode: 'docker', install_script: 'echo install',
      source_tree: null, dockerfile: null, color_palette: null, app_stylesheet: null,
    },
  }, 'spec.dns is purely additive: no VM gains a nic, moves an octet or changes a template');
  assert.deepStrictEqual(dns, { web_name: 'acme-clinic.com', web_vm: 'WEB-01' });
});

test('a v2 lane places no machine on a segment at all', () => {
  // v2 has ONE VNet, and a multi-NIC VM on it gets both cards and NO static
  // pinning (challenge-lane-deployer only runs the .240 pass under v3) — so a
  // nics array there would produce a machine whose spec claims an address it
  // never receives.
  for (const scheme of ['v1', 'v2']) {
    const { spec } = synth({ profile: profileWith('acme-clinic.com'), options: { subnetScheme: scheme } });
    assert.ok(spec.vms.every(vm => !('nics' in vm)), `${scheme} must emit no nics`);
    assert.ok(spec.vms.every(vm => vm.ipOctet >= SYNTH.SPEC_OCTET_MIN && vm.ipOctet <= SYNTH.SPEC_OCTET_MAX),
      `${scheme} keeps every machine in the band`);
  }
});

test('assignLaneAddressing is unchanged for every caller that names no DMZ host', () => {
  // Its one-argument form is what the plugin's own test and every pre-existing
  // path use. The dmzVmName option must be inert when absent, down to which
  // machine wins a contested alias.
  const vms = [
    { name: 'a', hostname: 'web_01', type: 'qemu' },
    { name: 'b', hostname: 'web-01', type: 'qemu' },
    { name: 'ct', hostname: 'ct', type: 'lxc' },
    { name: 'd', hostname: 'd', type: 'qemu', nics: [{ segment: 'ext' }, { segment: 'int' }] },
  ];
  const warn = console.warn;
  console.warn = () => {};
  try { SYNTH.assignLaneAddressing(vms); } finally { console.warn = warn; }

  assert.deepStrictEqual(vms.map(vm => vm.ipOctet),
    [SYNTH.SPEC_OCTET_MIN, SYNTH.SPEC_OCTET_MIN + 1, undefined, undefined],
    'LXC and multi-NIC machines are still skipped; nothing gets .240 unless it is NAMED as the bridge');
  assert.deepStrictEqual(vms[0].dns_aliases, ['web-01']);
  assert.ok(!vms[1].dns_aliases, 'first claimant still wins the alias');
});
