/**
 * ciab-dualhomed-dns.test.js — the company website's name on a v3 lane.
 *
 * WHY THIS FILE EXISTS
 *
 * A v3 lane's DMZ host is DUAL-HOMED: one NIC on the external segment Kali sits
 * on, one on the internal segment the company's servers sit on. It is the
 * machine the generated website runs on, and `spec.dns.web_vm` names it — which
 * is the whole point of spec.dns.
 *
 * It resolved to nothing. resolveLaneDnsExtras built its address table from
 * three sources, and a dual-homed host is in NONE of them BY DESIGN:
 *
 *   pinnedHosts     resolveSpecAddressing does `if (segs.length > 1) continue;`
 *                   before it can pin one — resolveVmNics builds a dual-homed
 *                   machine's NICs inline and ignores the pinned MAC, so a
 *                   reservation would be one nothing ever requests.
 *   goadMacs        the DMZ host is deliberately not a GOAD lab host.
 *   consoleOctets   it cannot be a console: cloneChallengeVm throws on that
 *                   combination outright.
 *
 * So a CORRECT v3 spec produced an empty record list and a warning that web_vm
 * could not be resolved — on exactly the topology profile-to-spec defaults to.
 * The student was handed a site name that answers NXDOMAIN.
 *
 * The address was never unknowable: the clone path writes that host a STATIC
 * .DUAL_HOMED_OCTET on BOTH segments (ipconfig0/ipconfig1), which is why it
 * needs no reservation. This file pins that the DNS table reads that same pin
 * back out, from the same exported constant the clone path writes — a second
 * literal 240 in that file is how the two would drift.
 *
 * THREE THINGS IT GUARDS, each of which fails SILENTLY in production:
 *
 *   1. The record points at the EXTERNAL .240. The host answers on both, and
 *      ext is the segment Kali is on; an int-side answer would route the
 *      student THROUGH the machine they are attacking.
 *   2. v1/v2 is a clean no-op. A multi-NIC spec on those schemes gets both NICs
 *      and NO static pinning, so there is no .240 — a record there would name an
 *      address nothing holds, which is worse than no record.
 *   3. Nothing malformed reaches the file. These lines land in the SAME file as
 *      the lane's DHCP reservations, and dnsmasq refuses to start on ONE bad
 *      directive — which takes DHCP down for the WHOLE lane while it still
 *      reports active.
 *
 * And the regression bound: the reservations file for an existing v2 challenge
 * and an existing GOAD challenge is asserted LINE FOR LINE against output
 * captured from the composer before the change.
 *
 * Run: node --test front-end/test/ciab-dualhomed-dns.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const UTILS = path.join(ROOT, 'src', 'utils');

// challenge-lane-deployer pulls site-config at module load (via batch-deployer),
// which reads a gitignored config/site.json. Same stub ciab-lane-dns.test.js uses.
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

// lane-deployer.hostRecordLine bakes LANE_DNS_DOMAIN at module load. Pinned
// before the require so the expected strings hold on a machine that overrides it.
process.env.LANE_DNS_DOMAIN = 'cybercore.lan';

const laneDeployer = require(path.join(UTILS, 'lane-deployer.js'));
const deployer = require(path.join(UTILS, 'challenge-lane-deployer.js'));
const { resolveLaneDnsExtras, writeLaneReservations, DUAL_HOMED_OCTET } = deployer;

const SRC = fs.readFileSync(path.join(UTILS, 'challenge-lane-deployer.js'), 'utf8');

const EXT = '10.39.17';
const INT = '10.39.18';

// ── the lane ────────────────────────────────────────────────────────────────
// A CiAB profile lane in its default shape: no GOAD lab, one internal server
// pinned out of the band, and the website on the dual-homed DMZ host. WEB-01
// carries no `nics` — role 'dmz' on v3 is what makes it dual-homed, which is
// the shape profile-to-spec emits and the shape resolveVmSegments derives.
const V3_LANE = {
  goadMacs: {},
  consoleOctets: {},
  pinnedHosts: [{ name: 'DC-01', octet: 80, subnetBase: INT }],
  extSubnetBase: EXT,
  subnetScheme: 'v3',
};

const WEB_SPEC = {
  dns: { web_name: 'www.acme-clinic.com', web_vm: 'WEB-01' },
  vms: [
    { name: 'DC-01', type: 'qemu', nics: [{ segment: 'int' }] },
    { name: 'WEB-01', type: 'qemu', role: 'dmz' },
  ],
};

/** resolveLaneDnsExtras with console.warn captured, so a skip is assertable. */
function linesAndWarnings(lane, spec) {
  const warned = [];
  const realWarn = console.warn;
  console.warn = (...a) => warned.push(a.join(' '));
  try {
    return { lines: resolveLaneDnsExtras({ ...lane, spec }), warned };
  } finally {
    console.warn = realWarn;
  }
}

/**
 * The WHOLE reservations file the deployer would install, as an array of lines.
 *
 * installLaneReservations is the only thing between writeLaneReservations and an
 * SSH session, so swapping it out renders the real file through the real
 * composer — header, dhcp-host lines, host-records and company lines in the real
 * order. Patched on the module's own exports object, because that is the object
 * the deployer dereferences at call time.
 */
async function reservationFile(args) {
  let captured = null;
  const realInstall = laneDeployer.installLaneReservations;
  const log = console.log;
  const warn = console.warn;
  laneDeployer.installLaneReservations = async ({ lines }) => { captured = lines.slice(); };
  console.log = () => {};
  console.warn = () => {};
  try {
    await writeLaneReservations(args);
  } finally {
    laneDeployer.installLaneReservations = realInstall;
    console.log = log;
    console.warn = warn;
  }
  // null means the composer returned early on a header-only file, which is a
  // different outcome from "wrote an empty file" and must not read as one.
  return captured;
}

const HEADER = [
  '# Lane DHCP reservations — generated by challenge-lane-deployer.js',
  '# Keyed on MAC, not client hostname: the clone names do not match the',
  '# hostname-keyed entries baked into the gateway template.',
];

// ════════════════════════════════════════════════════════════════════════════
// 1. the defect: the website now has a name
// ════════════════════════════════════════════════════════════════════════════

test('a v3 dual-homed web host resolves, at the EXTERNAL .240', () => {
  const { lines, warned } = linesAndWarnings(V3_LANE, WEB_SPEC);
  assert.deepStrictEqual(lines, [`host-record=www.acme-clinic.com,${EXT}.${DUAL_HOMED_OCTET}`],
    'the company website is the reason spec.dns exists; on the default v3 topology it produced '
    + 'nothing at all');
  assert.deepStrictEqual(warned, [], 'and it must not warn about a machine it just resolved');

  // The INTERNAL .240 exists too — the host answers on both — so the assertion
  // above is only half the contract. Kali is on ext; an int-side answer would
  // send the student through the machine they are attacking.
  assert.ok(!lines[0].includes(`${INT}.`), 'the record must not name the internal segment');
});

test('the address is the clone path\'s own constant, not a second spelling of 240', () => {
  // The whole failure mode the constant exists to prevent: someone moves the pin
  // (it has moved once already — .50 collided with Kali's RDP DNAT) and the DNS
  // table keeps publishing the old address, so the site resolves to a machine
  // that is not there.
  assert.strictEqual(DUAL_HOMED_OCTET, 240);
  assert.ok(SRC.includes('ip=${net.lanExt.base3}.${DUAL_HOMED_OCTET}/24'),
    'the clone path must write ipconfig0 from the exported constant');
  assert.ok(SRC.includes('ip=${net.lanInt.base3}.${DUAL_HOMED_OCTET}/24'),
    'and ipconfig1 with it');
  assert.ok(!/ipconfig[01]:\s+.ip=\$\{net\.lan(Ext|Int)\.base3\}\.240/.test(SRC),
    'no literal 240 may survive in the ipconfig lines — that is the drift');

  // The CiAB paper spells the same octet, because the brief has to tell the
  // student where the pivot lives. Its comment names THIS file as the authority,
  // so the two must agree or the paper describes a lane that does not exist.
  const MODEL = require(path.join(
    ROOT, 'modules/crucible/plugins/ciab/utils/engagement-model.js'));
  assert.strictEqual(MODEL.DUAL_HOMED_OCTET, DUAL_HOMED_OCTET,
    'engagement-model.DUAL_HOMED_OCTET and the deployer\'s pin are the same address');
});

test('an explicit two-segment nics[] is dual-homed too, whatever the role says', () => {
  // resolveVmSegments takes an explicit nics[] over the role derivation, and the
  // topology canvas authors that shape directly. The DNS table must ask the same
  // question the clone path asks, not a role-shaped approximation of it.
  const spec = {
    dns: { web_name: 'shop.acme-clinic.com', web_vm: 'SHOP' },
    vms: [{ name: 'SHOP', type: 'qemu', nics: [{ segment: 'ext' }, { segment: 'int' }] }],
  };
  const { lines } = linesAndWarnings(V3_LANE, spec);
  assert.deepStrictEqual(lines, [`host-record=shop.acme-clinic.com,${EXT}.${DUAL_HOMED_OCTET}`]);
});

test('the AD forwarder can name the dual-homed host too — one table, both records', () => {
  // The entry goes into the shared address table rather than into the web
  // branch, so a spec that puts its DC behind the same bridge is not a special
  // case that has to be discovered later.
  const spec = {
    dns: {
      ad_domain: 'corp.acme-clinic.local', ad_dc: 'WEB-01',
      web_name: 'www.acme-clinic.com', web_vm: 'WEB-01',
    },
    vms: WEB_SPEC.vms,
  };
  const { lines } = linesAndWarnings(V3_LANE, spec);
  assert.deepStrictEqual(lines, [
    `server=/corp.acme-clinic.local/${EXT}.${DUAL_HOMED_OCTET}`,
    `host-record=www.acme-clinic.com,${EXT}.${DUAL_HOMED_OCTET}`,
  ]);
});

// ════════════════════════════════════════════════════════════════════════════
// 2. v1/v2: a clean no-op, not a wrong record
// ════════════════════════════════════════════════════════════════════════════

test('the same spec on a v1/v2 lane emits nothing and does not throw', () => {
  // A multi-NIC spec on v1/v2 still gets both NICs, but the .240 ipconfig pass
  // is v3-only — so there is no static address to publish. Naming one anyway
  // would point the company's website at an address nothing on the lane holds,
  // which is strictly worse than the honest NXDOMAIN.
  for (const subnetScheme of ['v1', 'v2', undefined]) {
    const spec = {
      dns: { web_name: 'www.acme-clinic.com', web_vm: 'WEB-01' },
      // Explicit nics[], because role 'dmz' derives to a single 'lan' off v3.
      vms: [{ name: 'WEB-01', type: 'qemu', nics: [{ segment: 'ext' }, { segment: 'int' }] }],
    };
    const { lines, warned } = linesAndWarnings({ ...V3_LANE, subnetScheme }, spec);
    assert.deepStrictEqual(lines, [], `scheme ${subnetScheme} must publish no address`);
    assert.ok(warned.some(w => /WEB-01/.test(w)),
      'and it must say why the name was dropped rather than failing silently');
  }
});

test('an LXC is never dual-homed, however many segments its spec lists', () => {
  // resolveVmNics gives an LXC net1 and ONE segment whatever the spec says (the
  // template owns net0), so it never reaches the .240 ipconfig pass either.
  const spec = {
    dns: { web_name: 'www.acme-clinic.com', web_vm: 'WEB-01' },
    vms: [{ name: 'WEB-01', type: 'lxc', nics: [{ segment: 'ext' }, { segment: 'int' }] }],
  };
  const { lines, warned } = linesAndWarnings(V3_LANE, spec);
  assert.deepStrictEqual(lines, []);
  assert.ok(warned.length);
});

test('a single-homed v3 machine keeps its own address and gains no .240', () => {
  // The guard that stops this becoming "every machine answers at .240". DC-01 is
  // pinned on the INTERNAL base and must stay there.
  const spec = {
    dns: { ad_domain: 'corp.acme-clinic.local', ad_dc: 'DC-01' },
    vms: WEB_SPEC.vms,
  };
  const { lines } = linesAndWarnings(V3_LANE, spec);
  assert.deepStrictEqual(lines, [`server=/corp.acme-clinic.local/${INT}.80`]);
});

test('an address with a real reservation behind it wins over the inference', () => {
  // A machine already in the table has a dhcp-host line pointing at that
  // address. The inference must not overwrite the address the lane actually
  // hands out, or the record and the reservation in one file would disagree.
  const lane = {
    ...V3_LANE,
    goadMacs: { 'WEB-01': { mac: '02:00:CC:27:10:0A', static_ip: `${INT}.10`, role: 'member' } },
  };
  const { lines } = linesAndWarnings(lane, WEB_SPEC);
  assert.deepStrictEqual(lines, [`host-record=www.acme-clinic.com,${INT}.10`]);
});

// ════════════════════════════════════════════════════════════════════════════
// 3. nothing malformed reaches the file
// ════════════════════════════════════════════════════════════════════════════

test('a VM that is not on the lane at all still warns and drops', () => {
  // The spec names a machine no VM entry matches — a typo, or a machine deleted
  // from the topology after spec.dns was written. It must be dropped with a
  // warning naming what was there, never emitted half-formed.
  const spec = {
    dns: { web_name: 'www.acme-clinic.com', web_vm: 'ghost-01' },
    vms: WEB_SPEC.vms,
  };
  const { lines, warned } = linesAndWarnings(V3_LANE, spec);
  assert.deepStrictEqual(lines, []);
  assert.ok(warned.some(w => /ghost-01/.test(w) && /DC-01/.test(w)),
    'the warning names the machine asked for AND the machines the lane can resolve');
});

test('a .240 built on a broken subnet base is validated, not published', () => {
  // The address is BUILT here (`${extSubnetBase}.${DUAL_HOMED_OCTET}`), so a lane
  // whose base is malformed reaches the emit point as a plausible-looking
  // string. Four numbers separated by dots is not an address, and dnsmasq
  // refuses to START on the line rather than ignoring it — which takes DHCP down
  // for every machine on the lane while it still reports active.
  const { lines, warned } = linesAndWarnings({ ...V3_LANE, extSubnetBase: '10.39.999' }, WEB_SPEC);
  assert.deepStrictEqual(lines, []);
  assert.ok(warned.some(w => /10\.39\.999\.240/.test(w)), 'and it says which value it refused');
});

test('a lane with no external base publishes nothing rather than "undefined.240"', () => {
  const { lines } = linesAndWarnings({ ...V3_LANE, extSubnetBase: undefined }, WEB_SPEC);
  assert.deepStrictEqual(lines, []);
});

test('an unusable web name is still rejected before the address is ever used', () => {
  // The name check comes first, and the newly knowable address must not sneak a
  // line past it. The comma is the sharp one: dnsmasq splits host-record on
  // commas, so an unchecked value becomes extra fields.
  for (const bad of ['www acme.com', 'www,acme.com', 'acme.com-']) {
    const spec = { dns: { web_name: bad, web_vm: 'WEB-01' }, vms: WEB_SPEC.vms };
    const { lines, warned } = linesAndWarnings(V3_LANE, spec);
    assert.deepStrictEqual(lines, [], `emitted a line for web_name ${JSON.stringify(bad)}`);
    assert.ok(warned.length);
  }
});

test('a v3 spec with no dns block is untouched by any of this', () => {
  assert.deepStrictEqual(resolveLaneDnsExtras({ ...V3_LANE, spec: { vms: WEB_SPEC.vms } }), []);
  assert.deepStrictEqual(resolveLaneDnsExtras({ ...V3_LANE, spec: {} }), []);
  assert.deepStrictEqual(resolveLaneDnsExtras({}), []);
});

// ════════════════════════════════════════════════════════════════════════════
// 4. the WHOLE file — the regression bound
// ════════════════════════════════════════════════════════════════════════════
//
// The lines above are two of many in /etc/dnsmasq.d/lane-reservations.conf, and
// writeLaneReservations renders that file WHOLE-LANE and overwrites it. So the
// claim that has to hold is about the FILE, not about the resolver that
// contributes two of its lines: an existing challenge must install exactly the
// bytes it installed before. Both expectations below are output captured from
// the composer BEFORE this change and pasted in.

test('an existing v2 challenge writes a byte-identical reservations file', async () => {
  const lines = await reservationFile({
    gatewayVmId: 9100, node: 'n1', vxlanId: 10017, subnetScheme: 'v2',
    goadMacs: {}, attackBoxOctet: 50,
    consoleOctets: { web01: 60 },
    pinnedHosts: [
      { name: 'dc01', octet: 80, subnetBase: '10.39.17' },
      { name: 'web01x', octet: 81, subnetBase: '10.39.17' },
    ],
    dnsRecords: [{ alias: 'elk', ip: '10.39.17.81' }],
    // A multi-NIC machine AND a spec.dns block naming it: the exact spec whose
    // output this change is allowed to alter on v3, pinned here to prove it does
    // not alter it on v2. The record still comes from the CONSOLE octet.
    spec: {
      dns: { web_name: 'www.acme-clinic.com', web_vm: 'web01' },
      vms: [
        { name: 'dc01', type: 'qemu' },
        { name: 'web01', type: 'qemu', role: 'dmz', nics: [{ segment: 'ext' }, { segment: 'int' }] },
      ],
    },
    extSubnetBase: '10.39.17', intSubnetBase: '10.39.17',
    liveGoadController: false, laneId: 'lane-1', logTag: '[test]',
  });

  assert.deepStrictEqual(lines, [
    ...HEADER,
    'dhcp-host=02:00:CC:27:21:32,10.39.17.50,kali',
    'dhcp-host=02:00:CC:27:21:3C,10.39.17.60,web01',
    'dhcp-host=02:00:CC:27:21:50,10.39.17.80,dc01',
    'dhcp-host=02:00:CC:27:21:51,10.39.17.81,web01x',
    '# Stable per-role names (spec.vms[].dns_aliases).',
    'host-record=elk,elk.cybercore.lan,10.39.17.81',
    '# The company being attacked: AD forwarder + public web name (spec.dns).',
    'host-record=www.acme-clinic.com,10.39.17.60',
  ]);
});

test('an existing GOAD challenge writes a byte-identical reservations file', async () => {
  const lines = await reservationFile({
    gatewayVmId: 9200, node: 'n1', vxlanId: 10161, subnetScheme: 'v3',
    goadMacs: {
      DC01:  { mac: '02:00:CC:27:10:0A', static_ip: '10.39.161.10', role: 'dc' },
      DC02:  { mac: '02:00:CC:27:10:0B', static_ip: '10.39.161.11', role: 'dc' },
      SRV02: { mac: '02:00:CC:27:10:16', static_ip: '10.39.161.22', role: 'member' },
    },
    attackBoxOctet: 50, consoleOctets: {}, pinnedHosts: [], dnsRecords: [],
    // No spec.dns — which is every stored GOAD challenge in the tree, and the
    // reason the whole block is opt-in.
    spec: {
      goad: { enabled: true, domain: 'sevenkingdoms.local' },
      vms: [{ name: 'DC01', type: 'qemu' }],
    },
    extSubnetBase: '10.39.161', intSubnetBase: '10.167.161',
    liveGoadController: true, laneId: 'lane-2', logTag: '[test]',
  });

  assert.deepStrictEqual(lines, [
    ...HEADER,
    'dhcp-host=02:00:CC:27:B1:32,10.39.161.50,kali',
    'dhcp-host=02:00:CC:27:B1:05,10.167.161.5,goad-controller',
    'dhcp-host=02:00:CC:27:10:0A,10.39.161.10,DC01',
    'dhcp-host=02:00:CC:27:10:0B,10.39.161.11,DC02',
    'dhcp-host=02:00:CC:27:10:16,10.39.161.22,SRV02',
  ]);
});

test('the v3 lane\'s file carries the company line, in the file\'s own order', async () => {
  // The other half of the same claim: the file gains exactly one line, after the
  // reservations and under its own comment. dnsmasq reads this top-down.
  const lines = await reservationFile({
    gatewayVmId: 9300, node: 'n1', vxlanId: 10017, subnetScheme: 'v3',
    goadMacs: {}, attackBoxOctet: 50, consoleOctets: {},
    pinnedHosts: [{ name: 'DC-01', octet: 80, subnetBase: INT }],
    dnsRecords: [], spec: WEB_SPEC,
    extSubnetBase: EXT, intSubnetBase: INT,
    liveGoadController: false, laneId: 'lane-3', logTag: '[test]',
  });

  assert.deepStrictEqual(lines, [
    ...HEADER,
    'dhcp-host=02:00:CC:27:21:32,10.39.17.50,kali',
    // Lowercased: writeLaneReservations normalises the label, and a dnsmasq
    // hostname is case-insensitive anyway.
    'dhcp-host=02:00:CC:27:21:50,10.39.18.80,dc-01',
    '# The company being attacked: AD forwarder + public web name (spec.dns).',
    `host-record=www.acme-clinic.com,${EXT}.${DUAL_HOMED_OCTET}`,
  ]);

  // The DMZ host gets NO dhcp-host line, and that is correct: its address is
  // static (ipconfig0/1), so a reservation would be one nothing ever requests.
  assert.ok(!lines.some(l => l.startsWith('dhcp-host=') && /WEB-01/.test(l)),
    'a dual-homed host must not gain a reservation as a side effect of gaining a name');
});

// ════════════════════════════════════════════════════════════════════════════
// 5. the wiring
// ════════════════════════════════════════════════════════════════════════════

test('both writeLaneReservations call sites hand it the subnet scheme', () => {
  // Source text, because the failure is silent in exactly the way the missing
  // `spec` was: the resolver can be perfect while no caller tells it which
  // scheme the lane is on, and a v3 lane that looks like a v2 lane simply
  // publishes no website. The REBUILD site matters as much as the deploy one —
  // that file is rendered whole-lane and overwritten, so a rebuild that omitted
  // the scheme would DELETE the company's name from a lane nobody asked to
  // change.
  const calls = SRC.split('await writeLaneReservations({').slice(1);
  assert.strictEqual(calls.length, 2, 'expected the deploy and rebuild call sites');
  calls.forEach((call, i) => {
    const args = call.split('});')[0];
    assert.ok(/(^|[\s,{])subnetScheme\s*[,}]/.test(args),
      `writeLaneReservations call site ${i + 1} does not pass subnetScheme`);
  });
  assert.ok(/resolveLaneDnsExtras\(\{[^}]*subnetScheme/.test(SRC),
    'and writeLaneReservations must forward it to the resolver');
});
