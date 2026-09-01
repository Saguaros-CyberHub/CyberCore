/**
 * ciab-lane-dns.test.js — the lane's own DNS for the AD pivot, and the pre-baked
 * subnet guard that stops a lane lying about the forest it is serving.
 *
 * WHY THIS FILE EXISTS
 *
 * 1. LANE DNS (resolveLaneDnsExtras). Until now a grep for `server=/` across
 *    src/ returned nothing: the gateway served `cybercore.lan` and forwarded
 *    everything else upstream, so Kali resolved the lane's short names and knew
 *    nothing about the company's forest. Every AD tool invoked the way a student
 *    is taught to invoke it — `nxc smb dc01.corp.local`, `bloodhound-python -d
 *    corp.local`, `GetUserSPNs.py corp.local/user` with no `-dc-ip` — died at
 *    name resolution before touching the target once. One `server=/<domain>/<dc>`
 *    line fixes all of them, and dnsmasq matches the domain AND its subdomains,
 *    so the `_msdcs`/`_tcp` SRV records the DC-locator and Kerberos look up come
 *    along with it.
 *
 *    These lines land in the SAME file as the lane's DHCP reservations, and
 *    dnsmasq refuses to start on ONE malformed directive — which takes DHCP down
 *    for every machine on the lane while the lane still reports active. So the
 *    assertions below are as much about what is NOT written as what is: an
 *    unusable name or a machine with no address on this lane must be skipped
 *    with a warning, never emitted half-formed, and never thrown (a bad web name
 *    must not cost the student their DHCP).
 *
 * 2. THE PRE-BAKED GUARD (applyPrebakedFixedSubnet). A golden AD image bakes its
 *    addresses into its own DNS zone, SYSVOL paths and every SPN. Cloning it
 *    onto a per-lane subnet leaves all of those naming an address the lane does
 *    not have — and nothing fails: the VMs boot, DHCP answers, the lane reports
 *    active. The three call sites used to spell the pin as
 *    `if (prebaked && fixed_subnet) applyFixedSubnet(...)` with no else, so a
 *    spec that never declared the subnet took that silent path three times over.
 *
 * Both are pure over their inputs, like resolveSpecAddressing, so neither needs
 * Proxmox, SSH or a DB. challenge-lane-deployer pulls site-config at module load
 * (via batch-deployer), which reads a gitignored config/site.json — same
 * require.cache stub ciab-lane-provision.test.js uses.
 *
 * Run: node --test front-end/test/ciab-lane-dns.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
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

// lane-deployer.hostRecordLine bakes LANE_DNS_DOMAIN, which it reads from the
// environment ONCE at module load. Pinned before the require so the expected
// strings below hold on a machine that overrides it.
process.env.LANE_DNS_DOMAIN = 'cybercore.lan';

const {
  resolveLaneDnsExtras, applyPrebakedFixedSubnet,
} = require(path.join(UTILS, 'challenge-lane-deployer.js'));

// ── lanes ───────────────────────────────────────────────────────────────────
// Two shapes, because the AD pivot has two worlds and only one of them has GOAD.

/**
 * A GOAD lane. goadMacs is prepareGoadMacs' output: every lab host already has
 * a static IP on the INTERNAL segment and its role, which is what lets the
 * forwarder find the DC with nothing declared but the domain.
 */
const GOAD_LANE = {
  goadMacs: {
    DC01:  { mac: '02:00:CC:27:10:0A', static_ip: '10.167.161.10', role: 'dc' },
    DC02:  { mac: '02:00:CC:27:10:0B', static_ip: '10.167.161.11', role: 'dc' },
    SRV02: { mac: '02:00:CC:27:10:16', static_ip: '10.167.161.22', role: 'member' },
  },
  consoleOctets: { WEB01: 60 },
  pinnedHosts: [],
  extSubnetBase: '10.39.161',
};

/**
 * A CiAB profile lane: no GOAD lab at all. Its "DC" is an ordinary asset out of
 * the company profile, pinned by resolveSpecAddressing like every other machine
 * — so `dns.ad_dc` is the only way to point the forwarder at it.
 */
const PROFILE_LANE = {
  goadMacs: {},
  consoleOctets: { kali: 50 },
  pinnedHosts: [
    { name: 'dc01',  octet: 80, subnetBase: '10.39.17' },
    { name: 'web01', octet: 81, subnetBase: '10.39.17' },
  ],
  extSubnetBase: '10.39.17',
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

// ── 1. inert for every challenge that exists today ──────────────────────────

test('a spec with no dns block writes nothing, GOAD domain or not', () => {
  // The whole back-compat rule. Every stored GOAD challenge already carries
  // spec.goad.domain (lab-templates.js defaults it), so sourcing the forwarder
  // from that field ALONE would have changed what every existing GOAD lane
  // deploys. The block is keyed on spec.dns, which nothing in the tree has.
  const goadSpec = { goad: { enabled: true, domain: 'sevenkingdoms.local', version: 'GOAD-Light' } };
  assert.deepStrictEqual(resolveLaneDnsExtras({ ...GOAD_LANE, spec: goadSpec }), []);
  assert.deepStrictEqual(resolveLaneDnsExtras({ ...PROFILE_LANE, spec: {} }), []);
  assert.deepStrictEqual(resolveLaneDnsExtras({ ...PROFILE_LANE, spec: { dns: null } }), []);
  // An empty block is a spec that opted in and declared nothing — still nothing
  // to write, and still not an error.
  assert.deepStrictEqual(resolveLaneDnsExtras({ ...PROFILE_LANE, spec: { dns: {} } }), []);
});

test('resolveLaneDnsExtras survives being called with nothing at all', () => {
  // writeLaneReservations defaults `spec` to {}, and the rebuild path hands it
  // whatever cybercore_lane.config carried. A throw here would fail a deploy
  // over a spec key that is optional by design.
  assert.deepStrictEqual(resolveLaneDnsExtras({}), []);
});

// ── 2. the conditional forwarder ────────────────────────────────────────────

test('the forwarder points the forest at the lab DC, in dnsmasq syntax', () => {
  const { lines } = linesAndWarnings(GOAD_LANE, {
    goad: { enabled: true, domain: 'sevenkingdoms.local' },
    dns: { ad_domain: 'sevenkingdoms.local' },
  });
  // Exactly one line, and the FIRST dc-role host: a second `server=/<forest>/`
  // would send part of the lane's forest traffic to DC02, which in the stock
  // labs holds a different domain.
  assert.deepStrictEqual(lines, ['server=/sevenkingdoms.local/10.167.161.10']);
});

test('ad_dc names the machine, so a profile lane with no GOAD lab still forwards', () => {
  const { lines } = linesAndWarnings(PROFILE_LANE, {
    dns: { ad_domain: 'corp.acme-clinic.local', ad_dc: 'dc01' },
  });
  // .80 is the pinned address, not a pool lease — the only kind of address that
  // is knowable at deploy time and therefore safe to publish.
  assert.deepStrictEqual(lines, ['server=/corp.acme-clinic.local/10.39.17.80']);
});

test('naming only the DC reuses the domain the GOAD half of the spec declares', () => {
  // Writing the forest root twice in one spec is how the two drift.
  const { lines } = linesAndWarnings(GOAD_LANE, {
    goad: { enabled: true, domain: 'sevenkingdoms.local' },
    dns: { ad_dc: 'DC02' },
  });
  assert.deepStrictEqual(lines, ['server=/sevenkingdoms.local/10.167.161.11']);
});

test('the machine name is matched exactly, and the domain is normalised', () => {
  // GOAD hosts are 'DC01'; a profile lane's are lowercase hostnames. The name is
  // the SPEC name either way — the same string the author reads off the canvas —
  // so it is matched verbatim rather than case-folded into a near-miss.
  const { lines } = linesAndWarnings(GOAD_LANE, {
    dns: { ad_domain: '  SevenKingdoms.Local.  ', ad_dc: 'DC01' },
  });
  assert.deepStrictEqual(lines, ['server=/sevenkingdoms.local/10.167.161.10']);
});

test('a DC that is not on this lane skips the forwarder and names what is', () => {
  const { lines, warned } = linesAndWarnings(PROFILE_LANE, {
    dns: { ad_domain: 'corp.acme-clinic.local', ad_dc: 'DC-01' },
  });
  assert.deepStrictEqual(lines, [], 'a forwarder to nowhere is worse than none');
  assert.ok(warned.some(w => /DC-01/.test(w) && /dc01/.test(w) && /web01/.test(w)),
    `the warning must name the machines that WERE there: ${JSON.stringify(warned)}`);
});

test('a domain with no DC anywhere is skipped rather than half-written', () => {
  // No ad_dc, and no GOAD host carrying role 'dc' — there is nothing to forward
  // to, and `server=/domain/` with an empty address stops dnsmasq starting.
  const memberOnly = { ...GOAD_LANE, goadMacs: { SRV02: GOAD_LANE.goadMacs.SRV02 } };
  const { lines, warned } = linesAndWarnings(memberOnly, {
    dns: { ad_domain: 'sevenkingdoms.local' },
  });
  assert.deepStrictEqual(lines, []);
  assert.ok(warned.some(w => /sevenkingdoms\.local/.test(w)));
});

test('a DC named with no forest anywhere in the spec is called out', () => {
  // Half a declaration. Silence would read as "the author wanted no forwarder",
  // which is exactly the state that has to be distinguishable from a typo.
  const { lines, warned } = linesAndWarnings(GOAD_LANE, { dns: { ad_dc: 'DC01' } });
  assert.deepStrictEqual(lines, []);
  assert.ok(warned.some(w => /DC01/.test(w) && /ad_domain/.test(w)), JSON.stringify(warned));
});

// ── 3. the company's public web name ────────────────────────────────────────

test('a public web name is published verbatim, NOT suffixed with the lane domain', () => {
  const { lines } = linesAndWarnings(PROFILE_LANE, {
    dns: { web_name: 'www.acme-clinic.com', web_vm: 'web01' },
  });
  // hostRecordLine would publish `www.acme-clinic.com.cybercore.lan` and leave
  // the name the student was actually given unresolvable, so an already-qualified
  // name takes the two-field form of the same directive.
  assert.deepStrictEqual(lines, ['host-record=www.acme-clinic.com,10.39.17.81']);
  assert.ok(!lines[0].includes('cybercore.lan'), 'the lane search domain must not be appended');
});

test('a bare label goes through the shared helper so both forms resolve', () => {
  // lane-deployer.hostRecordLine owns this format — `elk.cybercore.lan` must not
  // mean one thing on a workstation lane and another on a challenge lane.
  const { lines } = linesAndWarnings(PROFILE_LANE, {
    dns: { web_name: 'intranet', web_vm: 'web01' },
  });
  assert.deepStrictEqual(lines, ['host-record=intranet,intranet.cybercore.lan,10.39.17.81']);
});

test('the web VM may be the console machine, whose address is on the EXTERNAL base', () => {
  const { lines } = linesAndWarnings(GOAD_LANE, {
    dns: { web_name: 'www.sevenkingdoms.com', web_vm: 'WEB01' },
  });
  // .60 on the ext base, matching writeLaneReservations' own console loop — the
  // two must agree or the record points at an off-subnet address.
  assert.deepStrictEqual(lines, ['host-record=www.sevenkingdoms.com,10.39.161.60']);
});

test('a web name with no machine behind it is skipped, not published', () => {
  const noVm = linesAndWarnings(PROFILE_LANE, { dns: { web_name: 'www.acme-clinic.com' } });
  assert.deepStrictEqual(noVm.lines, []);
  assert.ok(noVm.warned.some(w => /web_vm/.test(w)));

  const unknownVm = linesAndWarnings(PROFILE_LANE, {
    dns: { web_name: 'www.acme-clinic.com', web_vm: 'www-01' },
  });
  assert.deepStrictEqual(unknownVm.lines, []);
  assert.ok(unknownVm.warned.some(w => /www-01/.test(w) && /web01/.test(w)));
});

// ── 4. nothing malformed reaches the file ───────────────────────────────────

test('an unusable name is skipped with a warning and never thrown', () => {
  // The comma is the sharp one: dnsmasq splits `server=`/`host-record=` on
  // commas, so an unchecked value becomes extra fields — and a directive it
  // cannot parse stops it starting, which takes the lane's DHCP with it.
  for (const bad of ['corp local', 'corp,10.0.0.1', '-corp.local', 'corp..local', 'corp.local/x', '.']) {
    const { lines, warned } = linesAndWarnings(GOAD_LANE, { dns: { ad_domain: bad, ad_dc: 'DC01' } });
    assert.deepStrictEqual(lines, [], `emitted a line for ad_domain ${JSON.stringify(bad)}`);
    assert.ok(warned.length, `no warning for ad_domain ${JSON.stringify(bad)}`);
  }
  for (const bad of ['www .acme.com', 'www,acme.com', 'acme.com-', `${'a'.repeat(64)}.com`]) {
    const { lines, warned } = linesAndWarnings(PROFILE_LANE, { dns: { web_name: bad, web_vm: 'web01' } });
    assert.deepStrictEqual(lines, [], `emitted a line for web_name ${JSON.stringify(bad)}`);
    assert.ok(warned.length, `no warning for web_name ${JSON.stringify(bad)}`);
  }
});

test('an address that is not IPv4 is skipped, even though the machine exists', () => {
  // The IP is BUILT here (`${subnetBase}.${octet}`), so a spec with a malformed
  // fixed subnet reaches this function as a plausible-looking string. Four
  // numbers separated by dots is not an address.
  const brokenBase = {
    ...PROFILE_LANE,
    pinnedHosts: [{ name: 'dc01', octet: 80, subnetBase: '10.39.999' }],
  };
  const { lines, warned } = linesAndWarnings(brokenBase, {
    dns: { ad_domain: 'corp.acme-clinic.local', ad_dc: 'dc01' },
  });
  assert.deepStrictEqual(lines, []);
  assert.ok(warned.some(w => /10\.39\.999\.80/.test(w)));
});

test('both halves together, forwarder first', () => {
  // File order is the whole output contract for a config dnsmasq reads top-down.
  const { lines } = linesAndWarnings(PROFILE_LANE, {
    dns: {
      ad_domain: 'corp.acme-clinic.local', ad_dc: 'dc01',
      web_name: 'www.acme-clinic.com', web_vm: 'web01',
    },
  });
  assert.deepStrictEqual(lines, [
    'server=/corp.acme-clinic.local/10.39.17.80',
    'host-record=www.acme-clinic.com,10.39.17.81',
  ]);
});

test('one broken half does not take the other down with it', () => {
  const { lines } = linesAndWarnings(PROFILE_LANE, {
    dns: {
      ad_domain: 'corp local', ad_dc: 'dc01',
      web_name: 'www.acme-clinic.com', web_vm: 'web01',
    },
  });
  assert.deepStrictEqual(lines, ['host-record=www.acme-clinic.com,10.39.17.81']);
});

// ── 5. the resolver is actually WIRED into the file that gets written ───────

test('both writeLaneReservations call sites hand it the spec', () => {
  // Source text, because the failure it guards is silent: resolveLaneDnsExtras
  // can be perfect while no caller routes a spec into it, and a lane with no
  // forwarder looks exactly like a lane whose spec declared none. The rebuild
  // site matters as much as the deploy one — that file is rendered WHOLE-LANE
  // and overwritten, so a rebuild that omitted the spec would DELETE the
  // forwarder from a lane nobody asked to change.
  const src = fs.readFileSync(path.join(UTILS, 'challenge-lane-deployer.js'), 'utf8');
  const calls = src.split('await writeLaneReservations({').slice(1);
  assert.strictEqual(calls.length, 2, 'expected the deploy and rebuild call sites');
  calls.forEach((call, i) => {
    const args = call.split('});')[0];
    assert.ok(/(^|[\s,{])spec\s*[,}]/.test(args),
      `writeLaneReservations call site ${i + 1} does not pass spec`);
  });
  assert.ok(/resolveLaneDnsExtras\(\{/.test(src),
    'writeLaneReservations must build its DNS lines through resolveLaneDnsExtras');
});

// ── 6. the pre-baked fixed-subnet guard ─────────────────────────────────────

/** Shaped like resolveLaneNetworking's v3 output — the fields applyFixedSubnet edits. */
function laneNet() {
  return {
    wan:    { ip: '100.100.60.7/24', gw: '100.100.60.1' },
    lanExt: { base3: '10.39.161', cidr: '10.39.161.0/24', gatewayIp: '10.39.161.1' },
    lanInt: { base3: '10.167.161', cidr: '10.167.161.0/24', gatewayIp: '10.167.161.1' },
  };
}

test('a pre-baked spec with no fixed_subnet refuses to build the lane', () => {
  const spec = { goad: { enabled: true, prebaked: true } };
  assert.throws(
    () => applyPrebakedFixedSubnet(laneNet(), true, spec),
    (err) => {
      // The message has to name the STATE and the REMEDY: whoever hits this is
      // looking at a challenge that used to deploy, and the fix is a spec field
      // they have never heard of.
      assert.ok(/fixed_subnet/.test(err.message), err.message);
      assert.ok(/prebaked/.test(err.message), err.message);
      return true;
    });
});

test('an empty fixed_subnet.int is the same silence with a field to hide it', () => {
  // applyFixedSubnet ignores a falsy base, so `{ int: '' }` — exactly what the
  // topology canvas seeds a new pre-baked challenge with — would take the
  // per-lane subnet while looking answered.
  for (const fixed of [{}, { int: '' }, { int: '   ' }, { int: null, ext: '10.39.161' }]) {
    assert.throws(
      () => applyPrebakedFixedSubnet(laneNet(), true, { goad: { prebaked: true, fixed_subnet: fixed } }),
      /fixed_subnet/,
      `fixed_subnet ${JSON.stringify(fixed)} must not pass`);
  }
});

test('a declared fixed subnet pins the segments the golden images were baked on', () => {
  const net = applyPrebakedFixedSubnet(laneNet(), true, {
    goad: { prebaked: true, fixed_subnet: { int: '10.167.161', ext: '10.39.161' } },
  });
  assert.strictEqual(net.lanInt.base3, '10.167.161');
  assert.strictEqual(net.lanInt.gatewayIp, '10.167.161.1');
  assert.strictEqual(net.lanExt.base3, '10.39.161');
});

test('whitespace around a hand-typed base is trimmed, not built into an address', () => {
  // ' 10.167.161' is truthy, so the old form built ' 10.167.161.1' as the
  // gateway address — which Proxmox accepts and no guest can reach.
  const net = applyPrebakedFixedSubnet(laneNet(), true, {
    goad: { prebaked: true, fixed_subnet: { int: ' 10.167.161 ' } },
  });
  assert.strictEqual(net.lanInt.gatewayIp, '10.167.161.1');
});

test('pinning only the internal base leaves the external one per-lane', () => {
  // Back-compat: only the internal segment carries the baked AD, and defaulting
  // ext to int would put both v3 segments on one base.
  const net = applyPrebakedFixedSubnet(laneNet(), true, {
    goad: { prebaked: true, fixed_subnet: { int: '10.167.161' } },
  });
  assert.strictEqual(net.lanInt.base3, '10.167.161');
  assert.strictEqual(net.lanExt.base3, '10.39.161', 'the ext segment must be left alone');
});

test('a lane that is not pre-baked is untouched and never refused', () => {
  for (const spec of [{}, { goad: { enabled: true } }, { goad: { enabled: true, version: 'GOAD-Light' } }]) {
    const net = laneNet();
    assert.strictEqual(applyPrebakedFixedSubnet(net, true, spec), net);
    assert.strictEqual(net.lanInt.base3, '10.167.161');
  }
});

test('a v1/v2 lane pins its single LAN from the same field', () => {
  // isV3 false: applyFixedSubnet writes net.lan, and there is no lanExt/lanInt.
  const net = { wan: {}, lan: { base3: '10.39.17', cidr: '10.39.17.0/24', gatewayIp: '10.39.17.1' } };
  applyPrebakedFixedSubnet(net, false, {
    goad: { prebaked: true, fixed_subnet: { int: '192.18.0', ext: '192.18.0' } },
  });
  assert.strictEqual(net.lan.base3, '192.18.0');
});
