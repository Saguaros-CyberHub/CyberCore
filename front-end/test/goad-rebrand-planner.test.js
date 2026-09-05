'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const R = require('../src/utils/goad-lab-rebrand');

const specFor = (version, overrides = {}) => ({ goad: {
  version, domain: 'cy400test.org', rename_forest: true, extensions: ['elk', 'ws01', 'lx01'], ...overrides,
} });

test('production plans all three labs using only the five metadata files, even with source access forbidden', () => {
  const filename = require.resolve('../src/utils/goad-lab-rebrand');
  const source = fs.readFileSync(filename, 'utf8');
  const checked = operation => file => {
    assert.ok(path.resolve(file).startsWith(R.BASE_LABS_DIR + path.sep), `unexpected source access: ${file}`);
    assert.equal(path.basename(file), 'base.json');
    return fs[operation](file, 'utf8');
  };
  const isolatedModule = { exports: {} };
  const allowed = {
    fs: { existsSync: checked('existsSync'), readFileSync: checked('readFileSync') },
    path, crypto: require('node:crypto'), './ad-domain-rules': require('../src/utils/ad-domain-rules'),
  };
  vm.runInNewContext('(function(require,module,exports,__dirname) {' + source + '\n})', {})(
    name => { assert.ok(allowed[name], `unexpected dependency: ${name}`); return allowed[name]; },
    isolatedModule, isolatedModule.exports, path.dirname(filename));
  for (const version of ['GOAD-Mini', 'GOAD-Light', 'GOAD']) {
    const plan = isolatedModule.exports.preflightGoadRebrand(specFor(version)).goad.rename_plan;
    assert.equal(plan.base_lab, version);
    assert.ok(Buffer.byteLength(JSON.stringify(plan)) < 5000);
    assert.deepEqual(Object.keys(plan).sort(), ['schema', 'base_lab', 'lab_name', 'domain_mapping',
      'hostnames', 'selected_extensions', 'expected_identities'].sort());
  }
  assert.doesNotMatch(source, /GOAD_SOURCE_DIR|resolveGoadSourceDir|rebrandLab\(/);
  assert.equal(R.rebrandLab, undefined);
  assert.match(fs.readFileSync(path.join(__dirname, '../.dockerignore'), 'utf8'), /^\/test\/$/m);
});

for (const [version, domainCount, hostCount] of [['GOAD-Mini', 1, 1], ['GOAD-Light', 2, 3], ['GOAD', 3, 5]]) {
  for (const domain of ['cy400test.org', 'lab.cy400test.org', 'a.b.cy400test.org']) {
    test(`${version} plans ${domain} with complete neutral host/domain identities`, () => {
      const input = specFor(version, { domain });
      const original = JSON.stringify(input);
      const output = R.rebrandGoadSpec(input);
      const plan = output.goad.rename_plan;
      assert.equal(JSON.stringify(input), original);
      assert.equal(output.goad.generated_lab, undefined);
      assert.equal(output.goad.lab.baseLab, version);
      assert.equal(plan.schema, 2);
      assert.equal(plan.lab_name, output.goad.version);
      assert.equal(plan.domain_mapping.length, domainCount);
      assert.equal(Object.keys(plan.hostnames).length, hostCount);
      assert.equal(plan.expected_identities.length, hostCount + 2);
      assert.equal(plan.domain_mapping.find(item => item.kind === 'root').to, domain);
      assert.deepEqual(plan.expected_identities.filter(host => ['ws01', 'lx01'].includes(host.name)), [
        { name: 'ws01', hostname: 'ws01', domain }, { name: 'lx01', hostname: 'lx01', domain },
      ]);
      if (domainCount > 1) assert.equal(plan.domain_mapping.find(item => item.kind === 'child').to, `corp.${domain}`);
      if (domainCount > 2) {
        const labels = domain.split('.');
        labels[0] += '-partner';
        const partner = plan.domain_mapping.find(item => item.kind === 'partner');
        assert.equal(partner.to, labels.join('.'));
        assert.equal(partner.netbios, 'PARTNER');
        assert.ok(!partner.to.endsWith('.' + domain));
        assert.equal(plan.expected_identities.find(host => host.name === 'DC03').domain, partner.to);
      }
      assert.equal(R.rebrandGoadSpec(specFor(version, { domain })).goad.version, output.goad.version);
    });
  }
}

test('legacy identities and version aliases preserve the opt-in boundary', () => {
  for (const version of ['GOAD-Mini', 'GOAD-Light', 'GOAD', 'light', 'CIAB-existing']) {
    const legacy = specFor(version, { domain: 'cybersaguaros.local', child_subdomain: 'tumamoc', rename_forest: undefined });
    assert.equal(R.preflightGoadRebrand(legacy), legacy);
  }
  assert.equal(R.preflightGoadRebrand(specFor('light')).goad.lab.baseLab, 'GOAD-Light');
  assert.equal(R.preflightGoadRebrand(specFor('full')).goad.lab.baseLab, 'GOAD');
});

test('authored child labels normalize and invalid relationships are refused', () => {
  const label = R.preflightGoadRebrand(specFor('GOAD', { child_subdomain: 'Students' }));
  const fqdn = R.preflightGoadRebrand(specFor('GOAD', { child_subdomain: 'students.cy400test.org' }));
  assert.equal(label.goad.version, fqdn.goad.version);
  assert.equal(label.goad.child_subdomain, 'students');
  for (const input of [
    specFor('GOAD-Mini', { child_subdomain: 'corp' }),
    specFor('GOAD', { child_subdomain: 'elsewhere.org' }),
    specFor('GOAD', { child_subdomain: 'two.labels' }),
    specFor('GOAD', { child_subdomain: 'partner' }),
    specFor('GOAD', { domain: 'partner.org' }),
    specFor('GOAD-Light', { child_subdomain: 'cy400test' }),
  ]) assert.throws(() => R.preflightGoadRebrand(input), error => error.code === R.REBRAND_CODES.FOREIGN_DOMAIN);
});

test('explicit invalid requests cannot fall back to stock identity', () => {
  for (const domain of ['', null, 'singlelabel', 'https://cy400test.org:443/lab', 'cy400test.local']) {
    assert.throws(() => R.preflightGoadRebrand(specFor('GOAD-Mini', { domain })),
      error => error.code === R.REBRAND_CODES.UNUSABLE_DOMAIN);
  }
  for (const extensions of [['exchange'], ['guacamole'], ['elk', 'elk'], 'ws01']) {
    assert.throws(() => R.preflightGoadRebrand(specFor('GOAD', { extensions })),
      error => error.code === R.REBRAND_CODES.EXTENSION);
  }
  assert.throws(() => R.preflightGoadRebrand(specFor('GOAD', { prebaked: true })), error => error.code === R.REBRAND_CODES.PREBAKED);
  assert.throws(() => R.preflightGoadRebrand(specFor('NHA')), error => error.code === R.REBRAND_CODES.NO_BASE_TREE);
});

test('only unchanged in-memory plans may re-enter deployment', () => {
  const planned = R.preflightGoadRebrand(specFor('GOAD-Mini'));
  assert.equal(R.preflightGoadRebrand(planned), planned);
  const shallow = { ...planned };
  assert.equal(R.preflightGoadRebrand(shallow), shallow);
  for (const untrusted of [
    JSON.parse(JSON.stringify(planned)),
    specFor('GOAD-Mini', { lab: {} }),
    specFor('GOAD-Mini', { generated_lab: {} }),
    specFor('GOAD-Mini', { rename_plan: {} }),
  ]) assert.throws(() => R.preflightGoadRebrand(untrusted), error => error.code === R.REBRAND_CODES.ALREADY_GENERATED);
  planned.goad.rename_plan.expected_identities[0].domain = 'wrong.org';
  assert.throws(() => R.preflightGoadRebrand(planned), error => error.code === R.REBRAND_CODES.ALREADY_GENERATED);
});
