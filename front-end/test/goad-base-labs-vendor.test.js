/** CyberCore keeps identity metadata; the separate controller fork owns GOAD files. */
'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const R = require('../src/utils/goad-lab-rebrand');
const oracle = require('./support/goad-rebrand-oracle');
const repo = path.resolve(__dirname, '../..');
const metadataRoot = R.BASE_LABS_DIR;
const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const expectedPaths = ['GOAD/base.json', 'GOAD-Light/base.json', 'GOAD-Mini/base.json',
  '_extensions/lx01/base.json', '_extensions/ws01/base.json'].sort();

function walk(dir, prefix = '') {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const rel = prefix + entry.name;
    return entry.isDirectory() ? walk(path.join(dir, entry.name), rel + '/') : [rel];
  }).sort();
}

test('the webserver has exactly five small identity metadata files and no GOAD payloads', () => {
  assert.deepEqual(walk(metadataRoot), expectedPaths);
  for (const relative of expectedPaths) {
    const file = path.join(metadataRoot, relative);
    const metadata = readJson(file);
    assert.equal(metadata.schema_version, 2);
    assert.ok(fs.statSync(file).size < 12000);
    for (const key of ['files', 'derived_from', 'source_sha256', 'payloads', 'extension_principals']) {
      assert.equal(metadata[key], undefined, `${relative} must not contain controller source recipes`);
    }
    assert.ok(metadata.controller_recipe);
    for (const host of Object.values(metadata.stock.hosts)) {
      assert.equal(R.assertHostname(host.roster_name), host.roster_name);
    }
  }
});

test('metadata describes complete Mini, Light and full domain graphs and roster joins', () => {
  for (const [name, count] of [['GOAD-Mini', 1], ['GOAD-Light', 2], ['GOAD', 3]]) {
    const metadata = readJson(path.join(metadataRoot, name, 'base.json'));
    const domains = metadata.stock.domains || { [metadata.stock.forest_root]: { kind: 'root', dc: 'dc01' } };
    assert.equal(metadata.lab, name);
    assert.equal(Object.keys(domains).length, count);
    assert.deepEqual(new Set(metadata.lab_definition.domains), new Set(Object.keys(domains)));
    assert.equal(metadata.lab_definition.forestRoot, metadata.stock.forest_root);
    assert.deepEqual(new Set(metadata.lab_definition.vms.map(vm => vm.name)),
      new Set(Object.values(metadata.stock.hosts).map(host => host.roster_name)));
    for (const host of Object.values(metadata.stock.hosts)) assert.ok(domains[host.domain]);
    for (const domain of Object.values(domains)) assert.ok(metadata.stock.hosts[domain.dc]);
    assert.equal(Object.values(domains).filter(domain => domain.kind === 'root').length, 1);
    if (count === 1) assert.ok(!metadata.chain.includes('ad-child_domain.yml'));
    else assert.ok(metadata.chain.includes('ad-child_domain.yml'));
  }
});

test('git admits metadata but excludes accidental GOAD files below the metadata directory', t => {
  const check = relative => spawnSync('git', ['check-ignore', '--no-index', '--quiet', relative], { cwd: repo });
  if (check('.git').error) return t.skip('git is not installed');
  for (const relative of expectedPaths) {
    assert.equal(check('front-end/src/data/goad-base-labs/' + relative).status, 1, relative);
  }
  for (const relative of ['GOAD-Mini/data/config.json', 'GOAD/files/payload.exe', '_extensions/ws01/data/config.json']) {
    assert.equal(check('front-end/src/data/goad-base-labs/' + relative).status, 0, relative);
  }
});

test('optional separate-fork recipes agree with every metadata identity', t => {
  let source;
  try { source = oracle.resolveGoadSourceDir(); } catch (_) { return t.skip('separate GOAD checkout unavailable'); }
  for (const relative of expectedPaths) {
    const metadata = readJson(path.join(metadataRoot, relative));
    const recipeFile = path.join(source, 'scripts/cybercore/manifests', metadata.controller_recipe + '.json');
    if (!fs.existsSync(recipeFile)) return t.skip('checkout predates controller rename helper');
    const recipe = readJson(recipeFile);
    assert.deepEqual(metadata.stock, recipe.stock, relative);
    if (metadata.lab) {
      assert.deepEqual(metadata.lab_definition, recipe.lab_definition, relative);
      assert.deepEqual(metadata.chain, recipe.chain, relative);
    }
  }
});
