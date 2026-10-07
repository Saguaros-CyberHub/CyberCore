/** Optional development parity against the separate GOAD fork. Never installs files. */
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const planner = require('../src/utils/goad-lab-rebrand');
const oracle = require('./support/goad-rebrand-oracle');

test('controller Python and offline JS agree on every emitted identity, script and binary for all supported forests', t => {
  let source;
  try { source = oracle.resolveGoadSourceDir(); } catch (_) { return t.skip('separate GOAD checkout unavailable'); }
  if (!fs.existsSync(path.join(source, 'scripts/cybercore-rebrand.py'))) return t.skip('checkout predates controller helper');
  const python = process.env.PYTHON || 'python';
  const probe = spawnSync(python, ['-B', '-c', 'import yaml'], { encoding: 'utf8' });
  if (probe.error || probe.status !== 0) return t.skip('Python with PyYAML unavailable');
  const cases = ['GOAD-Mini', 'GOAD-Light', 'GOAD'].flatMap(baseLab =>
    ['cy400test.org', 'lab.cy400test.org', 'a.b.cy400test.org'].map(domain => ({ baseLab, domain })));
  const plans = cases.map(({ baseLab, domain }) => planner.preflightGoadRebrand({
    goad: { version: baseLab, domain, rename_forest: true, extensions: ['elk', 'ws01', 'lx01'] },
  }).goad.rename_plan);
  const script = [
    'import hashlib, importlib.util, json, pathlib, sys',
    'root = pathlib.Path(sys.argv[1]).resolve()',
    "spec = importlib.util.spec_from_file_location('compiler', root / 'scripts/cybercore-rebrand.py')",
    'compiler = importlib.util.module_from_spec(spec)',
    'spec.loader.exec_module(compiler)',
    'outputs = []',
    'for plan in json.load(sys.stdin):',
    '    files, extensions, report = compiler.compile_plan(root, plan)',
    "    outputs.append({'config': json.loads(files['data/config.json']), 'extensions': {key: json.loads(data) for key, data in extensions.items()},",
    "                    'hashes': {key: hashlib.sha256(data).hexdigest() for key, data in files.items() if key not in {'data/config.json', 'playbooks.yml'}},",
    "                    'chain': json.loads(files['playbooks.yml']), 'identities': report['identities']})",
    'print(json.dumps(outputs))',
  ].join('\n');
  const result = spawnSync(python, ['-B', '-c', script, source], {
    input: JSON.stringify(plans), encoding: 'utf8', maxBuffer: 10 * 1024 * 1024, timeout: 30000,
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  const outputs = JSON.parse(result.stdout);
  for (const [index, input] of cases.entries()) {
    const reference = oracle.rebrandLab(input);
    const output = outputs[index];
    const label = `${input.baseLab} / ${input.domain}`;
    assert.equal(reference.labName, plans[index].lab_name, label);
    assert.deepEqual(output.config, reference.config, label + ' config');
    assert.deepEqual(output.extensions, Object.fromEntries(Object.entries(reference.extensionConfigs)
      .map(([key, data]) => [key, JSON.parse(data)])), label + ' extension config');
    assert.deepEqual(output.chain, reference.chain, label + ' playbook chain');
    assert.deepEqual(output.hashes, Object.fromEntries(Object.entries(reference.files)
      .filter(([key]) => key !== 'data/config.json')
      .map(([key, data]) => [key, crypto.createHash('sha256').update(data).digest('hex')])), label + ' payload bytes');
    const byName = identities => identities.slice().sort((a, b) => a.name.localeCompare(b.name));
    assert.deepEqual(byName(output.identities), byName(plans[index].expected_identities), label + ' observed identity plan');
  }
});
