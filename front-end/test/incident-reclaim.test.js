'use strict';

const test = require('node:test');
const assert = require('node:assert');

const runner = require('../src/incident/runner');

test('reclaim never deletes a log that is still being written', () => {
  // The live files are held open by cc-emit.js (writing) and filestream
  // (reading). Deleting them frees nothing -- the writer keeps the inode -- and
  // costs the class its baseline until the next restart. The globs must require
  // the hyphen so they can only ever match a ROTATED file.
  const cmd = runner.buildReclaimCommand();
  for (const live of ['host.json', 'logs.json']) {
    assert.ok(
      !new RegExp(`-name '${live.replace('.', '\.')}'`).test(cmd),
      `reclaim targets the live ${live}`
    );
  }
  assert.match(cmd, /-name 'host-\*\.json'/);
  assert.match(cmd, /-name 'logs-\*\.json'/);
});

test('rotated logs keep an ingestion grace so events are not lost', () => {
  // filestream finishes a rotated file after the rename. Deleting one it has
  // not harvested drops those events from Kibana silently -- no error, no gap
  // the console can see, just a hole in the data a student is graded on.
  const cmd = runner.buildReclaimCommand();
  const graces = [...cmd.matchAll(/host-\*\.json'[^;]*?-mmin \+(\d+)/g)].map((m) => Number(m[1]));
  assert.ok(graces.length, 'no grace window found on the rotated-log sweep');
  for (const g of graces) assert.ok(g >= 30, `grace of ${g} minutes is too short for filestream to finish`);
});

test('the find expression is escaped for the shell it is passed to', () => {
  // This ran through a JS template literal, where an unescaped \( collapses to
  // a bare ( and the guest gets a subshell instead of a find grouping. It fails
  // as a find syntax error, deletes nothing, and reports success.
  const cmd = runner.buildReclaimCommand();
  assert.ok(cmd.includes('\( -name'), 'find grouping lost its backslashes');
  assert.ok(cmd.includes('\) -mmin'), 'find grouping lost its closing backslash');
});

test('the guest reports enough to tell the instructor whether it worked', () => {
  const cmd = runner.buildReclaimCommand();
  assert.match(cmd, /before_kb=/);
  assert.match(cmd, /after_kb=/);
  assert.match(cmd, /total_kb=/);

  const parsed = runner.parseReclaim('reclaim before_kb=850612 after_kb=18874368 total_kb=23068672');
  assert.deepEqual(parsed, { before_kb: 850612, after_kb: 18874368, total_kb: 23068672 });
});

test('a guest that printed nothing usable is reported, not silently counted', () => {
  // A lane that is powered off, or whose agent is wedged, must not be folded
  // into the success count -- that is the lane the instructor still has to fix.
  assert.deepEqual(
    runner.parseReclaim(''),
    { before_kb: null, after_kb: null, total_kb: null }
  );
  assert.deepEqual(
    runner.parseReclaim('bash: journalctl: command not found'),
    { before_kb: null, after_kb: null, total_kb: null }
  );
});

test('reclaim claims the unused disk, not just deleted files', () => {
  // The bake grows the block device by 12G and cloud-init's growpart does not
  // traverse LVM, so every lane ran a 10G filesystem on a 22G disk. Reclaiming
  // that is worth more than every deletion in this command combined.
  const cmd = runner.buildReclaimCommand();
  for (const step of ['growpart', 'pvresize', 'lvextend', 'xfs_growfs']) {
    assert.ok(cmd.includes(step), `LVM step ${step} is missing; the disk stays 10G`);
  }
});
