/**
 * Framework catalog loader. Loads CIS IG1 and NIST CSF 2.0 from data/frameworks/
 * once at first require, caches singletons.
 *
 * The CRA dashboard, the IG1 → CSF aggregation, and the PDF appendix all
 * resolve framework definitions through here so adding HIPAA later is one file.
 */

const fs = require('fs');
const path = require('path');

const FRAMEWORKS_DIR = path.join(__dirname, '..', 'data', 'frameworks');

let cisIg1   = null;
let nistCsf  = null;
let csfFunctionMap = null;   // ID → function object (built lazily)

function loadJson(filename) {
  return JSON.parse(fs.readFileSync(path.join(FRAMEWORKS_DIR, filename), 'utf8'));
}

function getCisIg1() {
  if (!cisIg1) cisIg1 = loadJson('cis-ig1.json');
  return cisIg1;
}

function getNistCsf() {
  if (!nistCsf) nistCsf = loadJson('nist-csf-2.0.json');
  return nistCsf;
}

function getCsfFunctionMap() {
  if (!csfFunctionMap) {
    csfFunctionMap = {};
    for (const fn of getNistCsf().functions) csfFunctionMap[fn.id] = fn;
  }
  return csfFunctionMap;
}

/**
 * Score one IG1 response value 0–1 (yes=1, partial=0.5, no=0, unknown=0).
 */
function ig1Score(value) {
  if (value === 'yes')     return 1;
  if (value === 'partial') return 0.5;
  return 0;
}

/**
 * Aggregate IG1 yes/partial/no/unknown responses into per-CSF-function maturity
 * scores 0–5. Each IG1 control's average response score is mapped to all CSF
 * functions it crosswalks to, then averaged per function and scaled to 5.
 *
 * Returns: { GV: 0–5, ID: 0–5, PR: 0–5, DE: 0–5, RS: 0–5, RC: 0–5 }
 *
 * @param {object} ig1Section — the `ig1` section of an intake payload.
 *   Keys are `ig1_X.X` with values 'yes'|'partial'|'no'|'unknown'.
 */
function aggregateIg1ToCsf(ig1Section) {
  const ig1 = getCisIg1();
  const crosswalk = ig1.csf_function_crosswalk || {};
  const safeguards = ig1.safeguards || [];
  const result = { GV: [], ID: [], PR: [], DE: [], RS: [], RC: [] };

  // Group safeguard scores by control number.
  const byControl = {};
  for (const sg of safeguards) {
    const v = ig1Section?.[`ig1_${sg.num}`];
    if (!v) continue;  // unanswered = doesn't contribute
    if (!byControl[sg.control]) byControl[sg.control] = [];
    byControl[sg.control].push(ig1Score(v));
  }

  // For each answered control, push its average score into each CSF function it maps to.
  for (const [controlNum, scores] of Object.entries(byControl)) {
    const fns = crosswalk[controlNum];
    if (!fns || scores.length === 0) continue;
    const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
    for (const fn of fns) {
      if (result[fn]) result[fn].push(avg);
    }
  }

  const out = {};
  for (const fn of Object.keys(result)) {
    const arr = result[fn];
    out[fn] = arr.length === 0 ? 0 : Math.round((arr.reduce((a, b) => a + b, 0) / arr.length) * 5 * 10) / 10;
  }
  return out;
}

/**
 * IG1 coverage: percent of safeguards answered yes (full credit) + partial (half).
 * Used by the dashboard's CIS coverage bar.
 */
function ig1Coverage(ig1Section) {
  const safeguards = getCisIg1().safeguards || [];
  if (safeguards.length === 0) return { yes: 0, partial: 0, no: 0, unknown: 0, score: 0, total: 0 };
  const buckets = { yes: 0, partial: 0, no: 0, unknown: 0 };
  for (const sg of safeguards) {
    const v = ig1Section?.[`ig1_${sg.num}`];
    if (!v) buckets.unknown++;
    else if (v === 'yes')     buckets.yes++;
    else if (v === 'partial') buckets.partial++;
    else if (v === 'no')      buckets.no++;
    else                      buckets.unknown++;
  }
  const score = Math.round(((buckets.yes + buckets.partial * 0.5) / safeguards.length) * 100);
  return { ...buckets, score, total: safeguards.length };
}

module.exports = {
  getCisIg1,
  getNistCsf,
  getCsfFunctionMap,
  aggregateIg1ToCsf,
  ig1Coverage,
  ig1Score,
};
