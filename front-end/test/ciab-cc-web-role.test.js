/**
 * ciab-cc-web-role.test.js — Track W2: the curated web ansible role is the
 * thing that makes the deployed site match the paper.
 *
 * WHY THIS FILE EXISTS
 * infrastructure/ansible/cc-web/ is YAML. Nothing in `npm test` executes it,
 * no CI box runs ansible, and the role's real failure mode is not a crash — it
 * is a task that reports SUCCESS and did nothing. An audit of the upstream GOAD
 * tree this role sits beside found TWENTY such sites, three of them shipped
 * vulnerabilities that are simply not present on the lane (vulns/adcs_esc7's
 * inverted Get-Module guard, move_to_ou consuming its own success stream with
 * `> $null`, no_ldap_signing writing a registry path Windows does not read).
 * Tree-wide, `changed_when` appears exactly TWICE and `error_action: stop` SIX
 * times, so neither "changed" nor the exit code carries information.
 *
 * So this file is static analysis with a specific job: hold the CyberCore role
 * to the rules the audit says GOAD's roles break, and hold the tree to the
 * boundary that keeps GOAD's roles read-only.
 *
 * ON THE PARSER, AND WHY IT IS HAND-ROLLED
 * The repo has no YAML dependency and the house rule is that validation is
 * hand-rolled (no ajv/joi/zod), so this file carries a small, deliberately
 * strict reader for the YAML SUBSET the role is written in: block mappings,
 * block sequences, compact `- key: value` items, block scalars, single-level
 * flow collections, quoted and plain scalars, comments.
 *
 * A REGEX SWEEP WOULD NOT HAVE BEEN ENOUGH. Half the rules below are per-TASK
 * ("this shell task must set changed_when", "this module's args must include
 * error_action"), and a task is a structural unit — its keys are whichever
 * lines sit at one indent under a `- name:`. Regex cannot see that boundary, so
 * a sweep would either miss a violation in the next task or credit a task with
 * its neighbour's changed_when.
 *
 * THE PARSER IS ITSELF UNDER TEST, for the obvious reason: a reader that
 * returned {} for every file would make every assertion below pass vacuously,
 * which is precisely the failure mode this file exists to catch. Section 0
 * round-trips a fixture that exercises each supported construct and asserts the
 * reader REJECTS malformed input. Section 1 then cross-checks the parse against
 * the raw text (the number of parsed tasks must equal the number of `- name:`
 * lines at task indent), so a reader that silently dropped tasks cannot hide.
 *
 * The reader is stricter than YAML on purpose — it rejects tabs, trailing
 * whitespace, inconsistent indentation, duplicate keys and multi-document
 * files. A file that passes here is a file the next reader can follow.
 *
 * Run: node --test front-end/test/ciab-cc-web-role.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const REPO = path.join(__dirname, '..', '..');
const TREE = path.join(REPO, 'infrastructure', 'ansible', 'cc-web');
const ROLE = path.join(TREE, 'roles', 'cc_web');

// ════════════════════════════════════════════════════════════════════════════
// 0. the reader
// ════════════════════════════════════════════════════════════════════════════

function indentOf(line) {
  return line.length - line.replace(/^ +/, '').length;
}

function unquote(s) {
  if (s.length >= 2 && s[0] === '"' && s[s.length - 1] === '"') return readDouble(s).value;
  if (s.length >= 2 && s[0] === "'" && s[s.length - 1] === "'") return readSingle(s).value;
  return s;
}

function readDouble(s) {
  let out = '';
  let i = 1;
  while (i < s.length) {
    const c = s[i];
    if (c === '\\') {
      const n = s[i + 1];
      if (n === 'n') out += '\n';
      else if (n === 't') out += '\t';
      else if (n === 'r') out += '\r';
      else out += n; // \\ -> \, \" -> ", \s -> s ... YAML would reject the last
      i += 2;
      continue;
    }
    if (c === '"') return { value: out, after: s.slice(i + 1) };
    out += c;
    i++;
  }
  throw new Error('unterminated double-quoted scalar');
}

function readSingle(s) {
  let out = '';
  let i = 1;
  while (i < s.length) {
    if (s[i] === "'") {
      if (s[i + 1] === "'") { out += "'"; i += 2; continue; }
      return { value: out, after: s.slice(i + 1) };
    }
    out += s[i];
    i++;
  }
  throw new Error('unterminated single-quoted scalar');
}

/**
 * Find the `key:` separator of a block-mapping line: the first colon at flow
 * depth 0, outside quotes, followed by whitespace or end of line. Returns null
 * when the line is not a mapping entry (a bare scalar in a sequence, say).
 */
function splitKey(s) {
  let i = 0;
  let depth = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '"' || c === "'") {
      const r = c === '"' ? readDouble(s.slice(i)) : readSingle(s.slice(i));
      i = s.length - r.after.length;
      continue;
    }
    if (c === '#' && (i === 0 || /\s/.test(s[i - 1]))) break;
    if (c === '[' || c === '{') { depth++; i++; continue; }
    if (c === ']' || c === '}') { depth--; i++; continue; }
    if (c === ':' && depth === 0 && (i + 1 >= s.length || /\s/.test(s[i + 1]))) {
      const key = s.slice(0, i).trim();
      if (!key) return null;
      return { key: unquote(key), rest: s.slice(i + 1).trim() };
    }
    i++;
  }
  return null;
}

function coerce(v) {
  if (v === '' || v === '~' || v === 'null') return null;
  if (v === 'true') return true;
  if (v === 'false') return false;
  if (/^-?\d+$/.test(v)) return parseInt(v, 10);
  if (/^-?\d*\.\d+$/.test(v)) return parseFloat(v);
  return v;
}

function splitFlow(inner) {
  const parts = [];
  let cur = '';
  let i = 0;
  while (i < inner.length) {
    const c = inner[i];
    if (c === '"' || c === "'") {
      const r = c === '"' ? readDouble(inner.slice(i)) : readSingle(inner.slice(i));
      const consumed = inner.length - i - r.after.length;
      cur += inner.slice(i, i + consumed);
      i += consumed;
      continue;
    }
    if (c === ',') { parts.push(cur); cur = ''; i++; continue; }
    cur += c;
    i++;
  }
  if (cur.trim() !== '') parts.push(cur);
  return parts;
}

function parseFlow(s, at) {
  const open = s[0];
  const close = open === '[' ? ']' : '}';
  const end = s.lastIndexOf(close);
  if (end < 0) throw new Error(`${at}: unterminated flow collection`);
  const tail = s.slice(end + 1).trim();
  if (tail && !tail.startsWith('#')) throw new Error(`${at}: trailing content after flow collection`);
  const inner = s.slice(1, end).trim();
  if (inner === '') return open === '[' ? [] : {};
  if (/[[\]{}]/.test(inner)) {
    // Deliberate: a nested flow collection is legal YAML and unreadable in a
    // role. Refusing it here keeps the reader small AND keeps the role plain.
    throw new Error(`${at}: nested flow collections are not supported`);
  }
  const parts = splitFlow(inner);
  if (open === '[') return parts.map((p) => parseScalar(p.trim(), at));
  const obj = {};
  for (const p of parts) {
    const kv = splitKey(p.trim());
    if (!kv) throw new Error(`${at}: flow mapping entry '${p}' is not key: value`);
    obj[kv.key] = parseScalar(kv.rest, at);
  }
  return obj;
}

function parseScalar(rest, at) {
  if (rest.startsWith('"')) {
    const r = readDouble(rest);
    const tail = r.after.trim();
    if (tail && !tail.startsWith('#')) throw new Error(`${at}: trailing content after quoted scalar`);
    return r.value;
  }
  if (rest.startsWith("'")) {
    const r = readSingle(rest);
    const tail = r.after.trim();
    if (tail && !tail.startsWith('#')) throw new Error(`${at}: trailing content after quoted scalar`);
    return r.value;
  }
  if (rest.startsWith('[') || rest.startsWith('{')) return parseFlow(rest, at);
  let v = rest;
  const cut = v.search(/\s#/);
  if (cut >= 0) v = v.slice(0, cut);
  return coerce(v.trim());
}

function skipBlanks(st) {
  while (st.i < st.lines.length) {
    const l = st.lines[st.i];
    if (l.trim() === '' || /^\s*#/.test(l)) { st.i++; continue; }
    return;
  }
}

function parseBlockScalar(st, indent, style, chomp) {
  const out = [];
  let child = null;
  while (st.i < st.lines.length) {
    const line = st.lines[st.i];
    if (line.trim() === '') { out.push(''); st.i++; continue; }
    const ind = indentOf(line);
    if (ind <= indent) break;
    if (child === null) child = ind;
    if (ind < child) break;
    out.push(line.slice(child));
    st.i++;
  }
  while (out.length && out[out.length - 1] === '') out.pop();
  let text;
  if (style === '|') {
    text = out.join('\n');
  } else {
    const parts = [];
    for (const l of out) {
      if (l === '') parts.push('\n');
      else if (parts.length && parts[parts.length - 1] !== '\n') parts[parts.length - 1] += ' ' + l;
      else parts.push(l);
    }
    text = parts.join('');
  }
  if (chomp !== '-') text += '\n';
  return text;
}

function parseValue(st, indent, rest, at) {
  const bs = rest.match(/^([|>])([+-]?)\s*(#.*)?$/);
  if (bs) return parseBlockScalar(st, indent, bs[1], bs[2]);
  if (rest !== '' && !rest.startsWith('#')) return parseScalar(rest, at);
  skipBlanks(st);
  if (st.i >= st.lines.length) return null;
  const ind = indentOf(st.lines[st.i]);
  if (ind < indent) return null;
  if (ind === indent) {
    const body = st.lines[st.i].slice(ind);
    if (/^-(\s|$)/.test(body)) return parseSequence(st, indent);
    return null;
  }
  return parseNode(st, ind);
}

function parseMapping(st, indent) {
  const map = {};
  for (;;) {
    skipBlanks(st);
    if (st.i >= st.lines.length) break;
    const line = st.lines[st.i];
    const ind = indentOf(line);
    if (ind < indent) break;
    if (ind > indent) {
      throw new Error(`${st.file}:${st.i + 1}: indent ${ind} where ${indent} was expected`);
    }
    const body = line.slice(ind);
    if (/^-(\s|$)/.test(body)) break;
    const kv = splitKey(body);
    if (!kv) throw new Error(`${st.file}:${st.i + 1}: '${body}' is not a 'key: value' line`);
    if (Object.prototype.hasOwnProperty.call(map, kv.key)) {
      throw new Error(`${st.file}:${st.i + 1}: duplicate key '${kv.key}'`);
    }
    const at = `${st.file}:${st.i + 1}`;
    st.i++;
    map[kv.key] = parseValue(st, indent, kv.rest, at);
  }
  return map;
}

function parseSequence(st, indent) {
  const arr = [];
  for (;;) {
    skipBlanks(st);
    if (st.i >= st.lines.length) break;
    const line = st.lines[st.i];
    const ind = indentOf(line);
    if (ind < indent) break;
    if (ind > indent) {
      throw new Error(`${st.file}:${st.i + 1}: indent ${ind} where ${indent} was expected`);
    }
    const body = line.slice(ind);
    const m = body.match(/^-( +)?/);
    if (!m) break;
    const gap = m[1] ? m[1].length : 0;
    const rest = body.slice(1 + gap);
    const at = `${st.file}:${st.i + 1}`;
    if (rest === '' || rest.startsWith('#')) {
      st.i++;
      skipBlanks(st);
      if (st.i < st.lines.length && indentOf(st.lines[st.i]) > indent) {
        arr.push(parseNode(st, indentOf(st.lines[st.i])));
      } else {
        arr.push(null);
      }
      continue;
    }
    const kv = splitKey(rest);
    if (kv) {
      // Compact mapping item: rewrite the line so the key sits at its real
      // column, then let parseMapping own it and every sibling under it.
      const col = ind + 1 + gap;
      st.lines[st.i] = ' '.repeat(col) + rest;
      arr.push(parseMapping(st, col));
      continue;
    }
    st.i++;
    arr.push(parseScalar(rest, at));
  }
  return arr;
}

function parseNode(st, indent) {
  skipBlanks(st);
  if (st.i >= st.lines.length) return null;
  const ind = indentOf(st.lines[st.i]);
  if (ind < indent) return null;
  if (ind > indent) throw new Error(`${st.file}:${st.i + 1}: indent ${ind} where ${indent} was expected`);
  const body = st.lines[st.i].slice(ind);
  if (/^-(\s|$)/.test(body)) return parseSequence(st, indent);
  return parseMapping(st, indent);
}

function parseYaml(text, file) {
  const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/);
  lines.forEach((l, n) => {
    if (l.includes('\t')) throw new Error(`${file}:${n + 1}: tab character`);
    if (l !== '' && /\s$/.test(l)) throw new Error(`${file}:${n + 1}: trailing whitespace`);
  });
  const st = { lines, file, i: 0 };
  skipBlanks(st);
  if (st.i < lines.length && lines[st.i].trim() === '---') st.i++;
  for (let j = st.i; j < lines.length; j++) {
    const t = lines[j].trim();
    if (t === '---' || t === '...') throw new Error(`${file}:${j + 1}: multi-document YAML is not supported`);
  }
  const value = parseNode(st, 0);
  skipBlanks(st);
  if (st.i < lines.length) throw new Error(`${file}:${st.i + 1}: unexpected trailing content`);
  return value;
}

// ── the reader is under test before anything is measured with it ────────────

const PARSER_FIXTURE = [
  '---',
  '# leading comment',
  'top: value          # trailing comment',
  'num: 3650',
  'quoted: "0640"',
  'empty_map: {}',
  'empty_list: []',
  'flow_list: [a, b]',
  'flow_map: {x: 1, y: two}',
  'nested:',
  '  a: 1',
  '  b:',
  '    - one',
  '    - two',
  'tasks:',
  '  - name: first',
  '    command:',
  '      cmd: echo hi',
  '    changed_when: false',
  '  - name: second',
  '    msg: >-',
  '      folded across',
  '      two lines',
  '  - name: third',
  '    msg: |',
  '      literal: with a colon',
  '      # not a comment here',
  '',
].join('\n');

test('the reader round-trips every construct the role is written in', () => {
  const got = parseYaml(PARSER_FIXTURE, '<fixture>');
  assert.strictEqual(got.top, 'value');
  assert.strictEqual(got.num, 3650);
  assert.strictEqual(got.quoted, '0640', 'a quoted 0640 must stay a STRING, not become 640');
  assert.deepStrictEqual(got.empty_map, {});
  assert.deepStrictEqual(got.empty_list, []);
  assert.deepStrictEqual(got.flow_list, ['a', 'b']);
  assert.deepStrictEqual(got.flow_map, { x: 1, y: 'two' });
  assert.deepStrictEqual(got.nested, { a: 1, b: ['one', 'two'] });
  assert.strictEqual(got.tasks.length, 3);
  assert.deepStrictEqual(got.tasks[0], {
    name: 'first', command: { cmd: 'echo hi' }, changed_when: false,
  });
  assert.strictEqual(got.tasks[1].msg, 'folded across two lines');
  assert.strictEqual(got.tasks[2].msg, 'literal: with a colon\n# not a comment here\n');
});

test('the reader refuses the malformed input a vacuous reader would swallow', () => {
  // Each of these would, if accepted, let a broken role file pass every
  // assertion below. A reader that never throws is a reader that measures
  // nothing.
  const bad = {
    tab: 'a:\n\t- x\n',
    indent: 'a:\n  b: 1\n   c: 2\n',
    duplicate: 'a: 1\na: 2\n',
    multidoc: 'a: 1\n---\nb: 2\n',
    nestedflow: 'a: [[1, 2]]\n',
    unterminated: 'a: "no closing quote\n',
    trailingws: 'a: 1 \n',
  };
  for (const [label, text] of Object.entries(bad)) {
    assert.throws(() => parseYaml(text, `<${label}>`), new RegExp('.'), `${label} must be rejected`);
  }
});

// ════════════════════════════════════════════════════════════════════════════
// harness
// ════════════════════════════════════════════════════════════════════════════

function walk(dir, acc) {
  const out = acc || [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

const ALL_FILES = walk(TREE);
const rel = (p) => path.relative(REPO, p).split(path.sep).join('/');
const read = (p) => fs.readFileSync(p, 'utf8');

const YAML_FILES = ALL_FILES.filter((f) => /\.ya?ml$/.test(f));
const TASK_FILES = YAML_FILES.filter((f) => f.includes(path.join('roles', 'cc_web', 'tasks')));
const TEMPLATE_FILES = ALL_FILES.filter((f) => f.endsWith('.j2'));

const parsed = new Map();
for (const f of YAML_FILES) parsed.set(f, parseYaml(read(f), rel(f)));

const defaults = parsed.get(path.join(ROLE, 'defaults', 'main.yml'));
const roleVars = parsed.get(path.join(ROLE, 'vars', 'main.yml'));

/** Every task in every task file, flattened, with its origin. */
const TASKS = [];
for (const f of TASK_FILES) {
  const list = parsed.get(f);
  if (!Array.isArray(list)) continue;
  list.forEach((t, idx) => TASKS.push({ file: rel(f), index: idx, task: t }));
}

// Keys that are ansible task KEYWORDS rather than the module being called.
const TASK_KEYWORDS = new Set([
  'name', 'when', 'become', 'become_user', 'become_method', 'register', 'loop',
  'loop_control', 'with_items', 'with_dict', 'changed_when', 'failed_when',
  'ignore_errors', 'no_log', 'tags', 'vars', 'notify', 'listen', 'delegate_to',
  'run_once', 'until', 'retries', 'delay', 'args', 'environment', 'check_mode',
  'diff', 'any_errors_fatal', 'throttle', 'connection', 'timeout',
]);

function moduleOf(task) {
  const keys = Object.keys(task).filter((k) => !TASK_KEYWORDS.has(k));
  return keys.length === 1 ? keys[0] : null;
}

const shortModule = (m) => String(m).replace(/^ansible\.(builtin|windows)\./, '')
  .replace(/^community\.[a-z]+\./, '');

// ════════════════════════════════════════════════════════════════════════════
// 1. the files parse, and the parse agrees with the raw text
// ════════════════════════════════════════════════════════════════════════════

test('the role tree exists and carries the files the README describes', () => {
  const expected = [
    'ansible.cfg', 'README.md', 'cc-web.yml',
    'roles/cc_web/defaults/main.yml', 'roles/cc_web/vars/main.yml',
    'roles/cc_web/meta/main.yml', 'roles/cc_web/handlers/main.yml',
    'roles/cc_web/tasks/main.yml', 'roles/cc_web/tasks/resolve.yml',
    'roles/cc_web/tasks/assert.yml', 'roles/cc_web/tasks/packages.yml',
    'roles/cc_web/tasks/content.yml', 'roles/cc_web/tasks/banner.yml',
    'roles/cc_web/tasks/tls.yml', 'roles/cc_web/tasks/vhosts.yml',
    'roles/cc_web/tasks/pivot_credential.yml', 'roles/cc_web/tasks/verify.yml',
  ];
  for (const f of expected) {
    assert.ok(fs.existsSync(path.join(TREE, f)), `${f} is missing from the cc-web tree`);
  }
});

test('every task file parses as a list of named tasks', () => {
  assert.ok(TASK_FILES.length >= 10, 'the task files disappeared — check the tree layout');
  for (const f of TASK_FILES) {
    const list = parsed.get(f);
    assert.ok(Array.isArray(list), `${rel(f)} must be a YAML sequence of tasks`);
    assert.ok(list.length > 0, `${rel(f)} has no tasks`);
    list.forEach((t, i) => {
      assert.ok(t && typeof t === 'object' && !Array.isArray(t),
        `${rel(f)}[${i}] is not a mapping`);
      assert.ok(typeof t.name === 'string' && t.name.trim().length > 0,
        `${rel(f)}[${i}] has no name — an unnamed task is unreadable in a 90-minute run's output`);
      assert.ok(moduleOf(t), `${rel(f)} '${t.name}': expected exactly one module key, got `
        + `[${Object.keys(t).filter((k) => !TASK_KEYWORDS.has(k)).join(', ')}]`);
    });
  }
});

test('the parse agrees with the raw text about how many tasks there are', () => {
  // The guard against a reader that silently drops tasks: count the `- name:`
  // lines at column 0 and require the same number of parsed entries. Every
  // assertion in this file is only as good as this equality.
  for (const f of TASK_FILES) {
    const raw = read(f).split(/\r?\n/).filter((l) => /^- name:/.test(l)).length;
    assert.strictEqual(parsed.get(f).length, raw,
      `${rel(f)}: parsed ${parsed.get(f).length} tasks but the file has ${raw} '- name:' lines at task indent`);
  }
});

test('defaults, vars, meta and handlers parse into the shapes the role expects', () => {
  assert.ok(defaults && typeof defaults === 'object' && !Array.isArray(defaults));
  assert.ok(roleVars && typeof roleVars === 'object' && !Array.isArray(roleVars));
  const meta = parsed.get(path.join(ROLE, 'meta', 'main.yml'));
  assert.deepStrictEqual(meta.dependencies, [],
    'meta dependencies must stay empty — a dependency resolves through roles_path, '
    + "whose later entries are upstream GOAD's read-only tree");
  const handlers = parsed.get(path.join(ROLE, 'handlers', 'main.yml'));
  assert.ok(Array.isArray(handlers) && handlers.length > 0);
  for (const h of handlers) {
    assert.ok(typeof h.listen === 'string' && h.listen.length > 0,
      `handler '${h.name}' must be addressed by \`listen\` — ansible does not error on a `
      + 'notify that matches nothing, so a renamed handler silently stops restarting');
  }
});

// ════════════════════════════════════════════════════════════════════════════
// 2. the boundary: CyberCore's tree can never shadow a GOAD role
// ════════════════════════════════════════════════════════════════════════════

function readAnsibleCfg() {
  const out = {};
  for (const line of read(path.join(TREE, 'ansible.cfg')).split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#') || t.startsWith(';') || t.startsWith('[')) continue;
    const eq = t.indexOf('=');
    if (eq < 0) continue;
    out[t.slice(0, eq).trim()] = t.slice(eq + 1).trim();
  }
  return out;
}

test("roles_path puts the local tree FIRST and still reaches GOAD's read-only roles", () => {
  const cfg = readAnsibleCfg();
  assert.ok(cfg.roles_path, 'ansible.cfg must define roles_path');
  const entries = cfg.roles_path.split(':').map((s) => s.trim()).filter(Boolean);
  assert.strictEqual(entries[0], './roles',
    `roles_path must start with ./roles, got '${entries[0]}'. Ansible takes the FIRST hit, `
    + 'so anything ahead of the local tree can resolve cc_web to someone else\'s directory.');
  assert.ok(entries.some((e) => /goad.*ansible\/roles$/i.test(e)),
    "roles_path must still reach upstream GOAD's roles — the point of the pattern is that "
    + 'core stays reachable and unedited, not that it disappears');
  // Upstream's own extension configs (extensions/*/ansible/ansible.cfg) are
  // spelled the same way. Diverging from them is how the next person concludes
  // this tree is a special case and edits ansible/roles/ instead.
  assert.ok(entries.length >= 2, 'roles_path must list the local tree and at least one GOAD tree');
});

test('every CyberCore role is cc_-prefixed, which is what makes shadowing impossible', () => {
  // Precedence alone guarantees nothing — first-wins is exactly what makes
  // shadowing possible. The naming rule is the guarantee: upstream has no
  // cc_-prefixed role, so no ordering of roles_path can change which directory
  // a GOAD play resolves.
  //
  // The hazard is real: the pinned GOAD tree already carries TWO different
  // roles called adcs_templates (ansible/roles/adcs_templates and
  // ansible/roles/vulns/adcs_templates), reached through different path
  // entries by different playbooks.
  const roles = fs.readdirSync(path.join(TREE, 'roles'), { withFileTypes: true })
    .filter((d) => d.isDirectory()).map((d) => d.name);
  assert.ok(roles.length > 0, 'roles/ is empty');
  for (const name of roles) {
    assert.ok(/^cc_/.test(name),
      `role '${name}' must be cc_-prefixed; without the prefix roles_path ordering becomes `
      + 'the only thing standing between this tree and a GOAD role of the same name');
  }
});

test('no CyberCore role name collides with a vendored GOAD role name', () => {
  // Cross-checked against the tracked manifest rather than against a GOAD
  // checkout, for the reason ciab-goad-role-manifest.test.js spells out: a
  // check that can only run on a machine with GOAD-main/ passes vacuously
  // everywhere else, including CI.
  const manifest = JSON.parse(read(path.join(
    REPO, 'front-end/modules/crucible/plugins/ciab/data/goad-role-manifest.json')));
  const goadNames = new Set(manifest.roles.map((r) => r.name));
  const roles = fs.readdirSync(path.join(TREE, 'roles'), { withFileTypes: true })
    .filter((d) => d.isDirectory()).map((d) => d.name);
  for (const name of roles) {
    assert.ok(!goadNames.has(name), `role '${name}' collides with a vendored GOAD role name`);
  }
  assert.ok(![...goadNames].some((n) => /^cc_/.test(n)),
    'upstream has grown a cc_-prefixed role — the prefix rule no longer guarantees anything '
    + 'and this tree needs a new namespace');
});

test('no file in the tree lands on a repository .gitignore rule', () => {
  // The exact trap ciab-goad-role-manifest.test.js documents for the manifest:
  // .gitignore carries `**/data/*`, `**/certs/**`, `**/secrets/*`,
  // `**/credentials/*` and a bare `site.yml`. A role file under any of those
  // names works perfectly on the machine that wrote it, is absent everywhere
  // else, and shows up in no diff.
  const bannedSegments = ['data', 'certs', 'secrets', 'credentials', 'cookies'];
  const bannedNames = ['site.yml', 'site.json', 'secrets.env', 'role_id'];
  for (const f of ALL_FILES) {
    const parts = rel(f).split('/');
    for (const seg of parts.slice(0, -1)) {
      assert.ok(!bannedSegments.includes(seg),
        `${rel(f)} sits under a gitignored directory name ('${seg}') and would be untracked`);
    }
    assert.ok(!bannedNames.includes(parts[parts.length - 1]),
      `${rel(f)} matches a gitignored filename and would be untracked`);
    assert.ok(!/\.(bkp|backup)$/.test(f), `${rel(f)} matches a gitignored suffix`);
  }
});

// ════════════════════════════════════════════════════════════════════════════
// 3. no tenant identity anywhere in the role
// ════════════════════════════════════════════════════════════════════════════

// RFC 2606 / RFC 6761 reserved names are placeholders, not tenants, and the
// README needs to show the shape of a value somewhere.
const RESERVED_FQDN = /(^|\.)(example|invalid|test|localhost)$/i;
const RESERVED_EXACT = new Set(['example.com', 'example.net', 'example.org']);
const FQDN = /\b(?:[a-z0-9][a-z0-9-]*\.)+(?:com|net|org|local|corp|internal|intranet|lan|example|invalid|test)\b/gi;

test('no hostname or domain literal appears anywhere in the tree', () => {
  for (const f of ALL_FILES) {
    const text = read(f);
    for (const m of text.matchAll(FQDN)) {
      const host = m[0].toLowerCase();
      const tld = host.slice(host.lastIndexOf('.') + 1);
      const ok = RESERVED_FQDN.test(`.${tld}`) || RESERVED_EXACT.has(host);
      assert.ok(ok,
        `${rel(f)} contains the hostname literal '${m[0]}'. The AI generates the content; `
        + 'this role installs it. Identity reaches the role through cc_web_server_name '
        + 'and the web-facts contract, never as a literal.');
    }
  }
});

test('no address literal other than loopback appears anywhere in the tree', () => {
  const QUAD = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
  const ALLOWED = new Set(['127.0.0.1', '0.0.0.0', '255.255.255.255']);
  for (const f of ALL_FILES) {
    for (const m of read(f).matchAll(QUAD)) {
      assert.ok(ALLOWED.has(m[0]),
        `${rel(f)} contains the address literal '${m[0]}'. Lane addressing is the deployer's `
        + 'business; the only address this role may know is the loopback it probes itself on.');
    }
  }
});

test('no credential literal appears anywhere in the tree', () => {
  // A secret-shaped key must resolve to a Jinja reference or to nothing. The
  // point is not that a literal here would leak — it is that a role with a
  // default password ships that password to every lane that forgets to override
  // it, and no one finds out until an audit.
  const SECRET = /\b(pass(?:word|wd)?|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*(\S.*)?$/gim;
  for (const f of ALL_FILES) {
    for (const m of read(f).matchAll(SECRET)) {
      const value = (m[2] || '').trim();
      const ok = value === '' || value === '{}' || value === '[]' || value === '""'
        || value === "''" || /^["']?\{\{/.test(value) || /^["']?\$\{/.test(value)
        || value.startsWith('|') || value.startsWith('>');
      assert.ok(ok,
        `${rel(f)} assigns a literal to a secret-shaped key: '${m[0].trim()}'. `
        + 'Secrets arrive from the caller (extra-vars or a vaulted file); defaults/ never carries one.');
    }
  }
});

test('defaults/ declares the identity-bearing variables and leaves every one of them empty', () => {
  assert.deepStrictEqual(defaults.cc_web_facts, {},
    'cc_web_facts must be declared and empty — declared so a reader can find the contract, '
    + 'empty so assert.yml can tell "not passed" from "passed as nothing"');
  assert.deepStrictEqual(defaults.cc_web_pivot, {},
    'cc_web_pivot must be declared and empty; a password with a default is a password that ships');
  assert.deepStrictEqual(defaults.cc_web_routes, [], 'cc_web_routes must be declared and empty');
  assert.strictEqual(defaults.cc_web_server_name, '',
    'cc_web_server_name must be declared and empty');
  assert.strictEqual(defaults.cc_web_pivot_required, true,
    'defaulting cc_web_pivot_required to false would make "we forgot the credential" and '
    + '"this host has no credential by design" the same silent outcome');
});

test('every verification switch defaults to ON', () => {
  // A verification you have to remember to enable is a verification that is off
  // on the lane that mattered.
  for (const [k, v] of Object.entries(defaults)) {
    if (!/^cc_web_verify_/.test(k)) continue;
    assert.strictEqual(v, true, `${k} must default to true`);
  }
  assert.ok(Object.keys(defaults).filter((k) => /^cc_web_verify_/.test(k)).length >= 4,
    'the verification switches vanished from defaults/');
});

test('templates carry no identity of their own', () => {
  // The positive form of the rule: every directive that names identity must be
  // templated. An assertion that only looks for known-bad strings cannot see a
  // hostname nobody thought of.
  const IDENTITY_DIRECTIVES = /^\s*(ServerName|ServerAlias|ServerAdmin|DocumentRoot|SSLCertificateFile|SSLCertificateKeyFile|Listen)\s+(.*)$/gim;
  for (const f of TEMPLATE_FILES) {
    for (const m of read(f).matchAll(IDENTITY_DIRECTIVES)) {
      assert.ok(/\{\{/.test(m[2]),
        `${rel(f)} hardcodes '${m[0].trim()}'. Identity-bearing directives must be templated `
        + 'from cc_web_* variables.');
    }
  }
});

// ════════════════════════════════════════════════════════════════════════════
// 4. the quality rules the GOAD audit says roles break
// ════════════════════════════════════════════════════════════════════════════

const POWERSHELL_MODULES = new Set(['win_powershell', 'powershell']);
const SHELLY_MODULES = new Set(['shell', 'command', 'raw', 'win_shell', 'win_command']);

/**
 * The two checkers, extracted so section 4 can prove they BITE. The role is
 * Linux-only, so there is no win_powershell task in it today and the
 * error_action rule would otherwise be vacuous — the exact shape of test this
 * repo distrusts. Running the checker against a fixture makes it a live rule
 * that catches the first IIS task anyone adds.
 */
function powershellViolations(tasks) {
  const bad = [];
  for (const { file, task } of tasks) {
    const mod = moduleOf(task);
    if (!mod || !POWERSHELL_MODULES.has(shortModule(mod))) continue;
    const args = task[mod];
    const ea = args && typeof args === 'object' ? args.error_action : undefined;
    if (ea !== 'stop') bad.push(`${file}: '${task.name}'`);
  }
  return bad;
}

function shellViolations(tasks) {
  const bad = [];
  for (const { file, task } of tasks) {
    const mod = moduleOf(task);
    if (!mod || !SHELLY_MODULES.has(shortModule(mod))) continue;
    if (!('changed_when' in task)) bad.push(`${file}: '${task.name}'`);
  }
  return bad;
}

test('every shell/command task states explicitly whether it changed anything', () => {
  // DELIBERATELY STRICTER THAN "changed_when OR failed_when". `failed_when`
  // alone leaves "changed" meaningless, and `changed_when` is the one GOAD
  // drops — it appears TWICE in the whole upstream tree. A replay-based
  // recovery model needs "changed" to mean something on the second run.
  const bad = shellViolations(TASKS);
  assert.deepStrictEqual(bad, [],
    `these shell/command tasks set no changed_when:\n  ${bad.join('\n  ')}`);
  const shelly = TASKS.filter((t) => {
    const m = moduleOf(t.task);
    return m && SHELLY_MODULES.has(shortModule(m));
  });
  assert.ok(shelly.length >= 4,
    'the shell/command tasks vanished — this rule must not be measuring an empty set');
});

test('the shell checker actually fails a task that omits changed_when', () => {
  // The rule above passes; this proves it passes for the right reason.
  const fixture = [
    { file: '<fixture>', task: { name: 'no changed_when', 'ansible.builtin.command': { cmd: 'true' } } },
    { file: '<fixture>', task: { name: 'has one', 'ansible.builtin.shell': { cmd: 'true' }, changed_when: false } },
  ];
  assert.deepStrictEqual(shellViolations(fixture), ["<fixture>: 'no changed_when'"]);
});

test('every powershell task sets error_action stop', () => {
  assert.deepStrictEqual(powershellViolations(TASKS), []);
});

test('the role is Linux-only today, and the powershell checker still bites', () => {
  // Stated rather than assumed: the DMZ web host is a standalone Debian VM, so
  // the error_action rule currently governs zero tasks. That is a vacuous pass
  // unless the checker is shown to work, so it is run against a fixture. The
  // day someone adds an IIS path, the real rule is already live.
  const live = TASKS.filter((t) => {
    const m = moduleOf(t.task);
    return m && POWERSHELL_MODULES.has(shortModule(m));
  });
  assert.strictEqual(live.length, 0,
    'a powershell task appeared in a role documented as Linux-only — update the README '
    + 'and this test together');
  const fixture = [
    { file: '<fixture>', task: { name: 'silent', 'ansible.windows.win_powershell': { script: 'Get-Item x' } } },
    { file: '<fixture>', task: { name: 'loud', 'ansible.windows.win_powershell': { script: 'Get-Item x', error_action: 'stop' } } },
  ];
  assert.deepStrictEqual(powershellViolations(fixture), ["<fixture>: 'silent'"]);
});

test('every task that handles the pivot password suppresses logging', () => {
  // The password must not reach the task banner, the job log an instructor can
  // open, or `ps` on the host.
  //
  // `assert` is the one exemption, and it is a reasoned one: ansible reports a
  // failed assertion by echoing the CONDITIONAL TEXT ("evaluated_to": false),
  // never the values it evaluated, so a length check on the password discloses
  // nothing — while no_log there would suppress the fail_msg that makes the
  // fail-fast gate worth having. The exemption is void the moment a fail_msg
  // interpolates the secret, which is checked rather than assumed.
  let covered = 0;
  for (const { file, task } of TASKS) {
    const mod = moduleOf(task);
    const blob = JSON.stringify(task);
    if (!/cc_web_pivot\.password/.test(blob)) continue;
    covered++;
    if (shortModule(mod) === 'assert') {
      const msg = String((task[mod] || {}).fail_msg || '');
      assert.ok(!/cc_web_pivot\.password/.test(msg),
        `${file}: '${task.name}' interpolates the password into its fail_msg`);
      continue;
    }
    assert.strictEqual(task.no_log, true,
      `${file}: '${task.name}' references cc_web_pivot.password without no_log: true`);
  }
  assert.ok(covered >= 1, 'no task references the pivot password — the credential path vanished');
  // The template task writes the file and must be silent too, even though the
  // password reaches it through the template rather than through its own args.
  const writer = TASKS.find((t) => t.file.endsWith('pivot_credential.yml')
    && shortModule(moduleOf(t.task)) === 'template');
  assert.ok(writer, 'pivot_credential.yml no longer writes the credential file');
  assert.strictEqual(writer.task.no_log, true,
    'the task that renders the credential file must set no_log: true');
});

test('every file mode is a quoted string', () => {
  // YAML 1.1 reads an unquoted 0640 as the decimal integer 640, which ansible
  // applies as 0o1200: a credential file the web user cannot read, so the
  // exercise's own LFI path finds nothing while every task reports green.
  for (const { file, task } of TASKS) {
    const mod = moduleOf(task);
    const args = task[mod];
    if (!args || typeof args !== 'object' || !('mode' in args)) continue;
    assert.strictEqual(typeof args.mode, 'string',
      `${file}: '${task.name}' sets mode as ${JSON.stringify(args.mode)} — quote it`);
  }
});

// ════════════════════════════════════════════════════════════════════════════
// 5. required variables are declared, and validated with a named message
// ════════════════════════════════════════════════════════════════════════════

const REQUIRED_VARS = [
  'cc_web_facts', 'cc_web_server_name', 'cc_web_docroot', 'cc_web_routes', 'cc_web_pivot',
];

test('assert.yml names every required variable in a failure message', () => {
  const raw = read(path.join(ROLE, 'tasks', 'assert.yml'));
  const asserts = parsed.get(path.join(ROLE, 'tasks', 'assert.yml'));
  for (const v of REQUIRED_VARS) {
    assert.ok(raw.includes(v), `assert.yml never mentions ${v}`);
  }
  // A `that:` without a fail_msg is "assertion failed" and a stack of Jinja —
  // useless to the operator, who is not the person who wrote the role.
  for (const t of asserts) {
    const mod = moduleOf(t);
    if (shortModule(mod) !== 'assert') continue;
    const args = t[mod];
    assert.ok(Array.isArray(args.that) && args.that.length > 0,
      `assert.yml '${t.name}' has no 'that' conditions`);
    assert.ok(typeof args.fail_msg === 'string' && args.fail_msg.length > 60,
      `assert.yml '${t.name}' needs a fail_msg that names the variable and says what to do`);
    assert.ok(/cc_web/.test(args.fail_msg),
      `assert.yml '${t.name}' fail_msg must name the variable it is about`);
  }
});

test('the fail-fast gate runs before anything touches the host', () => {
  const main = parsed.get(path.join(ROLE, 'tasks', 'main.yml'));
  // include_tasks takes its file as a bare scalar, so the module's args ARE the
  // filename; meta: flush_handlers reads the same way and is filtered out below
  // by simply not being one of the names looked for.
  const seq = main
    .map((t) => t[moduleOf(t)])
    .filter((a) => typeof a === 'string' && a.endsWith('.yml'));
  const iResolve = seq.indexOf('resolve.yml');
  const iAssert = seq.indexOf('assert.yml');
  const iInstall = seq.indexOf('packages.yml');
  const iVerify = seq.indexOf('verify.yml');
  assert.ok(iResolve >= 0 && iAssert >= 0 && iInstall >= 0 && iVerify >= 0,
    `main.yml must include resolve/assert/packages/verify, saw [${seq.join(', ')}]`);
  assert.ok(iResolve < iAssert, 'resolve must precede assert — assert validates the RESOLVED shape, '
    + 'so that the normalisation is checked too and not just the caller\'s typing');
  assert.ok(iAssert < iInstall, 'assert must run before the first task that mutates the host');
  assert.strictEqual(iVerify, seq.length - 1, 'verify.yml must be the last include');
});

test('handlers are flushed before the verification reads the host', () => {
  // Without an explicit flush, handlers run at the END of the play — after
  // verify.yml — so the verification would read the PREVIOUS config off a
  // still-running server and pass. This one line is the difference between a
  // verification and a ritual.
  const main = parsed.get(path.join(ROLE, 'tasks', 'main.yml'));
  const idxFlush = main.findIndex((t) => {
    const mod = moduleOf(t);
    return /(^|\.)meta$/.test(String(mod)) && t[mod] === 'flush_handlers';
  });
  const idxVerify = main.findIndex((t) => t[moduleOf(t)] === 'verify.yml');
  assert.ok(idxFlush >= 0, 'main.yml must flush handlers explicitly');
  assert.ok(idxFlush < idxVerify, 'the flush must come before the verification include');
});

test('every cc_web_ variable the role reads is declared, set or registered somewhere', () => {
  // The typo check. An undeclared variable in ansible is not an error until it
  // renders, and a `when: cc_web_verfy_tls | bool` that never renders is a
  // verification that never runs while the play stays green.
  const declared = new Set([...Object.keys(defaults), ...Object.keys(roleVars)]);
  // Deliberate sentinel: an undefined variable whose NAME is the error message,
  // used by templates/pivot-credential.j2 to make an unreachable branch raise.
  declared.add('cc_web_BUG_unsupported_pivot_format_reached_the_credential_template');
  for (const { task } of TASKS) {
    const mod = moduleOf(task);
    if (/(^|\.)set_fact$/.test(String(mod))) {
      for (const k of Object.keys(task[mod] || {})) declared.add(k);
    }
    if (typeof task.register === 'string') declared.add(task.register);
    // A tag NAMES ITSELF. `tags: [cc_web_tls]` is a declaration in exactly the
    // sense this check cares about, and treating it as a variable reference
    // would report eight phantom typos and train the next reader to skip the
    // failure.
    for (const t of [].concat(task.tags || [])) declared.add(String(t));
  }
  const NAME = /\bcc_web_[A-Za-z0-9_]+\b/g;
  const seen = new Map();
  for (const f of [...TASK_FILES, ...TEMPLATE_FILES]) {
    for (const m of read(f).matchAll(NAME)) {
      if (!seen.has(m[0])) seen.set(m[0], rel(f));
    }
  }
  const unknown = [...seen.entries()].filter(([n]) => !declared.has(n));
  assert.deepStrictEqual(unknown, [],
    'these cc_web_* names are read but never declared in defaults/, vars/, a set_fact or a '
    + `register:\n  ${unknown.map(([n, f]) => `${n} (${f})`).join('\n  ')}`);
});

// ════════════════════════════════════════════════════════════════════════════
// 6. the verification is real
// ════════════════════════════════════════════════════════════════════════════

test('verify.yml re-reads the host rather than trusting what the role wrote', () => {
  const verify = parsed.get(path.join(ROLE, 'tasks', 'verify.yml'));
  const mods = verify.map((t) => shortModule(moduleOf(t)));
  assert.ok(mods.includes('slurp'), 'verify must read a written config file back off disk');
  assert.ok(mods.includes('stat'), 'verify must stat the artifacts the role claims to have written');
  assert.ok(mods.filter((m) => m === 'assert').length >= 4,
    'verify must assert on what it read, not merely read it');
  const raw = read(path.join(ROLE, 'tasks', 'verify.yml'));
  // The four things the paper claims, each proved against the running host.
  assert.ok(/\bss\b/.test(raw), 'the ports must be read from the kernel, not from the Listen lines we wrote');
  assert.ok(/curl/.test(raw), 'the banner and the routes must be read from live responses');
  assert.ok(/s_client/.test(raw), 'each declared TLS protocol must be proved by a real handshake');
  assert.ok(/grep/.test(raw), 'the credential file must be proved to name the account');
});

test('the TLS proof runs in both directions', () => {
  // A listener that quietly offers TLS 1.2 beside the declared TLS 1.0 makes the
  // report false in the permissive direction, and the student's sslscan output
  // will not match the appendix they were handed.
  const verify = parsed.get(path.join(ROLE, 'tasks', 'verify.yml'));
  const positive = verify.find((t) => t.failed_when === 'cc_web_tls_proof.rc != 0');
  const negative = verify.find((t) => t.failed_when === 'cc_web_tls_negative.rc == 0');
  assert.ok(positive, 'verify must fail when a DECLARED protocol cannot complete a handshake');
  assert.ok(negative, 'verify must fail when an UNDECLARED protocol CAN complete a handshake');
  assert.ok(/difference\(cc_web_tls_protocols\)/.test(String(negative.loop)),
    'the negative proof must loop over the complement of the declared set');
});

test('verify publishes the OBSERVED facts in the shape readWebFacts consumes', () => {
  // The return path. A generator that reads this file writes a report about the
  // host that exists rather than about the host that was requested — which is
  // what turns "paper matches lane" from a checker into a structural property.
  const verify = parsed.get(path.join(ROLE, 'tasks', 'verify.yml'));
  const assemble = verify.find((t) => {
    const mod = moduleOf(t);
    return /set_fact$/.test(String(mod)) && (t[mod] || {}).cc_web_observed;
  });
  assert.ok(assemble, 'verify must assemble an observed-facts object');
  const observed = assemble[moduleOf(assemble)].cc_web_observed;
  // Exactly the field names service-inference.js documents for asset.web_facts,
  // so nothing downstream has to learn a second contract.
  for (const field of ['product', 'version', 'ports', 'tls', 'paths']) {
    assert.ok(field in observed, `observed facts must carry '${field}' like asset.web_facts does`);
  }
  for (const field of ['enabled', 'port', 'protocols']) {
    assert.ok(field in observed.tls, `observed facts tls must carry '${field}'`);
  }
  assert.ok(verify.some((t) => shortModule(moduleOf(t)) === 'copy'
    && String((t[moduleOf(t)] || {}).dest).includes('cc_web_facts_out')),
    'the observed facts must actually be written to cc_web_facts_out');
});

test('the last thing verify does is read its own output back', () => {
  const verify = parsed.get(path.join(ROLE, 'tasks', 'verify.yml'));
  const tail = verify.slice(-2).map((t) => shortModule(moduleOf(t)));
  assert.deepStrictEqual(tail, ['slurp', 'assert'],
    'verify must end by reading the published facts back and asserting they parse — a JSON file '
    + 'no consumer can load is the same nothing as a file that was never written');
});

// ════════════════════════════════════════════════════════════════════════════
// 7. the contract really is the one service-inference.js documents
// ════════════════════════════════════════════════════════════════════════════

test('the role consumes asset.web_facts verbatim, field for field', () => {
  // If the role invented its own spelling, the generator and the host would be
  // describing the same thing in two vocabularies, and every future change
  // would have to be made twice.
  const resolve = read(path.join(ROLE, 'tasks', 'resolve.yml'));
  for (const field of ['product', 'version', 'ports', 'paths']) {
    assert.ok(new RegExp(`cc_web_facts\\.${field}\\b`).test(resolve),
      `resolve.yml must read cc_web_facts.${field}`);
  }
  for (const field of ['enabled', 'port', 'protocols']) {
    assert.ok(new RegExp(`\\.${field}\\b`).test(resolve),
      `resolve.yml must read the tls.${field} the contract declares`);
  }
});

test('a TLS listener is asserted only when the facts say so, strictly', () => {
  // `tlsIn.enabled === true` in the JS. Anything looser is how POODLE findings
  // ended up on hosts that never opened 443.
  const resolve = read(path.join(ROLE, 'tasks', 'resolve.yml'));
  assert.ok(/is sameas true/.test(resolve),
    'cc_web_tls_enabled must be a strict identity test against true, mirroring readWebFacts; '
    + "`| bool` would promote 'yes' and every other truthy spelling");
});

test('the SSLProtocol line starts from -all so the declared set is exhaustive', () => {
  const resolve = read(path.join(ROLE, 'tasks', 'resolve.yml'));
  assert.ok(/-all\s+\{\{/.test(resolve),
    "SSLProtocol must start at '-all' and add back only the declared protocols; without it "
    + 'httpd keeps its compiled-in defaults and offers protocols the paper never claimed');
});
