/**
 * ticket-schema.test.js — the three copies of the ticket DDL must not drift.
 *
 * WHY THREE COPIES EXIST AT ALL
 * There is no single place to put a core-database schema change in this repo:
 *
 *   - front-end/migrations/ has NO runner. Nothing reads it; it is the
 *     operator's paper trail and a hand-run repair.
 *   - config/postgres/001_init_db.sql is mounted into
 *     /docker-entrypoint-initdb.d and therefore executes ONLY on a fresh volume.
 *   - src/utils/tickets.js ensureTicketTables() is the only one that runs on an
 *     existing deployment, at boot, on every start.
 *
 * So all three have to carry the same DDL, and nothing but a test can keep them
 * honest. The failure this catches is quiet and nasty: a status added to the
 * boot DDL but not to 001 means a value that works on every upgraded deployment
 * and violates a CHECK constraint the first time someone builds from scratch.
 *
 * Run: node front-end/test/ticket-schema.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const REPO = path.join(ROOT, '..');

const tickets = require(path.join(ROOT, 'src', 'utils', 'tickets.js'));
const { TICKET_STATUSES } = require(path.join(ROOT, 'src', 'utils', 'ticket-status.js'));

const MIGRATION = fs.readFileSync(
  path.join(ROOT, 'migrations', '034_support_tickets.sql'), 'utf8');
const INIT = fs.readFileSync(
  path.join(REPO, 'config', 'postgres', '001_init_db.sql'), 'utf8');
const BOOT = tickets.TICKET_TABLE_SQL + tickets.EVENT_TABLE_SQL
  + tickets.TICKET_INDEX_SQL.join('\n');

const SOURCES = { 'boot DDL (src/utils/tickets.js)': BOOT,
                  'migrations/034_support_tickets.sql': MIGRATION,
                  'config/postgres/001_init_db.sql': INIT };

/** Collapse whitespace so formatting differences are not treated as drift. */
const flat = s => s.replace(/\s+/g, ' ');

// ── the status vocabulary ───────────────────────────────────────────────────

test('the status CHECK is identical in all three copies', () => {
  const expected = flat(tickets.STATUS_CHECK);
  for (const [where, sql] of Object.entries(SOURCES)) {
    assert.ok(flat(sql).includes(expected),
      `${where} does not carry: ${tickets.STATUS_CHECK}`);
  }
});

test('the status CHECK lists exactly the statuses the code knows about', () => {
  // Catches the other direction: a status added to ticket-status.js but never
  // allowed by the constraint, which fails only at write time in production.
  const inCheck = tickets.STATUS_CHECK.match(/'([a-z_]+)'/g).map(s => s.replace(/'/g, ''));
  assert.deepStrictEqual(inCheck.sort(), [...TICKET_STATUSES].sort());
});

test('the partial active index covers exactly the non-terminal statuses', () => {
  const { ACTIVE_STATUSES } = require(path.join(ROOT, 'src', 'utils', 'ticket-status.js'));
  const expected = `WHERE status IN (${ACTIVE_STATUSES.map(s => `'${s}'`).join(',')})`;
  for (const [where, sql] of Object.entries(SOURCES)) {
    assert.ok(flat(sql).includes(flat(expected)),
      `${where} is missing the active-ticket partial index predicate`);
  }
});

// ── tables and columns ──────────────────────────────────────────────────────

test('both tables are created in all three copies', () => {
  for (const [where, sql] of Object.entries(SOURCES)) {
    for (const table of ['cybercore_ticket', 'cybercore_ticket_event']) {
      assert.match(flat(sql), new RegExp(`CREATE TABLE IF NOT EXISTS ${table} \\(`),
        `${where} does not create ${table}`);
    }
  }
});

test('every column of the ticket table appears in all three copies', () => {
  const columns = [
    'ticket_id', 'ticket_number', 'requester_user_id', 'requester_email', 'requester_name',
    'subject', 'body', 'status',
    'course_id', 'course_name', 'course_code', 'instructor_user_id', 'instructor_email',
    'lane_id', 'machine_key', 'machine_label', 'machine_vmid',
    'first_response_at', 'resolved_at', 'closed_at', 'created_at', 'updated_at',
  ];
  for (const [where, sql] of Object.entries(SOURCES)) {
    for (const col of columns) {
      assert.match(sql, new RegExp(`\\b${col}\\b`), `${where} is missing ${col}`);
    }
  }
});

test('every event kind the code writes is allowed by the CHECK', () => {
  const kinds = tickets.EVENT_KINDS;
  for (const [where, sql] of Object.entries(SOURCES)) {
    const m = flat(sql).match(/kind TEXT NOT NULL CHECK \(kind IN \(([^)]+)\)\)/);
    assert.ok(m, `${where} has no kind CHECK`);
    const listed = m[1].match(/'([a-z_]+)'/g).map(s => s.replace(/'/g, ''));
    assert.deepStrictEqual(listed.sort(), [...kinds].sort(), `${where} kind list disagrees`);
  }
});

// ── the design decisions that are easy to "fix" wrongly ────────────────────

test('there is NO foreign key from a ticket to a lane', () => {
  // An FK here would either block teardownLanes() -- a hot path that recycles
  // lanes routinely -- or, with ON DELETE CASCADE, silently delete support
  // history when a lane is torn down. The machine_label snapshot is what makes
  // a dangling lane_id harmless.
  for (const [where, sql] of Object.entries(SOURCES)) {
    // Slice the ticket table's own body: the boot DDL is a JS template string
    // with no trailing semicolons, so anchor on the NEXT table instead.
    const one = flat(sql);
    const from = one.indexOf('CREATE TABLE IF NOT EXISTS cybercore_ticket (');
    assert.ok(from >= 0, `${where} does not create cybercore_ticket`);
    const to = one.indexOf('CREATE TABLE IF NOT EXISTS cybercore_ticket_event', from);
    const block = one.slice(from, to > 0 ? to : undefined);
    assert.doesNotMatch(block, /lane_id\s+UUID\s+REFERENCES/,
      `${where} added an FK from cybercore_ticket.lane_id to a lane`);
  }
});

test('a deleted user leaves the ticket behind, not a cascade', () => {
  // ON DELETE CASCADE here would erase the record of what someone reported the
  // moment their account was removed at the end of a term.
  for (const [where, sql] of Object.entries(SOURCES)) {
    assert.match(flat(sql),
      /requester_user_id UUID REFERENCES cybercore_user\(user_id\) ON DELETE SET NULL/,
      `${where} does not preserve tickets past account deletion`);
  }
});

test('deleting a ticket DOES cascade its thread', () => {
  // The opposite call, deliberately: an event has no meaning without its ticket.
  for (const [where, sql] of Object.entries(SOURCES)) {
    assert.match(flat(sql),
      /ticket_id UUID NOT NULL REFERENCES cybercore_ticket\(ticket_id\) ON DELETE CASCADE/,
      `${where} would orphan ticket events`);
  }
});

test('visibility defaults to public', () => {
  // Defaulting to internal would silently hide a staff reply from the student
  // it was written for -- a failure nobody would report, because the student
  // would simply never know there was an answer.
  for (const [where, sql] of Object.entries(SOURCES)) {
    assert.match(flat(sql),
      /visibility TEXT NOT NULL DEFAULT 'public' CHECK \(visibility IN \('public','internal'\)\)/,
      `${where} does not default event visibility to public`);
  }
});

// ── the outbox columns ──────────────────────────────────────────────────────

test('the migration adds the Cc columns idempotently and mailer.js mirrors it', () => {
  // These two are NOT in 001_init_db.sql: cybercore_email_outbox is not defined
  // there at all -- ensureEmailOutbox() in mailer.js owns that table -- so its
  // columns travel with it, not with the ticket tables.
  const mailer = fs.readFileSync(path.join(ROOT, 'src', 'utils', 'mailer.js'), 'utf8');
  for (const col of ['cc_address', 'reply_to']) {
    assert.match(flat(MIGRATION),
      new RegExp(`ALTER TABLE cybercore_email_outbox ADD COLUMN IF NOT EXISTS ${col} TEXT`),
      `034 does not add ${col}`);
    assert.match(flat(mailer),
      new RegExp(`ALTER TABLE cybercore_email_outbox ADD COLUMN IF NOT EXISTS ${col} +TEXT`),
      `ensureEmailOutbox() does not add ${col}`);
  }
  assert.match(flat(MIGRATION), /idx_email_outbox_ticket/);
  assert.match(flat(mailer), /idx_email_outbox_ticket/);
});

test('mailer.js probes for the Cc columns instead of assuming them', () => {
  // Without the probe, a failed ALTER makes every INSERT reference a missing
  // column and ALL platform email dies -- activation links included -- while
  // enqueue()'s catch reports each one as merely "suppressed".
  const mailer = fs.readFileSync(path.join(ROOT, 'src', 'utils', 'mailer.js'), 'utf8');
  assert.match(mailer, /ccColumnsPresent/);
  // Both the write path and the claim path must be gated.
  const enqueueSlice = mailer.slice(mailer.indexOf('async function enqueue'),
                                    mailer.indexOf('async function enqueueMany'));
  assert.match(enqueueSlice, /await ccColumnsPresent\(\)/, 'enqueue does not probe');
  const drainSlice = mailer.slice(mailer.indexOf('async function drainOutbox'),
                                  mailer.indexOf('async function requeueStalledSends'));
  assert.match(drainSlice, /await ccColumnsPresent\(\)/, 'drainOutbox does not probe');
});

// ── idempotence, because the boot DDL runs on every start ──────────────────

test('every statement in all three copies is idempotent', () => {
  // ensureTicketTables() runs on EVERY boot. A bare CREATE or ALTER would throw
  // on the second start, and the surrounding try/catch would turn that into a
  // warning nobody reads plus a half-applied schema.
  for (const [where, sql] of Object.entries(SOURCES)) {
    for (const m of sql.match(/CREATE TABLE(?! IF NOT EXISTS)/g) || []) {
      assert.fail(`${where}: "${m}" is not idempotent`);
    }
    for (const m of sql.match(/CREATE (UNIQUE )?INDEX(?! IF NOT EXISTS)/g) || []) {
      assert.fail(`${where}: "${m}" is not idempotent`);
    }
    for (const m of sql.match(/ADD COLUMN(?! IF NOT EXISTS)/g) || []) {
      assert.fail(`${where}: "${m}" is not idempotent`);
    }
  }
});

test('the boot DDL is wired into server start()', () => {
  // migrations/ has no runner and config/postgres only runs on a fresh volume,
  // so this call is the ONLY thing that creates these tables on an existing
  // deployment. Unwired, the whole feature 500s and the tests still pass.
  const server = fs.readFileSync(path.join(ROOT, 'src', 'server.js'), 'utf8');
  assert.match(server, /require\('\.\/utils\/tickets'\)\.ensureTicketTables\(\)/);
  // And after the mailer, whose ensureEmailOutbox() adds the columns a ticket
  // notification needs in order to Cc the instructor.
  assert.ok(server.indexOf('ensureEmailOutbox()') < server.indexOf('ensureTicketTables()'),
    'ensureTicketTables must run after ensureEmailOutbox');
});
