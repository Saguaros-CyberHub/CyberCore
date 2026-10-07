/**
 * ============================================================================
 * CIAB MODULE STATES — the vocabulary, and nothing else
 * ============================================================================
 * Track D, phase D1: the module spine. A SECTION is a class; a MODULE is one
 * unit of work an instructor sequences inside it; a module names a CLIENT and
 * an ENGAGEMENT, and those resolve to an ENVIRONMENT. Every word below is a
 * word from that spine, or a code naming something the resolver decided.
 *
 * ONE VOCABULARY, NOT TWO. An instructor must never have to tell this program
 * and the plugin next door apart, so nothing from that plugin's naming reaches
 * a value, a code, a label or a sentence in this file.
 *
 * ----------------------------------------------------------------------------
 * WHY THE WORDS LIVE IN ONE FILE
 * ----------------------------------------------------------------------------
 * Two neighbours in src/utils exist for exactly this reason, and both were
 * written after the damage:
 *
 *   ticket-status.js — one status list had been spelled FOUR ways: the CHECK
 *     constraint on the table, the PATCH validator on the route, the filter
 *     chips and badge classes on the Admin page, and the subject line of the
 *     status-change email. Four copies, four chances to disagree.
 *
 *   lane-claims.js — one predicate had been spelled SIX ways, and two of the
 *     six were wrong in opposite directions. A failed lane's VXLAN id went
 *     straight back into the allocation pool while the audit still counted that
 *     same lane's machines as accounted for. The survivors were invisible at
 *     the exact moment the id was being reissued — and once a new lane took it,
 *     the contested-id guard correctly refused to let the old row destroy
 *     anything, ever. Those machines could not be found or removed by any code
 *     path that existed. That is what a duplicated vocabulary costs, and it is
 *     not a tidiness problem.
 *
 * The module spine opens with more readers than either of those had when it
 * broke: the CHECK constraints in migration 014, the pure gate in
 * module-spine.js, D2's route validators, D3 and D4's badges and selects, and
 * D8's grading writer. Six copies agreeing by good intentions is not the likely
 * outcome; it is the unlikely one.
 *
 * ----------------------------------------------------------------------------
 * AND ONE OF THOSE COPIES IS A CHECK CONSTRAINT
 * ----------------------------------------------------------------------------
 * Which is the copy that cannot be fixed cheaply. CREATE TABLE IF NOT EXISTS is
 * a silent no-op on any deployment that has already run migration 014, so
 * widening a CHECK there means a guarded DROP CONSTRAINT then ADD, for which
 * this tree has no precedent to copy. A value spelled here and missing there is
 * therefore not a lint failure: it is a 23514 the first time an instructor
 * picks it, in production, on a deployment where every fresh-database test
 * passed. A test asserts that this file and migration 014 agree in BOTH
 * directions, and the stored vocabularies were made deliberately generous in
 * the one commit where they are free.
 *
 * STORED VS DERIVED. Only three lists below are stored, and only those three
 * have a CHECK to agree with; each is named against its constraint where it is
 * declared. The rest are what the pure functions in module-spine.js are allowed
 * to RETURN. Nothing about availability is stored anywhere — "is this open" is
 * computed from (release_state, release_at, close_at, now) on every read — so
 * these lists exist so that computation cannot invent a sixth word for a state
 * that already has one.
 *
 * NO IMPORTS, no queries, no clock, and that is load-bearing exactly as it is
 * in both files above: a route validator, a page-data builder or a future
 * reconciler can require this without dragging in ./db, and therefore without
 * needing a pool to have been injected first. module-spine.js takes it as `S`.
 * ============================================================================
 */

// ── Stored: instructor intent, module-wide ──────────────────────────────────

/**
 * Stored on ciab_module.release_state — the instructor's INTENT, not the
 * effective answer. STORED: mirrors CHECK ciab_module_release_state_chk in
 * migration 014, in that constraint's order.
 *
 *   draft      being written, invisible to students. The column DEFAULT, so a
 *              half-written module cannot leak.
 *   scheduled  published; opens at release_at. A scheduled module with no
 *              release time never opens, and is reported to the instructor as
 *              a configuration error rather than silently read as "now".
 *   open       available now — the manual "Open it" button.
 *   closed     was available, now shut. Students keep read access to the brief
 *              and to their own state. This is the transition D5 will hang
 *              teardown from.
 *   archived   retired from the sequence but NOT deleted; every per-student row
 *              survives. It is the only removal that does not cascade away the
 *              record the grading phase reads, and it must stay
 *              distinguishable from 'draft' or a term rollover looks like a
 *              half-built section.
 */
const RELEASE_STATES = Object.freeze(['draft', 'scheduled', 'open', 'closed', 'archived']);

// ── Derived: what the pure functions may answer ─────────────────────────────

/**
 * Derived by module-spine.releasePhase(module, now). DERIVED: no CHECK,
 * because no column stores it and none should — a stored is_open boolean needs
 * a scheduled job to flip it, one missed tick leaves a module shut on the
 * morning it was meant to open, and the result is indistinguishable from a
 * module the instructor deliberately closed.
 *
 * Four of these five words are also release_state values. That is deliberate:
 * the same word, answering a different question about the same module.
 * 'scheduled' is an intent and can never be an answer; 'pending' is the answer
 * it produces, and covers BOTH "scheduled, not yet" and "open, but release_at
 * is still ahead of now".
 */
const RELEASE_PHASES = Object.freeze(['draft', 'pending', 'open', 'closed', 'archived']);

/**
 * Derived by module-spine.evaluateGate(), per (module, student). DERIVED.
 *
 *   hidden  the student is never told it exists. Draft and archived modules are
 *           DROPPED from the student payload, module_id included, because an id
 *           alone is enough to guess a URL.
 *   locked  it exists and they may not enter it yet. A reason always says why:
 *           a lock with no reason is unactionable in a UI.
 *   open    they may work in it.
 *   closed  they may read the brief and their own state, and nothing else.
 */
const ACCESS_STATES = Object.freeze(['hidden', 'locked', 'open', 'closed']);

// ── Stored: the two per-student facts ───────────────────────────────────────

/**
 * Stored on ciab_module_student.completion. STORED: mirrors CHECK
 * ciab_module_student_completion_chk in migration 014, in that constraint's
 * order.
 *
 *   auto        the DEFAULT, and the state of every student with no row at all.
 *               It is the ABSENCE of a decision: defer to the tracker that
 *               already owns the answer, which for a module bound to a client
 *               and an assessment part is that student's own
 *               assessment_progress row. Stores nothing.
 *   incomplete  an explicit REJECTION, which beats a derived submission. This
 *               is what makes 'auto' safe to default to: an instructor can
 *               always say no.
 *   complete    an explicit decision. Satisfies a prerequisite.
 *   waived      excused — a late joiner, an accommodation. ALSO satisfies a
 *               prerequisite, but is counted separately so a waiver is never
 *               reported as work done.
 *
 * There is deliberately no 'in_progress' and no 'submitted' here: those are
 * assessment_progress.status, and restating them is the fourth progress tracker
 * migration 014's header exists to argue against.
 */
const COMPLETION_DECISIONS = Object.freeze(['auto', 'incomplete', 'complete', 'waived']);

/**
 * The ANSWER module-spine.resolveCompletion() gives. DERIVED.
 *
 * 'auto' is an INPUT only. It is a decision not to decide, so it can never be
 * the resolved answer — with no signal to defer to it resolves 'incomplete'.
 */
const COMPLETIONS = Object.freeze(['incomplete', 'complete', 'waived']);

/**
 * The completions that let a student past a module that requires this one.
 *
 * Separate from COMPLETIONS because this is the ONE sentence defining what
 * "done" means for gating, and satisfiesPrereq() below is the only place it is
 * ever asked. D2 and D6 must not re-spell it — a second spelling is how
 * 'waived' quietly stops counting for somebody.
 */
const SATISFYING_COMPLETIONS = Object.freeze(['complete', 'waived']);

/**
 * Where a resolved completion came from. DERIVED, and reported alongside the
 * answer so an instructor UI can distinguish "I said so" from "the tracker
 * says so".
 *
 *   decision  someone recorded a value other than 'auto'. The decision outranks
 *             the derivation in BOTH directions, the explicit rejection
 *             included.
 *   derived   read from that student's own assessment_progress row.
 *   default   nothing said anything: 'auto' with no signal is 'incomplete'.
 */
const COMPLETION_SOURCES = Object.freeze(['decision', 'derived', 'default']);

/**
 * Stored on ciab_module_student.release_override, which is NULLABLE. STORED:
 * mirrors CHECK ciab_module_student_override_chk in migration 014.
 *
 *   unlock  an extension, a make-up, an accommodation, for ONE student. Beats a
 *           pending release AND a closed window AND an unmet prerequisite,
 *           because an instructor's explicit grant is an authority the resolver
 *           must not second-guess. It cannot beat 'draft' or 'archived' — you
 *           cannot grant access to a module that has not been written — and it
 *           cannot beat an archived section, because the enrollment gate would
 *           refuse the request the UI would then be offering.
 *   lock    an integrity hold for ONE student, checked before every open path
 *           so it always wins. override_reason is shown to them verbatim.
 *
 * The absent value means "follow the module" and is deliberately NOT a member
 * of this list: the column is nullable and the resolver tests for the absence
 * of a value, so listing a non-word here would put something in a vocabulary
 * that no CHECK can carry.
 */
const RELEASE_OVERRIDES = Object.freeze(['unlock', 'lock']);

// ── Borrowed: the one signal D1 derives completion from ─────────────────────

/**
 * assessment_progress.status values that count as DONE for a prerequisite.
 *
 * BORROWED, NOT OWNED, and the one list here with no CHECK to agree with:
 * assessment_progress.status is a bare VARCHAR(20) with no constraint
 * (001_ciab_schema.sql), carrying 'not_started', 'in_progress', 'submitted' and
 * 'reviewed' in practice. This pair is the same one routes/progress.js counts
 * as submitted and the same one the instructor dashboard's parts_submitted
 * filter uses; naming it here is what stops a third spelling appearing.
 *
 * 'submitted' is deliberately enough. A student must not have to wait on
 * grading before starting the module that follows.
 */
const COMPLETING_PART_STATUSES = Object.freeze(['submitted', 'reviewed']);

// ── The state of a student with no row ──────────────────────────────────────

/**
 * A student with NO ciab_module_student row is in exactly this state.
 *
 * Rows are SPARSE and nothing pre-creates them, so this is not a placeholder —
 * it is the real, complete and correct state of most students on most modules.
 * The alternative is the neighbouring plugin's: insert an empty row per student
 * at deploy time as a marker, whose submitted_at DEFAULTs to now(), after which
 * "has this student finished" is unanswerable from the schema.
 *
 * module_id and user_id are absent on purpose: there is no row, so there is no
 * pair to name. module-spine.rowToStudentState() COPIES this object rather than
 * returning it, so a caller cannot be handed a frozen singleton it then wants
 * to annotate.
 */
const DEFAULT_STUDENT_STATE = Object.freeze({
  completion:       'auto',
  completed_at:     null,
  completed_by:     null,
  release_override: null,
  override_reason:  null,
  override_by:      null,
  override_at:      null,
});

// ── Codes ───────────────────────────────────────────────────────────────────

/**
 * Why a module is not open for this student, in the order evaluateGate() tests
 * them — the order IS the policy.
 *
 * code -> code, on purpose. A misspelled member is `undefined` at runtime,
 * which a test catches and a UI renders as a blank badge, rather than a string
 * literal that is silently never matched by anything. Every code here has an
 * entry in MESSAGE.
 */
const REASON = Object.freeze({
  SECTION_ARCHIVED:   'SECTION_ARCHIVED',
  NOT_ENROLLED:       'NOT_ENROLLED',
  MODULE_DRAFT:       'MODULE_DRAFT',
  MODULE_ARCHIVED:    'MODULE_ARCHIVED',
  INSTRUCTOR_LOCKED:  'INSTRUCTOR_LOCKED',
  MODULE_CLOSED:      'MODULE_CLOSED',
  NOT_YET_RELEASED:   'NOT_YET_RELEASED',
  PREREQ_CYCLE:       'PREREQ_CYCLE',
  PREREQ_MISSING:     'PREREQ_MISSING',
  PREREQ_INCOMPLETE:  'PREREQ_INCOMPLETE',
});

/**
 * Something the student should be TOLD that does not close the door.
 *
 * Advisories ride alongside an 'open' access, never instead of a reason. One
 * code today; the shape exists so the second one is not a second boolean on the
 * response.
 */
const ADVISORY = Object.freeze({
  INSTRUCTOR_UNLOCKED: 'INSTRUCTOR_UNLOCKED',
});

/**
 * Configuration problems with a SECTION, for the instructor who can fix them.
 *
 * NEVER returned on a student path: a student can act on none of them, and
 * several name modules the student must not know exist. Same code -> code
 * discipline as REASON, and PREREQ_CYCLE / PREREQ_MISSING deliberately reuse
 * the reason codes — they are one fact seen from two sides, and two spellings
 * of it is this file's whole subject.
 *
 * PREREQ_UNPUBLISHED has NO twin in REASON, and that asymmetry is the point.
 * The student on the far side of a published module gated on a draft one is
 * told only that a prerequisite could not be checked — naming the draft would
 * hand them its id and its title. The instructor is the only person who can
 * see the whole configuration and the only one who can fix it, so the sentence
 * that says "this can never open" is theirs alone.
 */
const ISSUE = Object.freeze({
  PREREQ_CYCLE:           'PREREQ_CYCLE',
  PREREQ_MISSING:         'PREREQ_MISSING',
  PREREQ_UNPUBLISHED:     'PREREQ_UNPUBLISHED',
  SCHEDULED_WITHOUT_DATE: 'SCHEDULED_WITHOUT_DATE',
  CLOSE_BEFORE_RELEASE:   'CLOSE_BEFORE_RELEASE',
  CLIENT_UNBOUND:         'CLIENT_UNBOUND',
  DUPLICATE_POSITION:     'DUPLICATE_POSITION',
  NO_PUBLISHED_MODULES:   'NO_PUBLISHED_MODULES',
  SHARED_ENVIRONMENT:     'SHARED_ENVIRONMENT',
});

/**
 * How loudly each issue is shown: 'error' | 'warning' | 'info'.
 *
 *   error    a module can NEVER open in its current configuration, or is locked
 *            for everyone. Students are affected right now and cannot act.
 *            PREREQ_UNPUBLISHED is the quietest member: a published module
 *            gated on a draft one is locked for the WHOLE roster and reads, in
 *            every other surface, exactly like a class that has not got to it
 *            yet.
 *   warning  it is probably not what the instructor meant, but the section
 *            still works.
 *   info     a legitimate, common consequence the instructor should know about.
 *            SHARED_ENVIRONMENT is the whole of this category today: two
 *            sequential modules against one client on one engagement is normal
 *            and correct, and is exactly why D5 must refcount before it tears
 *            anything down.
 */
const ISSUE_SEVERITY = Object.freeze({
  PREREQ_CYCLE:           'error',
  PREREQ_MISSING:         'error',
  PREREQ_UNPUBLISHED:     'error',
  SCHEDULED_WITHOUT_DATE: 'error',
  CLOSE_BEFORE_RELEASE:   'error',
  CLIENT_UNBOUND:         'warning',
  DUPLICATE_POSITION:     'warning',
  NO_PUBLISHED_MODULES:   'warning',
  SHARED_ENVIRONMENT:     'info',
});

/**
 * Full sentences, written for the person who reads them, naming the remedy
 * where there is one. Used for both reason.message and issue.message.
 *
 * Not templated. A message that needs a value — a date, a list of blocking
 * modules — carries it in the reason's `detail` instead, so the sentence stays
 * one fixed string and the value stays typed.
 */
const MESSAGE = Object.freeze({
  SECTION_ARCHIVED:    'This section has been archived.',
  NOT_ENROLLED:        'You are not enrolled on this section.',
  MODULE_DRAFT:        'This module has not been published yet.',
  MODULE_ARCHIVED:     'This module has been archived.',
  INSTRUCTOR_LOCKED:   'Your instructor has locked this module.',
  INSTRUCTOR_UNLOCKED: 'Your instructor opened this module for you individually.',
  MODULE_CLOSED:       'This module has closed.',
  NOT_YET_RELEASED:    'This module opens later.',
  PREREQ_CYCLE:        'This module’s prerequisites form a loop and must be fixed by your instructor.',
  PREREQ_MISSING:      'A prerequisite for this module could not be checked. Ask your instructor.',
  PREREQ_INCOMPLETE:   'Finish the module(s) this one follows first.',
  PREREQ_UNPUBLISHED:  'This module follows one that has not been published, so it can never open. Publish the earlier module first.',
  SCHEDULED_WITHOUT_DATE: 'Scheduled with no release time, so it will never open.',
  CLOSE_BEFORE_RELEASE:   'The close time is on or before the release time, so this module can never open.',
  CLIENT_UNBOUND:      'No client has been assigned to this module yet.',
  DUPLICATE_POSITION:  'Two or more modules share a position in the sequence.',
  NO_PUBLISHED_MODULES: 'Every module in this section is still a draft, so students see an empty page.',
  SHARED_ENVIRONMENT:  'These modules run against the same client and engagement and will share one environment.',
});

// ── Labels ──────────────────────────────────────────────────────────────────

/**
 * Title Case, for a badge or a select.
 *
 * Each map covers its whole family — the stored word AND the derived one — so a
 * template never has to know which vocabulary produced the value it was handed,
 * and a missing key can never be the reason a badge renders empty.
 *
 * 'pending' is the one entry that is not a mechanical capitalisation: it is a
 * derived phase, and "Pending" on its own does not say pending what.
 */
const RELEASE_LABELS = Object.freeze({
  draft:     'Draft',
  scheduled: 'Scheduled',
  pending:   'Not Yet Open',
  open:      'Open',
  closed:    'Closed',
  archived:  'Archived',
});

/** Title Case, for a badge. Covers every ACCESS_STATES value. */
const ACCESS_LABELS = Object.freeze({
  hidden: 'Hidden',
  locked: 'Locked',
  open:   'Open',
  closed: 'Closed',
});

/**
 * Title Case, for a badge or a select. Keyed by COMPLETION_DECISIONS, which
 * contains every COMPLETIONS value, so one map labels both the stored decision
 * and the resolved answer.
 */
const COMPLETION_LABELS = Object.freeze({
  auto:       'Auto',
  incomplete: 'Incomplete',
  complete:   'Complete',
  waived:     'Waived',
});

// ── Predicates: pure, and backed by Sets built once ─────────────────────────
// Built once at require time rather than per call, because the instructor view
// runs the gate modules x roster times in memory — 50 modules against 500
// students is ~25k evaluations, and a linear scan per word is the kind of cost
// nobody ever comes back to find.

const RELEASE_STATE_SET       = new Set(RELEASE_STATES);
const RELEASE_PHASE_SET       = new Set(RELEASE_PHASES);
const ACCESS_STATE_SET        = new Set(ACCESS_STATES);
const COMPLETION_DECISION_SET = new Set(COMPLETION_DECISIONS);
const COMPLETION_SET          = new Set(COMPLETIONS);
const RELEASE_OVERRIDE_SET    = new Set(RELEASE_OVERRIDES);
const SATISFYING_SET          = new Set(SATISFYING_COMPLETIONS);

/** Is this a value ciab_module.release_state may hold? */
function isReleaseState(value) {
  return RELEASE_STATE_SET.has(value);
}

/** Is this a phase releasePhase() may answer? */
function isReleasePhase(value) {
  return RELEASE_PHASE_SET.has(value);
}

/** Is this a verdict evaluateGate() may answer? */
function isAccessState(value) {
  return ACCESS_STATE_SET.has(value);
}

/**
 * Is this a value ciab_module_student.completion may hold?
 *
 * This is the one a WRITE validates against, so it includes 'auto': clearing a
 * decision is a legitimate write, and refusing it would leave an instructor
 * unable to undo their own mistake.
 */
function isCompletionDecision(value) {
  return COMPLETION_DECISION_SET.has(value);
}

/** Is this an answer resolveCompletion() may give? Excludes 'auto'. */
function isCompletion(value) {
  return COMPLETION_SET.has(value);
}

/**
 * Is this a value ciab_module_student.release_override may hold?
 *
 * The absent value is NOT accepted here. Clearing an override is a legitimate
 * write, but it is the caller's explicit branch rather than a member of the
 * vocabulary — see RELEASE_OVERRIDES.
 */
function isReleaseOverride(value) {
  return RELEASE_OVERRIDE_SET.has(value);
}

/**
 * Does this resolved completion let a student past a module that requires the
 * one it came from?
 *
 * THE definition of "done" for gating, and the only place it is written.
 * 'waived' counts exactly as 'complete' does — the whole point of a waiver is
 * that the student moves on — while 'incomplete', an instructor's explicit
 * rejection, does not.
 *
 * @param {string} completion one of COMPLETIONS
 * @returns {boolean}
 */
function satisfiesPrereq(completion) {
  return SATISFYING_SET.has(completion);
}

/**
 * The sentence for a reason, advisory or issue code.
 *
 * Falls back rather than throwing: a code with no message must degrade to a
 * dull badge, never to a 500 on a page a student is trying to read. The typeof
 * test is what keeps an inherited property name from being answered with
 * something that is not a sentence.
 *
 * @param {string} code a REASON, ADVISORY or ISSUE member
 * @returns {string}
 */
function messageFor(code) {
  const message = MESSAGE[code];
  return typeof message === 'string' ? message : 'Unavailable.';
}

module.exports = {
  // Stored — each mirrored by a named CHECK in migration 014
  RELEASE_STATES,
  COMPLETION_DECISIONS,
  RELEASE_OVERRIDES,
  // Derived — what the pure functions in module-spine.js may answer
  RELEASE_PHASES,
  ACCESS_STATES,
  COMPLETIONS,
  SATISFYING_COMPLETIONS,
  COMPLETION_SOURCES,
  // Borrowed, and the default row that is not a row
  COMPLETING_PART_STATUSES,
  DEFAULT_STUDENT_STATE,
  // Codes and the sentences they render as
  REASON,
  ADVISORY,
  ISSUE,
  ISSUE_SEVERITY,
  MESSAGE,
  // Labels
  RELEASE_LABELS,
  ACCESS_LABELS,
  COMPLETION_LABELS,
  // Pure predicates
  isReleaseState,
  isReleasePhase,
  isAccessState,
  isCompletionDecision,
  isCompletion,
  isReleaseOverride,
  satisfiesPrereq,
  messageFor,
};
