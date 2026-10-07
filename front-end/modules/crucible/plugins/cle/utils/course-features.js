/**
 * CLE Plugin — Per-course feature registry
 * ----------------------------------------------------------------------------
 * Which tabs a course shows. Before this existed, courses.html rendered all six
 * tabs for every course and the two course-specific ones were documented only
 * in a comment — so CYBR 480 got an Attack Console that could never do anything
 * but say "No active lanes found for this course."
 *
 * ADDING A FEATURE is one entry below plus a `data-feature` attribute on the
 * tab in public/pages/courses.html. MAKING AN EXISTING TAB OPTIONAL is flipping
 * `optional` and giving it a `defaultFor`. Nothing else needs a migration: the
 * values live in one JSONB column (cle_course.features, migration 007).
 *
 * THIS FILE IS AUTHORITATIVE. courses.html carries a small presentation-only
 * mirror (labels and hints for the modal checkboxes); the defaults and the
 * route gating are decided here, server-side, so a stale browser cannot grant
 * itself a feature.
 *
 * NOT A SECURITY BOUNDARY. Flags are planted on lane VMs by the deploy path
 * whatever this says, and POST /api/flags/submit is core and not course-scoped.
 * This decides which tabs an instructor sees and which boards a student is
 * offered — treat it as visibility, not access control.
 */

const { getManagedCourse } = require('./course-access');

/**
 * Normalise a course code for default-matching: strip punctuation and upcase,
 * so 'CYBR-480-7W1-1', 'CYBR480-1' and 'cybr 480' all match alike.
 *
 * migrations/007_cle_course_features.sql applies the SAME rule in SQL. Change
 * one and you must change the other — the backfill and this resolver have to
 * agree, or a course's tabs would depend on whether the migration had reached
 * its row yet.
 */
function normalizeCode(code) {
  return String(code == null ? '' : code).replace(/[^a-z0-9]/gi, '').toUpperCase();
}

/** Every tab on the course detail page, in display order. */
const COURSE_FEATURES = [
  { key: 'overview',         label: 'Overview',        optional: false },
  { key: 'students',         label: 'Students',        optional: false },
  { key: 'vm-management',    label: 'VM Management',   optional: false },
  { key: 'vulnerable-labs',  label: 'Environments',    optional: false },
  {
    key: 'flags',
    label: 'Flags',
    optional: true,
    // Only CYBR 480 ran capture-the-flag when this column was introduced.
    defaultFor: (code) => normalizeCode(code).startsWith('CYBR480'),
  },
  {
    key: 'attack_console',
    label: 'Attack Console',
    optional: true,
    // Only CYBR 400 has the loggen sensor image the console dispatches to.
    defaultFor: (code) => normalizeCode(code).startsWith('CYBR400'),
  },
  {
    key: 'blue_team',
    label: 'Blue Team Board',
    optional: true,
    // The defensive half of the same course. Same default as the Attack
    // Console and for the same reason: CYBR 400 is the course whose lanes carry
    // a sensor and a SIEM, so it is the only one where a board has anything to
    // grade. A course without them would show a tab whose every run is empty.
    //
    // Separate from attack_console rather than folded into it, because the two
    // are read by different people: an instructor can run the console while the
    // board stays closed, which is exactly the state a class is in between the
    // launch and the debrief.
    defaultFor: (code) => normalizeCode(code).startsWith('CYBR400'),
  },
];

const OPTIONAL_FEATURES = COURSE_FEATURES.filter((f) => f.optional);
const OPTIONAL_KEYS = OPTIONAL_FEATURES.map((f) => f.key);

/**
 * The complete on/off map for a course. Always returns a boolean for every
 * optional key, so no caller has to re-implement the defaulting.
 *
 * A stored value always wins; the fallback is PER KEY, so only keys the row
 * does not carry consult defaultFor(code). That is what stops a course whose
 * instructor disabled Flags from having them reappear at the next boot when
 * migration 007 re-runs, and what lets a feature added later land on existing
 * courses with its intended default instead of forced off. NULL and {} are
 * therefore equivalent, and the UI never writes a partial row anyway --
 * readFeatureCheckboxes() sends every key on every save.
 *
 * @param {{code?: string, features?: object|null}} course  a cle_course row
 * @returns {Object<string, boolean>}
 */
function resolveFeatures(course) {
  const stored = (course && typeof course.features === 'object' && course.features) || {};
  const code = course ? course.code : '';
  const out = {};
  for (const feature of OPTIONAL_FEATURES) {
    out[feature.key] = Object.prototype.hasOwnProperty.call(stored, feature.key)
      ? stored[feature.key] === true
      : Boolean(feature.defaultFor && feature.defaultFor(code));
  }
  return out;
}

/** Replace each row's raw `features` with the resolved map, in place. */
function attachFeatures(courseRows) {
  for (const row of courseRows || []) row.features = resolveFeatures(row);
  return courseRows;
}

/**
 * Coerce a request body's `features` into something safe to store.
 *
 * Unknown keys are dropped rather than rejected: the tab list is expected to
 * grow, and a browser left open across a deploy should lose the key it no
 * longer understands instead of failing the whole save.
 *
 * @returns {Object<string, boolean>|null} null when nothing usable was sent, so
 *   callers can pass it straight to COALESCE($n::jsonb, features) and have
 *   "absent" mean "unchanged".
 */
function sanitizeFeaturesInput(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const out = {};
  for (const key of OPTIONAL_KEYS) {
    if (Object.prototype.hasOwnProperty.call(raw, key)) out[key] = raw[key] === true;
  }
  return Object.keys(out).length ? out : null;
}

/** Defaults for a brand-new course, so create paths need not know the rules. */
function defaultFeaturesForCode(code) {
  return resolveFeatures({ code, features: null });
}

/** @returns {boolean} whether `key` is on for this course row. */
function isFeatureEnabled(course, key) {
  return resolveFeatures(course)[key] === true;
}

/**
 * Express gate for a course-scoped route that belongs to an optional feature.
 *
 * 404 rather than 403 on a disabled feature: to a caller, a course with Flags
 * off has no flags endpoint. 403 would imply the resource exists and they are
 * merely not allowed it, which is the answer to a different question — and it
 * is the answer getManagedCourse() already gives for a course they cannot
 * manage at all.
 *
 * Reads courseId from res.locals (set by the nested-router shim in routes/api.js)
 * falling back to req.params, so it works mounted either way.
 */
function requireCourseFeature(key) {
  return async function courseFeatureGate(req, res, next) {
    try {
      const courseId = res.locals.courseId || req.params.courseId;
      const course = await getManagedCourse(courseId, req.user, 'course_id, code, features');
      if (!course) {
        return res.status(404).json({ error: 'Course not found or access denied' });
      }
      if (!isFeatureEnabled(course, key)) {
        const label = (COURSE_FEATURES.find((f) => f.key === key) || {}).label || key;
        return res.status(404).json({ error: `${label} is not enabled for this course` });
      }
      next();
    } catch (error) {
      console.error('[CLE] Course feature gate error:', error.message);
      res.status(500).json({ error: error.message });
    }
  };
}

module.exports = {
  COURSE_FEATURES,
  OPTIONAL_KEYS,
  normalizeCode,
  resolveFeatures,
  attachFeatures,
  sanitizeFeaturesInput,
  defaultFeaturesForCode,
  isFeatureEnabled,
  requireCourseFeature,
};
