/**
 * ============================================================================
 * CIAB PROFILE-LANE STUDENT ACCOUNTS
 * ----------------------------------------------------------------------------
 * One student account per deployed lane, plus the matching Guacamole user.
 *
 * Lifted out of ciab/routes/profile-deploy.js, where the identical loop existed
 * TWICE — once in runProfileDeploy for the initial deploy, once in the
 * add-lanes route for lanes appended to an existing group. The two had already
 * started to drift (only one of them logged, only one of them built a
 * `students[]` array), which is the same failure mode Track A is retiring in
 * the deploy path itself, one scale down.
 *
 * WHY THIS EXISTS AT ALL
 * ----------------------
 * cybercore_lane.user_id must be the STUDENT's id, not the deploying admin's:
 * hub.html's "Remote Workspaces -> My Workspaces" filters on it, so a lane
 * owned by the admin appears in nobody's workspace list. That is the whole
 * reason CIAB mints accounts here rather than deploying to a roster the way
 * CLE does — an admin deploying from a profile has no roster yet.
 *
 * WHY provisionOrRotateAccount AND NOT AN INSERT
 * ----------------------------------------------
 * Re-deploying a group with the same name must ROTATE the password while
 * keeping the same user_id: the student's prior workspaces and Guacamole
 * permissions hang off that id. An INSERT ... ON CONFLICT DO NOTHING would
 * leave the admin holding a credential sheet that does not work; a delete +
 * re-insert would orphan every lane they already had.
 *
 * Passwords are returned to the caller and never stored in plaintext — only the
 * hash reaches the database. The caller hands the credential sheet to the
 * instructor once and cannot retrieve it again.
 * ============================================================================
 */

const accountProvisioning = require('../../../../../src/utils/account-provisioning');
const { guacAPI } = require('../../../../../src/utils/guacamole');

const LOG = '[CIAB ProfileStudents]';

/** Guacamole user attributes, identical for every minted student. */
const GUAC_ATTRIBUTES = { disabled: null, timezone: 'America/Phoenix' };

/**
 * The group-name slug that every student email and lane name is built from.
 *
 * One owner for the transform, because it is load-bearing in three places that
 * must agree: the student's email, the Guacamole username (same string), and
 * the lane's display name (`kali-<slug>-student<N>-<vmid>`). A group renamed
 * from "Cochise 101" to "cochise101" has to keep resolving to one slug or the
 * next deploy mints a second set of accounts alongside the first.
 */
function slugForGroup(groupName) {
  return String(groupName || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

/**
 * The login for lane N of a group. `@clinic.local` is deliberately a
 * non-routable domain — these are lab accounts and no mail must ever leave for
 * them (see src/utils/mailer.js, which blackholes .local).
 */
function studentEmail(groupSlug, index) {
  return `${groupSlug}-student${index}@clinic.local`;
}

/**
 * Create-or-rotate one student account per lane index, plus its Guacamole user.
 *
 * @param {object}   a
 * @param {string}   a.groupName      the group's display name; slugged for emails
 * @param {string}   a.groupId        recorded as the provenance ref
 * @param {number[]} a.indices        lane numbers to mint — [1..n] on the initial
 *   deploy, continuing from MAX(lane_index) when lanes are added later. Passed in
 *   rather than derived, because only the caller knows which of the two it is.
 * @param {string}   [a.actingUserId] the admin performing the deploy, for provenance
 * @returns {Promise<{groupSlug: string, students: Array, credentials: Array}>}
 *   students:    [{ id, email, name, index }] — `id` is what cybercore_lane.user_id
 *                must be set to.
 *   credentials: [{ email, password, role }] — the one-time sheet for the instructor.
 */
async function provisionLaneStudents({ groupName, groupId, indices, actingUserId = null }) {
  const groupSlug = slugForGroup(groupName);
  const students = [];
  const credentials = [];

  for (const index of indices) {
    const email = studentEmail(groupSlug, index);

    const outcome = await accountProvisioning.provisionOrRotateAccount({
      email,
      username: email,
      firstName: 'Student',
      lastName: String(index),
      organization: groupName,
      role: 'student',
      emailVerified: true,
      mustChangePassword: false,
      provenance: { by: actingUserId || null, via: 'group_deploy', ref: String(groupId) },
    });
    const password = outcome.password;

    students.push({ id: outcome.user.user_id, email, name: `Student ${index}`, index });
    credentials.push({ email, password, role: 'student' });

    // Best-effort: if Guacamole is down the deploy still completes and the admin
    // can create the user by hand. Failing the deploy here would destroy a lane
    // that is otherwise fine.
    try {
      await guacAPI('POST', '/users', { username: email, password, attributes: GUAC_ATTRIBUTES });
    } catch (_) {
      // Already present from a previous deploy — PUT to refresh the password so
      // it matches the sheet the admin is about to hand out.
      try {
        await guacAPI('PUT', `/users/${encodeURIComponent(email)}`,
          { username: email, password, attributes: GUAC_ATTRIBUTES });
      } catch (_) {}
    }
  }

  console.log(`${LOG} Group ${groupName}: provisioned ${students.length} student account(s) (1 per lane)`);
  return { groupSlug, students, credentials };
}

module.exports = {
  provisionLaneStudents,
  slugForGroup,
  studentEmail,
};
