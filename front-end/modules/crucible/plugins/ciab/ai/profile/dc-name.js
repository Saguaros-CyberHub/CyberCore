/**
 * ai/profile/dc-name.js — "is this record a domain controller?", defined ONCE.
 * ============================================================================
 * WHY THIS FILE EXISTS AS A FILE.
 *
 * Two consumers ask the same question of the same asset register, and they must
 * never disagree:
 *
 *   - validators.js/validateSizing (S-01, S-02) STRIPS controllers off a
 *     register whose org-sizing says the client is below the domain floor, or
 *     trims them down to max_dcs. What survives is what the student's paper
 *     says the client owns.
 *   - utils/goad-lab-compile.js/paperForestNames ADOPTS the register's names
 *     into the forest, splitting them into the controller and member pools the
 *     chassis binds against.
 *
 * A name that counts as a controller for one side and a member for the other
 * produces a profile whose paper and lane disagree about which machines run the
 * directory. That does not fail at generation time: the bake mints its own
 * controller name, the golden templates are named after machines the deploy
 * spec never asks for, and profile-deploy refuses with BAKE_GOLDEN_UNMATCHED —
 * roughly ninety minutes in. The predicate used to be duplicated byte-for-byte
 * in both files with a comment forbidding anyone to re-derive it, which is a
 * social contract enforcing a mechanical invariant. This module is the
 * mechanical version: one definition, two `require`s, no drift possible.
 *
 * It requires nothing, deliberately — validators.js is a leaf module today and
 * goad-lab-compile.js already reaches into this directory for org-sizing and
 * hash, so importing from here introduces no cycle in either direction.
 *
 * ── WHAT COUNTS AS A CONTROLLER NAME ─────────────────────────────────────────
 *
 * The predicate reads `<role> <hostname>` and used to be
 * `/domain controller|\bdc\b|active directory/i`. `\bdc\b` requires a word
 * boundary on BOTH sides of the token, which the generated themes happen to
 * satisfy (`dc-01`, `tuc-dc-01`) and which real-world names never do: in
 * `SVO-DC01`, `HQDC1`, `ADDC01`, `DC1` and `CORPDC02` the `dc` is followed
 * immediately by a digit, so there is no trailing boundary and the client's
 * actual domain controller was filed as a member server. That path is the
 * REAL-CLIENT INTAKE, where hostnames are typed by the client rather than
 * rendered by a theme, so it is the path where the names are least likely to be
 * hyphen-delimited and most likely to be authoritative.
 *
 * The widening is on the two sides of the token separately, because the two
 * directions of error are not symmetrical — a false negative leaves the DC pool
 * short (warned by name at bake, refused at deploy), while a false positive
 * silently turns a file server into a domain controller and changes the forest
 * the answer key was written against. So:
 *
 *   LEFT   anything that is not a letter — start of string, a separator, a
 *          digit — keeps the old `\bdc\b` reading (`DC-01`, `SVO-DC01`).
 *          Letters are allowed on the left ONLY when a digit follows, which is
 *          what admits `HQDC1`, `ADDC01`, `CORPDC02`.
 *   RIGHT  never a letter. This single rule is what rejects every named
 *          near-miss: `FS-DCOM01` (a fileserver's DCOM box), `ABDCEF`, and
 *          `dc` buried inside an ordinary word — handcuff, broadcast, hardcopy
 *          all carry a letter after the `dc`.
 *
 * A bare `ABDC` — letters before, nothing after — is deliberately NOT a
 * controller. Nothing in the register's vocabulary suggests it is one, the old
 * predicate did not claim it, and admitting it would only buy false positives.
 *
 * Everything the old predicate matched, this one still matches: `\bdc\b`
 * guarantees a non-word character on each side, and a non-word character is
 * never a letter.
 */

/**
 * Matches the role/hostname text of a domain controller.
 *
 * Alternatives, in order: the spelled-out role (with or without a separator, so
 * `domain-controller` and `domaincontroller` read the same as `domain
 * controller`); the same for Active Directory; the `dc` token with a non-letter
 * on its left; and the `dc` token glued to a site or org prefix with digits
 * immediately after it.
 */
const DC_NAME_RE = /domain[\s_-]?controller|active[\s_-]?directory|(?<![A-Za-z])dc(?![A-Za-z])|(?<=[A-Za-z])dc(?=\d)/i;

/**
 * Does this text name a domain controller?
 *
 * @param {*} text anything; coerced, so a null role is simply not a controller
 * @returns {boolean}
 */
function looksLikeDcName(text) {
  return DC_NAME_RE.test(text == null ? '' : String(text));
}

/**
 * Is this asset/server record the register's domain controller?
 *
 * Both consumers read the SAME two fields in the SAME order — the role sentence
 * first, then the hostname — because the composed string is what the regex was
 * calibrated against; a caller that composed it differently would be a third
 * opinion by the back door.
 *
 * The asset's `function` prose is NOT consulted. It is LLM-authored, and a
 * false positive there quietly makes the file server a domain controller while
 * every document the student holds still calls it a file server.
 *
 * @param {object} record { role, hostname }
 * @returns {boolean}
 */
function isDcRecord(record) {
  if (!record || typeof record !== 'object') return false;
  const role = record.role == null ? '' : String(record.role);
  const hostname = record.hostname == null ? '' : String(record.hostname);
  return looksLikeDcName(`${role} ${hostname}`);
}

module.exports = {
  DC_NAME_RE,
  looksLikeDcName,
  isDcRecord,
};
