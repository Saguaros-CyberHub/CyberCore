/**
 * ============================================================================
 * engagement-model.js — Track B, phase B0: the ENGAGEMENT MODEL vocabulary
 * ============================================================================
 * Migration 010 gave an engagement a NETWORK: a carved VXLAN block and a
 * provision status. The B0 migration gives it a JOB — what is in scope, what is
 * out, which techniques are permitted, which accounts the client agreed to hand
 * over, where each machine SITS relative to the perimeter, and the brief the
 * student reads.
 *
 * This file is the single place those words are spelled. Every other reader —
 * the compile in engagement-plan.js, the projection in engagement-provision.js,
 * B1's route validator, B1's screen, B2's spec writeback — takes them from
 * here. It holds NO database access and NO I/O of any kind.
 *
 * ----------------------------------------------------------------------------
 * THE PURITY CONTRACT — THIS FILE CONTAINS ZERO require CALLS
 * ----------------------------------------------------------------------------
 * Not ./db. Not a src/utils path. Not pg. A source scan in
 * test/ciab-engagement-model.test.js asserts it, and both reasons are real:
 *
 *   (a) test/ciab-reservation.test.js:599,627 loads routes/profile-deploy.js on
 *       a STUBBED module cache whose clinic_db handle is a poison pill that
 *       throws on any query (:225-229). Anything this module pulled in
 *       transitively would surface there as a failure naming the wrong file.
 *   (b) src/utils/vm-template-resolver.js:83 -> src/utils/site-config.js:29-30
 *       does an unguarded fs.readFileSync of config/site.json, which is ABSENT
 *       from this checkout (only example-site.json is committed). One import of
 *       the wrong neighbour turns a pure vocabulary module into a module that
 *       cannot be loaded at all.
 *
 * So: constants, predicates and normalizers. Nothing else. If a future phase
 * needs a lookup, it belongs in the caller, not here.
 *
 * ----------------------------------------------------------------------------
 * IT DOES NOT FORK sanitizeEngagementType
 * ----------------------------------------------------------------------------
 * There is exactly one sanitizer, at lane-reservation.js:108-111, and it
 * DELETES disallowed characters rather than rejecting them: 'External Blackbox'
 * becomes 'externalblackbox'. This file never re-implements it — callers
 * sanitize first. What it does instead is state that sanitizer's output
 * alphabet positively: every registry key matches /^[a-z0-9_-]{1,32}$/, which
 * is exactly the condition for a slug to be a fixed point of it. The test
 * asserts that without loading lane-reservation.js (which pulls pg and proxmox).
 *
 * ----------------------------------------------------------------------------
 * THE VALIDATORS RETURN A REPORT. THEY NEVER THROW.
 * ----------------------------------------------------------------------------
 * assignLaneAddressing (profile-to-spec.js:181-192) throws a bare Error with no
 * statusCode, and routes/profile-deploy.js renders `err.statusCode || 500`. A
 * self-correctable authoring mistake therefore reaches an instructor as an
 * unexplained 500. Every validator here returns
 *
 *     { errors: [{path, code, message}], warnings: [...], value: <normalized> }
 *
 * and the caller decides whether to write or to 400. `value` is ALWAYS safe to
 * persist: an offending entry is DROPPED from it rather than carried through
 * with an error beside it. (One deliberate exception, documented at
 * validateIssuedCredentials: a secret-named KEY is stripped and its entry kept,
 * because losing a whole account intent to a stray form field is the worse
 * failure and the key is gone either way.)
 *
 * ----------------------------------------------------------------------------
 * NEVER A SECRET IN issued_credentials
 * ----------------------------------------------------------------------------
 * That column records the ACCOUNT INTENT the client agreed to hand over — who,
 * on which machine, at what privilege, delivered where.
 *   NEVER a password. NEVER an activation token. NEVER a key.
 * (Same prohibition, same wording, as 008_ciab_enrollment.sql:159-161.)
 *
 * The row is scoped to (client, engagement), so anything secret stored there is
 * by construction the SAME secret for every student. The real password is
 * minted PER LANE at deploy time by src/utils/password-generator.js and already
 * lives in the guest, in the lane row and in Guacamole. A third plaintext copy
 * here would have no reader that needs it — and it would be tempting to hand to
 * B3's delivery step, which must be a FILE precisely because the generator
 * guarantees a symbol from SYMBOLS = '!@#$%&*' (password-generator.js:13) and
 * script_args is interpolated UNQUOTED onto a command line
 * (script-executor.js:249 for PowerShell, :624 for sh), where a single '&'
 * backgrounds the command.
 *
 * normalizeCredentialSlot below builds each entry from a WHITELIST of known
 * keys and never copies an unrecognised one through. That is the guarantee. The
 * secret-key CHECK constraint in the migrations is a backstop for writers that
 * are not this normalizer (a psql session, a future import script).
 *
 * ----------------------------------------------------------------------------
 * PLACEMENT, NOT PUBLISHING
 * ----------------------------------------------------------------------------
 * The website stays INTERNAL to the lane. There is no gateway perimeter
 * publish, no DNAT, no wan-port table — so this file has no notion of a
 * published port and no reserved-port rule, because it has no subject.
 *
 * What an engagement declares instead is PLACEMENT: which segment each machine
 * is homed on. The mechanism already exists in shared core and needs no gateway
 * change:
 *
 *   src/utils/lane-networking.js:379 — on a v3 lane a spec VM with
 *     role 'dmz' (and type !== 'lxc') resolves to BOTH segments, ['ext','int'].
 *     An explicit vmSpec.nics array wins over that inference.
 *   src/utils/challenge-lane-deployer.js:758-772 — that dual-homed host is
 *     pinned to .240 on BOTH segments, which is above the gateway's DHCP pool
 *     (.10-.200), so no lease can claim it and no gateway re-bake is needed.
 *   src/utils/topology-validate.js:26,45 — EXTERNAL_ROLES = {'dmz','attacker'};
 *     a role 'dmz' VM is deliberately external, as the dual-homed vuln website.
 *
 * So the external exercise is: the attack box on ext reaches the website on ext
 * as an L2 neighbour, and because that host is ALSO homed on int, compromising
 * it IS the pivot. See PLACEMENTS below for the three rungs and why there is
 * exactly one pivot.
 * ============================================================================
 */

// ─── Small local helpers (no dependencies, by contract) ─────────────────────

/** Deep-freeze a plain object/array tree. Registry entries are frozen so a
 *  caller cannot mutate the vocabulary out from under the next reader. */
function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}

/** true only for a plain object — not an array, not null, not a Date. */
function isPlainObject(v) {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/** Trim to a string, or null when there is nothing left. Numbers coerce. */
function trimOrNull(v, max) {
  if (v === null || v === undefined) return null;
  if (typeof v === 'object') return null;
  let s = String(v).trim();
  if (!s) return null;
  if (max && s.length > max) s = s.slice(0, max);
  return s;
}

/** Title-case a slug that has no registry entry: 'red_team-lite' -> 'Red Team Lite'. */
function titleCaseSlug(slug) {
  return String(slug)
    .replace(/[_-]+/g, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map(w => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

// ─── Vocabulary ─────────────────────────────────────────────────────────────

/** The engagement_type every production writer emits today
 *  (public/js/admin-profile-lanes.js:411 posts it literally) and the value
 *  migration 009's DEFAULT backfilled every pre-existing group to. */
const DEFAULT_TYPE_KEY = 'default';

/** Which side of the perimeter the team starts on. Stored, defaulted, queried,
 *  and mirrored by a named CHECK in the B0 guards migration. */
const PERSPECTIVES = Object.freeze(['internal', 'external']);

/** Whether the client hands over working accounts. ORTHOGONAL to perspective:
 *  (external, credentialed) is an authenticated web assessment and must stay
 *  expressible. Also mirrored by a named CHECK. */
const CREDENTIAL_POSTURES = Object.freeze(['none', 'credentialed']);

/**
 * Scope-rule kinds. The kind is EXPLICIT rather than sniffed because
 * asset.subnet is heterogeneous in a client profile — a subnet NAME on
 * LLM-authored servers, a CIDR STRING on assets rebuilt by
 * reconcile-workstations — so a rule has to say which join it means.
 *
 * Only RESOLVABLE_SCOPE_KINDS can move a machine in or out of scope. The rest
 * are documentation: a spec VM carries an ipOctet, not an address, and the lane
 * base is per-lane and unknown at compile time, so a 'cidr' or 'url' rule is
 * carried verbatim into the compile's declared_only[] and never used to include
 * or exclude anything. Saying so is more honest than a half-working match.
 */
const SCOPE_KINDS = Object.freeze([
  'all', 'vm', 'role', 'cidr', 'url', 'hostname_pattern', 'text',
]);
const RESOLVABLE_SCOPE_KINDS = Object.freeze(['all', 'vm', 'role']);

/** What kind of account an issued credential names. */
const ACCOUNT_KINDS = Object.freeze(['local', 'domain', 'app', 'service']);

/** Where the account came from, so B3 knows which minting path to use. */
const CREDENTIAL_SOURCES = Object.freeze([
  'cloudinit', 'template', 'baked', 'app_seed', 'manual',
]);

/** Where B3 lands the credential FILE. 'console' means the student console VM. */
const DELIVERY_TARGETS = Object.freeze(['console', 'vm']);

/** How an objective is satisfied. */
const OBJECTIVE_KINDS = Object.freeze(['flag', 'manual']);

/** Exactly cybercore_lane_flag's own CHECK (migrations/023_lane_flags.sql:29-40).
 *  Achievement is NOT stored on the engagement — objectives are DEFINITIONS and
 *  per-engagement scoring is a view over that table. This platform already has
 *  three progress trackers; do not add a fourth. */
const FLAG_TYPES = Object.freeze(['user', 'root']);

/**
 * PLACEMENTS — where a machine sits relative to the lane perimeter.
 *
 *   'pivot'    role 'dmz', dual-homed ext+int. The bridge. The deployer pins it
 *              to .240 on both segments.
 *   'public'   single-homed on ext. This is already the v3 default for an
 *              ordinary VM (lane-networking.js:381), so it costs nothing.
 *   'internal' single-homed on int. Requires an explicit nics array on the spec,
 *              because the v3 default for a non-'dmz' VM is ext.
 *
 * EXACTLY ONE PIVOT PER LANE, AND THAT IS A DELIBERATE CONSTRAINT rather than a
 * limitation to work around. The deployer defines exactly one dual-homed
 * address — .240 on each segment (challenge-lane-deployer.js:766-770) — so a
 * second pivot has nowhere to land.
 *
 * Extra EXPOSED hosts are free: 'public' is the v3 default, so putting three or
 * four ordinary machines on ext costs nothing and is the cheap way to make
 * "which host is the bridge?" a real question instead of a host count of one.
 * The teaching value is in the search, not in the number of bridges.
 */
const PLACEMENTS = Object.freeze(['pivot', 'public', 'internal']);

/**
 * The octet a dual-homed host actually gets, on BOTH segments.
 *
 * AUTHORITY: src/utils/challenge-lane-deployer.js:766-770. It used to be .50,
 * but the gateway firstboot reserves ext .50 for the attack box's RDP DNAT
 * (wan0:3389 -> ext.50), so the two collided and student RDP landed on the web
 * host. .240 is above the gateway's DHCP pool (.10-.200), so no lease can claim
 * it and no gateway re-bake is needed.
 *
 * This constant exists so the PAPER can say where the pivot lives. The compile
 * stamps it onto hosts[].ip_octet for a 'pivot' host instead of the .80-.99
 * band octet the synthesizer would otherwise imply — because .8x would be a
 * true statement about a spec field and a false statement about the lane.
 * IMPORT IT; do not re-spell 240 anywhere else.
 */
const DUAL_HOMED_OCTET = 240;

/**
 * The NIC array each placement implies, and the reason this mapping is here
 * rather than inferred downstream.
 *
 * TWO RULES DECIDE "IS THIS HOST PINNABLE", AND THEY ARE NOT THE SAME RULE:
 *
 *   profile-to-spec.js:178   !(Array.isArray(vm.nics) && vm.nics.length > 1)
 *   challenge-lane-deployer.js:310-311
 *                            const segs = resolveVmSegments(vmSpec, ...);
 *                            if (segs.length > 1) continue;
 *
 * For a role 'dmz' VM carrying NO explicit nics those two DISAGREE: the
 * synthesizer believes it is single-homed and stamps an ipOctet in the .80-.99
 * band, while the deployer treats it as dual-homed and pins .240. The LANE is
 * right either way — the deployer never writes a .8x reservation for that host
 * — so this is not a deploy bug. It is a paper-vs-lane divergence, and B2's IP
 * writeback, Track C's manifest and the scan documents all read the spec.
 *
 * It is latent today only because nothing emits role 'dmz'. B0 is where that
 * starts. The repair is to make the two rules agree BY CONSTRUCTION: the
 * compile emits an EXPLICIT nics array for every placement that has an opinion,
 * so a pivot arrives at the synthesizer with nics.length === 2 and
 * assignLaneAddressing's EXISTING filter already excludes it from the band. No
 * change to profile-to-spec.js — which is byte-pinned by
 * test/ciab-deploy-parity.test.js — and the divergence cannot occur.
 *
 * 'public' maps to null, meaning "leave the spec's default alone": the v3
 * default for an ordinary VM is already a single ext NIC, and writing that out
 * explicitly would add a field with no reader.
 *
 * The segment names are lane-networking.js's own ('ext', 'int', 'lan'); an
 * explicit nics entry is `{segment}` and wins over every inference
 * (lane-networking.js:374-375).
 */
const PLACEMENT_SEGMENTS = deepFreeze({
  pivot: ['ext', 'int'],
  public: null,
  internal: ['int'],
});

/**
 * A key whose NAME matches this is refused wherever engagement data is
 * authored. It matches a KEY, never a value, so a note reading "the password
 * policy is weak" is fine and {password: '...'} is not.
 *
 * Structural rather than a literal blocklist on purpose: 'pass' catches
 * password_hash, temp_password and guac_password, which an alternation of bare
 * whole words would not.
 */
const SECRET_KEY_PATTERN =
  /(pass|pwd|passphrase|secret|token|plaintext|cipher|private_key|otp|credential_value|api_key|apikey|jwt|auth_?token)/i;

/**
 * Characters that make a path unusable as a script argument.
 *
 * B3 lands the credential file with a single agentShellExec (the
 * flag-manager.plantLinuxRootFlag pattern), so the delivery path goes onto a
 * command line where script_args is interpolated UNQUOTED
 * (script-executor.js:249 for PowerShell, :624 for sh). An unvalidated path is
 * the same defect as an unvalidated password, through the back door.
 *
 * src/utils/flag-manager.js isSafePath (exported at :906) is the RUNTIME
 * authority B3 must also call. These are the authoring-time twins, duplicated
 * only because this module must stay dependency-free — see the purity contract
 * in the header. If they ever disagree, flag-manager wins.
 */
const UNSAFE_PATH_RE = /["'`$;&|<>*?()\r\n\\]|\.\./;

/**
 * The engagement model's columns, in the order the B0 migration adds them.
 *
 * The UPDATE writer in engagement-provision.js builds its SET list dynamically
 * over this array, so a column added to the migration without a matching entry
 * here is simply never written — and a name here with no column raises 42703 on
 * the first PATCH. Keep the two in lockstep.
 */
const MODEL_FIELDS = Object.freeze([
  'display_name',
  'perspective',
  'credential_posture',
  'asset_selection',
  'scope_in',
  'scope_out',
  'allowed_techniques',
  'issued_credentials',
  'exposure_plan',
  'objectives',
  'brief',
  'authored_fields',
  'synthesis_meta',
]);

/**
 * The fields a HUMAN may edit, and therefore the fields a later "refresh from
 * the client file" action must not clobber. perspective and credential_posture
 * are absent deliberately: they are decided by the engagement type's registry
 * entry (or, for a custom slug, by the one explicit patch that sets them), not
 * proposed by a compile.
 */
const AUTHORABLE_FIELDS = Object.freeze([
  'display_name',
  'asset_selection',
  'scope_in',
  'scope_out',
  'allowed_techniques',
  'issued_credentials',
  'exposure_plan',
  'objectives',
  'brief',
]);

/** Which MODEL_FIELDS are jsonb columns — the writer casts these ::jsonb and
 *  JSON.stringify's their values. display_name, perspective,
 *  credential_posture and brief are the four that are not. */
const JSONB_MODEL_FIELDS = new Set([
  'asset_selection',
  'scope_in',
  'scope_out',
  'allowed_techniques',
  'issued_credentials',
  'exposure_plan',
  'objectives',
  'authored_fields',
  'synthesis_meta',
]);

/**
 * Ceilings. Every one of these is an AUTHORING limit, not a capacity limit —
 * the real capacity ceiling is the .80-.99 pin band in profile-to-spec.js, and
 * the compile computes it from that file's own exported constants so it cannot
 * drift.
 */
const LIMITS = Object.freeze({
  display_name: 200,
  brief: 20000,
  scope_rules: 200,
  scope_value: 400,
  techniques: 100,
  credentials: 50,
  exposure: 32,
  objectives: 200,
  slot_key: 64,
  username: 128,
  vm_name: 128,
  note: 500,
  services: 32,
  service_label: 64,
});

// ─── The registry (NOT an allowlist) ────────────────────────────────────────

/**
 * ENGAGEMENT_TYPES is a REGISTRY WITH A TOTAL FALLBACK, and the difference
 * matters enough to spell out.
 *
 * createEngagement sanitizes a caller's slug and never validates it against a
 * vocabulary, and the sanitizer DELETES disallowed characters rather than
 * rejecting: 'External Blackbox' becomes 'externalblackbox' and "'; DROP
 * TABLE--" becomes 'droptable--'. Both reach the INSERT today, and
 * test/ciab-reservation.test.js:296-297 pins that behaviour. So a vocabulary
 * that REJECTED would turn every off-vocabulary slug into an unhandled 500, and
 * a CHECK constraint on the column would do the same at the database.
 *
 * describeEngagementType is therefore TOTAL: every string, and null, gets a
 * usable descriptor. Unknown slugs get known:false and the conservative
 * (internal, none) posture, which is what every row in the table has today.
 *
 * 'default' IS NOT OPTIONAL. It is the only engagement_type any production
 * writer emits (admin-profile-lanes.js:411), it is what 009's DEFAULT
 * backfilled every group to, lane-reservation.js:89 falls back to it, and the
 * two legacy-key fallbacks at lane-reservation.js:266,434 are keyed on it.
 * Removing it strands every existing row and every pre-engagement reservation,
 * and a second VXLAN block gets carved for a client that already has one —
 * permanently, because the allocator only ever climbs and never re-uses.
 *
 * Vocabulary discipline: Section / Module / Client / Engagement / Environment.
 * No label or summary here may say course, material, or anything from the
 * neighbouring plugin's naming.
 */
const ENGAGEMENT_TYPES = deepFreeze({
  internal_credentialed: {
    key: 'internal_credentialed',
    label: 'Internal — credentialed',
    perspective: 'internal',
    credential_posture: 'credentialed',
    summary: 'The team starts on the inside, with accounts handed over on day one.',
  },
  external_blackbox: {
    key: 'external_blackbox',
    label: 'External — black box',
    perspective: 'external',
    credential_posture: 'none',
    summary: 'The team starts on the outside, with nothing but the forward-facing site.',
  },
  default: {
    key: 'default',
    label: 'Standard engagement',
    perspective: 'internal',
    credential_posture: 'none',
    summary: 'The original single-engagement shape: the whole environment, no issued accounts.',
  },
});

/**
 * DISPLAY-ONLY aliases. These NEVER rewrite a stored slug.
 *
 * The slug is baked into the reservation key ciab-profile-<id8>-<slug>
 * (lane-reservation.js:113-117), so rewriting 'externalblackbox' to
 * 'external_blackbox' would orphan a carved block that nothing can ever name
 * again. describeEngagementType deliberately does NOT consult this map — it
 * reports the slug it was given, unknown and all — and only
 * engagementDisplayName uses it, to put a readable name on a screen.
 */
const ENGAGEMENT_TYPE_ALIASES = deepFreeze({
  internalcredentialed: 'internal_credentialed',
  'internal-credentialed': 'internal_credentialed',
  externalblackbox: 'external_blackbox',
  'external-blackbox': 'external_blackbox',
});

// ─── Type descriptors ───────────────────────────────────────────────────────

/**
 * Describe an ALREADY-SANITIZED engagement slug.
 *
 * TOTAL. Never throws, never rejects. null / undefined / '' give the 'default'
 * descriptor with known:true; anything else that is not a registry key gives
 * known:false, the conservative (internal, none) posture and a title-cased
 * label derived from the slug.
 *
 * @param {string|null} engagementType
 * @returns {{key:string, known:boolean, label:string, perspective:string,
 *            credential_posture:string, summary:string}}
 */
function describeEngagementType(engagementType) {
  const raw = engagementType === null || engagementType === undefined
    ? '' : String(engagementType).trim();

  if (!raw) return { known: true, ...ENGAGEMENT_TYPES[DEFAULT_TYPE_KEY] };

  const hit = Object.prototype.hasOwnProperty.call(ENGAGEMENT_TYPES, raw)
    ? ENGAGEMENT_TYPES[raw] : null;
  if (hit) return { known: true, ...hit };

  return {
    key: raw,
    known: false,
    label: titleCaseSlug(raw) || raw,
    perspective: 'internal',
    credential_posture: 'none',
    summary: 'A locally defined engagement type. Its posture is whatever this engagement declares.',
  };
}

/** Resolve a display alias to a canonical registry key, or null. Never applied
 *  to a stored slug — see ENGAGEMENT_TYPE_ALIASES. */
function resolveEngagementTypeAlias(engagementType) {
  const raw = String(engagementType == null ? '' : engagementType).trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(ENGAGEMENT_TYPE_ALIASES, raw)
    ? ENGAGEMENT_TYPE_ALIASES[raw] : null;
}

/**
 * The ONLY label any screen may render for an engagement.
 *
 * The stored display_name wins; otherwise the registry label, resolving a
 * display alias so a slug the sanitizer mangled still reads properly. Falls
 * back to a title-cased slug. Never emits a word from outside the
 * Section / Module / Client / Engagement / Environment vocabulary.
 */
function engagementDisplayName(engagement) {
  const explicit = trimOrNull(engagement && engagement.display_name, LIMITS.display_name);
  if (explicit) return explicit;

  const slug = engagement ? engagement.engagement_type : null;
  const aliased = resolveEngagementTypeAlias(slug);
  if (aliased) return ENGAGEMENT_TYPES[aliased].label;

  return describeEngagementType(slug).label;
}

/**
 * Is this engagement still holding its block?
 *
 * Retirement is a nullable TIMESTAMPTZ, not a lifecycle enum, precisely so no
 * future phase needs constraint surgery inside a migrations directory that
 * re-runs every boot as one implicit transaction. Read it through here so the
 * `retired_at IS NULL` test is spelled once.
 */
function isEngagementLive(engagement) {
  return !!engagement && (engagement.retired_at === null || engagement.retired_at === undefined);
}

/** The NIC array a placement implies, or null for "leave the spec alone".
 *  Returns a FRESH array each call — B2 writes this straight onto a spec VM and
 *  must be able to mutate it. See PLACEMENT_SEGMENTS for why this exists.
 *
 *  TOTAL FOR EVERY STRING, INCLUDING AN INHERITED ONE. PLACEMENT_SEGMENTS is a
 *  plain object literal, so a bare `PLACEMENT_SEGMENTS[placement]` resolves
 *  'constructor', 'toString', 'valueOf' and every other Object.prototype key to
 *  a FUNCTION — truthy, and with no .map — and the call threw a TypeError for a
 *  placement string this module itself is the authority on. The placement
 *  reaching here comes from a stored jsonb column and from a route body, so it
 *  is untrusted text: look it up as an OWN key only. */
function nicsForPlacement(placement) {
  const key = String(placement == null ? '' : placement);
  if (!Object.prototype.hasOwnProperty.call(PLACEMENT_SEGMENTS, key)) return null;
  const segs = PLACEMENT_SEGMENTS[key];
  if (!Array.isArray(segs)) return null;
  return segs.map(segment => ({ segment }));
}

/** A complete, valid, EMPTY model for a type — every MODEL_FIELD present, each
 *  at the DEFAULT its column carries, with the posture the registry declares. */
function defaultModelForType(engagementType) {
  const d = describeEngagementType(engagementType);
  return {
    display_name: null,
    perspective: d.perspective,
    credential_posture: d.credential_posture,
    asset_selection: [],
    scope_in: [],
    scope_out: [],
    allowed_techniques: [],
    issued_credentials: [],
    exposure_plan: [],
    objectives: [],
    brief: null,
    authored_fields: [],
    synthesis_meta: {},
  };
}

// ─── Path and secret predicates ─────────────────────────────────────────────

/** An absolute directory safe to interpolate onto a command line. No trailing
 *  slash, so `dir + '/' + filename` is unambiguous. */
function isDeliveryDir(dir) {
  if (typeof dir !== 'string') return false;
  if (!/^\/[A-Za-z0-9._/-]{1,180}$/.test(dir)) return false;
  if (UNSAFE_PATH_RE.test(dir)) return false;
  if (dir.endsWith('/')) return false;
  return true;
}

/** A single filename. Rejects EVERY separator, so dir + '/' + filename is
 *  structurally unable to escape dir. */
function isDeliveryFilename(name) {
  if (typeof name !== 'string') return false;
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(name)) return false;
  if (UNSAFE_PATH_RE.test(name)) return false;
  return true;
}

/**
 * Does this value carry a secret-shaped KEY anywhere in its tree?
 *
 * Walks KEY NAMES only. containsSecret({note: 'password policy'}) is false;
 * containsSecret({delivery: {api_token: null}}) is true — it is the key's
 * PRESENCE that is refused, not its value, so a form posting `password: ''` is
 * caught rather than silently accepted and filled in later.
 */
function containsSecret(value, _seen) {
  if (!value || typeof value !== 'object') return false;
  const seen = _seen || new Set();
  if (seen.has(value)) return false;
  seen.add(value);

  if (Array.isArray(value)) {
    for (const item of value) if (containsSecret(item, seen)) return true;
    return false;
  }
  for (const key of Object.keys(value)) {
    if (SECRET_KEY_PATTERN.test(key)) return true;
    if (containsSecret(value[key], seen)) return true;
  }
  return false;
}

/** Collect the dotted paths of every secret-named key under `value`. Used to
 *  report WHICH field offended rather than just that one did. */
function secretKeyPaths(value, prefix, out, seen) {
  const acc = out || [];
  const marks = seen || new Set();
  if (!value || typeof value !== 'object' || marks.has(value)) return acc;
  marks.add(value);

  if (Array.isArray(value)) {
    value.forEach((item, i) => secretKeyPaths(item, `${prefix}[${i}]`, acc, marks));
    return acc;
  }
  for (const key of Object.keys(value)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (SECRET_KEY_PATTERN.test(key)) acc.push(path);
    else secretKeyPaths(value[key], path, acc, marks);
  }
  return acc;
}

/** The one sentence every secret-field rejection carries. Names the two
 *  mechanisms that make a stored secret actively dangerous rather than merely
 *  untidy. Deliberately mentions no file whose NAME is outside the instructor
 *  vocabulary. */
const SECRET_FIELD_MESSAGE =
  'Secret-named field refused: an engagement records the ACCOUNT INTENT only — who, on which ' +
  'machine, at what privilege, delivered where. The real password is minted per environment at ' +
  'deploy time by password-generator.js, whose SYMBOLS = \'!@#$%&*\' (:13) makes it unusable as a ' +
  'script argument, because script-executor.js interpolates script_args UNQUOTED onto a command ' +
  'line (:249 PowerShell, :624 sh) where a single \'&\' backgrounds the command. Put the account ' +
  'name here and let the delivery step write the file.';

// ─── Report plumbing ────────────────────────────────────────────────────────

function makeReport() {
  return { errors: [], warnings: [], value: [] };
}
function pushProblem(list, path, code, message) {
  list.push({ path, code, message });
}

/** Normalize a free-text note the same way everywhere. */
function noteOf(raw) {
  return trimOrNull(raw, LIMITS.note);
}

/** Lower-case, underscore-joined key normalizer used by techniques and
 *  objectives. Strips everything outside `extra`+[a-z0-9_] rather than
 *  rejecting, so the only possible failure is "nothing survived" — which is
 *  exactly the one code each of those validators has for it. */
function slugifyKey(raw, extra, max) {
  const allowed = new RegExp(`[^a-z0-9_${extra || ''}]+`, 'g');
  return String(raw == null ? '' : raw)
    .trim()
    .toLowerCase()
    .replace(/[\s]+/g, '_')
    .replace(allowed, '')
    .replace(/_{2,}/g, '_')
    .replace(/^[_]+|[_]+$/g, '')
    .slice(0, max);
}

// ─── Validator 1: scope rules ───────────────────────────────────────────────

/** Infer the kind of a bare scope value. Mirrors the column comment's ladder. */
function inferScopeKind(value) {
  const s = String(value || '').trim();
  if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(s)) return 'cidr';
  if (/^https?:\/\//i.test(s)) return 'url';
  if (s.includes('*')) return 'hostname_pattern';
  return 'vm';
}

/**
 * Normalize one scope list (scope_in or scope_out).
 *
 * Two arrays rather than one array with a direction field: "is this in scope"
 * is asked far more often than "list every rule", and an empty out-of-scope
 * list must stay distinguishable from an unauthored one.
 *
 * A bare string is lifted to an entry and its kind inferred, because a screen
 * that lets an instructor type '10.20.0.0/16' into a box should not force them
 * to also pick 'cidr' from a select. An OBJECT with no kind gets the same
 * inference; an object with a kind that is not in SCOPE_KINDS is an error,
 * because a typo'd kind would otherwise silently become 'vm'.
 *
 * @param {*} rules
 * @param {{field?:string}} [opts]
 * @returns {{errors:Array, warnings:Array, value:Array}}
 */
function validateScopeRules(rules, opts) {
  const field = (opts && opts.field) || 'scope_in';
  const report = makeReport();

  if (rules === null || rules === undefined) return report;
  if (!Array.isArray(rules)) {
    pushProblem(report.errors, field, 'SCOPE_NOT_ARRAY',
      `${field} must be a list of scope rules.`);
    return report;
  }
  if (rules.length > LIMITS.scope_rules) {
    pushProblem(report.errors, field, 'SCOPE_TOO_MANY',
      `${field} carries ${rules.length} rules; at most ${LIMITS.scope_rules} are kept.`);
  }

  const seen = new Set();
  rules.slice(0, LIMITS.scope_rules).forEach((raw, i) => {
    const path = `${field}[${i}]`;

    let entry;
    if (typeof raw === 'string' || typeof raw === 'number') {
      const value = String(raw).trim();
      entry = { kind: inferScopeKind(value), value, note: null };
    } else if (isPlainObject(raw)) {
      const declared = trimOrNull(raw.kind);
      const value = trimOrNull(raw.value, LIMITS.scope_value + 1) || '';
      if (declared && !SCOPE_KINDS.includes(declared.toLowerCase())) {
        pushProblem(report.errors, `${path}.kind`, 'SCOPE_KIND_UNKNOWN',
          `Scope kind '${declared}' is not one of ${SCOPE_KINDS.join(', ')}.`);
        return;
      }
      entry = {
        kind: declared ? declared.toLowerCase() : inferScopeKind(value),
        value,
        note: noteOf(raw.note),
      };
    } else {
      pushProblem(report.errors, path, 'SCOPE_ENTRY_NOT_OBJECT',
        'Each scope rule must be an object or a plain string.');
      return;
    }

    if (entry.kind === 'all') {
      entry.value = '';
    } else if (!entry.value) {
      pushProblem(report.errors, `${path}.value`, 'SCOPE_VALUE_REQUIRED',
        `A '${entry.kind}' scope rule needs a value.`);
      return;
    } else if (entry.value.length > LIMITS.scope_value) {
      pushProblem(report.errors, `${path}.value`, 'SCOPE_VALUE_TOO_LONG',
        `Scope value is longer than ${LIMITS.scope_value} characters.`);
      return;
    }

    // Deduped on kind+value, first wins. Silent: a repeated rule is a UI
    // accident, not something an instructor needs told about.
    const dedupe = `${entry.kind}|${entry.value.toLowerCase()}`;
    if (seen.has(dedupe)) return;
    seen.add(dedupe);

    // Rebuilt key by key — an unrecognised extra key is never carried through.
    report.value.push({ kind: entry.kind, value: entry.value, note: entry.note });
  });

  return report;
}

// ─── Validator 2: allowed techniques ────────────────────────────────────────

/**
 * Rules of engagement, as one ordered list carrying both permissions and
 * prohibitions — because that is how it renders in the brief. Per-entry
 * qualifiers go in `constraint` ('at most 5 attempts per account per hour').
 * Nothing joins or filters on this list.
 */
function validateAllowedTechniques(list) {
  const report = makeReport();
  if (list === null || list === undefined) return report;
  if (!Array.isArray(list)) {
    pushProblem(report.errors, 'allowed_techniques', 'TECHNIQUES_NOT_ARRAY',
      'allowed_techniques must be a list.');
    return report;
  }
  if (list.length > LIMITS.techniques) {
    pushProblem(report.errors, 'allowed_techniques', 'TECHNIQUES_TOO_MANY',
      `allowed_techniques carries ${list.length} entries; at most ${LIMITS.techniques} are kept.`);
  }

  const seen = new Set();
  list.slice(0, LIMITS.techniques).forEach((raw, i) => {
    const path = `allowed_techniques[${i}]`;
    if (!isPlainObject(raw)) {
      pushProblem(report.errors, path, 'TECHNIQUE_ENTRY_NOT_OBJECT',
        'Each rule of engagement must be an object.');
      return;
    }

    const key = slugifyKey(raw.key || raw.label, '', 48);
    if (!key) {
      pushProblem(report.errors, `${path}.key`, 'TECHNIQUE_KEY_REQUIRED',
        'A rule of engagement needs a key, or a label one can be derived from.');
      return;
    }
    if (seen.has(key)) {
      pushProblem(report.errors, `${path}.key`, 'TECHNIQUE_KEY_DUPLICATE',
        `Rule of engagement '${key}' is listed more than once.`);
      return;
    }
    seen.add(key);

    report.value.push({
      key,
      label: trimOrNull(raw.label, 200) || titleCaseSlug(key),
      // `allowed: false` must survive, so the default is applied on null/undefined
      // only — never with a truthiness test.
      allowed: raw.allowed === null || raw.allowed === undefined ? true : !!raw.allowed,
      constraint: trimOrNull(raw.constraint, 400),
      note: noteOf(raw.note),
    });
  });

  return report;
}

// ─── Validator 3: issued credentials ────────────────────────────────────────

/**
 * ACCOUNT INTENTS ONLY. See the NEVER A SECRET section of this file's header.
 *
 * Each entry is CONSTRUCTED from a whitelist:
 *   {slot_key, username, account_kind, target_vm, privilege, source,
 *    delivery:{target, vm_name, dir, filename, owner, mode}, note}
 * so an unrecognised key is never copied through, whatever it is called.
 *
 * slot_key is the stable handle the per-environment secret is minted AGAINST at
 * deploy time; it is the only field B3 joins on, which is why it is validated
 * as an identifier rather than as prose.
 *
 * THE ONE EXCEPTION TO "OFFENDING ENTRIES ARE DROPPED": a secret-named key does
 * not take its entry with it. The key is gone either way (the whitelist never
 * copies it), and losing an entire account intent because a form helpfully
 * posted an empty `password` field is the worse failure. The error is still an
 * error, so a route still answers 400 — it just does not silently discard the
 * instructor's work along the way.
 *
 * @param {*} list
 * @param {{knownVmNames?:string[]}} [opts]
 */
function validateIssuedCredentials(list, opts) {
  const known = new Set(((opts && opts.knownVmNames) || []).map(n => String(n).toLowerCase()));
  const report = makeReport();

  if (list === null || list === undefined) return report;
  if (!Array.isArray(list)) {
    pushProblem(report.errors, 'issued_credentials', 'CREDENTIALS_NOT_ARRAY',
      'issued_credentials must be a list of account intents.');
    return report;
  }
  if (list.length > LIMITS.credentials) {
    pushProblem(report.errors, 'issued_credentials', 'CREDENTIALS_TOO_MANY',
      `issued_credentials carries ${list.length} entries; at most ${LIMITS.credentials} are kept.`);
  }

  const seen = new Set();
  list.slice(0, LIMITS.credentials).forEach((raw, i) => {
    const path = `issued_credentials[${i}]`;
    if (!isPlainObject(raw)) {
      pushProblem(report.errors, path, 'CREDENTIAL_ENTRY_NOT_OBJECT',
        'Each issued credential must be an object.');
      return;
    }

    // Secret-named keys, at any depth. Reported per key so the instructor is
    // told WHICH field to remove; the entry itself survives, stripped.
    for (const secretPath of secretKeyPaths(raw, '', [], new Set())) {
      pushProblem(report.errors, `${path}.${secretPath}`, 'CREDENTIAL_SECRET_FIELD',
        SECRET_FIELD_MESSAGE);
    }

    const slotKey = slugifyKey(raw.slot_key, '.\\-', LIMITS.slot_key);
    if (!trimOrNull(raw.slot_key)) {
      pushProblem(report.errors, `${path}.slot_key`, 'CREDENTIAL_SLOT_KEY_REQUIRED',
        'Each issued credential needs a slot_key — the handle the per-environment secret is minted against.');
      return;
    }
    if (!slotKey || !/^[a-z0-9_.-]{1,64}$/.test(slotKey)) {
      pushProblem(report.errors, `${path}.slot_key`, 'CREDENTIAL_SLOT_KEY_INVALID',
        `slot_key '${String(raw.slot_key)}' must be 1-${LIMITS.slot_key} characters of a-z, 0-9, dot, dash or underscore.`);
      return;
    }
    if (seen.has(slotKey)) {
      pushProblem(report.errors, `${path}.slot_key`, 'CREDENTIAL_SLOT_KEY_DUPLICATE',
        `slot_key '${slotKey}' is used more than once.`);
      return;
    }

    const username = trimOrNull(raw.username, LIMITS.username);
    if (!username) {
      pushProblem(report.errors, `${path}.username`, 'CREDENTIAL_USERNAME_REQUIRED',
        'Each issued credential needs the account name the client is handing over.');
      return;
    }

    const accountKind = (trimOrNull(raw.account_kind) || 'local').toLowerCase();
    if (!ACCOUNT_KINDS.includes(accountKind)) {
      pushProblem(report.errors, `${path}.account_kind`, 'CREDENTIAL_ACCOUNT_KIND_UNKNOWN',
        `account_kind '${accountKind}' is not one of ${ACCOUNT_KINDS.join(', ')}.`);
      return;
    }

    const source = (trimOrNull(raw.source) || 'cloudinit').toLowerCase();
    if (!CREDENTIAL_SOURCES.includes(source)) {
      pushProblem(report.errors, `${path}.source`, 'CREDENTIAL_SOURCE_UNKNOWN',
        `source '${source}' is not one of ${CREDENTIAL_SOURCES.join(', ')}.`);
      return;
    }

    const targetVm = trimOrNull(raw.target_vm, LIMITS.vm_name);
    if (targetVm && known.size && !known.has(targetVm.toLowerCase())) {
      // A WARNING, not an error: the model can legitimately be authored before
      // the environment is synthesized, and an engagement outliving one estate
      // revision must not become unsaveable.
      pushProblem(report.warnings, `${path}.target_vm`, 'CREDENTIAL_TARGET_UNKNOWN',
        `'${targetVm}' is not a machine in this environment.`);
    }

    // ── delivery ──────────────────────────────────────────────────────────
    // dir and filename are split so no path is ever built by interpolation,
    // and both halves are validated against the character class that makes a
    // string unusable as a script argument. See UNSAFE_PATH_RE.
    const rawDelivery = isPlainObject(raw.delivery) ? raw.delivery : {};
    const deliveryTarget = String(rawDelivery.target || 'console').trim().toLowerCase() === 'vm'
      ? 'vm' : 'console';

    const dir = trimOrNull(rawDelivery.dir) || '/opt/engagement';
    if (!isDeliveryDir(dir)) {
      pushProblem(report.errors, `${path}.delivery.dir`, 'CREDENTIAL_DELIVERY_DIR_INVALID',
        `Delivery directory '${dir}' is not an absolute path safe to place on a command line.`);
      return;
    }

    const filename = trimOrNull(rawDelivery.filename) || 'credentials.txt';
    if (!isDeliveryFilename(filename)) {
      pushProblem(report.errors, `${path}.delivery.filename`, 'CREDENTIAL_DELIVERY_FILENAME_INVALID',
        `Delivery filename '${filename}' must be a single name with no path separator.`);
      return;
    }

    const mode = String(trimOrNull(rawDelivery.mode) || '600');
    if (!/^[0-7]{3,4}$/.test(mode)) {
      pushProblem(report.errors, `${path}.delivery.mode`, 'CREDENTIAL_DELIVERY_MODE_INVALID',
        `Delivery mode '${mode}' must be three or four octal digits.`);
      return;
    }

    // On 'vm' delivery the machine is REQUIRED; on 'console' it is forced null,
    // so a stale value cannot survive a target change and send the file to the
    // wrong guest.
    const deliveryVm = deliveryTarget === 'vm'
      ? trimOrNull(rawDelivery.vm_name, LIMITS.vm_name) : null;
    if (deliveryTarget === 'vm' && !deliveryVm) {
      pushProblem(report.errors, `${path}.delivery.vm_name`, 'CREDENTIAL_DELIVERY_VM_REQUIRED',
        'Delivery to a machine needs delivery.vm_name.');
      return;
    }
    if (deliveryVm && known.size && !known.has(deliveryVm.toLowerCase())) {
      pushProblem(report.warnings, `${path}.delivery.vm_name`, 'CREDENTIAL_TARGET_UNKNOWN',
        `'${deliveryVm}' is not a machine in this environment.`);
    }

    seen.add(slotKey);
    report.value.push({
      slot_key: slotKey,
      username,
      account_kind: accountKind,
      target_vm: targetVm,
      privilege: trimOrNull(raw.privilege, 120),
      source,
      delivery: {
        target: deliveryTarget,
        vm_name: deliveryVm,
        dir,
        filename,
        owner: trimOrNull(rawDelivery.owner, 64),
        mode,
      },
      note: noteOf(raw.note),
    });
  });

  return report;
}

// ─── Validator 4: exposure plan ─────────────────────────────────────────────

/**
 * WHERE EACH MACHINE SITS, not what is published.
 *
 *   [{vm_name, placement, services, note}]
 *
 * There is no gateway perimeter publish anywhere in this product: the
 * environment stays internal to the lane, and the only thing an engagement
 * declares is which segment a machine is homed on. See the PLACEMENT, NOT
 * PUBLISHING section of this file's header for the three shared-core mechanisms
 * that make that work with no gateway change.
 *
 * `services` is documentation for the brief and the scan documents — the
 * repo's service inference is the compile's business, and an entry here is an
 * instructor OVERRIDING or annotating it, never a port that gets opened.
 *
 * @param {*} list
 * @param {{knownVmNames?:string[], subnetScheme?:string|null}} [opts]
 */
function validateExposurePlan(list, opts) {
  const known = new Set(((opts && opts.knownVmNames) || []).map(n => String(n).toLowerCase()));
  const subnetScheme = trimOrNull(opts && opts.subnetScheme);
  const report = makeReport();

  if (list === null || list === undefined) return report;
  if (!Array.isArray(list)) {
    pushProblem(report.errors, 'exposure_plan', 'EXPOSURE_NOT_ARRAY',
      'exposure_plan must be a list of placements.');
    return report;
  }
  if (list.length > LIMITS.exposure) {
    pushProblem(report.errors, 'exposure_plan', 'EXPOSURE_TOO_MANY',
      `exposure_plan carries ${list.length} entries; at most ${LIMITS.exposure} are kept.`);
  }

  const seen = new Set();
  let pivotVm = null;

  list.slice(0, LIMITS.exposure).forEach((raw, i) => {
    const path = `exposure_plan[${i}]`;
    if (!isPlainObject(raw)) {
      pushProblem(report.errors, path, 'EXPOSURE_ENTRY_NOT_OBJECT',
        'Each exposure entry must be an object.');
      return;
    }

    const vmName = trimOrNull(raw.vm_name, LIMITS.vm_name);
    if (!vmName) {
      pushProblem(report.errors, `${path}.vm_name`, 'EXPOSURE_VM_REQUIRED',
        'Each exposure entry names the machine it places.');
      return;
    }

    const placement = (trimOrNull(raw.placement) || '').toLowerCase();
    if (!PLACEMENTS.includes(placement)) {
      pushProblem(report.errors, `${path}.placement`, 'EXPOSURE_PLACEMENT_UNKNOWN',
        `placement '${raw.placement}' is not one of ${PLACEMENTS.join(', ')}.`);
      return;
    }

    const dedupe = vmName.toLowerCase();
    if (seen.has(dedupe)) {
      pushProblem(report.errors, `${path}.vm_name`, 'EXPOSURE_VM_DUPLICATE',
        `'${vmName}' is placed more than once; a machine sits in exactly one place.`);
      return;
    }

    if (placement === 'pivot') {
      if (pivotVm) {
        // ERROR, and the reason travels with it. The deployer defines exactly
        // ONE dual-homed address — .240 on each segment — so a second pivot has
        // nowhere to land. Authority: challenge-lane-deployer.js:766-770,
        // cited here in the comment rather than in the message because the
        // instructor-facing vocabulary is Section / Module / Client /
        // Engagement / Environment and a message must not import a word from
        // outside it.
        pushProblem(report.errors, `${path}.placement`, 'EXPOSURE_MULTIPLE_PIVOTS',
          `'${vmName}' cannot also be the pivot: '${pivotVm}' already is. The deployer pins exactly ` +
          'one dual-homed machine to .240 on BOTH segments, and that single address is the only ' +
          'place a pivot can land — so a second one has nowhere to go. Exactly one bridge per ' +
          'environment is deliberate: extra machines on the outside are free, and finding which ' +
          'one bridges is the exercise.');
        return;
      }
      pivotVm = vmName;
    }

    // v1/v2 is one flat lan0 — resolveVmSegments returns ['lan'] for every VM
    // (lane-networking.js:381) — so there is no ext/int boundary for a pivot to
    // straddle or an internal machine to hide behind. A warning rather than an
    // error: the model can be authored before the environment's scheme is
    // settled, and B1 can offer to switch the environment to v3.
    if (subnetScheme && subnetScheme !== 'v3' && placement !== 'public') {
      pushProblem(report.warnings, `${path}.placement`, 'EXPOSURE_REQUIRES_V3',
        `A '${placement}' placement needs a v3 environment; '${subnetScheme}' is one flat segment, ` +
        'so the placement would be a fiction.');
    }

    if (known.size && !known.has(dedupe)) {
      pushProblem(report.warnings, `${path}.vm_name`, 'EXPOSURE_TARGET_UNKNOWN',
        `'${vmName}' is not a machine in this environment.`);
    }

    seen.add(dedupe);
    report.value.push({
      vm_name: vmName,
      placement,
      services: normalizeServiceLabels(raw.services),
      note: noteOf(raw.note),
    });
  });

  return report;
}

/** Service labels are documentation. Non-strings are dropped rather than
 *  reported: the field is an annotation, and a bad one must not cost an
 *  instructor the placement it annotates. */
function normalizeServiceLabels(raw) {
  if (!Array.isArray(raw)) return [];
  const out = [];
  const seen = new Set();
  for (const item of raw) {
    if (item === null || item === undefined || typeof item === 'object') continue;
    const label = trimOrNull(item, LIMITS.service_label);
    if (!label) continue;
    const key = label.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(label);
    if (out.length >= LIMITS.services) break;
  }
  return out;
}

// ─── Validator 5: objectives ────────────────────────────────────────────────

/**
 * Objective DEFINITIONS. Achievement is NOT stored here.
 *
 *   [{objective_key, title, points, maps_to}]
 *   maps_to: {kind:'flag', vm_name, flag_type:'user'|'root'} | {kind:'manual'}
 *
 * (vm_name, flag_type) is EXACTLY cybercore_lane_flag's own unit — its UNIQUE
 * is (lane_id, vm_name, flag_type) and it already carries an unused `points`
 * column (migrations/023_lane_flags.sql:29-40). Scoring is a VIEW over that
 * table, not a fourth progress tracker and not a new table.
 */
function validateObjectives(list) {
  const report = makeReport();
  if (list === null || list === undefined) return report;
  if (!Array.isArray(list)) {
    pushProblem(report.errors, 'objectives', 'OBJECTIVES_NOT_ARRAY',
      'objectives must be a list.');
    return report;
  }
  if (list.length > LIMITS.objectives) {
    pushProblem(report.errors, 'objectives', 'OBJECTIVES_TOO_MANY',
      `objectives carries ${list.length} entries; at most ${LIMITS.objectives} are kept.`);
  }

  const seen = new Set();
  list.slice(0, LIMITS.objectives).forEach((raw, i) => {
    const path = `objectives[${i}]`;
    if (!isPlainObject(raw)) {
      pushProblem(report.errors, path, 'OBJECTIVE_ENTRY_NOT_OBJECT',
        'Each objective must be an object.');
      return;
    }

    const title = trimOrNull(raw.title, 300);
    if (!title) {
      pushProblem(report.errors, `${path}.title`, 'OBJECTIVE_TITLE_REQUIRED',
        'Each objective needs a title.');
      return;
    }

    const key = slugifyKey(raw.objective_key || title, '.\\-', 64);
    if (!key) {
      pushProblem(report.errors, `${path}.objective_key`, 'OBJECTIVE_TITLE_REQUIRED',
        'No objective key could be derived from this title.');
      return;
    }
    if (seen.has(key)) {
      pushProblem(report.errors, `${path}.objective_key`, 'OBJECTIVE_KEY_DUPLICATE',
        `Objective key '${key}' is used more than once.`);
      return;
    }

    // Clamped rather than rejected: points is a weighting, and a typo'd 100000
    // should not cost the instructor the objective.
    let points = parseInt(raw.points, 10);
    if (!Number.isInteger(points)) points = 10;
    points = Math.max(0, Math.min(1000, points));

    const rawMap = isPlainObject(raw.maps_to) ? raw.maps_to : { kind: 'manual' };
    const mapKind = String(rawMap.kind || 'manual').trim().toLowerCase();
    if (!OBJECTIVE_KINDS.includes(mapKind)) {
      pushProblem(report.errors, `${path}.maps_to`, 'OBJECTIVE_MAPS_TO_INVALID',
        `maps_to.kind '${rawMap.kind}' is not one of ${OBJECTIVE_KINDS.join(', ')}.`);
      return;
    }

    let mapsTo;
    if (mapKind === 'flag') {
      const vmName = trimOrNull(rawMap.vm_name, LIMITS.vm_name);
      if (!vmName) {
        pushProblem(report.errors, `${path}.maps_to.vm_name`, 'OBJECTIVE_MAPS_TO_INVALID',
          'A flag objective names the machine the flag is planted on.');
        return;
      }
      const flagType = String(rawMap.flag_type || '').trim().toLowerCase();
      if (!FLAG_TYPES.includes(flagType)) {
        pushProblem(report.errors, `${path}.maps_to.flag_type`, 'OBJECTIVE_FLAG_TYPE_UNKNOWN',
          `flag_type '${rawMap.flag_type}' is not one of ${FLAG_TYPES.join(', ')}.`);
        return;
      }
      mapsTo = { kind: 'flag', vm_name: vmName, flag_type: flagType };
    } else {
      mapsTo = { kind: 'manual' };
    }

    seen.add(key);
    report.value.push({ objective_key: key, title, points, maps_to: mapsTo });
  });

  return report;
}

// ─── Asset selection ────────────────────────────────────────────────────────

/**
 * EXACTLY four keys: {hostname, role, os, included}.
 *
 * The same shape as ciab_profile_lane_groups.asset_selection and as
 * routes/profile-deploy.js defaultAssetSelection (:108-116), byte for byte, so
 * that storing a selection on the engagement is provably a no-op for a client
 * whose engagement is the legacy 'default'. A fifth key here would be a fifth
 * key profile-to-spec.js has never seen.
 *
 * Returns the array directly rather than a report: the only failure mode is a
 * missing hostname, and an entry with no hostname names nothing.
 */
function validateAssetSelection(raw) {
  if (!Array.isArray(raw)) return [];
  const out = [];
  const seen = new Set();
  for (const item of raw) {
    if (!isPlainObject(item)) continue;
    const hostname = trimOrNull(item.hostname, LIMITS.vm_name);
    if (!hostname) continue;
    const key = hostname.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      hostname,
      role: trimOrNull(item.role, 64),
      os: trimOrNull(item.os, 120),
      included: !!item.included,
    });
  }
  return out;
}

// ─── authored_fields ────────────────────────────────────────────────────────

/** Unique, sorted, and intersected with AUTHORABLE_FIELDS — so a stored list
 *  can never hold back a field a refresh is entitled to write. */
function normalizeAuthoredFields(raw) {
  if (!Array.isArray(raw)) return [];
  const seen = new Set();
  for (const item of raw) {
    const name = trimOrNull(item, 64);
    if (name && AUTHORABLE_FIELDS.includes(name)) seen.add(name);
  }
  return Array.from(seen).sort();
}

// ─── The top-level validator ────────────────────────────────────────────────

/**
 * Validate a PARTIAL patch of the engagement model.
 *
 * PARTIAL PATCH SEMANTICS: only keys PRESENT on `patch` appear in `value`, so
 * the UPDATE writes exactly the columns the caller sent and never blanks one it
 * did not mention. An unknown key is ignored — EXCEPT a secret-named one, which
 * is an error wherever it appears.
 *
 * NEVER THROWS. The route turns `errors` into a 400; a value that reached
 * Postgres and tripped a CHECK would raise 23514, which
 * routes/profile-deploy.js renders as `err.statusCode || 500` — an unhandled
 * 500 in place of the 400 the route already knows how to produce. THE JS
 * VALIDATOR RUNS FIRST, ALWAYS.
 *
 * @param {object} patch
 * @param {{engagementType?:string, knownVmNames?:string[], subnetScheme?:string|null}} [opts]
 * @returns {{valid:boolean, errors:Array, warnings:Array, value:object}}
 */
function validateEngagementPlan(patch, opts) {
  const options = opts || {};
  const engagementType = options.engagementType === undefined
    ? DEFAULT_TYPE_KEY : options.engagementType;
  const knownVmNames = options.knownVmNames || [];
  const subnetScheme = options.subnetScheme || null;

  const errors = [];
  const warnings = [];
  const value = {};

  if (!isPlainObject(patch)) {
    errors.push({
      path: '', code: 'PATCH_NOT_OBJECT',
      message: 'An engagement model patch must be an object.',
    });
    return { valid: false, errors, warnings, value };
  }

  const has = k => Object.prototype.hasOwnProperty.call(patch, k);

  // Any key at all whose NAME looks like a secret is refused, even one this
  // model has no column for — a caller that sends {password} is a caller whose
  // next request will send it somewhere that stores it.
  for (const key of Object.keys(patch)) {
    if (SECRET_KEY_PATTERN.test(key)) {
      errors.push({ path: key, code: 'SECRET_FIELD_REJECTED', message: SECRET_FIELD_MESSAGE });
    }
  }

  // ── scalars ───────────────────────────────────────────────────────────────
  if (has('display_name')) {
    const raw = patch.display_name;
    const trimmed = trimOrNull(raw);
    if (trimmed && trimmed.length > LIMITS.display_name) {
      errors.push({
        path: 'display_name', code: 'DISPLAY_NAME_TOO_LONG',
        message: `The engagement name is longer than ${LIMITS.display_name} characters.`,
      });
    }
    value.display_name = trimmed ? trimmed.slice(0, LIMITS.display_name) : null;
  }

  if (has('brief')) {
    const trimmed = trimOrNull(patch.brief);
    if (trimmed && trimmed.length > LIMITS.brief) {
      errors.push({
        path: 'brief', code: 'BRIEF_TOO_LONG',
        message: `The brief is longer than ${LIMITS.brief} characters.`,
      });
    }
    value.brief = trimmed ? trimmed.slice(0, LIMITS.brief) : null;
  }

  // ── posture, and the reconciliation between three representations ─────────
  //
  // The same fact is spelled in three places: the engagement_type slug, the
  // perspective column, and the credential_posture column. Nothing used to
  // reconcile them. For a KNOWN slug the registry is authoritative and a
  // contradicting patch is an error naming both values. For an UNKNOWN slug
  // there is nothing to contradict, so any legal value is accepted — which is
  // exactly what keeps a locally defined engagement type able to declare
  // itself external.
  const descriptor = describeEngagementType(engagementType);

  if (has('perspective')) {
    const p = String(patch.perspective === null || patch.perspective === undefined
      ? '' : patch.perspective).trim().toLowerCase();
    if (!PERSPECTIVES.includes(p)) {
      errors.push({
        path: 'perspective', code: 'PERSPECTIVE_UNKNOWN',
        message: `perspective '${patch.perspective}' is not one of ${PERSPECTIVES.join(', ')}.`,
      });
    } else if (descriptor.known && p !== descriptor.perspective) {
      errors.push({
        path: 'perspective', code: 'PERSPECTIVE_CONTRADICTS_TYPE',
        message: `Engagement type '${descriptor.key}' is ${descriptor.perspective}; ` +
          `this patch sets perspective '${p}'. Change the engagement type, or use a locally ` +
          'defined type that declares its own posture.',
      });
      value.perspective = p;
    } else {
      value.perspective = p;
    }
  }

  if (has('credential_posture')) {
    const c = String(patch.credential_posture === null || patch.credential_posture === undefined
      ? '' : patch.credential_posture).trim().toLowerCase();
    if (!CREDENTIAL_POSTURES.includes(c)) {
      errors.push({
        path: 'credential_posture', code: 'CREDENTIAL_POSTURE_UNKNOWN',
        message: `credential_posture '${patch.credential_posture}' is not one of ${CREDENTIAL_POSTURES.join(', ')}.`,
      });
    } else if (descriptor.known && c !== descriptor.credential_posture) {
      errors.push({
        path: 'credential_posture', code: 'CREDENTIAL_POSTURE_CONTRADICTS_TYPE',
        message: `Engagement type '${descriptor.key}' hands over '${descriptor.credential_posture}'; ` +
          `this patch sets credential_posture '${c}'. Change the engagement type, or use a locally ` +
          'defined type that declares its own posture.',
      });
      value.credential_posture = c;
    } else {
      value.credential_posture = c;
    }
  }

  // ── lists ─────────────────────────────────────────────────────────────────
  const absorb = (field, report) => {
    for (const e of report.errors) errors.push(e);
    for (const w of report.warnings) warnings.push(w);
    value[field] = report.value;
    // A non-empty list that normalized down to nothing is reported: silently
    // storing [] would look to the instructor like the database lost the work.
    if (Array.isArray(patch[field]) && patch[field].length > 0 && report.value.length === 0) {
      errors.push({
        path: field, code: 'FIELD_FULLY_REJECTED',
        message: `Every entry in ${field} was rejected, so nothing would be stored.`,
      });
    }
  };

  if (has('asset_selection')) {
    if (!Array.isArray(patch.asset_selection)) {
      errors.push({
        path: 'asset_selection', code: 'ASSET_SELECTION_NOT_ARRAY',
        message: 'asset_selection must be a list of {hostname, role, os, included}.',
      });
    } else {
      const selected = validateAssetSelection(patch.asset_selection);
      value.asset_selection = selected;
      if (patch.asset_selection.length > 0 && selected.length === 0) {
        errors.push({
          path: 'asset_selection', code: 'FIELD_FULLY_REJECTED',
          message: 'Every entry in asset_selection was rejected, so nothing would be stored.',
        });
      }
    }
  }

  if (has('scope_in')) absorb('scope_in', validateScopeRules(patch.scope_in, { field: 'scope_in' }));
  if (has('scope_out')) absorb('scope_out', validateScopeRules(patch.scope_out, { field: 'scope_out' }));
  if (has('allowed_techniques')) absorb('allowed_techniques', validateAllowedTechniques(patch.allowed_techniques));
  if (has('issued_credentials')) {
    absorb('issued_credentials', validateIssuedCredentials(patch.issued_credentials, { knownVmNames }));
  }
  if (has('exposure_plan')) {
    absorb('exposure_plan', validateExposurePlan(patch.exposure_plan, { knownVmNames, subnetScheme }));
  }
  if (has('objectives')) absorb('objectives', validateObjectives(patch.objectives));

  // ── bookkeeping columns ───────────────────────────────────────────────────
  if (has('authored_fields')) {
    if (!Array.isArray(patch.authored_fields)) {
      errors.push({
        path: 'authored_fields', code: 'AUTHORED_FIELDS_NOT_ARRAY',
        message: 'authored_fields must be a list of field names.',
      });
    } else {
      value.authored_fields = normalizeAuthoredFields(patch.authored_fields);
    }
  }

  if (has('synthesis_meta')) {
    if (!isPlainObject(patch.synthesis_meta)) {
      errors.push({
        path: 'synthesis_meta', code: 'SYNTHESIS_META_NOT_OBJECT',
        message: 'synthesis_meta must be an object.',
      });
    } else {
      value.synthesis_meta = patch.synthesis_meta;
    }
  }

  return { valid: errors.length === 0, errors, warnings, value };
}

/**
 * The throwing wrapper, for a route that wants one line.
 *
 * Matches createEngagement's existing idiom (engagement-provision.js:327-335):
 * an Error carrying `status`, so `res.status(err.status || 500)` renders a 400
 * rather than the unhandled 500 a bare throw would produce.
 */
function assertValidEngagementPlan(patch, opts) {
  const report = validateEngagementPlan(patch, opts);
  if (report.valid) return report.value;

  const first = report.errors[0];
  const extra = report.errors.length - 1;
  const message = `${first.path ? `${first.path}: ` : ''}${first.message}` +
    (extra > 0 ? ` (+${extra} more)` : '');

  throw Object.assign(new Error(message), {
    status: 400,
    code: 'ENGAGEMENT_PLAN_INVALID',
    errors: report.errors,
    warnings: report.warnings,
  });
}

// ─── Reading a row back ─────────────────────────────────────────────────────

/** jsonb comes back already parsed from pg. The parse below is belt and braces
 *  for a test fixture, a CSV import, or a future driver change — and it must
 *  never throw, because a malformed column is a data problem, not a crash. */
function parseJsonColumn(raw, fallback) {
  if (raw === null || raw === undefined) return fallback;
  let v = raw;
  if (typeof v === 'string') {
    const s = v.trim();
    if (!s) return fallback;
    try { v = JSON.parse(s); } catch { return fallback; }
  }
  if (Array.isArray(fallback)) return Array.isArray(v) ? v : fallback;
  if (isPlainObject(fallback)) return isPlainObject(v) ? v : fallback;
  return v;
}

/**
 * Project a raw SELECT * row onto the engagement model.
 *
 * EVERY MODEL_FIELD IS ALWAYS PRESENT. A NULL, missing, or string-delivered
 * column falls back to the DEFAULT its migration assigns, so a row created by
 * adoptExistingReservation's fixed 8-column INSERT — which runs on the READ
 * path and will never supply any of these — reads back as a valid empty model
 * rather than a bag of undefineds. On a database where the B0 migration has not
 * yet run, every added key is simply its default and no existing key changes
 * value, which is what makes widening rowToEngagement a no-op for current
 * callers.
 */
function engagementModelFromRow(row) {
  const r = isPlainObject(row) ? row : {};
  const fallback = defaultModelForType(r.engagement_type);

  return {
    display_name: trimOrNull(r.display_name, LIMITS.display_name),
    perspective: PERSPECTIVES.includes(String(r.perspective || '').toLowerCase())
      ? String(r.perspective).toLowerCase() : fallback.perspective,
    credential_posture: CREDENTIAL_POSTURES.includes(String(r.credential_posture || '').toLowerCase())
      ? String(r.credential_posture).toLowerCase() : fallback.credential_posture,
    asset_selection: parseJsonColumn(r.asset_selection, []),
    scope_in: parseJsonColumn(r.scope_in, []),
    scope_out: parseJsonColumn(r.scope_out, []),
    allowed_techniques: parseJsonColumn(r.allowed_techniques, []),
    issued_credentials: parseJsonColumn(r.issued_credentials, []),
    exposure_plan: parseJsonColumn(r.exposure_plan, []),
    objectives: parseJsonColumn(r.objectives, []),
    brief: trimOrNull(r.brief, LIMITS.brief),
    authored_fields: normalizeAuthoredFields(parseJsonColumn(r.authored_fields, [])),
    synthesis_meta: parseJsonColumn(r.synthesis_meta, {}),
  };
}

// ─── Proposals vs authored work ─────────────────────────────────────────────

/**
 * Split a compiler's proposal into what may be written and what must not.
 *
 * authored_fields is the one column that CANNOT be added later: once
 * instructors have edited scope and a refresh action exists, which fields were
 * authored is unrecoverable retroactively. This function is the reader that
 * makes it pay — a refresh fills everything NOT in the list and leaves
 * everything that is.
 *
 * PURE. It does not write, and it does not decide whether to write.
 *
 * @returns {{patch:object, skipped:string[]}} skipped is in AUTHORABLE_FIELDS
 *   order, so a screen listing "kept your edits to ..." reads consistently.
 */
function mergeProposal(engagement, proposal) {
  const authored = new Set(normalizeAuthoredFields(engagement && engagement.authored_fields));
  const patch = {};
  const offered = isPlainObject(proposal) ? proposal : {};

  for (const key of Object.keys(offered)) {
    if (authored.has(key)) continue;
    patch[key] = offered[key];
  }

  const skipped = AUTHORABLE_FIELDS.filter(
    f => authored.has(f) && Object.prototype.hasOwnProperty.call(offered, f)
  );

  return { patch, skipped };
}

// ─── Exports ────────────────────────────────────────────────────────────────

module.exports = {
  // Vocabulary
  DEFAULT_TYPE_KEY,
  PERSPECTIVES,
  CREDENTIAL_POSTURES,
  SCOPE_KINDS,
  RESOLVABLE_SCOPE_KINDS,
  ACCOUNT_KINDS,
  CREDENTIAL_SOURCES,
  DELIVERY_TARGETS,
  OBJECTIVE_KINDS,
  FLAG_TYPES,
  PLACEMENTS,
  PLACEMENT_SEGMENTS,
  DUAL_HOMED_OCTET,
  // Patterns and ceilings
  SECRET_KEY_PATTERN,
  UNSAFE_PATH_RE,
  LIMITS,
  // Column sets — the UPDATE writer and the tests read these
  MODEL_FIELDS,
  AUTHORABLE_FIELDS,
  JSONB_MODEL_FIELDS,
  // The registry
  ENGAGEMENT_TYPES,
  ENGAGEMENT_TYPE_ALIASES,
  // Descriptors
  describeEngagementType,
  resolveEngagementTypeAlias,
  engagementDisplayName,
  isEngagementLive,
  defaultModelForType,
  nicsForPlacement,
  // Predicates
  isDeliveryDir,
  isDeliveryFilename,
  containsSecret,
  // List validators
  validateScopeRules,
  validateAllowedTechniques,
  validateIssuedCredentials,
  validateExposurePlan,
  validateObjectives,
  validateAssetSelection,
  normalizeAuthoredFields,
  // Top level
  validateEngagementPlan,
  assertValidEngagementPlan,
  engagementModelFromRow,
  mergeProposal,
};
