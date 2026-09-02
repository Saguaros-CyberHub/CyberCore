/**
 * ============================================================================
 * CALDERA SSO — THE SIGNED, SINGLE-USE IDENTITY TOKEN
 * ============================================================================
 *
 * ############################################################################
 * # NOTHING IN THIS FILE HAS EVER BEEN VERIFIED BY A REAL CALDERA. The other #
 * # half of this contract is infrastructure/caldera/login_handler.py, which  #
 * # has never been executed inside Caldera either. What IS proved is that    #
 * # the two implementations agree byte for byte on a committed set of test   #
 * # vectors, and that python3 accepts a token this file minted — see         #
 * # front-end/test/caldera-sso.test.js.                                      #
 * ############################################################################
 *
 * WHY A SIGNED TOKEN AND NOT A PLAIN HEADER
 * ----------------------------------------------------------------------------
 * Caddy advisory GHSA-7r4p-vjf4-gxv4: `forward_auth` with `copy_headers` does
 * NOT strip the client's own copy of a copied header. If the auth service
 * answers 2xx without setting a configured header, Caddy copies nothing and the
 * CLIENT'S value survives onto the proxied request. Every stable Caddy from
 * v2.10.0 is affected, and docker-compose.yml pins the floating `caddy:2-alpine`
 * tag, so this deployment is affected today and could regress tomorrow.
 *
 * The usual header-SSO shape — `X-CyberCore-User: <id>` plus a trusting
 * upstream — is therefore an identity-injection primitive here: anyone who can
 * reach the path sends their own header and becomes whoever they like.
 *
 * So identity does not travel in a header we HOPE gets overwritten. It travels
 * in a token that is worthless without the key:
 *
 *     X-CyberCore-Auth: v1.<b64url(payload_json)>.<b64url(hmac_sha256)>
 *
 * A forged header still arrives. It simply does not verify. The Caddy config
 * ALSO strips the header inbound, so the advisory's failure mode is closed
 * twice — but the signature is the control, and the strip is the belt.
 *
 * WHY THE MAC COVERS THE ENCODED STRING, NOT THE JSON
 * ----------------------------------------------------------------------------
 * The signature is computed over the ASCII string "v1.<b64url(payload)>"
 * EXACTLY as it appears on the wire — never over the raw JSON and never over
 * the decoded bytes. That is the JWS rule and it exists because JSON has no
 * canonical form: key order, whitespace and Unicode escaping all vary between
 * languages, so a verifier that re-serialised before checking would reject
 * tokens its own minter produced. Node and Python cannot be relied on to agree
 * on a JSON encoding; they agree trivially on a byte string.
 *
 * WHY 60 SECONDS AND SINGLE USE
 * ----------------------------------------------------------------------------
 * The token is minted by Caddy's forward_auth subrequest and consumed by the
 * very next hop. Its whole life is one proxy hop, so a 60-second window is
 * already generous. Single use closes the rest: a token captured anywhere on
 * that path (a proxy log, a crash dump, an operator's tcpdump) is dead the
 * instant the real login used it, rather than replayable for the remainder of
 * the minute. The burn is server-side in CyberCore because the Caldera
 * container has no Redis of its own — see routes/caldera-authoring.js.
 *
 * FAIL CLOSED, ALWAYS
 * ----------------------------------------------------------------------------
 * If CALDERA_SSO_SECRET is unset or under 32 bytes, mintToken THROWS and
 * verifyToken refuses. There is deliberately no default and no dev fallback: a
 * baked-in default key is a published key, and this key is the only thing
 * standing between a forged header and an authoring console.
 *
 * NOTHING HERE EVER LOGS. Not the token, not the jti, not the secret, not even
 * a truncated prefix of any of them. Every failure is reported as a short
 * reason CODE to the caller, which decides what (if anything) to record.
 *
 * Run: node --test front-end/test/caldera-sso.test.js
 * ============================================================================
 */

'use strict';

const crypto = require('crypto');

/**
 * The ONE header. Identity is never carried in a plain header such as
 * X-CyberCore-User — see the advisory note above.
 */
const SSO_HEADER = 'X-CyberCore-Auth';

/** Wire format version. A future v2 changes this string and nothing else. */
const TOKEN_VERSION = 'v1';

/** Mint-to-expiry window. One proxy hop; see the note above. */
const TOKEN_TTL_SECONDS = 60;

/**
 * How long a burnt jti is remembered. Deliberately LONGER than the token TTL.
 *
 * The reason is clock skew, not replay inside the window: if the nonce were
 * forgotten exactly at exp, two boxes a few seconds apart would open a gap in
 * which CyberCore has forgotten the burn but Caldera still considers the token
 * live. Doubling it costs one 40-byte key per login and closes that gap.
 */
const REDEEM_TTL_SECONDS = TOKEN_TTL_SECONDS * 2;

/** Minimum key material. 32 bytes is the HMAC-SHA256 block-equivalent floor. */
const MIN_SECRET_BYTES = 32;

/**
 * The roles that may hold a token AT ALL. Not a UI list — this is the second
 * place the decision is enforced, on the far side of the network, so that a
 * mistake in the minting route cannot on its own let a student in.
 */
const SSO_ROLES = Object.freeze(['instructor', 'admin']);

/**
 * Whitespace stripped from the secret before use, on BOTH sides.
 *
 * A secret usually arrives from a file (`CALDERA_SSO_SECRET=$(cat /etc/...)`)
 * and files end in a newline, so trimming is unavoidable in practice. What
 * matters is that Node and Python trim the SAME set: JS .trim() and Python
 * .strip() disagree at the edges (JS eats U+FEFF and U+00A0, Python does not),
 * and a secret that differs by one invisible byte between the two ends fails
 * with a bad-signature error that looks nothing like its cause. Both sides
 * therefore strip exactly these four ASCII characters and nothing else.
 */
const SECRET_TRIM = ' \t\r\n';

function trimSecret(raw) {
  let s = 0;
  let e = raw.length;
  while (s < e && SECRET_TRIM.includes(raw[s])) s++;
  while (e > s && SECRET_TRIM.includes(raw[e - 1])) e--;
  return raw.slice(s, e);
}

/**
 * An error that is safe to log.
 *
 * Every throw from this module carries a short `code` and a message that names
 * the FAILURE, never the material. Nothing here interpolates the secret, the
 * token or the jti into a string — a log line is a file, and this key's whole
 * value is that it is not in one.
 */
class CalderaSsoError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'CalderaSsoError';
    this.code = code;
  }
}

/**
 * Read and validate the signing key, at CALL time.
 *
 * Read per call rather than captured at module load for the same reason
 * routes/chat-status.js does it: a test can flip process.env without
 * require-cache games, and an operator who fixes a short key gets the fix on
 * restart rather than on a rebuild.
 *
 * THROWS when the key is missing or short. Callers must not turn that into a
 * 2xx — see the mint-first/respond-second structure in
 * routes/caldera-authoring.js.
 */
function resolveSecret(env) {
  const raw = (env || process.env).CALDERA_SSO_SECRET;
  if (typeof raw !== 'string') {
    throw new CalderaSsoError('SECRET_MISSING', 'CALDERA_SSO_SECRET is not set');
  }
  const secret = trimSecret(raw);
  if (Buffer.byteLength(secret, 'utf8') < MIN_SECRET_BYTES) {
    // Report the FLOOR, never the length we found. "your key is 12 bytes" is a
    // free search-space hint, and this message can reach a log.
    throw new CalderaSsoError(
      'SECRET_TOO_SHORT',
      `CALDERA_SSO_SECRET must be at least ${MIN_SECRET_BYTES} bytes`
    );
  }
  return secret;
}

/** Is a signing key present and long enough, without throwing? */
function secretConfigured(env) {
  try {
    resolveSecret(env);
    return true;
  } catch (_) {
    return false;
  }
}

const b64urlEncode = (buf) => Buffer.from(buf).toString('base64url');

/**
 * Decode STRICTLY — canonical, unpadded base64url or nothing.
 *
 * Buffer.from(s, 'base64url') is lenient: it silently drops characters outside
 * the alphabet and tolerates padding. On a signed structure that laxity is a
 * malleability seam — several distinct wire strings would decode to the same
 * payload bytes — so the charset is checked first and a round-trip comparison
 * rejects anything that does not re-encode to exactly itself.
 */
function b64urlDecodeStrict(s) {
  if (typeof s !== 'string' || s.length === 0) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(s)) return null;
  const buf = Buffer.from(s, 'base64url');
  if (buf.toString('base64url') !== s) return null;
  return buf;
}

/**
 * HMAC-SHA256 over the signing input, as raw bytes.
 *
 * `signingInput` is the ASCII string "v1.<b64url(payload_json)>" — the first
 * two dot-separated fields of the token, verbatim. BOTH SIDES BUILD IT BY
 * SLICING THE RECEIVED TOKEN, never by rebuilding it from parsed values.
 */
function sign(signingInput, secret) {
  return crypto.createHmac('sha256', Buffer.from(secret, 'utf8'))
    .update(signingInput, 'ascii')
    .digest();
}

/**
 * Does a token's `path` claim cover the path being requested?
 *
 * Segment-aware on purpose. A naive startsWith() would let a token minted for
 * "/caldera" authorise "/caldera-admin" — a different mount, a different
 * upstream, the same string prefix. Equality, a '/' boundary or a query string,
 * and nothing else.
 *
 * Trailing slashes are normalised away first so "/caldera" and "/caldera/" are
 * the same claim; Caddy's `redir /caldera /caldera/` makes both shapes real.
 */
function pathMatches(tokenPath, requestPath) {
  if (typeof tokenPath !== 'string' || typeof requestPath !== 'string') return false;
  if (!tokenPath.startsWith('/') || !requestPath.startsWith('/')) return false;
  const t = tokenPath.length > 1 ? tokenPath.replace(/\/+$/, '') : tokenPath;
  if (t === '/') return true;
  if (requestPath === t) return true;
  return requestPath.startsWith(`${t}/`) || requestPath.startsWith(`${t}?`);
}

/**
 * Mint a token. THIS IS THE ONLY PLACE A TOKEN IS CREATED.
 *
 * Throws — never returns a sentinel — when the key is unusable or a claim is
 * wrong. A caller that wants a 2xx must therefore be holding a real token in a
 * variable before it can write a status, which is the structural reason
 * /authorize cannot answer 2xx without one.
 *
 * `now` and `jti` are injectable for the committed cross-language vectors ONLY.
 * Production callers pass neither, and no request can steer either one: see the
 * source-text assertion in test/caldera-sso.test.js that the route never reads
 * req.query.
 */
function mintToken(claims, opts) {
  const o = opts || {};
  const secret = resolveSecret(o.env);

  const sub = claims && claims.sub;
  const role = claims && claims.role;
  const path = claims && claims.path;

  if (typeof sub !== 'string' || sub.length === 0) {
    throw new CalderaSsoError('BAD_SUB', 'sub must be a non-empty string');
  }
  if (typeof role !== 'string' || !SSO_ROLES.includes(role)) {
    // The role is checked HERE as well as at the gate. A token is a capability;
    // refusing to create one for a role that may not hold it means a future
    // caller which forgets its own check still cannot mint a student token.
    throw new CalderaSsoError('BAD_ROLE', 'role must be instructor or admin');
  }
  if (typeof path !== 'string' || !path.startsWith('/')) {
    throw new CalderaSsoError('BAD_PATH', 'path must be an absolute path');
  }

  const nowSec = typeof o.now === 'number' ? Math.floor(o.now) : Math.floor(Date.now() / 1000);
  // 128 bits of nonce. Not a counter and not derived from the user: a
  // predictable jti would let anyone who can reach the redeem endpoint burn a
  // login before it happens.
  const jti = typeof o.jti === 'string' ? o.jti : crypto.randomBytes(16).toString('hex');

  // Key order is fixed so the committed vectors are reproducible. It is NOT
  // load-bearing for interop — verification signs the received bytes and never
  // re-serialises — but a stable order makes a vector diff readable.
  const payload = { sub, role, path, exp: nowSec + TOKEN_TTL_SECONDS, jti };
  const signingInput = `${TOKEN_VERSION}.${b64urlEncode(Buffer.from(JSON.stringify(payload), 'utf8'))}`;
  return `${signingInput}.${b64urlEncode(sign(signingInput, secret))}`;
}

/**
 * Verify a token. Mirrors steps 1-5 of the Python verifier, in the same order.
 *
 * Step 6 — SINGLE USE — is deliberately NOT here. Burning a nonce is a side
 * effect against Redis, and a function called `verify` that mutates shared
 * state gets called twice by the next person to touch this file, whereupon the
 * second call fails for no visible reason. The burn lives in the redeem
 * endpoint, which is the only place it belongs.
 *
 * Returns { ok: true, payload } or { ok: false, reason }. A REASON CODE, never
 * an error string, and callers must not put it in a response body: "expired"
 * versus "bad_signature" tells an attacker which half of their forgery worked.
 */
function verifyToken(token, options) {
  const o = options || {};

  let secret;
  try {
    secret = resolveSecret(o.env);
  } catch (err) {
    return { ok: false, reason: err.code === 'SECRET_MISSING' ? 'secret_missing' : 'secret_too_short' };
  }

  // 1. shape
  if (typeof token !== 'string' || token.length === 0) return { ok: false, reason: 'malformed' };
  const parts = token.split('.');
  if (parts.length !== 3) return { ok: false, reason: 'malformed' };
  const [version, payloadB64, macB64] = parts;
  if (version !== TOKEN_VERSION) return { ok: false, reason: 'bad_version' };

  const payloadBytes = b64urlDecodeStrict(payloadB64);
  const macBytes = b64urlDecodeStrict(macB64);
  if (!payloadBytes || !macBytes) return { ok: false, reason: 'malformed' };

  // 2. MAC, in constant time.
  //
  // timingSafeEqual THROWS on a length mismatch, which would escape as a 500 —
  // itself a coarse oracle — so the length is compared first and a wrong-length
  // MAC is simply 'bad_signature'. The digest length is public anyway: it is 32
  // bytes, because the algorithm is named by the version tag.
  const expected = sign(`${version}.${payloadB64}`, secret);
  if (macBytes.length !== expected.length) return { ok: false, reason: 'bad_signature' };
  if (!crypto.timingSafeEqual(macBytes, expected)) return { ok: false, reason: 'bad_signature' };

  // Parsing happens only AFTER the MAC verifies. Running JSON.parse on
  // unauthenticated bytes is a decision, not an accident: everything below this
  // line is trusted precisely because the signature covered it.
  let payload;
  try {
    payload = JSON.parse(payloadBytes.toString('utf8'));
  } catch (_) {
    return { ok: false, reason: 'malformed' };
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, reason: 'malformed' };
  }
  for (const key of ['sub', 'role', 'path', 'exp', 'jti']) {
    if (payload[key] === undefined || payload[key] === null) return { ok: false, reason: 'missing_claim' };
  }
  if (typeof payload.sub !== 'string' || typeof payload.role !== 'string'
      || typeof payload.path !== 'string' || typeof payload.jti !== 'string') {
    return { ok: false, reason: 'malformed' };
  }

  // 3. expiry
  if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) {
    return { ok: false, reason: 'malformed' };
  }
  const nowSec = typeof o.now === 'number' ? o.now : Date.now() / 1000;
  if (payload.exp <= nowSec) return { ok: false, reason: 'expired' };

  // 4. role
  if (!SSO_ROLES.includes(payload.role)) return { ok: false, reason: 'bad_role' };

  // 5. path. Skipped ONLY when the caller genuinely has no request path to
  // check against — the redeem endpoint, which is a nonce burn and not the
  // surface the token authorises. Every consumer that IS a surface passes one.
  if (o.path !== undefined && o.path !== null) {
    if (!pathMatches(payload.path, o.path)) return { ok: false, reason: 'path_mismatch' };
  }

  // Shape of the nonce, checked LAST so this line sits at the same position as
  // its twin in login_handler.py's verify_token(). The two verifiers must
  // reject the same token for the same reason — a divergence here would show up
  // as "Node says fine, Python says no" in production and nowhere in the
  // vectors. isValidJti is also what stops an attacker-chosen key reaching
  // Redis, but by the time we are here the payload is already authenticated.
  if (!isValidJti(payload.jti)) return { ok: false, reason: 'malformed' };

  return { ok: true, payload };
}

/** The Redis key a jti is burnt under. Namespaced, and carries no identity. */
function redeemKey(jti) {
  return `caldera:sso:jti:${jti}`;
}

/**
 * A jti is 128 bits of lowercase hex and nothing else.
 *
 * Checked before the value is concatenated into a Redis key: node-redis speaks
 * RESP, so a newline in a key is not a command-injection seam the way it would
 * be in an inline protocol — but an unbounded attacker-chosen key IS a memory
 * exhaustion seam, and constraining the shape costs one regex.
 */
function isValidJti(jti) {
  return typeof jti === 'string' && /^[0-9a-f]{32}$/.test(jti);
}

module.exports = {
  SSO_HEADER,
  TOKEN_VERSION,
  TOKEN_TTL_SECONDS,
  REDEEM_TTL_SECONDS,
  MIN_SECRET_BYTES,
  SSO_ROLES,
  CalderaSsoError,
  resolveSecret,
  secretConfigured,
  mintToken,
  verifyToken,
  pathMatches,
  redeemKey,
  isValidJti,
  // Exported for the cross-language vector test only.
  _b64urlDecodeStrict: b64urlDecodeStrict,
};
