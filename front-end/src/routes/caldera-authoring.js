/**
 * ============================================================================
 * CALDERA AUTHORING — THE AUTHORIZATION PROBE, AND NOTHING ELSE
 * ============================================================================
 *
 * ############################################################################
 * # THIS FILE HOLDS NO CALDERA CREDENTIAL AND NEVER AUTHENTICATES TO ONE.    #
 * #                                                                          #
 * # There IS a real Caldera now — the `caldera` compose service, built from   #
 * # infrastructure/caldera/ and served on its own hostname — so the older     #
 * # "no Caldera anywhere in this repository" banner that stood here is gone.  #
 * # What has NOT changed is this file's reach into it: the only request made  #
 * # from here is an unauthenticated liveness GET at the instance's root.      #
 * # Read /status's `reachable` as "something accepted a TCP connection and    #
 * # spoke HTTP" — never as "Caldera is healthy", and never as "an instructor  #
 * # can log in". What actually logs the console in is Caldera's own KEY       #
 * # header, injected by Caddy AFTER the gate below says yes, and this file    #
 * # never sees that value.                                                    #
 * ############################################################################
 *
 * WHAT THIS ROUTER IS FOR
 * ----------------------------------------------------------------------------
 * There is ONE standalone Caldera "authoring" instance — the `caldera` compose
 * service on cybercore-net, outside every lane, with NO agents and NO implants
 * and no agent contact configured. (It used to be a Proxmox VM on the lab
 * network; several comments in this file said so long after it moved, which is
 * why the sentence you are reading names the service.)
 * Instructors open its real web UI to BUILD adversaries; CyberCore later reads
 * an adversary back out and replicates it into each lane's own lane-local
 * Caldera at launch time. Nothing inside a lane ever talks to the authoring
 * box, and dispatch into a lane goes over guest-exec (agentShellExec via the
 * Proxmox API) the way every other lane operation in this codebase does.
 *
 * THIS IS AN AUTHORING SURFACE, NOT AN EXECUTION SURFACE. Nothing here
 * registers, selects, or dispatches an incident engine — engineFor('caldera')
 * still throws and registeredEngines() is still ["synthetic"]. Authoring is
 * shippable now precisely because it touches nothing in any lane.
 *
 * WHY AN "AUTHORIZE" ENDPOINT AND NOT PROXY MIDDLEWARE
 * ----------------------------------------------------------------------------
 * Caddy does the proxying — that is the established pattern here, and
 * config/caddy/Caddyfile has same-origin-proxied Guacamole under /guacamole*
 * in both site blocks since long before this. There is no reverse-proxy
 * middleware anywhere in front-end/src/ and this does not add the first one.
 *
 * What Caddy cannot do is answer "is this browser an instructor on THIS
 * platform". So the split is: CADDY PROXIES, THE APP AUTHORIZES. Caddy's
 * forward_auth turns a request into a subrequest against
 * GET /api/caldera-authoring/authorize, and forwards the original request to
 * the authoring instance only if that subrequest answered 2xx.
 *
 * ON ITS OWN HOSTNAME, NOT A SUBPATH. It WAS `handle_path /caldera*` on the
 * main site, and that could not be made to work: Caldera's magma UI is a Vue
 * SPA that bootstraps by calling GET /api/v2/config/main at the ORIGIN ROOT,
 * so it uses the default base for the one call that would have told it a
 * different base — under /caldera/ the shell loaded and the SPA then 404'd its
 * own API, rendering a login form that looked like an auth failure and was not.
 * So config/caddy/Caddyfile now serves the console from TWO site blocks on
 * {$CALDERA_HOST} (one per scheme, because a Cloudflare tunnel may deliver
 * either), each of which does nothing but `import caldera_gate` — the snippet
 * that strips client-supplied identity headers, runs the forward_auth above,
 * and only then injects Caldera's KEY and proxies. The gate therefore covers
 * EVERY request to that host: page, asset, XHR and websocket upgrade alike.
 *
 * The main site keeps `redir /caldera* https://{$CALDERA_HOST}/ 302` so links
 * printed before the move do not dead-end. That redirect is the ONLY thing
 * PUBLIC_PATH still describes — see its docblock, and see consoleConfig() for
 * where the console actually is.
 *
 * WHY CYBERCORE OWNS THE AUTHZ AT ALL
 * ----------------------------------------------------------------------------
 * Caldera has NO per-user and NO per-object ownership. Its conf/local.yml
 * `users:` block is a map of credentials into a 'red' or 'blue' GROUP, which is
 * a ROLE, not tenancy — every red user sees every adversary. So Caldera cannot
 * be asked "may this instructor see this content"; it is a content store with a
 * good authoring UI. CyberCore keeps that decision, the same way it already
 * does with requireCiabAccess / sectionsManagedBy / requireCourseFeature, and
 * this router is where that decision is made for the authoring console.
 *
 * THE ATTRIBUTION TRADE-OFF, STATED PLAINLY
 * ----------------------------------------------------------------------------
 * Every instructor who reaches the console signs in to Caldera with the SAME
 * shared 'red' credential from conf/local.yml, so CALDERA-SIDE ATTRIBUTION IS
 * LOST: its own logs cannot tell which instructor edited an adversary. That is
 * accepted, for two reasons:
 *
 *   1. It is not fixable from here. Caldera has no user provisioning API and no
 *      SSO; the only alternative is one static credential per instructor typed
 *      into conf/local.yml by hand and re-baked, which drifts the moment staff
 *      changes.
 *   2. CyberCore retains attribution for the thing that matters. Authoring an
 *      adversary changes nothing in any lane. LAUNCHING one does, and a launch
 *      writes cybercore_incident_run.launched_by (NOT NULL, see
 *      src/incident/schema.js) with the CyberCore user id — which this router's
 *      gate has already proven is an instructor or an admin.
 *
 * WHAT THE GATE NOW HANDS BACK, AND WHY IT IS NOT A PLAIN HEADER
 * ----------------------------------------------------------------------------
 * The gate used to answer with a status and nothing else. It now also mints a
 * SIGNED, SINGLE-USE, 60-SECOND token into the X-CyberCore-Auth response
 * header, which Caddy's `copy_headers` carries onto the proxied request.
 *
 * READ WHAT CONSUMES IT, HONESTLY: right now, nothing does.
 * infrastructure/caldera/conf/local.yml sets `auth.login.handler.module:
 * default`, because Caldera never calls a custom login handler on a browser
 * page load — check_permissions() short-circuits on the KEY header and returns
 * before the handler is reached. So the token is currently belt, not braces:
 * the KEY header injected by the gate is what logs the console in. The mint is
 * kept, and kept MANDATORY, for the reason in the next paragraph — a 2xx with
 * no header is the whole of the Caddy advisory — and so that a future handler
 * has an identity to attach an instructor to without a shared password.
 *
 * IDENTITY IS NEVER PUT IN A PLAIN HEADER. Caddy advisory GHSA-7r4p-vjf4-gxv4:
 * `copy_headers` does not strip the CLIENT's copy of a copied header, so if
 * this endpoint ever answered 2xx WITHOUT setting the header, the browser's own
 * X-CyberCore-Auth would ride through untouched — identity injection, straight
 * to admin. Two things close that, and only the first is a control:
 *
 *   1. The value is an HMAC over the payload. A client-supplied header is
 *      simply not a valid token, whatever it says, because the client does not
 *      hold CALDERA_SSO_SECRET.
 *   2. The Caddyfile also strips the header inbound (another agent owns that
 *      file). Belt, not braces.
 *
 * And because the advisory bites specifically on "2xx with no header", the
 * handler below MINTS FIRST AND RESPONDS SECOND: the token is in a local
 * variable before any status is written, and every failure path — including a
 * missing or short signing key — writes a NON-2xx. There is no ordering of
 * statements in that handler that produces a 2xx without a fresh token.
 *
 * THE BURN IS HERE BECAUSE THE CONTAINER HAS NO REDIS
 * ----------------------------------------------------------------------------
 * A 60-second window is still a window: the same token replayed twice inside it
 * would be two logins. Single use fixes that, and single use needs shared
 * state. The authoring instance is a container with no Redis of its own, so the
 * nonce store lives here: POST /api/caldera/redeem burns a jti with a Redis
 * SET NX and answers 200 exactly once, 409 forever after. See the long note on
 * createCalderaRedeemRouter for why that endpoint is not a browser endpoint and
 * what stops the public internet driving it.
 *
 * And note what is deliberately absent: THIS APP HOLDS NO CALDERA CREDENTIAL AT
 * ALL. It does not forge a Caldera session, does not log in on an instructor's
 * behalf, and never puts a credential in a URL, a redirect, or anything the
 * client can see. (Nor does the instructor: Caddy injects CALDERA_API_KEY_RED
 * as the KEY header on the already-approved request, so the console opens with
 * no login form at all — an earlier revision of this comment said the
 * instructor typed a shared password, which has not been true since the gate
 * started injecting KEY.) There is therefore nothing here to leak. If a future phase
 * genuinely needs the app to hold one (to READ an adversary back out over the
 * API, say — that is the engine adapter's API key, not this UI password), it
 * arrives as a root-owned 0600 FILE the way bake-caldera-server.sh delivers
 * every other secret, and never as a script_arg: src/utils/script-executor.js
 * interpolates args UNQUOTED and password-generator.js guarantees a character
 * from !@#$%&*, where '&' backgrounds the command.
 *
 * Run: node --test front-end/test/caldera-authoring-access.test.js
 * ============================================================================
 */

'use strict';

const express = require('express');
const { authenticateToken, requireRole } = require('../middleware/auth');
const sso = require('../utils/caldera-sso');

/**
 * Who may reach the authoring console.
 *
 * Named once and exported so the test asserts the same list the route uses,
 * rather than a copy of it that can drift open.
 */
const AUTHORING_ROLES = Object.freeze(['instructor', 'admin']);

/**
 * LEGACY — the subpath the console USED to be mounted on.
 *
 * IT IS NOT A MOUNT POINT ANY MORE. config/caddy/Caddyfile's public site holds
 * exactly one thing at this path now, `redir /caldera* https://{$CALDERA_HOST}/
 * 302`, so an old link lands on the console's own hostname instead of a 404.
 * The console itself is at consoleConfig().url; see the header for why a
 * subpath could not work at all.
 *
 * The constant survives the move because it is still LOAD-BEARING in two
 * places, and deleting it would break both:
 *
 *   1. It is the `path` claim minted into every SSO token below.
 *      utils/caldera-sso.js requires an absolute path (BAD_PATH otherwise) and
 *      test/caldera-sso.test.js verifies tokens against '/caldera', so this
 *      value is half of a signed contract, not decoration.
 *   2. /status still reports it as `path` for callers written before
 *      console_url existed. NEW UI MUST LINK console_url — `path` only gets a
 *      reader as far as the 302.
 */
const PUBLIC_PATH = '/caldera';

/**
 * Where to look when the operator has not said — a SENTINEL, deliberately not
 * the truth.
 *
 * THE TRUTH IS `caldera:8888`. The authoring instance is a compose SERVICE now
 * (`caldera` in docker-compose.yml, built from infrastructure/caldera/, on
 * cybercore-net), and compose passes exactly that string as
 * CALDERA_AUTHORING_UPSTREAM to both this app and Caddy. It moved there from a
 * Proxmox VM on the lab network, and the comment that stood here said the
 * opposite — "not a compose service, so there is no `caldera:8888` service
 * name to use" — long after the move.
 *
 * SO WHY IS THE DEFAULT NOT `caldera:8888`? Because `configured` below means
 * "an operator set the variable", and a default that happened to be RIGHT
 * would make it permanently true. /status could then never answer "authoring
 * is not set up"; a deployment that simply forgot the variable would be told
 * the box is unreachable and sent hunting a network fault instead of setting
 * one env var. So the default stays an obviously-unreal name — nothing
 * resolves it, and probeReachable() is never pointed at it (see the /status
 * handler's not-configured branch). Changing it to a real address would
 * silently destroy that distinction.
 */
const DEFAULT_UPSTREAM = 'caldera-authoring.cybercore.lan:8888';

/**
 * Liveness deadline. Short on purpose — an instructor is waiting on this to
 * decide whether to render a link, and Node's fetch() has NO default timeout,
 * so a box that accepts the connection and then never answers would hang the
 * request forever (the same trap src/utils/guacamole.js and
 * src/incident/caldera/client.js each call out).
 */
const PROBE_TIMEOUT_MS = Number(process.env.CALDERA_AUTHORING_PROBE_TIMEOUT_MS) > 0
  ? Number(process.env.CALDERA_AUTHORING_PROBE_TIMEOUT_MS)
  : 3000;

/**
 * Resolve the authoring instance's address from the environment, at CALL time.
 *
 * Read per-request rather than captured at module load for the same reason
 * routes/chat-status.js does it: a test can flip process.env without
 * require-cache games, and an operator who changes the compose env gets the new
 * value on restart rather than on a rebuild.
 *
 * ONE variable configures both halves of this feature. CALDERA_AUTHORING_UPSTREAM
 * is what config/caddy/Caddyfile substitutes into its reverse_proxy, and it is
 * accepted here as a bare host:port so a deployment sets it once.
 * CALDERA_AUTHORING_URL wins when both are set, for a deployment that fronts the
 * instance with TLS and needs a scheme.
 */
function authoringConfig(env) {
  const e = env || process.env;
  const raw = String(e.CALDERA_AUTHORING_URL || e.CALDERA_AUTHORING_UPSTREAM || '').trim();
  const configured = raw.length > 0;
  const value = configured ? raw : DEFAULT_UPSTREAM;
  // A bare host:port is the documented form; a full URL is accepted so a TLS
  // deployment does not need a second variable.
  const baseUrl = /^https?:\/\//i.test(value)
    ? value.replace(/\/+$/, '')
    : `http://${value.replace(/\/+$/, '')}`;
  let upstream = null;
  try {
    upstream = new URL(baseUrl).host;
  } catch (_) {
    // A malformed value is a configuration error, not a crash: report it as
    // "not configured" and let /status say so.
    return { configured: false, baseUrl: null, upstream: null, malformed: configured };
  }
  return { configured, baseUrl, upstream, malformed: false };
}

/**
 * WHERE THE INSTRUCTOR'S BROWSER ACTUALLY GOES.
 *
 * Two different addresses fell out of the hostname move and they must not be
 * confused, which is why this is a second function rather than another field on
 * authoringConfig():
 *
 *   CALDERA_AUTHORING_UPSTREAM  is where CADDY dials, container to container on
 *                               cybercore-net (`caldera:8888`). It is not
 *                               resolvable from a browser and must never be
 *                               rendered as a link.
 *   CALDERA_HOST                is where the BROWSER goes — the console's own
 *                               public hostname, the one config/caddy/Caddyfile
 *                               opens its two `import caldera_gate` site blocks
 *                               on. THIS is the link.
 *
 * READING THE SAME VARIABLE CADDY READS is the whole point: docker-compose.yml
 * hands CALDERA_HOST to Caddy, and one value with two consumers cannot drift
 * the way a literal in this file would. (The app service must be given the
 * variable too, or this correctly answers null — see the unset case below.)
 *
 * https UNLESS THE OPERATOR WROTE A SCHEME. The Caddyfile's own redirect
 * hard-codes https://, and the plain-http site block exists only because a
 * Cloudflare tunnel may deliver either scheme to this container; the
 * browser-facing URL is https. A value that already carries a scheme is
 * honoured, for the same reason CALDERA_AUTHORING_URL is honoured above.
 *
 * UNSET IS A FIRST-CLASS ANSWER, and the shape is authoringConfig()'s on
 * purpose — configured:false plus a malformed flag, no second vocabulary. No
 * CALDERA_HOST means url:null, which is what lets a UI render "authoring is not
 * set up" instead of a link to nowhere. Note what is NOT done here: this does
 * not fall back to req.hostname or to PUBLIC_PATH. Either would manufacture a
 * plausible URL for a host Caddy has no site block for, and a confidently wrong
 * link is worse than an honest null — it is the exact dead link the /status
 * endpoint exists to prevent.
 *
 * Read at CALL time, for the same reason authoringConfig() is.
 */
function consoleConfig(env) {
  const e = env || process.env;
  const raw = String(e.CALDERA_HOST || '').trim();
  if (!raw) return { configured: false, url: null, malformed: false };

  const withScheme = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  let origin;
  try {
    origin = new URL(withScheme).origin;
  } catch (_) {
    // A malformed value is a configuration error, not a crash. Same call as
    // authoringConfig() makes: report it, let /status say so.
    return { configured: false, url: null, malformed: true };
  }
  // ORIGIN, then exactly one slash. url.origin is scheme://host[:port] with no
  // trailing slash and no path, so this cannot produce '//' (two slashes is a
  // different origin to some clients and an ugly link to every human) and
  // cannot carry a stray path a magma SPA would then bootstrap from.
  return { configured: true, url: `${origin}/`, malformed: false };
}

/**
 * Is anything listening, and does it speak HTTP?
 *
 * ANY HTTP status counts as reachable, including 401 and 302 — Caldera answers
 * its own login page there, and this probe deliberately carries no credential,
 * so a 200 is not available to us and demanding one would report every
 * correctly-secured instance as down.
 *
 * Never throws. A probe that can fail the request would turn "the lab VLAN is
 * down" into a 500 on a status endpoint whose entire job is to report exactly
 * that condition calmly.
 */
async function probeReachable(baseUrl, fetchImpl) {
  const started = Date.now();
  try {
    const res = await fetchImpl(`${baseUrl}/`, {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    return {
      reachable: true,
      http_status: typeof res?.status === 'number' ? res.status : null,
      latency_ms: Date.now() - started,
      detail: null,
    };
  } catch (err) {
    // A CODE, not the error text. err.message from undici carries the resolved
    // address and the failing syscall, and this body is rendered in a browser;
    // "unreachable" plus the host we tried is everything an instructor can act
    // on, and everything ops needs is already in the container log.
    const timedOut = err && (err.name === 'TimeoutError' || err.name === 'AbortError');
    return {
      reachable: false,
      http_status: null,
      latency_ms: Date.now() - started,
      detail: timedOut ? 'timeout' : 'unreachable',
    };
  }
}

/**
 * Make every response from the gate a STATUS AND NOTHING ELSE.
 *
 * THIS IS THE POINT OF THE WHOLE ENDPOINT. Caddy's forward_auth treats the
 * subrequest's STATUS as the decision and, on a non-2xx, copies that response
 * STRAIGHT TO THE CLIENT. So whatever authenticateToken and requireRole would
 * have written lands in the browser of whoever probed the console host — and
 * what they write is informative by design:
 *
 *     { "error": "Access denied. Insufficient permissions.",
 *       "requiredRoles": ["instructor","admin"], "userRole": "student" }
 *
 * That names the platform's role vocabulary and confirms the prober holds a
 * valid session, to an endpoint that is reachable from the lab subnets (the
 * internal :80 listener carries this route too). It is a small leak, and it is
 * an unnecessary one: nothing consumes the body.
 *
 * The override is an OWN PROPERTY on this one response object — res.json and
 * res.send are inherited from Express's response prototype, so assigning here
 * shadows them for this request only and cannot reach another request or
 * another route. Reusing the real middleware and silencing its body is
 * deliberate: the alternative, a hand-rolled token check, is a second copy of
 * authenticate() that would quietly miss the stage-token rule that stops a
 * half-finished sign-in (password accepted, MFA not yet) from counting as a
 * session.
 */
function statusOnly(req, res, next) {
  const end = () => {
    if (!res.headersSent) {
      res.removeHeader('Content-Type');
      res.removeHeader('Content-Length');
    }
    res.end();
    return res;
  };
  res.json = end;
  res.send = end;
  next();
}

/**
 * Build the router.
 *
 * A factory so the liveness probe's transport can be injected, on the same
 * reasoning as src/incident/caldera/client.js: monkey-patching globalThis.fetch
 * inside a test file leaks into everything that file requires, and a restore
 * missed on a throw poisons unrelated suites in the same process. An argument
 * cannot leak.
 */
function createCalderaAuthoringRouter(deps) {
  const d = deps || {};
  const fetchImpl = d.fetch || ((...args) => globalThis.fetch(...args));
  const router = express.Router();

  /**
   * GET /api/caldera-authoring/authorize — THE GATE.
   *
   * 204 to allow, 401/403 to deny, and no body in any case.
   *
   * WHY 401 RATHER THAN A REDIRECT TO /login. forward_auth hands the deny
   * response back verbatim, and it fires for EVERY subrequest the console makes
   * — every asset, every XHR, every websocket upgrade — not just the top-level
   * navigation. A 302 would therefore be answered to fetch() calls as a
   * successful-looking redirect into an HTML login page, which is a far more
   * confusing failure than an empty 401. An instructor who is not signed in
   * signs in at the main site first.
   *
   * WHY NO AUDIT ROW ON ALLOW. Same reason: this runs per subrequest, so an
   * allow-side audit would write hundreds of rows for one console visit. The
   * DENY side is already audited by requireRole's auditDenial(), which dedupes
   * per (user, route) for a minute and so cannot be flooded either.
   */
  router.get(
    '/authorize',
    statusOnly,
    authenticateToken,
    requireRole(...AUTHORING_ROLES),
    (req, res) => {
      // ----------------------------------------------------------------------
      // THE ROLE IS SERVER TRUTH, AND ONLY SERVER TRUTH.
      //
      // req.user is built by authenticate() from a JWT this platform signed —
      // see middleware/auth.js. It is the ONLY input to the decision below.
      //
      // THIS MATTERS MORE HERE THAN ALMOST ANYWHERE. CyberCore has a Student
      // View: an instructor flips a localStorage flag and the entire interface
      // re-draws as a student, which is why public/js/app.js keeps `user` (the
      // DRAWN role, rewritten to 'student') apart from `realUser` (the server's
      // answer, never rewritten) and why Auth.isRealInstructor() exists. That
      // preview is carried to the server as `?view=student`, and server code
      // DOES honour it — ciab/utils/enrollment.js canSeeCiab() reads
      // req.query.view so the sidebar preview stays faithful.
      //
      // Honouring it here would be a catastrophe of the opposite sign: a
      // QUERY PARAMETER that changes an access decision is the exact bypass
      // this whole design exists to prevent, and Caddy's forward_auth copies
      // the original request's query string onto the subrequest, so the client
      // controls it end to end. So: no req.query, no req.body, no role or view
      // header is read anywhere in this file's authorize path. The test asserts
      // that structurally (the file contains no `req.query` at all) as well as
      // behaviourally.
      //
      // Note also that the direction of the bypass does not matter. A student
      // cannot reach this line — requireRole already denied them — and an
      // instructor previewing as a student must NOT be locked out mid-lecture.
      // Reading server truth is right in both directions.
      // ----------------------------------------------------------------------
      const role = req.user.role;

      // MINT FIRST. The advisory (GHSA-7r4p-vjf4-gxv4) bites when an auth
      // service answers 2xx without setting the header it promised, because
      // Caddy then copies nothing and the CLIENT's header survives. Minting
      // before any status is written makes "2xx with no token" unreachable:
      // there is no branch below that can write a 2xx unless `token` already
      // holds a fresh one.
      let token;
      try {
        token = sso.mintToken({ sub: req.user.userId, role, path: PUBLIC_PATH });
      } catch (err) {
        // FAIL CLOSED. A missing or short CALDERA_SSO_SECRET means we cannot
        // prove identity to the upstream, and a 2xx here would proxy the
        // request anyway — with whatever header the client sent. 503 is
        // non-2xx, so forward_auth denies, and it is the honest status: the
        // caller is an instructor, the deployment is misconfigured.
        //
        // err.code, never err.message and never the material. mintToken's
        // messages are already secret-free (see utils/caldera-sso.js), but a
        // code cannot regress into carrying one.
        console.error('[CalderaAuthoring] cannot mint SSO token:', err && err.code);
        return res.status(503).end();
      }

      // no-store so nothing on the path can cache an ALLOW and hand it — and
      // the single-use token stapled to it — to the next person through the
      // same proxy.
      res.set('Cache-Control', 'no-store');
      res.set(sso.SSO_HEADER, token);
      // 204 is kept deliberately: forward_auth reads the STATUS, any 2xx
      // proxies, and a body would only be another thing to leak. Headers ride
      // on a 204 perfectly well — a 204 forbids a BODY, not metadata.
      res.status(204).end();
    }
  );

  /**
   * GET /api/caldera-authoring/status — where is authoring, is it set up, and
   * is it up?
   *
   * So a UI can render a WORKING LINK, or "authoring is not set up", or
   * "authoring is unreachable" — instead of sending an instructor somewhere
   * dead and letting them conclude the platform is broken.
   *
   * THE LINK IS `console_url`, NOT `path`. This endpoint used to answer with
   * `path: '/caldera'` and nothing else, which stopped being an address the day
   * the console moved to its own hostname: following it now costs a 302 at best
   * and, on any deployment whose main site drops that redirect, 404s. `path` is
   * still emitted because removing a field breaks callers written against it
   * and the redirect does still work — but it is LEGACY, and a UI that renders
   * it instead of console_url is rendering the old address.
   *
   * THE TWO "configured" FLAGS ARE INDEPENDENT, and that is not redundancy —
   * they are two different variables that fail in two different ways:
   *   configured / upstream           CALDERA_AUTHORING_UPSTREAM: whether CADDY
   *                                   can reach the container at all.
   *   console_configured / console_url  CALDERA_HOST: whether there is a public
   *                                   hostname to send a BROWSER to.
   * A deployment can have either without the other, and a UI needs to tell
   * "nobody configured the console's hostname" from "the box is down".
   *
   * Instructor-gated like the console itself. It is a small internal-topology
   * disclosure (one lab hostname and port) and staff are the audience for it;
   * a student has no reason to learn the address of a box they must never
   * reach.
   *
   * NOTE that this path ends in /status, which server.js's
   * RATE_LIMIT_SKIP_PATTERNS already exempts from the abuse limiter (it was
   * written for lane status polls). So a staff account can call this in a loop
   * and make the app dial the authoring container each time. Accepted: the address is
   * fixed by the environment and cannot be steered by the caller — this is not
   * an SSRF seam — the deadline is PROBE_TIMEOUT_MS, and the caller has already
   * proven they are an instructor or admin.
   */
  router.get(
    '/status',
    authenticateToken,
    requireRole(...AUTHORING_ROLES),
    async (req, res) => {
      const cfg = authoringConfig();
      const con = consoleConfig();
      const base = {
        // WHERE TO SEND THE INSTRUCTOR — the only field a UI should turn into a
        // link. null when CALDERA_HOST is unset, which is a renderable answer
        // ("authoring is not set up"), never a dead link. See consoleConfig().
        console_url: con.url,
        // Said plainly, so a UI does not have to infer it from a null: false
        // means nobody has told this deployment where the console is published.
        console_configured: con.configured,
        // The same vocabulary the upstream's `detail` uses, for the same reason
        // — an operator must be able to tell "unset" from "garbage", because
        // the fixes are different.
        console_detail: con.configured
          ? null
          : (con.malformed ? 'malformed_host' : 'not_configured'),
        // LEGACY. NOT where the console lives — see the docblock above. The
        // main site keeps a 302 from this path to console_url so old links do
        // not dead-end, and this is still the SSO token's `path` claim, which
        // is why the constant survives. New UI links console_url.
        path: PUBLIC_PATH,
        configured: cfg.configured,
        upstream: cfg.upstream,
        checked_at: new Date().toISOString(),
      };

      if (!cfg.configured) {
        // Do NOT probe the default name. It is a placeholder, and reporting
        // "unreachable" for a host nobody configured sends the operator hunting
        // a network fault instead of setting one variable.
        return res.json({
          ...base,
          reachable: null,
          http_status: null,
          detail: cfg.malformed ? 'malformed_upstream' : 'not_configured',
        });
      }

      const probe = await probeReachable(cfg.baseUrl, fetchImpl);
      return res.json({ ...base, ...probe });
    }
  );

  return router;
}

/**
 * ============================================================================
 * THE NONCE BURN — POST /api/caldera/redeem
 * ============================================================================
 *
 * WHO CALLS THIS. In the design: the Caldera CONTAINER, once, from inside
 * cybercore-net, as step 6 of infrastructure/caldera/login_handler.py's
 * verification. NOT a browser — nothing in public/js/ calls it and nothing
 * should.
 *
 * IN THE DEPLOYMENT AS IT STANDS: nobody. conf/local.yml sets
 * `auth.login.handler.module: default`, because Caldera never reaches a custom
 * login handler on a browser page load — check_permissions() short-circuits on
 * the KEY header Caddy injects and returns first. So this endpoint is live,
 * correct and currently unexercised. It is kept rather than deleted because the
 * token it burns is still minted on every allow (removing the burn would make
 * that token replayable the moment a handler is wired back up), and because
 * deleting a half of a two-sided contract is how the other half rots.
 *
 * WHY IT EXISTS AT ALL. A 60-second token is still replayable for 60 seconds,
 * and the one place that could remember "this jti has been spent" is not the
 * container: the authoring instance has no Redis, no database and no state
 * worth trusting. CyberCore has Redis already (src/utils/redis.js, a compose
 * service), so the burn happens here and the container asks.
 *
 * ATOMICITY IS THE WHOLE POINT. This is SET NX — one round trip, decided by
 * Redis. A GET-then-SET would let two simultaneous replays both read "absent"
 * and both be told 200, which is precisely the race single-use exists to
 * prevent. The TTL is REDEEM_TTL_SECONDS (twice the token TTL, for clock skew)
 * so the key space cannot grow without bound.
 *
 * IS THIS REACHABLE FROM THE PUBLIC INTERNET? YES — and that is not an
 * oversight, it is a fact about config/caddy/Caddyfile: both site blocks end in
 * a bare `handle { reverse_proxy app:3000 }` catch-all, so EVERY path the app
 * serves, including this one, is published. There is no /api-specific network
 * boundary to hide behind and adding one would mean editing the Caddyfile,
 * which another agent owns. So the guard is in the endpoint:
 *
 *   THE CALLER MUST PRESENT THE TOKEN ITSELF, not merely its jti.
 *
 * The request carries X-CyberCore-Auth (the same token the container just
 * verified) and a body of { jti }, and both must agree. That turns the endpoint
 * from "anyone can burn any nonce they can guess" into "only a party already
 * holding a valid, unexpired, correctly-signed token can burn THAT token's
 * nonce" — which is the party that is about to log in anyway. It costs the
 * container nothing: it is holding the token when it calls.
 *
 * WHAT THAT GUARD BUYS, PRECISELY. A jti is 128 bits of CSPRNG hex and never
 * leaves the signed payload, so guessing one was never realistic; the real
 * exposure was a PRE-BURN DENIAL OF SERVICE by anyone who obtained a token —
 * from a proxy log, say — and wanted to lock its owner out rather than use it.
 * Requiring the token means such an attacker could have logged in instead, so
 * the guard costs them the anonymity, not the capability. What it genuinely
 * removes is the unauthenticated Redis-write primitive that a bare {jti}
 * endpoint would publish to the internet.
 *
 * NO REDIS, NO 200. If the client is not ready the answer is 503, never a
 * cheerful 200 — an unrecorded burn is not a burn, and the login handler
 * requires exactly 200. A Redis outage therefore takes the authoring console
 * offline. That is the correct trade: the alternative is replayable logins.
 *
 * WHY THE REDIS CLIENT IS REQUIRED LAZILY. src/utils/redis.js calls
 * redisClient.connect() at module load and retries a dead server for an hour.
 * Requiring it at the TOP of this file would make every suite that touches this
 * router — test/caldera-authoring-access.test.js does — open a live socket and
 * hold the test process open long past the last assertion. Required inside the
 * handler, and injectable, it is touched only when a burn actually happens.
 */
function createCalderaRedeemRouter(deps) {
  const d = deps || {};
  // Injected in tests; resolved lazily in production. See the note above.
  const getRedis = d.redis
    ? () => d.redis
    // eslint-disable-next-line global-require
    : () => require('../utils/redis');

  const router = express.Router();

  // The body is one 32-character hex string, so 1kb is generous.
  //
  // Note honestly what this does and does not do. body-parser marks a request
  // it has handled (req._body) and later instances no-op, so IN PRODUCTION the
  // global parser in src/server.js runs first and its 10mb /api/* limit is what
  // applies — this line does not tighten it. It is here so the router is
  // self-contained: mounted in a test (or anywhere else) without that global
  // parser, req.body would otherwise be undefined and every burn a 400 for the
  // wrong reason.
  router.use(express.json({ limit: '1kb' }));

  router.post('/redeem', async (req, res) => {
    // ------------------------------------------------------------------------
    // Every failure answers a bare status with no body. The caller is a machine
    // that only reads the status, and a body here would tell an anonymous
    // prober which of "not a token", "expired" and "already spent" it hit.
    // ------------------------------------------------------------------------
    const header = req.get(sso.SSO_HEADER);
    const verdict = sso.verifyToken(header, { /* no path: this is not the guarded surface */ });
    if (!verdict.ok) {
      // 401 covers a missing key too (verifyToken reports secret_missing /
      // secret_too_short). That is deliberately indistinguishable from a bad
      // token from outside: an unauthenticated prober must not be able to
      // fingerprint the deployment's configuration.
      return res.status(401).end();
    }

    const body = req.body;
    const jti = body && typeof body.jti === 'string' ? body.jti : null;
    if (!sso.isValidJti(jti)) return res.status(400).end();

    // The body must name the token's OWN nonce. Without this the token would be
    // a bearer capability to burn anyone's jti, which is the DoS the guard note
    // above is about. Constant-time compare is not needed — both values are
    // already authenticated to the same holder and neither is a secret.
    if (jti !== verdict.payload.jti) return res.status(400).end();

    let client;
    try {
      client = getRedis();
    } catch (err) {
      console.error('[CalderaRedeem] redis unavailable:', err && err.code);
      return res.status(503).end();
    }
    if (!client || client.isReady !== true) {
      // Fail closed. See "NO REDIS, NO 200" above.
      console.error('[CalderaRedeem] redis not ready — refusing to confirm a burn');
      return res.status(503).end();
    }

    try {
      // SET NX PX — the burn. '1' as the value on purpose: the key must carry
      // no identity, because Redis is shared with sessions and this is the one
      // structure that maps 1:1 to "person X logged into the authoring console
      // at time T".
      const stored = await client.set(sso.redeemKey(jti), '1', {
        NX: true,
        PX: sso.REDEEM_TTL_SECONDS * 1000,
      });
      // node-redis v4 answers 'OK' when NX took the key and null when it did
      // not. null is the replay.
      if (stored === null) return res.status(409).end();
      return res.status(200).end();
    } catch (err) {
      // Never assume the write landed. err.code only — a node-redis error
      // message can carry the command, and the command contains the jti.
      console.error('[CalderaRedeem] burn failed:', err && err.code);
      return res.status(503).end();
    }
  });

  return router;
}

module.exports = createCalderaAuthoringRouter();
// Exported for server.js (the mount path is asserted against the Caddyfile) and
// for the test, which builds its own router with an injected transport.
module.exports.createCalderaAuthoringRouter = createCalderaAuthoringRouter;
module.exports.authoringConfig = authoringConfig;
// Where a BROWSER goes, as opposed to where Caddy dials. Exported for the test
// and for any caller that needs the link without a round trip to /status.
module.exports.consoleConfig = consoleConfig;
module.exports.AUTHORING_ROLES = AUTHORING_ROLES;
module.exports.PUBLIC_PATH = PUBLIC_PATH;
module.exports.MOUNT_PATH = '/api/caldera-authoring';
module.exports.AUTHORIZE_PATH = '/api/caldera-authoring/authorize';

// The nonce burn. A SEPARATE router on a SEPARATE mount, because the path is
// half of a contract with infrastructure/caldera/login_handler.py and with the
// container's CYBERCORE_REDEEM_URL: it is /api/caldera/redeem on both sides,
// and nesting it under /api/caldera-authoring to save a mount would silently
// break a login handler that cannot be tested from here.
//
// Exported as a FACTORY and not as a built router, so a test injects a fake
// Redis by argument rather than by require-cache surgery — the same reasoning
// as createCalderaAuthoringRouter's injected fetch. server.js calls it once.
module.exports.createCalderaRedeemRouter = createCalderaRedeemRouter;
module.exports.REDEEM_MOUNT_PATH = '/api/caldera';
module.exports.REDEEM_PATH = '/api/caldera/redeem';
module.exports.SSO_HEADER = sso.SSO_HEADER;
