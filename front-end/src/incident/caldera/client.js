/**
 * ============================================================================
 * CALDERA HTTP CLIENT — the ONLY place in this adapter that opens a socket
 * ============================================================================
 *
 * ############################################################################
 * # THIS FILE HAS NEVER TALKED TO A REAL CALDERA SERVER.                     #
 * #                                                                          #
 * # There is no Caldera anywhere in this repository, no Caldera server on any #
 * # cluster, and no lane has ever had one. Not one request below has been    #
 * # sent and not one response shape has been observed. Every path, header    #
 * # name, field name and status code is taken from upstream's DOCUMENTED v2  #
 * # API and is UNVERIFIED — including whether `KEY` is the header this       #
 * # release wants, whether POST /api/v2/adversaries upserts or 409s on a     #
 * # repeat, and whether a link's `status` is 0-on-success at all.            #
 * #                                                                          #
 * # What IS verified is everything on THIS side of the transport seam: the   #
 * # request each method builds, the errors it raises, and how a response is  #
 * # turned into a value — all of it driven in test/caldera-engine.test.js by #
 * # an injected fake. Read this file as "the shape we will try first", never #
 * # as "this works".                                                         #
 * ############################################################################
 *
 * WHY EVERY REQUEST IS FUNNELLED THROUGH ONE INJECTABLE TRANSPORT
 * ----------------------------------------------------------------------------
 * Not for tidiness. It is the single thing that makes the engine adapter
 * testable at all. There is no server to test against and there will not be one
 * for months; if src/incident/engines/caldera.js called fetch() directly, then
 * every one of its behaviours — does a failed link fail the target, is abort
 * idempotent, does engine_ref round-trip — could only be checked by standing up
 * a C2. With the seam here, all of that is a plain unit test and the untested
 * surface shrinks to exactly one function: defaultTransport().
 *
 * The rule that keeps it true: NO OTHER FILE IN THE ADAPTER MAY MAKE A REQUEST.
 * test/caldera-engine.test.js gates the engine's source text on it.
 *
 * WHY A TRANSPORT FUNCTION RATHER THAN A MOCKED fetch()
 * ----------------------------------------------------------------------------
 * Monkey-patching globalThis.fetch inside a test file leaks: the global is
 * shared with everything that file requires, and a restore that is missed on a
 * throw poisons unrelated suites in the same process. An argument cannot leak.
 *
 * WHY THE DEFAULT TRANSPORT LOOKS LIKE src/utils/guacamole.js
 * ----------------------------------------------------------------------------
 * Because that is this codebase's answer to "talk HTTP to a service", and its
 * header spells out the trap: Node's fetch() has NO default timeout, so a
 * service that accepts a connection and then never answers hangs the caller
 * forever. src/utils/tailscale.js makes the same point. Every call here carries
 * an explicit AbortSignal.timeout for that reason and no other.
 *
 * There is deliberately NO generic http helper in src/utils to reuse — the two
 * that exist (proxmox.js, guacamole.js) are service-specific by design, each
 * carrying its own auth, its own error vocabulary and its own deadline policy.
 * This is the third of those, not a fourth abstraction over them.
 *
 * WHY THE API KEY IS NEVER LOGGED, EVEN ON FAILURE
 * ----------------------------------------------------------------------------
 * It is a C2 credential. bake-caldera-server.sh goes to real lengths to keep it
 * off a command line (a 0600 file in the guest, never a script_arg, because
 * src/utils/script-executor.js interpolates args unquoted and the '&' that
 * password-generator.js guarantees would background the command). Undoing that
 * by printing the key into an error message that lands in the audit log is the
 * same leak by a slower route, so redact() scrubs it from every error string.
 * ============================================================================
 */

'use strict';

/**
 * Socket deadline for one Caldera call.
 *
 * Deliberately more generous than Guacamole's: creating an operation makes the
 * server compile an agent payload with the Go toolchain (that is why the bake
 * gives the box 4GB), and a first call after boot can be slow. Still a hard
 * ceiling, because the alternative is the sweeper's concurrency budget held
 * open by a socket that will never answer.
 */
const DEFAULT_TIMEOUT_MS = Number(process.env.CALDERA_HTTP_TIMEOUT_MS) > 0
  ? Number(process.env.CALDERA_HTTP_TIMEOUT_MS) : 20000;

/** How much of an error body is worth keeping. Enough to name a bad ability id. */
const ERROR_BODY_CHARS = 400;

/**
 * One failed Caldera call.
 *
 * A named class with a `code`, on the same reasoning as
 * UnknownIncidentEngineError in src/incident/engines/index.js: the caller has to
 * tell "the server said no" (a fact about the operation — fail the target) from
 * "the server did not answer" (a fact about the network — burn a check failure
 * and look again). A string match on a message is not a contract.
 */
class CalderaError extends Error {
  constructor(message, opts) {
    super(message);
    const o = opts || {};
    this.name = 'CalderaError';
    this.code = o.code || 'CALDERA_ERROR';
    this.status = o.status == null ? null : o.status;
    this.operation = o.operation == null ? null : o.operation;
    if (o.cause) this.cause = o.cause;
  }
}

/**
 * True for the errors that are a fact about the NETWORK rather than an answer.
 *
 * readTargetState lets exactly these propagate, because the worker's
 * check_failures ladder is the correct handling for them and it already exists.
 * Everything else is diagnosed here instead of being thrown at a sweeper.
 */
function isTransportFailure(err) {
  return !!err && (err.code === 'CALDERA_TIMEOUT' || err.code === 'CALDERA_UNREACHABLE');
}

/**
 * Remove a secret from a string that is about to become an error message.
 *
 * Substring replace rather than a regex: the key is arbitrary bytes and
 * building a regex from it would either need escaping or blow up on a '('.
 */
function redact(text, secret) {
  const s = String(text == null ? '' : text);
  if (!secret) return s;
  return s.split(String(secret)).join('«redacted»');
}

/**
 * The default transport: one HTTP round trip, flattened to {status, ok, text}.
 *
 * Shaped exactly like src/utils/guacamole.js's guacFetchText, including the
 * catch: AbortSignal.timeout rejects with a TimeoutError DOMException while
 * undici surfaces an aborted body read as an AbortError, and both mean the same
 * thing — no answer inside the budget.
 *
 * THIS IS THE ONE FUNCTION IN THE WHOLE ADAPTER THAT NO TEST COVERS, and that is
 * deliberate: covering it needs either a live server or a mocked global, and the
 * entire point of the seam is that nothing else needs either.
 *
 * @param {{method:string,url:string,headers:object,body:?string,timeoutMs:number,operation:string}} req
 * @returns {Promise<{status:number, ok:boolean, text:string}>}
 */
async function defaultTransport(req) {
  const budget = Number(req.timeoutMs) > 0 ? Number(req.timeoutMs) : DEFAULT_TIMEOUT_MS;
  let resp;
  try {
    resp = await fetch(req.url, {
      method: req.method,
      headers: req.headers,
      body: req.body == null ? undefined : req.body,
      signal: AbortSignal.timeout(budget),
    });
  } catch (err) {
    if (err && (err.name === 'TimeoutError' || err.name === 'AbortError')) {
      throw new CalderaError(
        'Caldera did not respond in ' + Math.round(budget / 1000) + 's — ' + req.operation,
        { code: 'CALDERA_TIMEOUT', operation: req.operation, cause: err }
      );
    }
    // ECONNREFUSED, EAI_AGAIN, TLS — all "no server there", which for a
    // lane-local C2 is overwhelmingly the first symptom anyone will meet.
    throw new CalderaError(
      'Caldera unreachable — ' + req.operation + ': ' + (err && err.message ? err.message : String(err)),
      { code: 'CALDERA_UNREACHABLE', operation: req.operation, cause: err }
    );
  }
  // The signal stays armed across the body read deliberately, same as
  // guacFetchText: a server that stalls AFTER headers hangs .text() identically.
  const text = resp.status === 204 ? '' : await resp.text();
  return { status: resp.status, ok: resp.ok, text };
}

/** Trim a trailing slash so path joining never produces '//api/v2/...'. */
function normalizeBaseUrl(raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) {
    throw new CalderaError('caldera client: baseUrl is required', { code: 'CALDERA_NO_BASE_URL' });
  }
  if (!/^https?:\/\//i.test(s)) {
    throw new CalderaError(
      'caldera client: baseUrl must be an absolute http(s) URL, got ' + JSON.stringify(s),
      { code: 'CALDERA_BAD_BASE_URL' }
    );
  }
  return s.replace(/\/+$/, '');
}

/**
 * A client bound to ONE Caldera server.
 *
 * One per server and never a module-level singleton, because the design is
 * LANE-LOCAL: bake-caldera-server.sh clones a template per lane and forbids a
 * shared instance, on the grounds that an agent able to reach a controller
 * outside its own lane is a live pivot into every other student's lane. There
 * is no "the" Caldera server to cache, and a cached client would be a bug
 * waiting for the first run that dispatches two lanes at once.
 *
 * @param {object}   opts
 * @param {string}   opts.baseUrl     e.g. 'http://100.100.60.9:8888'
 * @param {string}   opts.apiKey      the RED key. Never logged — see redact().
 * @param {Function} [opts.transport] injected by tests; defaults to fetch above
 * @param {number}   [opts.timeoutMs]
 */
function createCalderaClient(opts) {
  const o = opts || {};
  const baseUrl = normalizeBaseUrl(o.baseUrl);
  const apiKey = String(o.apiKey == null ? '' : o.apiKey);
  if (!apiKey) {
    throw new CalderaError('caldera client: apiKey is required', { code: 'CALDERA_NO_API_KEY' });
  }
  const transport = typeof o.transport === 'function' ? o.transport : defaultTransport;
  const timeoutMs = Number(o.timeoutMs) > 0 ? Number(o.timeoutMs) : DEFAULT_TIMEOUT_MS;

  /**
   * One call.
   *
   * @param {number[]} [tolerate] status codes that are an ANSWER rather than a
   *   failure — e.g. a 404 on abort, which means the operation is already gone,
   *   which is precisely what abort was asking for. Surfaced as
   *   {tolerated:true, status} so a caller can tell it from a real body.
   */
  async function call(method, path, body, operation, tolerate) {
    const headers = {
      // UNVERIFIED header name. Upstream's v2 docs use `KEY`; if a release wants
      // `Authorization` instead, this is the one line that changes.
      KEY: apiKey,
      Accept: 'application/json',
    };
    let payload = null;
    if (body !== undefined && body !== null) {
      payload = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
    }

    const res = await transport({
      method,
      url: baseUrl + path,
      headers,
      body: payload,
      timeoutMs,
      operation,
    });

    const status = Number(res && res.status);
    const ok = res && (typeof res.ok === 'boolean' ? res.ok : status >= 200 && status < 300);
    const text = res && res.text != null ? String(res.text) : '';

    if (!ok) {
      if (Array.isArray(tolerate) && tolerate.includes(status)) {
        return { tolerated: true, status };
      }
      throw new CalderaError(
        'Caldera ' + operation + ' failed (' + status + '): '
        + redact(text, apiKey).slice(0, ERROR_BODY_CHARS),
        {
          code: (status === 401 || status === 403) ? 'CALDERA_UNAUTHORIZED' : 'CALDERA_HTTP',
          status,
          operation,
        }
      );
    }

    if (!text.trim()) return null;
    try {
      return JSON.parse(text);
    } catch (err) {
      // A non-JSON body from an endpoint that promised JSON is almost always an
      // HTML error page from something in front of the server, and saying so
      // beats "Unexpected token < in JSON at position 0".
      throw new CalderaError(
        'Caldera ' + operation + ' returned ' + status + ' with a non-JSON body: '
        + redact(text, apiKey).slice(0, ERROR_BODY_CHARS),
        { code: 'CALDERA_BAD_RESPONSE', status, operation, cause: err }
      );
    }
  }

  return {
    baseUrl,

    /**
     * Liveness. Documented as unauthenticated on the release the bake pins —
     * which that script's hand-off block lists as unconfirmed. The key is sent
     * anyway: a server that ignores it is fine, and a server that requires it
     * works.
     */
    health() {
      return call('GET', '/api/v2/health', null, 'GET /health');
    },

    /**
     * The server's ability catalog.
     *
     * THE CATALOG IS PER-SERVER STATE, which is exactly why
     * src/incident/caldera/adversary.js takes it as an argument instead of
     * fetching it: two servers with different plugin sets carry different
     * ability ids for the same technique. This is the one place it is fetched.
     */
    listAbilities() {
      return call('GET', '/api/v2/abilities', null, 'GET /abilities');
    },

    /**
     * Create (or re-assert) an adversary profile.
     *
     * `adversary_id` from the compiler is a deterministic uuidv5 over the
     * scenario id and the ordered ability list, so re-creating it is a no-op by
     * construction. 409 is tolerated for the same reason: prepare() must be safe
     * to call twice (a retry re-enters), and "it already exists" is success.
     */
    createAdversary(adversary) {
      return call('POST', '/api/v2/adversaries', adversary, 'POST /adversaries', [409]);
    },

    /** Agents that have beaconed to this server. */
    listAgents() {
      return call('GET', '/api/v2/agents', null, 'GET /agents');
    },

    createOperation(operation) {
      return call('POST', '/api/v2/operations', operation, 'POST /operations');
    },

    /**
     * One operation's own row.
     *
     * 404 is TOLERATED rather than thrown: an operation that is gone is a real,
     * reportable state (the server was rebuilt, someone deleted it in the UI),
     * and readTargetState has to turn that into a refusal the instructor can
     * read — not into a check failure that retries until the run is overdue.
     */
    getOperation(operationId) {
      return call('GET', '/api/v2/operations/' + encodeURIComponent(operationId), null,
        'GET /operations/' + operationId, [404]);
    },

    /** The links (one ability executed against one agent) of an operation. */
    listLinks(operationId) {
      return call('GET', '/api/v2/operations/' + encodeURIComponent(operationId) + '/links', null,
        'GET /operations/' + operationId + '/links', [404]);
    },

    /**
     * Move an operation to a terminal state.
     *
     * 404 tolerated: abort races the sweeper by construction and the contract in
     * engines/index.js requires idempotence. An operation that is already gone
     * is already stopped.
     */
    finishOperation(operationId) {
      return call('PATCH', '/api/v2/operations/' + encodeURIComponent(operationId),
        { state: 'finished' }, 'PATCH /operations/' + operationId + ' finished', [404]);
    },

    /**
     * Stop an operation NOW.
     *
     * The same request as finishOperation on the documented API — there is no
     * separate abort verb — but kept under its own name because the two mean
     * different things at the call site and a future release may well split
     * them. The duplication is one line; a reader finding `finishOperation` in
     * the abort path is a permanent question.
     */
    abortOperation(operationId) {
      return call('PATCH', '/api/v2/operations/' + encodeURIComponent(operationId),
        { state: 'finished' }, 'PATCH /operations/' + operationId + ' abort', [404]);
    },
  };
}

module.exports = {
  createCalderaClient,
  defaultTransport,
  CalderaError,
  isTransportFailure,
  redact,
  normalizeBaseUrl,
  DEFAULT_TIMEOUT_MS,
};
