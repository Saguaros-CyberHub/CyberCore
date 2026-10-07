/**
 * blueteam-api.js — the board's transport, and the ONLY thing in this directory
 * that knows a URL.
 *
 * SCOPE-AGNOSTIC BY CONSTRUCTION. Every method takes its path from a `base`
 * given at construction — `/api/cle/courses/<id>/incidents` on the course page,
 * `/api/engagements/<id>/incidents` on the clinic page. Nothing below branches
 * on which one it got, and nothing below contains the word 'course' or
 * 'engagement'. That is what lets one board serve two products; the moment this
 * file grows an `if (isCourse)` there are two boards again.
 *
 * WHY IT DOES NOT USE THE GLOBAL `API` OBJECT
 * ----------------------------------------------------------------------------
 * `API` in public/js/app.js is declared with `const` at script top level, which
 * makes it a BARE binding and NOT a property of window — so `window.API` is
 * undefined and a defensive `window.API || …` fallback silently takes the wrong
 * branch. (The same trap has already been fixed once in this codebase, for
 * `window.Auth`.) Depending on it would also pin this file to app.js's load
 * order on three different pages. Forty lines of fetch is cheaper than either.
 *
 * Requires nothing. Global: window.BlueTeamApi
 */
(function (global) {
  'use strict';

  /** The auth header, read fresh per request — a token can be rotated mid-page. */
  function authHeaders() {
    var headers = { 'Content-Type': 'application/json' };
    var token = null;
    try { token = localStorage.getItem('token'); } catch (e) { token = null; }
    if (token) headers.Authorization = 'Bearer ' + token;
    return headers;
  }

  /**
   * One request.
   *
   * Always parses JSON, and treats a non-JSON body as an error rather than as
   * an empty success: every route in this feature answers JSON on every path,
   * so a body that is not JSON means something upstream (a proxy, an HTML error
   * page) answered instead of the app.
   */
  function request(url, options) {
    var opts = options || {};
    var config = {
      method: opts.method || 'GET',
      credentials: 'include',
      headers: authHeaders()
    };
    if (opts.body) config.body = JSON.stringify(opts.body);

    return fetch(url, config).then(function (response) {
      return response.text().then(function (raw) {
        var data = null;
        try { data = raw ? JSON.parse(raw) : {}; } catch (e) { data = null; }
        if (data === null) {
          var parseErr = new Error('The server did not answer with JSON (HTTP ' + response.status + ').');
          parseErr.status = response.status;
          throw parseErr;
        }
        if (!response.ok) {
          var err = new Error(data.error || ('Request failed (HTTP ' + response.status + ')'));
          err.status = response.status;
          err.code = data.code || null;
          throw err;
        }
        return data;
      });
    });
  }

  /**
   * @param {{base: string}} opts base is the incidents collection URL, with or
   *   without a trailing slash.
   */
  function create(opts) {
    var base = String((opts && opts.base) || '').replace(/\/+$/, '');
    if (!base) throw new Error('BlueTeamApi.create needs a base URL');

    var run = function (runId) { return base + '/' + encodeURIComponent(runId); };

    return {
      base: base,

      listRuns: function () { return request(base); },

      /** The whole board. Shape depends on the caller's tier, decided server-side. */
      getBoard: function (runId) { return request(run(runId)); },

      /**
       * The 2s poll.
       *
       * The /status suffix is not decoration: src/server.js exempts GETs
       * matching /\/status$/ from the global API rate limiter. Polling any
       * other path at this interval 429s an instructor mid-exercise.
       */
      getStatus: function (runId) { return request(run(runId) + '/status'); },

      submitFinding: function (runId, body) {
        return request(run(runId) + '/findings', { method: 'POST', body: body });
      },

      withdrawFinding: function (runId, findingId) {
        return request(run(runId) + '/findings/' + encodeURIComponent(findingId), { method: 'DELETE' });
      },

      // ── instructor ──────────────────────────────────────────────────────
      overrideFinding: function (runId, findingId, patch) {
        return request(run(runId) + '/findings/' + encodeURIComponent(findingId),
          { method: 'PATCH', body: patch });
      },

      score: function (runId) { return request(run(runId) + '/score', { method: 'POST' }); },

      release: function (runId, released, userId) {
        return request(run(runId) + '/release', {
          method: 'POST',
          body: { released: released !== false, user_id: userId || undefined }
        });
      }
    };
  }

  global.BlueTeamApi = { create: create };
})(window);
