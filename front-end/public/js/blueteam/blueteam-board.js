/**
 * blueteam-board.js — the board itself.
 *
 * ONE COMPONENT, TWO PRODUCTS, TWO AUDIENCES.
 *
 *   mount(el, { base, role, runId })
 *
 * `base` is the incidents collection URL and is the ONLY thing that differs
 * between the CYBR 400 course page and a Clinic-in-a-Box engagement page. No
 * code below branches on which product it is running in, and none of it
 * contains the words 'course' or 'engagement' — the vocabulary gate
 * (test/ciab-vocabulary.test.js) applies to anything a clinic page loads, and
 * an instructor running a clinic never sees a course word.
 *
 * `role` picks the layout, but it is NOT a permission. The server decides what
 * a caller may see and returns a `tier` on every read; this file renders the
 * tier it was GIVEN, not the role it was told. A student who edits `role` in
 * the console gets the staff layout drawn around a student payload — an empty
 * table, not a disclosure.
 *
 * THE PRE-RELEASE STATE IS THE DEFAULT STATE. A student sees their own
 * submissions with no verdicts and no counts until an instructor releases. Do
 * not add a "N of M found" line here: the M is not in the payload before
 * release, deliberately (src/incident/projection.js), and reconstructing it
 * from the findings list would defeat the gate from the client side.
 *
 * Requires: /js/blueteam/blueteam-api.js, blueteam-score.js, blueteam-timeline.js
 * Global: window.BlueTeamBoard
 */
(function (global) {
  'use strict';

  var STYLE_ID = 'bt-board-style';

  /**
   * A small stylesheet, injected once.
   *
   * This component is loaded by three pages with three different stylesheets
   * (admin.html, CLE's courses.html, CiAB's workspace/instructor pages), so it
   * carries its own rather than depending on classes it cannot see. Every
   * colour is a main.css custom property WITH A FALLBACK, so it looks right in
   * both themes on the pages that define them and merely plain on the ones that
   * do not.
   */
  function ensureStyle() {
    if (document.getElementById(STYLE_ID)) return;
    var css = ''
      + '.bt-board{display:flex;flex-direction:column;gap:16px}'
      + '.bt-card{background:var(--bg-card,#fff);border:1px solid var(--border-color,#e5e7eb);'
      + 'border-radius:var(--border-radius,8px);padding:16px}'
      + '.bt-card-head,.bt-score-head{font-weight:600;margin-bottom:8px;color:var(--text-primary,#111827)}'
      + '.bt-muted{color:var(--text-muted,#6b7280);font-size:.9em}'
      + '.bt-tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}'
      + '.bt-tile{background:var(--bg-page,#f3f4f6);border-radius:6px;padding:12px}'
      + '.bt-tile-value{font-size:1.4em;font-weight:600;color:var(--text-primary,#111827)}'
      + '.bt-tile-label{font-size:.85em;color:var(--text-secondary,#374151)}'
      + '.bt-tile-hint{font-size:.75em;color:var(--text-muted,#6b7280)}'
      + '.bt-list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:8px}'
      + '.bt-row{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap;'
      + 'border-bottom:1px solid var(--border-light,#f3f4f6);padding-bottom:8px}'
      + '.bt-row-withdrawn{opacity:.5;text-decoration:line-through}'
      + '.bt-tl{list-style:none;margin:0;padding:0}'
      + '.bt-tl-item{display:flex;gap:10px;align-items:baseline;padding:6px 0}'
      + '.bt-tl-step{display:inline-flex;width:22px;height:22px;border-radius:50%;'
      + 'align-items:center;justify-content:center;font-size:.75em;'
      + 'background:var(--primary-light,#1e5288);color:#fff;flex:0 0 auto}'
      + '.bt-tl-tech,.bt-tech{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:600}'
      + '.bt-badge{font-size:.75em;padding:2px 8px;border-radius:999px;'
      + 'background:var(--gray-200,#e5e7eb);color:var(--gray-800,#1f2937)}'
      + '.bt-badge-hit,.bt-badge-true_positive{background:var(--success,#4f9153);color:#fff}'
      + '.bt-badge-partial,.bt-badge-benign_true_positive{background:var(--warning,#f59e0b);color:#1f2937}'
      + '.bt-badge-false_positive{background:var(--danger,#ab0520);color:#fff}'
      + '.bt-link{background:none;border:0;padding:0;color:var(--info,#378dbd);cursor:pointer;font-size:.85em}'
      + '.bt-form{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;align-items:end}'
      + '.bt-form label{display:flex;flex-direction:column;gap:4px;font-size:.85em;'
      + 'color:var(--text-secondary,#374151)}'
      + '.bt-form input,.bt-form select,.bt-form textarea{padding:8px;border-radius:6px;'
      + 'border:1px solid var(--border-color,#e5e7eb);background:var(--bg-input,#fff);'
      + 'color:var(--text-primary,#111827);font:inherit}'
      + '.bt-form textarea{grid-column:1/-1;min-height:64px}'
      + '.bt-err{color:var(--danger,#ab0520);font-size:.9em;min-height:1.2em}';
    var style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = css;
    document.head.appendChild(style);
  }

  function esc(v) {
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  var IOC_TYPES = ['host', 'user', 'ip', 'path', 'process', 'domain', 'hash', 'port'];

  function submitForm() {
    return '<div class="bt-card">'
      + '<div class="bt-card-head">Record what you found</div>'
      + '<form class="bt-form" data-bt-form>'
      + '<label>Kind<select name="kind">'
      + '<option value="finding">Finding (a technique)</option>'
      + '<option value="ioc">Indicator</option>'
      + '<option value="timeline">Timeline entry</option>'
      + '</select></label>'
      + '<label>Technique<input name="technique_id" placeholder="T1110.001" autocomplete="off"></label>'
      + '<label data-bt-ioc hidden>Indicator type<select name="ioc_type">'
      + IOC_TYPES.map(function (t) { return '<option value="' + t + '">' + t + '</option>'; }).join('')
      + '</select></label>'
      + '<label data-bt-ioc hidden>Value<input name="ioc_value" placeholder="203.0.113.11"></label>'
      + '<label>When you think it happened<input type="datetime-local" name="observed_at"></label>'
      + '<label>Title<input name="title" placeholder="Brute force against auth-01"></label>'
      + '<label style="grid-column:1/-1">The query you ran'
      + '<input name="query" placeholder=\'loggen.metadata.src_ip : "203.0.113.11"\'></label>'
      + '<textarea name="narrative" placeholder="What you saw, and why you concluded this."></textarea>'
      + '<button type="submit" class="btn btn-primary">Record</button>'
      + '<div class="bt-err" data-bt-error></div>'
      + '</form></div>';
  }

  function findingRow(f, canWithdraw) {
    var badge = global.BlueTeamTimeline ? global.BlueTeamTimeline.verdictBadge(f.verdict) : '';
    var what = f.kind === 'ioc'
      ? '<span class="bt-tech">' + esc(f.ioc_type) + ':' + esc(f.ioc_value) + '</span>'
      : '<span class="bt-tech">' + esc(f.technique_id || '—') + '</span>';
    return '<li class="bt-row' + (f.withdrawn_at ? ' bt-row-withdrawn' : '') + '">'
      + what
      + '<span>' + esc(f.title || '') + '</span>'
      + badge
      + (f.note ? '<span class="bt-muted">' + esc(f.note) + '</span>' : '')
      + (canWithdraw && !f.withdrawn_at
        ? '<button type="button" class="bt-link bt-withdraw" data-finding-id="'
          + esc(f.finding_id) + '">withdraw</button>'
        : '')
      + '</li>';
  }

  /** Local datetime-local value → ISO, or null. */
  function toIso(value) {
    if (!value) return null;
    var t = Date.parse(value);
    return isFinite(t) ? new Date(t).toISOString() : null;
  }

  function mount(el, options) {
    if (!el) throw new Error('BlueTeamBoard.mount needs an element');
    var opts = options || {};
    if (!opts.runId) throw new Error('BlueTeamBoard.mount needs a runId');
    ensureStyle();

    var api = global.BlueTeamApi.create({ base: opts.base });
    var runId = opts.runId;
    var pollTimer = null;
    var destroyed = false;
    var lastStatus = null;

    el.classList.add('bt-board');
    el.innerHTML = '<div class="bt-card"><span class="bt-muted">Loading the board…</span></div>';

    function renderStudent(payload) {
      var released = !!(payload.score && payload.score.released);
      var active = (payload.findings || []).filter(function (f) { return f.kind !== 'timeline'; });

      el.innerHTML = ''
        + '<div data-bt-score></div>'
        + (released ? '' : submitForm())
        + '<div class="bt-card"><div class="bt-card-head">Findings and indicators</div>'
        + (active.length
          ? '<ul class="bt-list">' + active.map(function (f) { return findingRow(f, !released); }).join('') + '</ul>'
          : '<p class="bt-muted">Nothing recorded yet.</p>')
        + '</div>'
        + '<div data-bt-timeline></div>';

      global.BlueTeamScore.render(el.querySelector('[data-bt-score]'), payload.score);
      global.BlueTeamTimeline.render(el.querySelector('[data-bt-timeline]'), payload.findings);
      wireStudent();
    }

    function renderStaff(payload) {
      var byUser = {};
      (payload.findings || []).forEach(function (f) {
        (byUser[f.user_id] = byUser[f.user_id] || []).push(f);
      });
      var scores = {};
      (payload.scores || []).forEach(function (s) { scores[s.user_id] = s; });

      var blocks = Object.keys(byUser).map(function (uid) {
        var s = scores[uid] || {};
        return '<div class="bt-card"><div class="bt-card-head">'
          + esc(uid) + ' <span class="bt-muted">'
          + esc((s.final_points == null ? '—' : Number(s.final_points).toFixed(2)) + ' pts')
          + (s.released ? ' · released' : ' · not released') + '</span></div>'
          + '<ul class="bt-list">' + byUser[uid].map(function (f) {
            return '<li class="bt-row">'
              + '<span class="bt-tech">'
              + esc(f.kind === 'ioc' ? (f.ioc_type + ':' + f.ioc_value) : (f.technique_id || '—'))
              + '</span>'
              + '<span>' + esc(f.title || '') + '</span>'
              + '<span class="bt-badge bt-badge-' + esc(f.override_verdict || f.auto_verdict || 'unscored') + '">'
              + esc(f.override_verdict || f.auto_verdict || 'unscored') + '</span>'
              + '<select class="bt-override" data-finding-id="' + esc(f.finding_id) + '">'
              + ['', 'hit', 'partial', 'false_positive', 'unscored'].map(function (v) {
                return '<option value="' + v + '"' + (f.override_verdict === v ? ' selected' : '') + '>'
                  + (v || 'override…') + '</option>';
              }).join('')
              + '</select></li>';
          }).join('') + '</ul></div>';
      }).join('');

      el.innerHTML = '<div class="bt-card"><div class="bt-card-head">Instructor</div>'
        + '<button type="button" class="btn" data-bt-score-all>Re-run the scorer</button> '
        + '<button type="button" class="btn btn-primary" data-bt-release>Release scores</button> '
        + '<button type="button" class="bt-link" data-bt-retract>Retract</button>'
        + '<div class="bt-err" data-bt-error></div></div>'
        + (blocks || '<div class="bt-card"><p class="bt-muted">No submissions yet.</p></div>');
      wireStaff();
    }

    function showError(message) {
      var box = el.querySelector('[data-bt-error]');
      if (box) box.textContent = message || '';
      // Toast is app.js's BARE binding, not a window property — feature-detect
      // through typeof so a page that has not loaded app.js does not throw a
      // ReferenceError here and lose the inline message as well.
      try { if (typeof Toast !== 'undefined' && message) Toast.error(message); } catch (e) { /* inline only */ }
    }

    function wireStudent() {
      var form = el.querySelector('[data-bt-form]');
      if (form) {
        var kind = form.elements.kind;
        var toggleIoc = function () {
          var isIoc = kind.value === 'ioc';
          el.querySelectorAll('[data-bt-ioc]').forEach(function (n) { n.hidden = !isIoc; });
        };
        kind.addEventListener('change', toggleIoc);
        toggleIoc();

        form.addEventListener('submit', function (ev) {
          ev.preventDefault();
          showError('');
          var body = {
            kind: form.elements.kind.value,
            technique_id: form.elements.technique_id.value || null,
            ioc_type: form.elements.ioc_type ? form.elements.ioc_type.value : null,
            ioc_value: form.elements.ioc_value ? form.elements.ioc_value.value : null,
            observed_at: toIso(form.elements.observed_at.value),
            title: form.elements.title.value || null,
            narrative: form.elements.narrative.value || null,
            evidence: { query: form.elements.query.value || null }
          };
          api.submitFinding(runId, body)
            .then(refresh)
            .catch(function (err) { showError(err.message); });
        });
      }

      el.querySelectorAll('.bt-withdraw').forEach(function (btn) {
        btn.addEventListener('click', function () {
          api.withdrawFinding(runId, btn.getAttribute('data-finding-id'))
            .then(refresh)
            .catch(function (err) { showError(err.message); });
        });
      });
    }

    function wireStaff() {
      var scoreBtn = el.querySelector('[data-bt-score-all]');
      if (scoreBtn) {
        scoreBtn.addEventListener('click', function () {
          api.score(runId).then(refresh).catch(function (e) { showError(e.message); });
        });
      }
      var rel = el.querySelector('[data-bt-release]');
      if (rel) {
        rel.addEventListener('click', function () {
          api.release(runId, true).then(refresh).catch(function (e) { showError(e.message); });
        });
      }
      var retract = el.querySelector('[data-bt-retract]');
      if (retract) {
        retract.addEventListener('click', function () {
          api.release(runId, false).then(refresh).catch(function (e) { showError(e.message); });
        });
      }
      el.querySelectorAll('.bt-override').forEach(function (sel) {
        sel.addEventListener('change', function () {
          api.overrideFinding(runId, sel.getAttribute('data-finding-id'),
            { override_verdict: sel.value || null })
            .then(refresh)
            .catch(function (e) { showError(e.message); });
        });
      });
    }

    function refresh() {
      return api.getBoard(runId).then(function (payload) {
        if (destroyed) return;
        // The SERVER's tier, not the caller's `role`. See the header.
        if (payload.tier === 'staff') renderStaff(payload);
        else renderStudent(payload);
      }).catch(function (err) {
        if (destroyed) return;
        el.innerHTML = '<div class="bt-card"><p class="bt-err">' + esc(err.message) + '</p></div>';
      });
    }

    /**
     * Poll while the incident is in flight, and only then.
     *
     * Stops on a terminal status: a finished run's board changes only when
     * somebody presses a button on it, and thirty idle tabs polling a completed
     * exercise for the rest of the day is the kind of load nobody attributes to
     * a page they left open.
     */
    function poll() {
      if (destroyed) return;
      api.getStatus(runId).then(function (st) {
        if (destroyed) return;
        var key = st.status + '|' + st.released + '|' + st.submitted;
        if (lastStatus !== null && key !== lastStatus) refresh();
        lastStatus = key;
        var live = ['scheduling', 'dispatching', 'running'].indexOf(st.status) !== -1;
        if (live) pollTimer = setTimeout(poll, 2000);
      }).catch(function () { /* a poll failure is not worth a toast */ });
    }

    refresh().then(function () { lastStatus = null; poll(); });

    return {
      refresh: refresh,
      destroy: function () {
        destroyed = true;
        if (pollTimer) clearTimeout(pollTimer);
        el.innerHTML = '';
      }
    };
  }

  global.BlueTeamBoard = { mount: mount };
})(window);
