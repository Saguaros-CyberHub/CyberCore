/**
 * blueteam-timeline.js — the student's asserted ordering, drawn.
 *
 * The board's third artifact, after findings and indicators: "these techniques
 * happened, in this order". The server scores it with Kendall tau over the
 * entries whose technique is in the key, EXCLUDING the ones that are not rather
 * than counting them as inversions — an uncorrelated entry has already been
 * charged once as a false positive, and charging it again to the ordering would
 * be double jeopardy for one mistake.
 *
 * WHAT THIS FILE MUST NEVER DO: draw the KEY's order beside the student's. That
 * is the answer, laid out as a diff. Pre-release it renders the student's order
 * alone; post-release each entry carries its own verdict, which is the most the
 * projection gives it, and the most it should.
 *
 * Sorted by the student's asserted `observed_at`, falling back to submission
 * order — the same rule the scorer uses, so what the student sees is the
 * sequence they are graded on.
 *
 * Global: window.BlueTeamTimeline
 */
(function (global) {
  'use strict';

  function esc(v) {
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function ms(v) {
    if (!v) return null;
    var t = Date.parse(v);
    return isFinite(t) ? t : null;
  }

  function clock(v) {
    var t = ms(v);
    if (t == null) return '';
    var d = new Date(t);
    return ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2);
  }

  /** Verdict → a class and a word. Absent verdict renders as nothing at all. */
  function verdictBadge(verdict) {
    if (!verdict) return '';
    var label = {
      hit: 'correct',
      partial: 'also seen in normal traffic',
      false_positive: 'not part of this incident',
      unscored: 'not scored',
      true_positive: 'true positive',
      benign_true_positive: 'benign true positive'
    }[verdict] || verdict;
    return '<span class="bt-badge bt-badge-' + esc(verdict) + '">' + esc(label) + '</span>';
  }

  /**
   * @param {HTMLElement} el
   * @param {Array} findings  the student's findings; this picks the timeline ones
   */
  function render(el, findings) {
    if (!el) return;
    var entries = (findings || [])
      .filter(function (f) { return f.kind === 'timeline' && !f.withdrawn_at; })
      .sort(function (a, b) {
        var av = ms(a.observed_at) != null ? ms(a.observed_at) : ms(a.submitted_at);
        var bv = ms(b.observed_at) != null ? ms(b.observed_at) : ms(b.submitted_at);
        return (av || 0) - (bv || 0);
      });

    if (!entries.length) {
      el.innerHTML = '<div class="bt-card"><div class="bt-card-head">Timeline</div>'
        + '<p class="bt-muted">Nothing ordered yet. Add the techniques you found in the order you '
        + 'believe they happened — the order itself is graded, separately from the findings.</p></div>';
      return;
    }

    var rows = entries.map(function (f, i) {
      return '<li class="bt-tl-item" data-finding-id="' + esc(f.finding_id) + '">'
        + '<span class="bt-tl-step">' + (i + 1) + '</span>'
        + '<span class="bt-tl-tech">' + esc(f.technique_id || '—') + '</span>'
        + '<span class="bt-tl-when">' + esc(clock(f.observed_at)) + '</span>'
        + '<span class="bt-tl-title">' + esc(f.title || '') + '</span>'
        + verdictBadge(f.verdict)
        + '<button type="button" class="bt-link bt-withdraw" data-finding-id="'
        + esc(f.finding_id) + '">withdraw</button>'
        + '</li>';
    }).join('');

    el.innerHTML = '<div class="bt-card"><div class="bt-card-head">Timeline</div>'
      + '<ol class="bt-tl">' + rows + '</ol></div>';
  }

  global.BlueTeamTimeline = { render: render, verdictBadge: verdictBadge };
})(window);
