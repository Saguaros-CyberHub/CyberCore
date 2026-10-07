/**
 * blueteam-score.js — the scorecard, and the pre-release face of it.
 *
 * TWO STATES, AND THE UNRELEASED ONE IS THE IMPORTANT ONE.
 *
 * Before an instructor releases a run, this renders what the student has
 * SUBMITTED and nothing else. No verdicts, no points, and — the one that is
 * easy to add without noticing — NO TECHNIQUE COUNT. "6 techniques, you found
 * 2" tells a student exactly how much longer to keep hunting, which is most of
 * the skill the exercise is teaching.
 *
 * The server enforces that (src/incident/projection.js withholds the counts
 * entirely, so they are not in the payload to leak). This file must not invent
 * them back: it renders what it is given, and when `released` is false the
 * fields simply are not there. If a future change makes this file compute a
 * total from the findings list, the gate is gone.
 *
 * Global: window.BlueTeamScore
 */
(function (global) {
  'use strict';

  function esc(v) {
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  /** Seconds as a human duration. Null stays null — "—", never "0s". */
  function duration(seconds) {
    if (seconds == null) return '—';
    var s = Math.max(0, Math.round(Number(seconds)));
    if (s < 60) return s + 's';
    var m = Math.floor(s / 60);
    if (m < 60) return m + 'm ' + (s % 60) + 's';
    return Math.floor(m / 60) + 'h ' + (m % 60) + 'm';
  }

  /**
   * Kendall tau, in words.
   *
   * NULL IS NOT ZERO and must not render as a number. Fewer than two correlated
   * entries makes a rank correlation undefined, and "0.00" there reads as "you
   * ordered it no better than chance" — a claim about a student nobody
   * measured.
   */
  function tau(value) {
    if (value == null) return '<span class="bt-muted">not enough entries to score</span>';
    var v = Number(value);
    var label = v >= 0.8 ? 'in order' : (v >= 0.3 ? 'roughly in order' : (v > -0.3 ? 'mixed' : 'reversed'));
    return esc(v.toFixed(2)) + ' <span class="bt-muted">(' + label + ')</span>';
  }

  function tile(label, value, hint) {
    return '<div class="bt-tile">'
      + '<div class="bt-tile-value">' + value + '</div>'
      + '<div class="bt-tile-label">' + esc(label) + '</div>'
      + (hint ? '<div class="bt-tile-hint">' + esc(hint) + '</div>' : '')
      + '</div>';
  }

  /**
   * @param {HTMLElement} el
   * @param {object} score  projectScoreForStudent()'s output, or a staff row
   */
  function render(el, score) {
    if (!el) return;
    var s = score || {};

    if (s.released !== true) {
      var sub = s.submitted || {};
      el.innerHTML = '<div class="bt-card bt-score bt-score-pending">'
        + '<div class="bt-score-head">Not yet released</div>'
        + '<p class="bt-muted">Your work is recorded. Verdicts and your score appear once your '
        + 'instructor releases this incident.</p>'
        + '<div class="bt-tiles">'
        + tile('Findings', esc(sub.findings || 0))
        + tile('Indicators', esc(sub.iocs || 0))
        + tile('Timeline entries', esc(sub.timeline || 0))
        + '</div>'
        + '</div>';
      return;
    }

    el.innerHTML = '<div class="bt-card bt-score">'
      + '<div class="bt-score-head">Score</div>'
      + '<div class="bt-tiles">'
      + tile('Points', esc(s.points == null ? '—' : Number(s.points).toFixed(2)))
      + tile('Techniques', esc((s.techniques_found || 0) + ' / ' + (s.techniques_total || 0)))
      + tile('Indicators', esc((s.iocs_found || 0) + ' / ' + (s.iocs_total || 0)))
      + tile('False positives', esc(s.false_positives || 0))
      + tile('Time to detect', esc(duration(s.ttd_seconds)), 'from the incident start')
      + tile('Timeline', tau(s.timeline_score))
      + '</div>'
      + '</div>';
  }

  global.BlueTeamScore = { render: render, duration: duration, escape: esc };
})(window);
