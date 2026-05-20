<?php
// ============================================================================
// SaguaroBot floating chat widget
// ============================================================================
// Emitted on every page by render_footer(). Opens in-place — no navigation.
// Conversational replies come from /api/chat.php; pasting a dataset URL makes
// SaguaroBot fetch it via /api/verify.php (the SSRF surface of the challenge).
// ============================================================================
?>
<button id="sbot-toggle" type="button" aria-label="Open SaguaroBot chat">
  <svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor"
       stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M21 11.5a8.4 8.4 0 0 1-8.5 8.5 8.5 8.5 0 0 1-3.8-.9L3 21l1.9-5.7A8.5 8.5 0 1 1 21 11.5z"/>
  </svg>
</button>
<div id="sbot-panel" hidden>
  <div class="sbot-head">
    <strong>&#127797; SaguaroBot</strong>
    <button type="button" id="sbot-close" aria-label="Close">&times;</button>
  </div>
  <div id="sbot-log">
    <div class="sbot-msg sbot-bot">SaguaroBot: Hi! I'm the CyberSaguaros research
      assistant. Ask me anything — or paste a dataset URL and I'll fetch it to
      verify its integrity.</div>
  </div>
  <form id="sbot-form" autocomplete="off">
    <input type="text" id="sbot-input" placeholder="Message SaguaroBot...">
    <button type="submit">Send</button>
  </form>
</div>
<script>
(function () {
  var toggle = document.getElementById('sbot-toggle');
  var panel  = document.getElementById('sbot-panel');
  var closeB = document.getElementById('sbot-close');
  var log    = document.getElementById('sbot-log');
  var form   = document.getElementById('sbot-form');
  var input  = document.getElementById('sbot-input');

  function setOpen(o) { panel.hidden = !o; if (o) { input.focus(); } }
  toggle.addEventListener('click', function () { setOpen(panel.hidden); });
  closeB.addEventListener('click', function () { setOpen(false); });

  function add(role, text, pre) {
    var d = document.createElement(pre ? 'pre' : 'div');
    d.className = 'sbot-msg sbot-' + role + (pre ? ' sbot-pre' : '');
    d.textContent = pre ? text
      : ((role === 'user' ? 'You: ' : 'SaguaroBot: ') + text);
    log.appendChild(d);
    log.scrollTop = log.scrollHeight;
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    var msg = input.value.trim();
    if (!msg) { return; }
    add('user', msg);
    input.value = '';

    try {
      var r = await fetch('/api/chat.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: msg })
      });
      var j = await r.json();
      add('bot', j.reply || '(no response)');
    } catch (_) {
      add('bot', "I couldn't reach the research server.");
    }

    // SaguaroBot verifies any dataset URL it is given.
    var u = msg.match(/https?:\/\/[^\s]+/i);
    if (u) {
      add('bot', 'Fetching that dataset to verify its integrity...');
      try {
        var v = await fetch('/api/verify.php', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'url=' + encodeURIComponent(u[0])
        });
        add('bot', await v.text(), true);
      } catch (_) {
        add('bot', 'The integrity check failed to run.');
      }
    }
  });
})();
</script>
