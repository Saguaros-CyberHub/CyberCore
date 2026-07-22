<?php
require_once __DIR__ . '/../includes/layout.php';
render_header('SaguaroBot', '/chat.php');
?>
<section class="split">
  <div>
    <h1>SaguaroBot</h1>
    <p>Hi — I'm SaguaroBot, the CyberSaguaros research assistant. Ask me about
       the project, our datasets, or how to submit your own.</p>

    <div id="chat-log" class="chatlog">
      <div class="msg bot">SaguaroBot: Welcome to CyberSaguaros. How can I help
        with your cactus research today?</div>
    </div>
    <form id="chat-form" class="chatbar" autocomplete="off">
      <input type="text" id="chat-input" placeholder="Ask SaguaroBot...">
      <button type="submit">Send</button>
    </form>
  </div>

  <div>
    <h2>Dataset integrity check</h2>
    <p>Submitting a dataset? Paste its URL and SaguaroBot will fetch the file
       and verify its integrity for you before our researchers review it.</p>
    <form id="verify-form" class="stack">
      <label>Dataset URL
        <input type="url" id="verify-url"
               placeholder="https://data.example.org/my-dataset.csv" required>
      </label>
      <button type="submit">Verify dataset</button>
    </form>
    <pre id="verify-result" class="verifybox">No dataset checked yet.</pre>
  </div>
</section>

<script>
const log = document.getElementById('chat-log');
function add(role, text) {
  const d = document.createElement('div');
  d.className = 'msg ' + role;
  d.textContent = (role === 'bot' ? 'SaguaroBot: ' : 'You: ') + text;
  log.appendChild(d);
  log.scrollTop = log.scrollHeight;
}

document.getElementById('chat-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = document.getElementById('chat-input');
  const msg = input.value.trim();
  if (!msg) return;
  add('user', msg);
  input.value = '';
  const r = await fetch('/api/chat.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: msg })
  });
  const j = await r.json();
  add('bot', j.reply || '(no response)');
});

document.getElementById('verify-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = document.getElementById('verify-url').value.trim();
  const box = document.getElementById('verify-result');
  box.textContent = 'SaguaroBot is fetching the dataset...';
  const r = await fetch('/api/verify.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'url=' + encodeURIComponent(url)
  });
  box.textContent = await r.text();
});
</script>
<?php render_footer(); ?>
