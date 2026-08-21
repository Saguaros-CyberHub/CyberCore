<?php
// ============================================================================
// SaguaroBot transcript review.
// ============================================================================
// *** ESCAPING HERE IS LOAD-BEARING. ***
// chat_logs holds raw visitor input. Students WILL have typed
// <script>alert(1)</script> and loopback URLs into the bot before an
// instructor ever opens this page. Rendering `message` unescaped would turn
// this into an accidental stored-XSS sink firing inside the admin panel — a
// second injectable surface this challenge deliberately does not have.
// /research.php is the one injection point in this app.
//
// Rendered escaped inside monospace turns, so a payload shows up as visible
// text. That is a better teaching artifact than a popup anyway.
// ============================================================================
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/layout.php';
require_admin();

$session = $_GET['session'] ?? '';

if ($session !== '') {
    $stmt = $pdo->prepare(
        'SELECT speaker, message, created_at FROM chat_logs
          WHERE session_id = ? ORDER BY id ASC'
    );
    $stmt->execute([$session]);
    $turns = $stmt->fetchAll();

    render_header('Transcript', '');
    ?>
    <section>
      <h1>Transcript</h1>
      <p class="muted">Session <?= htmlspecialchars($session) ?> &middot;
         <a href="/admin/chat.php">all transcripts</a></p>
      <?php if (!$turns): ?>
        <p class="muted">No messages recorded for that session.</p>
      <?php else: ?>
        <div class="transcript">
          <?php foreach ($turns as $t): ?>
            <div class="turn <?= $t['speaker'] === 'user' ? 'user' : 'bot' ?>">
              <span class="speaker"><?= htmlspecialchars($t['speaker']) ?>
                &middot; <?= htmlspecialchars((string) $t['created_at']) ?></span><?= htmlspecialchars((string) $t['message']) ?>
            </div>
          <?php endforeach; ?>
        </div>
      <?php endif; ?>
    </section>
    <?php
    render_footer();
    exit;
}

$rows = $pdo->query(
    'SELECT session_id, COUNT(*) AS msgs,
            MIN(created_at) AS started, MAX(created_at) AS last_seen
       FROM chat_logs
      GROUP BY session_id
      ORDER BY last_seen DESC
      LIMIT 100'
)->fetchAll();

render_header('SaguaroBot Transcripts', '');
?>
<section>
  <h1>SaguaroBot Transcripts</h1>
  <p class="muted">Conversations visitors have had with the research assistant.
     Retained for quality review.</p>
  <?php if (!$rows): ?>
    <p class="muted">No conversations recorded yet.</p>
  <?php else: ?>
    <table class="data">
      <thead><tr><th>Session</th><th>Messages</th><th>Started</th><th>Last message</th></tr></thead>
      <tbody>
      <?php foreach ($rows as $r): ?>
        <tr>
          <td><a href="/admin/chat.php?session=<?= urlencode($r['session_id']) ?>">
              <?= htmlspecialchars($r['session_id']) ?></a></td>
          <td><?= (int)$r['msgs'] ?></td>
          <td class="muted"><?= htmlspecialchars((string) $r['started']) ?></td>
          <td class="muted"><?= htmlspecialchars((string) $r['last_seen']) ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  <?php endif; ?>
</section>
<?php render_footer(); ?>
