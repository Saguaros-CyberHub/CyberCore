<?php
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/layout.php';
require_admin();

// Which of the two surfaces let this request in. A token session has no user
// row, so the panel names whichever one authorised the request.
$who = admin_identity();

$userCount    = $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
$datasetCount = $pdo->query('SELECT COUNT(*) FROM datasets')->fetchColumn();
$uploadCount  = $pdo->query('SELECT COUNT(*) FROM uploads')->fetchColumn();
$articleCount = $pdo->query('SELECT COUNT(*) FROM articles')->fetchColumn();

render_header('Control Panel', '');
?>
<section>
  <h1>CyberSaguaros Control Panel</h1>

  <?php if ($who['via'] === 'session'): ?>
    <p class="muted">Signed in as
       <strong><?= htmlspecialchars($who['display_name']) ?></strong>
       (@<?= htmlspecialchars((string) $who['username']) ?>) — portal administrator.</p>
  <?php else: ?>
    <?php
      // admin_sessions.label comes back out of the database — escape it.
    ?>
    <p class="muted">Authorised by an <strong>admin session token</strong> —
       <?= htmlspecialchars($who['label']) ?>. No portal user is associated with
       this session.</p>
  <?php endif; ?>

  <div class="cards">
    <article class="card"><h3><?= (int)$userCount ?></h3><p>portal users</p></article>
    <article class="card"><h3><?= (int)$datasetCount ?></h3><p>datasets</p></article>
    <article class="card"><h3><?= (int)$articleCount ?></h3><p>articles</p></article>
    <article class="card"><h3><?= (int)$uploadCount ?></h3><p>gallery images</p></article>
  </div>

  <h2>Tools</h2>
  <ul class="pubs">
    <li><strong><a href="/admin/storage.php">Cloud Storage</a></strong>
        <p>Upload cactus imagery to the CyberSaguaros gallery archive.</p></li>
    <li><strong><a href="/admin/datasets.php">Dataset Review</a></strong>
        <p>Review and mark submitted datasets as verified.</p></li>
    <li><strong><a href="/admin/users.php">Portal Users</a></strong>
        <p>Research staff accounts and their portal roles.</p></li>
    <li><strong><a href="/admin/chat.php">SaguaroBot Transcripts</a></strong>
        <p>Review conversations visitors have had with the research assistant.</p></li>
  </ul>
</section>
<?php render_footer(); ?>
