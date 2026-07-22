<?php
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/layout.php';
require_admin();

$userCount    = $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
$datasetCount = $pdo->query('SELECT COUNT(*) FROM datasets')->fetchColumn();
$uploadCount  = $pdo->query('SELECT COUNT(*) FROM uploads')->fetchColumn();

render_header('Control Panel', '');
?>
<section>
  <h1>CyberSaguaros Control Panel</h1>
  <p class="muted">Authenticated via admin session. Restricted to research staff.</p>

  <div class="cards">
    <article class="card"><h3><?= (int)$userCount ?></h3><p>portal users</p></article>
    <article class="card"><h3><?= (int)$datasetCount ?></h3><p>datasets</p></article>
    <article class="card"><h3><?= (int)$uploadCount ?></h3><p>gallery images</p></article>
  </div>

  <h2>Tools</h2>
  <ul class="pubs">
    <li><strong><a href="/admin/storage.php">Cloud Storage</a></strong>
        <p>Upload cactus imagery to the CyberSaguaros gallery archive.</p></li>
    <li><strong><a href="/admin/datasets.php">Dataset Review</a></strong>
        <p>Review and mark submitted datasets as verified.</p></li>
  </ul>
</section>
<?php render_footer(); ?>
