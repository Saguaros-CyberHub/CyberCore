<?php
require_once __DIR__ . '/../includes/layout.php';
require_once __DIR__ . '/../includes/db.php';

$uploads = $pdo->query('SELECT filename, original_name, uploaded_by, created_at
                        FROM uploads ORDER BY id DESC LIMIT 60')->fetchAll();

render_header('Gallery', '/gallery.php');
?>
<section>
  <h1>Field gallery</h1>
  <p>Cactus imagery contributed to the CyberSaguaros archive. New images are
     added through the research control panel ("Cloud Storage").</p>

  <?php if (!$uploads): ?>
    <p class="muted">No images in the archive yet.</p>
  <?php else: ?>
    <div class="gallery">
      <?php foreach ($uploads as $u): ?>
        <figure>
          <img src="/uploads/<?= rawurlencode($u['filename']) ?>"
               alt="<?= htmlspecialchars($u['original_name']) ?>">
          <figcaption>
            <?= htmlspecialchars($u['original_name']) ?><br>
            <span class="muted"><?= htmlspecialchars((string)$u['uploaded_by']) ?></span>
          </figcaption>
        </figure>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>
</section>
<?php render_footer(); ?>
