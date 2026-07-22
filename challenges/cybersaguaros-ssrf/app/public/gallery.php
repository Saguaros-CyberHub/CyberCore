<?php
require_once __DIR__ . '/../includes/layout.php';

// The field gallery shows every image in two directories:
//   assets/gallery/  — curated saguaro photography shipped with the portal
//   uploads/         — images contributed through the admin "Cloud Storage"
// Drop more saguaro photos into assets/gallery/ and they appear automatically.
$imageExt = ['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp'];

function gallery_scan(string $absDir, string $webBase, array $exts): array {
    if (!is_dir($absDir)) {
        return [];
    }
    $out = [];
    foreach (scandir($absDir) ?: [] as $f) {
        if ($f[0] === '.') {
            continue;
        }
        $ext = strtolower(pathinfo($f, PATHINFO_EXTENSION));
        if (in_array($ext, $exts, true)) {
            $out[] = ['src' => $webBase . '/' . rawurlencode($f), 'name' => $f];
        }
    }
    return $out;
}

$images = array_merge(
    gallery_scan(__DIR__ . '/assets/gallery', '/assets/gallery', $imageExt),
    gallery_scan(__DIR__ . '/uploads', '/uploads', $imageExt)
);

render_header('Gallery', '/gallery.php');
?>
<section>
  <h1>Field gallery</h1>
  <p>Saguaro imagery from the CyberSaguaros archive — curated field photography
     plus images contributed through the research control panel.</p>

  <?php if (!$images): ?>
    <p class="muted">No images in the archive yet.</p>
  <?php else: ?>
    <div class="gallery">
      <?php foreach ($images as $img): ?>
        <figure>
          <img src="<?= htmlspecialchars($img['src']) ?>"
               alt="<?= htmlspecialchars($img['name']) ?>" loading="lazy">
          <figcaption><?= htmlspecialchars($img['name']) ?></figcaption>
        </figure>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>
</section>
<?php render_footer(); ?>
