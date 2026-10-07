<?php
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/layout.php';
require_admin();

$msg = null;
$err = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $f    = $_FILES['file'];
    $name = basename($f['name']);

    $allowed = '/\.(jpe?g|png|gif|svg|webp)/i';

    if ($f['error'] !== UPLOAD_ERR_OK) {
        $err = 'Upload failed (error code ' . $f['error'] . ').';
    } elseif ($name === '' || strpos($name, "\0") !== false) {
        $err = 'Invalid object name.';
    } elseif (!preg_match($allowed, $name)) {
        $err = 'Only image files (jpg, jpeg, png, gif, svg, webp) may be '
             . 'uploaded to Cloud Storage.';
    } else {
        $dest = UPLOAD_DIR . '/' . $name;
        if (move_uploaded_file($f['tmp_name'], $dest)) {
            $stmt = $pdo->prepare(
                'INSERT INTO uploads (filename, original_name, uploaded_by)
                 VALUES (?, ?, ?)'
            );
            $stmt->execute([$name, $f['name'], 'admin']);
            $msg = 'Uploaded to Cloud Storage: ' . htmlspecialchars($name);
        } else {
            $err = 'Could not store the uploaded file.';
        }
    }
}

$stored = $pdo->query(
    'SELECT filename, uploaded_by, created_at
       FROM uploads ORDER BY id DESC LIMIT 50'
)->fetchAll();

render_header('Cloud Storage', '');
?>
<section class="narrow">
  <h1>Cloud Storage</h1>
  <p class="muted">Upload cactus imagery to the CyberSaguaros gallery archive.
     Accepted formats: SVG, PNG, JPEG, GIF, WEBP.</p>

  <?php if ($msg): ?><p class="formok"><?= $msg ?></p><?php endif; ?>
  <?php if ($err): ?><p class="formerr"><?= htmlspecialchars($err) ?></p><?php endif; ?>

  <form method="post" enctype="multipart/form-data" class="stack">
    <label>Cactus image
      <input type="file" name="file" required>
    </label>
    <button type="submit">Upload to Cloud Storage</button>
  </form>

  <h2>Stored objects</h2>
  <?php if (!$stored): ?>
    <p class="muted">Nothing has been contributed to the archive yet.</p>
  <?php else: ?>
    <table class="data">
      <thead><tr><th>Object</th><th>Uploaded by</th><th>Stored</th></tr></thead>
      <tbody>
      <?php foreach ($stored as $r): ?>
        <tr>
          <td><a href="/uploads/<?= rawurlencode($r['filename']) ?>">
              <?= htmlspecialchars($r['filename']) ?></a></td>
          <td><?= htmlspecialchars((string) $r['uploaded_by']) ?></td>
          <td class="muted"><?= htmlspecialchars((string) $r['created_at']) ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  <?php endif; ?>

  <p class="muted">Contributed imagery also appears in the public
     <a href="/gallery.php">field gallery</a>.</p>
</section>
<?php render_footer(); ?>
