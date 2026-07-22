<?php
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/layout.php';
require_admin();

$msg = null;
$err = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $f    = $_FILES['file'];
    $name = basename($f['name']);

    // "Cloud Storage" accepts cactus imagery only.
    //
    // *** VULNERABILITY: file-upload extension-filter bypass ***
    // The upload is validated by the file's LAST extension only. That blocks
    // a naive `shell.php`, but the file keeps its full original name, so a
    // double-extension upload such as `shell.php.jpg` passes the check (its
    // last extension is `.jpg`). It lands in /uploads/, where the
    // deliberately misconfigured nginx (`location ~ \.php`, not anchored
    // with `$`) routes any path *containing* ".php" to PHP-FPM — whose
    // `security.limit_extensions` has been widened to allow it — and the
    // webshell executes.
    $allowedExt = ['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp'];
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));

    if ($f['error'] !== UPLOAD_ERR_OK) {
        $err = 'Upload failed (error code ' . $f['error'] . ').';
    } elseif (!in_array($ext, $allowedExt, true)) {
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

render_header('Cloud Storage', '');
?>
<section class="narrow">
  <h1>Cloud Storage</h1>
  <p class="muted">Upload cactus imagery to the CyberSaguaros gallery archive.
     Accepted formats: SVG, PNG, JPEG, GIF.</p>

  <?php if ($msg): ?><p class="formok"><?= $msg ?></p><?php endif; ?>
  <?php if ($err): ?><p class="formerr"><?= htmlspecialchars($err) ?></p><?php endif; ?>

  <form method="post" enctype="multipart/form-data" class="stack">
    <label>Cactus image
      <input type="file" name="file" required>
    </label>
    <button type="submit">Upload to Cloud Storage</button>
  </form>

  <p class="muted">Uploaded images appear in the public
     <a href="/gallery.php">field gallery</a>.</p>
</section>
<?php render_footer(); ?>
