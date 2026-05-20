<?php
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/layout.php';
require_admin();

$msg = null;
$err = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $f = $_FILES['file'];

    // "Cloud Storage" — cactus imagery is meant to be the only thing uploaded.
    //
    // *** VULNERABILITY: unrestricted file upload ***
    // The only check is the MIME type, taken from $_FILES['file']['type'] —
    // that value is the client-supplied Content-Type header and is trivially
    // spoofable. There is no extension check, no content sniffing, and the
    // file keeps its original name. A PHP file sent with an image
    // Content-Type lands in /uploads/ where nginx + PHP-FPM will execute it.
    $allowedTypes = ['image/svg+xml', 'image/png', 'image/jpeg', 'image/gif'];

    if ($f['error'] !== UPLOAD_ERR_OK) {
        $err = 'Upload failed (error code ' . $f['error'] . ').';
    } elseif (!in_array($f['type'], $allowedTypes, true)) {
        $err = 'Only cactus images may be uploaded to Cloud Storage.';
    } else {
        $name = basename($f['name']);
        $dest = UPLOAD_DIR . '/' . $name;
        if (move_uploaded_file($f['tmp_name'], $dest)) {
            $admin = 'admin';
            $stmt = $pdo->prepare(
                'INSERT INTO uploads (filename, original_name, uploaded_by)
                 VALUES (?, ?, ?)'
            );
            $stmt->execute([$name, $f['name'], $admin]);
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
