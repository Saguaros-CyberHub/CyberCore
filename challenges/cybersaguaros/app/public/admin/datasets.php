<?php
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/layout.php';
require_admin();

// Mark a dataset verified (flavor admin tooling).
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['verify_id'])) {
    $stmt = $pdo->prepare('UPDATE datasets SET verified = 1 WHERE id = ?');
    $stmt->execute([(int)$_POST['verify_id']]);
    header('Location: /admin/datasets.php');
    exit;
}

$rows = $pdo->query('SELECT id, name, dataset_url, verified FROM datasets ORDER BY id')
            ->fetchAll();

render_header('Dataset Review', '');
?>
<section>
  <h1>Dataset Review</h1>
  <p class="muted">Review submitted datasets and mark them verified.</p>
  <table class="data">
    <thead><tr><th>Dataset</th><th>Source URL</th><th>Status</th><th></th></tr></thead>
    <tbody>
    <?php foreach ($rows as $r): ?>
      <tr>
        <td><?= htmlspecialchars($r['name']) ?></td>
        <td class="muted"><?= htmlspecialchars((string)$r['dataset_url']) ?></td>
        <td><?= $r['verified'] ? 'verified' : 'pending' ?></td>
        <td>
          <?php if (!$r['verified']): ?>
            <form method="post" style="margin:0">
              <input type="hidden" name="verify_id" value="<?= (int)$r['id'] ?>">
              <button type="submit">Mark verified</button>
            </form>
          <?php endif; ?>
        </td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
</section>
<?php render_footer(); ?>
