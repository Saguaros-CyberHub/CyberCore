<?php
// ============================================================================
// Portal user administration.
// ============================================================================
// Deliberately does NOT render password_hash. A real admin panel would not,
// and rendering it here would hand the SSRF route the same hashes the SQLi
// route works for — collapsing two distinct paths into one.
// ============================================================================
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/layout.php';
require_admin();

$rows = $pdo->query(
    'SELECT id, username, display_name, email, role FROM users ORDER BY id'
)->fetchAll();

render_header('Portal Users', '');
?>
<section>
  <h1>Portal Users</h1>
  <p class="muted">Research staff accounts. Portal roles control access to this
     control panel; they are unrelated to accounts on the field station hosts.</p>
  <table class="data">
    <thead><tr><th>#</th><th>Username</th><th>Name</th><th>Email</th><th>Role</th></tr></thead>
    <tbody>
    <?php foreach ($rows as $r): ?>
      <tr>
        <td><?= (int)$r['id'] ?></td>
        <td><a href="/author.php?u=<?= urlencode($r['username']) ?>">
            <?= htmlspecialchars($r['username']) ?></a></td>
        <td><?= htmlspecialchars($r['display_name']) ?></td>
        <td class="muted"><?= htmlspecialchars($r['email']) ?></td>
        <td>
          <?php if ($r['role'] === 'admin'): ?>
            <span class="badge role">admin</span>
          <?php else: ?>
            <?= htmlspecialchars($r['role']) ?>
          <?php endif; ?>
        </td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
</section>
<?php render_footer(); ?>
