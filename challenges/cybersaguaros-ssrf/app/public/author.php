<?php
// ============================================================================
// Author profile — a staff page listing one researcher's articles.
// ============================================================================
// Reinforces the @username disclosure from the bylines and gives it a stable
// address a student can enumerate. Prepared lookup by username; not an
// injection sink.
//
// The role badge below tells a student which of the three portal accounts is
// the administrator, and therefore which cracked hash is the one worth using.
// That is intentional — it is what makes the SQLi -> crack -> sign in route
// discoverable. It is also the single line to remove if the challenge ever
// needs to be harder.
//
// password_hash is NEVER rendered here or anywhere else in the app.
// ============================================================================
require_once __DIR__ . '/../includes/layout.php';   // pulls auth.php -> db.php

$u    = $_GET['u'] ?? '';
$stmt = $pdo->prepare(
    'SELECT id, username, display_name, email, role FROM users WHERE username = ?'
);
$stmt->execute([$u]);
$author = $stmt->fetch() ?: null;

if (!$author) {
    http_response_code(404);
    render_header('Author not found', '/publications.php');
    echo '<section class="narrow"><h1>Author not found</h1>'
       . '<p class="muted">No research staff member matches that address. '
       . '<a href="/publications.php">Back to publications</a>.</p></section>';
    render_footer();
    exit;
}

$sql = 'SELECT slug, title, abstract, published_on, status
          FROM articles WHERE author_id = ?';
if (!current_researcher()) {
    $sql .= " AND status = 'published'";
}
$sql .= " ORDER BY (status = 'draft') DESC, published_on DESC, id DESC";
$stmt = $pdo->prepare($sql);
$stmt->execute([$author['id']]);
$articles = $stmt->fetchAll();

render_header($author['display_name'], '/publications.php');
?>
<section>
  <div class="authorhead">
    <span class="avatar-lg"><?= htmlspecialchars(initials((string) $author['display_name'])) ?></span>
    <div>
      <h1><?= htmlspecialchars($author['display_name']) ?></h1>
      <p class="byline">
        <span class="muted">@<?= htmlspecialchars($author['username']) ?></span>
        &middot; <a href="mailto:<?= htmlspecialchars($author['email']) ?>"><?= htmlspecialchars($author['email']) ?></a>
        &middot;
        <?php if ($author['role'] === 'admin'): ?>
          <span class="badge role">Portal administrator</span>
        <?php else: ?>
          <span class="badge role">Research staff</span>
        <?php endif; ?>
      </p>
    </div>
  </div>

  <h2>Publications</h2>
  <?php if (!$articles): ?>
    <p class="muted">No published output on file.</p>
  <?php else: ?>
    <ul class="pubs">
      <?php foreach ($articles as $a): ?>
        <li>
          <strong><a href="/article.php?slug=<?= urlencode($a['slug']) ?>">
            <?= htmlspecialchars($a['title']) ?></a></strong>
          <?php if ($a['status'] === 'draft'): ?>
            <span class="badge draft">Draft</span>
          <?php endif; ?>
          <p class="byline">
            <?php if (!empty($a['published_on'])): ?>
              <?= htmlspecialchars(date('F Y', strtotime((string) $a['published_on']))) ?>
            <?php else: ?>
              unpublished
            <?php endif; ?>
          </p>
          <p><?= htmlspecialchars((string) $a['abstract']) ?></p>
        </li>
      <?php endforeach; ?>
    </ul>
  <?php endif; ?>
</section>
<?php render_footer(); ?>
