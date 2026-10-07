<?php
// ============================================================================
// Publications — the article index.
// ============================================================================
// Bylines link through to the author pages. The naming convention is not
// uniform: most accounts are finitial+lastname, but not all of them.
//
// Drafts are visible to any signed-in portal account, published pieces to
// everyone.
// ============================================================================
require_once __DIR__ . '/../includes/layout.php';   // pulls auth.php -> db.php

$showDrafts = current_researcher() !== null;

// Two literal query strings selected by a bool. Nothing user-supplied is
// concatenated.
$sql = 'SELECT a.slug, a.title, a.abstract, a.published_on, a.status,
               a.co_authors, u.username, u.display_name
          FROM articles a
          JOIN users u ON u.id = a.author_id';
if (!$showDrafts) {
    $sql .= " WHERE a.status = 'published'";
}
$sql .= " ORDER BY (a.status = 'draft') DESC, a.published_on DESC, a.id DESC";
$stmt = $pdo->prepare($sql);
$stmt->execute();
$articles = $stmt->fetchAll();

render_header('Publications', '/publications.php');
?>
<section>
  <h1>Publications</h1>
  <p>Selected output from the CyberSaguaros Research Group.</p>

  <?php if (!$showDrafts): ?>
    <p class="notice">Working papers and internal notes are visible to
       signed-in research staff. <a href="/login.php">Sign in</a> to read them.</p>
  <?php endif; ?>

  <ul class="pubs">
    <?php foreach ($articles as $a): ?>
      <li>
        <strong><a href="/article.php?slug=<?= urlencode($a['slug']) ?>">
          <?= htmlspecialchars($a['title']) ?></a></strong>
        <?php if ($a['status'] === 'draft'): ?>
          <span class="badge draft">Draft</span>
        <?php endif; ?>
        <p class="byline">
          <a href="/author.php?u=<?= urlencode($a['username']) ?>">
            <?= htmlspecialchars($a['display_name']) ?></a>
          <span class="muted">@<?= htmlspecialchars($a['username']) ?></span>
          <?php if (!empty($a['co_authors'])): ?>
            &middot; with <?= htmlspecialchars($a['co_authors']) ?>
          <?php endif; ?>
          <?php if (!empty($a['published_on'])): ?>
            &middot; <?= htmlspecialchars(date('F Y', strtotime((string) $a['published_on']))) ?>
          <?php else: ?>
            &middot; unpublished
          <?php endif; ?>
        </p>
        <p><?= htmlspecialchars((string) $a['abstract']) ?></p>
      </li>
    <?php endforeach; ?>
  </ul>
</section>
<?php render_footer(); ?>
