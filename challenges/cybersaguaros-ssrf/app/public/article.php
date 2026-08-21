<?php
// ============================================================================
// A single article.
// ============================================================================
// Prepared lookup by slug. This page is deliberately NOT a second injection
// sink — /research.php is the one SQLi surface in this app and the bake
// asserts it there.
// ============================================================================
require_once __DIR__ . '/../includes/layout.php';   // pulls auth.php -> db.php

$slug = $_GET['slug'] ?? '';
$stmt = $pdo->prepare(
    'SELECT a.slug, a.title, a.abstract, a.body, a.co_authors, a.published_on,
            a.status, u.username, u.display_name
       FROM articles a
       JOIN users u ON u.id = a.author_id
      WHERE a.slug = ?'
);
$stmt->execute([$slug]);
$article = $stmt->fetch() ?: null;

$signedIn = current_researcher() !== null;
$locked   = $article && $article['status'] === 'draft' && !$signedIn;

if (!$article) {
    http_response_code(404);
    render_header('Article not found', '/publications.php');
    echo '<section class="narrow"><h1>Article not found</h1>'
       . '<p class="muted">No article matches that address. '
       . '<a href="/publications.php">Back to publications</a>.</p></section>';
    render_footer();
    exit;
}

if ($locked) {
    // Deliberately a 403 that ADVERTISES itself rather than a 404 that hides.
    // The point of gating drafts is that a student can see there is something
    // behind the portal login and go looking for credentials.
    http_response_code(403);
    render_header($article['title'], '/publications.php');
    ?>
    <section class="narrow">
      <h1><?= htmlspecialchars($article['title']) ?></h1>
      <p class="notice">This is an unpublished working paper. Sign in with a
         CyberSaguaros portal account to read it.</p>
      <p><a class="btn" href="/login.php">Researcher sign-in</a></p>
    </section>
    <?php
    render_footer();
    exit;
}

render_header($article['title'], '/publications.php');
?>
<section>
  <article class="paper">
    <h1><?= htmlspecialchars($article['title']) ?>
      <?php if ($article['status'] === 'draft'): ?>
        <span class="badge draft">Draft</span>
      <?php endif; ?>
    </h1>
    <p class="byline">
      <a href="/author.php?u=<?= urlencode($article['username']) ?>">
        <?= htmlspecialchars($article['display_name']) ?></a>
      <span class="muted">@<?= htmlspecialchars($article['username']) ?></span>
      <?php if (!empty($article['co_authors'])): ?>
        &middot; with <?= htmlspecialchars($article['co_authors']) ?>
      <?php endif; ?>
      <?php if (!empty($article['published_on'])): ?>
        &middot; <?= htmlspecialchars(date('j F Y', strtotime((string) $article['published_on']))) ?>
      <?php else: ?>
        &middot; unpublished working paper
      <?php endif; ?>
    </p>

    <p class="abstract"><?= htmlspecialchars((string) $article['abstract']) ?></p>

    <?php
      // htmlspecialchars FIRST, then nl2br. Reversed, the escaping would eat
      // the <br> tags nl2br just inserted.
    ?>
    <div class="paper-body">
      <p><?= nl2br(htmlspecialchars((string) $article['body'])) ?></p>
    </div>

    <p><a href="/publications.php">&larr; All publications</a></p>
  </article>
</section>
<?php render_footer(); ?>
