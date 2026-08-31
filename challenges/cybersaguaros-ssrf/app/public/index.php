<?php
require_once __DIR__ . '/../includes/layout.php';
require_once __DIR__ . '/../includes/db.php';

$datasets = $pdo->query('SELECT name, description FROM datasets ORDER BY id DESC LIMIT 3')
                ->fetchAll();

// Latest published articles for the homepage strip. Drafts never appear here:
// this band is rendered for anonymous visitors.
$latest = $pdo->query(
    "SELECT a.slug, a.title, a.abstract, a.published_on, u.username, u.display_name
       FROM articles a JOIN users u ON u.id = a.author_id
      WHERE a.status = 'published'
      ORDER BY a.published_on DESC, a.id DESC LIMIT 3"
)->fetchAll();

// Pull a few gallery thumbnails for the homepage strip.
$thumbs = [];
$galleryDir = __DIR__ . '/assets/gallery';
if (is_dir($galleryDir)) {
    foreach (scandir($galleryDir) ?: [] as $f) {
        if (preg_match('/\.(svg|png|jpe?g|gif|webp)$/i', $f)) {
            $thumbs[] = $f;
        }
    }
}
$thumbs = array_slice($thumbs, 0, 4);

render_header('Home', '/');
?>
<section class="hero fullbleed">
  <div class="wrap">
    <h1>Applying cyber algorithms to the desert's slowest scientists.</h1>
    <p>The CyberSaguaros Research Group instruments, models, and predicts the
       life of the saguaro cactus. Our pipelines turn decades of slow growth
       into fast, queryable science.</p>
    <p><a class="btn" href="/research.php">Explore the research</a>
       <a class="btn ghost" href="/gallery.php">Open the gallery</a></p>
  </div>
</section>

<section class="fullbleed band-sand">
  <div class="wrap">
    <h2>Latest datasets</h2>
    <div class="cards">
      <?php foreach ($datasets as $d): ?>
        <article class="card">
          <h3><?= htmlspecialchars($d['name']) ?></h3>
          <p><?= htmlspecialchars($d['description']) ?></p>
        </article>
      <?php endforeach; ?>
    </div>
  </div>
</section>

<section class="fullbleed band-deep">
  <div class="wrap">
    <h2>What we do</h2>
    <div class="cards">
      <article class="card plain"><h3>Instrument</h3>
        <p>Low-power telemetry on 240+ saguaros across the Sonoran study grid.</p></article>
      <article class="card plain"><h3>Model</h3>
        <p>Spine-density and growth-stage classifiers trained on field imagery.</p></article>
      <article class="card plain"><h3>Predict</h3>
        <p>The cyber-algorithmic regression pipeline forecasts bloom and growth.</p></article>
      <article class="card plain"><h3>Publish</h3>
        <p>Open datasets released for the wider desert-ecology community.</p></article>
    </div>
  </div>
</section>

<section class="fullbleed band-sand">
  <div class="wrap">
    <h2>Latest publications</h2>
    <p>Peer-reviewed output and working papers from the research group.</p>
    <div class="cards">
      <?php foreach ($latest as $a): ?>
        <article class="card">
          <h3><a href="/article.php?slug=<?= urlencode($a['slug']) ?>">
            <?= htmlspecialchars($a['title']) ?></a></h3>
          <p class="byline">
            <a href="/author.php?u=<?= urlencode($a['username']) ?>">
              <?= htmlspecialchars($a['display_name']) ?></a>
            <span class="muted">@<?= htmlspecialchars($a['username']) ?></span>
            <?php if (!empty($a['published_on'])): ?>
              &middot; <?= htmlspecialchars(date('F Y', strtotime((string) $a['published_on']))) ?>
            <?php endif; ?>
          </p>
          <p><?= htmlspecialchars((string) $a['abstract']) ?></p>
        </article>
      <?php endforeach; ?>
    </div>
    <p><a class="btn" href="/publications.php">All publications</a></p>
  </div>
</section>

<section class="fullbleed band-deep">
  <div class="wrap">
    <h2>Field gallery</h2>
    <p>Saguaro imagery contributed by field researchers across the Sonoran
       study grid.</p>
    <?php if ($thumbs): ?>
      <div class="gallery">
        <?php foreach ($thumbs as $t): ?>
          <figure><a href="/gallery.php">
            <img src="/assets/gallery/<?= rawurlencode($t) ?>" alt="Saguaro"
                 loading="lazy">
          </a></figure>
        <?php endforeach; ?>
      </div>
    <?php endif; ?>
    <p><a class="btn" href="/gallery.php">Browse the full gallery</a></p>
  </div>
</section>

<section class="fullbleed band-green">
  <div class="wrap center">
    <h2>Open desert science</h2>
    <p>CyberSaguaros publishes its datasets and methods for the wider
       desert-ecology community — slow science, made queryable.</p>
    <p><a class="btn" href="/publications.php">Read our publications</a></p>
  </div>
</section>
<?php render_footer(); ?>
