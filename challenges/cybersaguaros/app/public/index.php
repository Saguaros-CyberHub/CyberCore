<?php
require_once __DIR__ . '/../includes/layout.php';
require_once __DIR__ . '/../includes/db.php';

$datasets = $pdo->query('SELECT name, description FROM datasets ORDER BY id DESC LIMIT 3')
                ->fetchAll();

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

<section>
  <h2>Latest datasets</h2>
  <div class="cards">
    <?php foreach ($datasets as $d): ?>
      <article class="card">
        <h3><?= htmlspecialchars($d['name']) ?></h3>
        <p><?= htmlspecialchars($d['description']) ?></p>
      </article>
    <?php endforeach; ?>
  </div>
</section>

<section class="band fullbleed">
  <div class="wrap">
    <h2>What we do</h2>
    <div class="cards">
      <article class="card plain">
        <h3>Instrument</h3>
        <p>Low-power telemetry on 240+ saguaros across the Sonoran study grid.</p>
      </article>
      <article class="card plain">
        <h3>Model</h3>
        <p>Spine-density and growth-stage classifiers trained on field imagery.</p>
      </article>
      <article class="card plain">
        <h3>Predict</h3>
        <p>The cyber-algorithmic regression pipeline forecasts bloom and growth.</p>
      </article>
      <article class="card plain">
        <h3>Publish</h3>
        <p>Open datasets released for the wider desert-ecology community.</p>
      </article>
    </div>
  </div>
</section>

<section>
  <h2>Field gallery</h2>
  <p>Cactus imagery contributed by field researchers and the public — browse
     the <a href="/gallery.php">CyberSaguaros gallery</a>.</p>
</section>
<?php render_footer(); ?>
