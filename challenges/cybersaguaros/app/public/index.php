<?php
require_once __DIR__ . '/../includes/layout.php';
require_once __DIR__ . '/../includes/db.php';

$datasets = $pdo->query('SELECT name, description FROM datasets ORDER BY id DESC LIMIT 3')
                ->fetchAll();

render_header('Home', '/');
?>
<section class="hero">
  <h1>Applying cyber algorithms to the desert's slowest scientists.</h1>
  <p>The CyberSaguaros Research Group instruments, models, and predicts the
     life of the saguaro cactus. Our pipelines turn decades of slow growth into
     fast, queryable science.</p>
  <p><a class="btn" href="/research.php">Explore the research</a>
     <a class="btn ghost" href="/chat.php">Ask SaguaroBot</a></p>
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

<section class="split">
  <div>
    <h2>SaguaroBot</h2>
    <p>Our research assistant answers questions about the project and will
       <strong>verify the integrity of any dataset you submit</strong> — just
       give it a URL and it fetches the file to check it. Visiting researchers
       use it constantly.</p>
    <p><a href="/chat.php">Open SaguaroBot &rarr;</a></p>
  </div>
  <div>
    <h2>Field gallery</h2>
    <p>Cactus imagery contributed by field researchers and the public.
       Browse the <a href="/gallery.php">gallery</a> or, if you have a
       researcher account, sign in to contribute.</p>
  </div>
</section>
<?php render_footer(); ?>
