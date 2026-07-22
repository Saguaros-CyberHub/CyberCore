<?php
require_once __DIR__ . '/../includes/layout.php';
require_once __DIR__ . '/../includes/db.php';

// Dataset search. NOTE: the query parameter is concatenated straight into the
// SQL string — a deliberate SQL-injection point (secondary recon path; sqlmap
// will dump the `users` table from here).
$q       = $_GET['q'] ?? '';
$rows    = [];
$sqlErr  = null;
if ($q !== '') {
    $sql = "SELECT name, description, dataset_url, verified
            FROM datasets
            WHERE name LIKE '%$q%' OR description LIKE '%$q%'";
    try {
        $rows = $pdo->query($sql)->fetchAll();
    } catch (Throwable $e) {
        $sqlErr = $e->getMessage();
    }
}

render_header('Research', '/research.php');
?>
<section>
  <h1>Research datasets</h1>
  <p>Search the CyberSaguaros open dataset catalogue.</p>
  <form method="get" class="searchbar">
    <input type="text" name="q" placeholder="e.g. bloom, spine, frost"
           value="<?= htmlspecialchars($q) ?>">
    <button type="submit">Search</button>
  </form>

  <?php if ($sqlErr !== null): ?>
    <pre class="dberr"><?= htmlspecialchars($sqlErr) ?></pre>
  <?php endif; ?>

  <?php if ($q !== '' && !$sqlErr): ?>
    <p class="muted"><?= count($rows) ?> result(s) for
       "<?= htmlspecialchars($q) ?>".</p>
    <table class="data">
      <thead><tr><th>Dataset</th><th>Description</th><th>Status</th></tr></thead>
      <tbody>
      <?php foreach ($rows as $r): ?>
        <tr>
          <td><?= htmlspecialchars($r['name']) ?></td>
          <td><?= htmlspecialchars($r['description']) ?></td>
          <td><?= $r['verified'] ? 'verified' : 'pending' ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  <?php endif; ?>
</section>
<?php render_footer(); ?>
