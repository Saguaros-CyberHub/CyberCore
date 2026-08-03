<?php
require_once __DIR__ . '/../includes/layout.php';
require_once __DIR__ . '/../includes/db.php';

// Dataset search.
//
// *** VULNERABILITY: SQL injection ***
// The query parameter is concatenated straight into the SQL string — a
// deliberate injection point (secondary recon path; sqlmap will dump the
// `users` table from here).
//
// *** VULNERABILITY: reflected cross-site scripting (XSS) ***
// $q is echoed back into the response body unencoded — see the "Showing
// results for" paragraph below. Off the critical path: there is no session
// cookie worth stealing here and no victim bot, so it exists purely as a live
// demo target for the XSS lesson. The safe form is htmlspecialchars($q),
// which IS still applied to the <input value> and to the SQL error text.
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

  <?php if ($q !== ''): ?>
    <?php
      // *** VULNERABILITY: reflected XSS sink ***
      // Deliberately NOT htmlspecialchars()'d. Rendered outside the $sqlErr
      // guard on purpose, so quote-bearing payloads — which break the LIKE
      // string above and set $sqlErr — still reflect. Payload:
      //   /research.php?q=<script>alert(1)</script>
    ?>
    <p class="muted">Showing results for "<?= $q ?>".</p>
  <?php endif; ?>

  <?php if ($sqlErr !== null): ?>
    <pre class="dberr"><?= htmlspecialchars($sqlErr) ?></pre>
  <?php endif; ?>

  <?php if ($q !== '' && !$sqlErr): ?>
    <p class="muted"><?= count($rows) ?> result(s).</p>
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
