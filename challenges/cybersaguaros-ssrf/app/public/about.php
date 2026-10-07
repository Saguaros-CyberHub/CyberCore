<?php
require_once __DIR__ . '/../includes/layout.php';
render_header('About', '/about.php');
?>
<section>
  <h1>About CyberSaguaros</h1>
  <p>CyberSaguaros is a cactus research group operating out of a field station
     in the Sonoran Desert. We pair long-baseline botanical fieldwork with
     modern computational methods — "cyber algorithms", as our founder insists
     on calling them — to model how saguaros grow, bloom, and respond to a
     changing climate.</p>

  <h2>What we do</h2>
  <ul>
    <li>Instrument saguaros with low-power telemetry and collect bloom data.</li>
    <li>Train growth-stage and spine-density classifiers on field imagery.</li>
    <li>Run the cyber-algorithmic regression pipeline that fits growth curves.</li>
    <li>Publish open datasets for the wider desert-ecology community.</li>
  </ul>

  <h2>The team</h2>
  <p>The portal is maintained by our research staff. Dataset submissions and
     integrity checks are handled by <strong>SaguaroBot</strong>, our automated
     research assistant. For portal access issues, contact the site
     administrator, Dr. Paul Wagner.</p>

  <h2>Contact</h2>
  <p>Sonoran Desert Field Station &middot; cybersaguaros.local</p>
</section>
<?php render_footer(); ?>
