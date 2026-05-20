<?php
require_once __DIR__ . '/../includes/layout.php';
render_header('Publications', '/publications.php');

$papers = [
    ['Cyber-Algorithmic Growth Curves for Carnegiea gigantea',
     'Wagner, P. &amp; Green, R.', 2025,
     'A regression pipeline that fits multi-decade saguaro growth from sparse telemetry.'],
    ['SaguaroNet: Spine-Density Classification from Field Imagery',
     'Valmont, D.', 2025,
     'A convolutional classifier for estimating spine density and plant age.'],
    ['Frost-Stress Signatures in Thermal Saguaro Imagery',
     'Green, R. &amp; Wagner, P.', 2024,
     'Detecting and grading winter frost-stress events across the study grid.'],
    ['Bloom-Timing Prediction under Monsoon Variability',
     'Wagner, P.', 2024,
     'Forecasting bloom onset from soil-moisture and temperature telemetry.'],
];
?>
<section>
  <h1>Publications</h1>
  <p>Selected output from the CyberSaguaros Research Group.</p>
  <ul class="pubs">
    <?php foreach ($papers as $p): ?>
      <li>
        <strong><?= $p[0] ?></strong><br>
        <span class="muted"><?= $p[1] ?> &middot; <?= $p[2] ?></span>
        <p><?= $p[3] ?></p>
      </li>
    <?php endforeach; ?>
  </ul>
</section>
<?php render_footer(); ?>
