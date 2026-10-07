<%@ Page Language="C#" %>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FieldOps :: Copper Ridge Mining &amp; Aggregate</title>
<link rel="stylesheet" href="/assets/fieldops.css" />
</head><body>

<div class="topbar">
  <div class="inner">
    <div>
      <span class="brand">Copper Ridge</span>
      <span class="brandsub">Mining &amp; Aggregate</span>
    </div>
    <div class="topnav"><a href="/Login.aspx">Employee Sign In</a></div>
  </div>
</div>

<div class="strip">
  <div class="inner">
    <span><b>FIELDOPS</b> Equipment Maintenance &amp; Dispatch</span>
    <span>Pit 4 &middot; Shift B &middot; Node TUC-WEB01</span>
  </div>
</div>

<div class="wrap">

  <div class="panel">
    <h2>Notice to Field Personnel</h2>
    <div class="body">
      <p>FieldOps is the system of record for equipment downtime, preventive maintenance
         intervals, and haul fleet dispatch. All unplanned downtime must be logged before
         end of shift &mdash; do not hold entries for the morning handover.</p>
      <p>Mechanics uploading component failure photographs should include the unit number
         in the filename (for example <span class="mono">HT-214-frontidler.jpg</span>).</p>
    </div>
  </div>

  <div class="panel">
    <h2>Operations Status</h2>
    <div class="body">
      <table class="grid">
        <tr><th>System</th><th>State</th><th>Last Check</th></tr>
        <tr><td>Haul Fleet Telemetry</td><td class="ok">ONLINE</td><td class="mono">02:14</td></tr>
        <tr><td>Crusher Line 2 PLC Gateway</td><td class="ok">ONLINE</td><td class="mono">02:14</td></tr>
        <tr><td>Scale House Interface</td><td class="ok">ONLINE</td><td class="mono">02:14</td></tr>
        <tr><td>Assay Lab LIMS Bridge</td><td class="warn">DEGRADED</td><td class="mono">01:48</td></tr>
        <tr><td>Nightly Config Backup</td><td class="ok">COMPLETE</td><td class="mono">02:15</td></tr>
      </table>
    </div>
  </div>

  <div class="panel">
    <h2>Support</h2>
    <div class="body">
      <p>Portal access, password resets, and handheld provisioning go through the IT desk
         at extension <b>2280</b>. Do not call the dispatch line for account problems.</p>
      <p class="muted">Contractor and partner access is arranged through the site IT
         coordinator. Copper Ridge does not extend domain accounts to partner
         organisations.</p>
      <!-- TODO(dmercer): the nightly config dump under /backup is world readable on the
           site LAN. Raised with IT as CR-3318, no movement in two quarters. -->
    </div>
  </div>

</div>

<div class="foot">
  Copper Ridge Mining &amp; Aggregate &mdash; FieldOps <span class="mono">v3.1.4</span><br>
  TUC-WEB01 &middot; ASP.NET <%= Environment.Version.ToString() %> &middot; IIS/10.0 &middot;
  &copy; 2016&ndash;2024 Copper Ridge Mining &amp; Aggregate, Pima County AZ
</div>

</body></html>
