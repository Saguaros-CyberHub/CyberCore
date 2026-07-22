<?php
// ============================================================================
// CyberSaguaros — internal admin-session provisioning API
// ============================================================================
// Used by on-host automation (backup jobs, the dataset reviewer cron) to
// obtain a working admin session without an interactive login.
//
// nginx restricts the entire /api/internal/ path to 127.0.0.1, so the team
// considers this endpoint "safe to leave unauthenticated." It is reachable
// from loopback only — which is exactly what the SaguaroBot SSRF provides.
// ============================================================================
require_once __DIR__ . '/../../../includes/db.php';
header('Content-Type: application/json');

$token = bin2hex(random_bytes(24));
$stmt  = $pdo->prepare(
    'INSERT INTO admin_sessions (token, label, expires_at)
     VALUES (?, ?, NOW() + INTERVAL 7 DAY)'
);
$stmt->execute([$token, 'provisioned via /api/internal']);

echo json_encode([
    'service'       => 'cybersaguaros-internal-provisioning',
    'admin_session' => $token,
    'usage'         => 'Set cookie  admin_session=<token>  to access /admin/.',
    'expires_in'    => '7 days',
], JSON_PRETTY_PRINT);
