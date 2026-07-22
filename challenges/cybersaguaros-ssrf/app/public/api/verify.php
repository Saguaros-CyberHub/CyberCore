<?php
// ============================================================================
// SaguaroBot — dataset integrity verification
// ============================================================================
// The bot fetches the researcher-supplied dataset URL server-side to check
// it before review.
//
// *** VULNERABILITY: Server-Side Request Forgery ***
// There is no scheme or host allowlist. The fetch runs from the web server,
// so any URL the caller supplies is requested with the server's network
// position — including loopback and internal-only services. The response
// body snippet is returned to the caller, making this a fully readable SSRF.
// ============================================================================
header('Content-Type: application/json');

$url = $_REQUEST['url'] ?? '';
if ($url === '') {
    http_response_code(400);
    echo json_encode(['error' => 'A dataset URL is required.']);
    exit;
}

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL            => $url,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS      => 5,
    CURLOPT_TIMEOUT        => 6,
    CURLOPT_CONNECTTIMEOUT => 5,
    CURLOPT_USERAGENT      => 'SaguaroBot-IntegrityCheck/1.0',
]);
$body = curl_exec($ch);

if ($body === false) {
    echo json_encode([
        'ok'    => false,
        'url'   => $url,
        'error' => 'SaguaroBot could not fetch the dataset: ' . curl_error($ch),
    ]);
    curl_close($ch);
    exit;
}

$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$ctype  = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
curl_close($ch);

echo json_encode([
    'ok'           => true,
    'url'          => $url,
    'status'       => $status,
    'content_type' => $ctype,
    'size'         => strlen($body),
    'sha256'       => hash('sha256', $body),
    'snippet'      => substr($body, 0, 1024),
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
