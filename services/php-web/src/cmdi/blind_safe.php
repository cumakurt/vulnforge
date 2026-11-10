<?php
// @control id=CMDI-002-C twin_of=CMDI-002 url=/php/cmdi/blind_safe.php method=GET param=host service=php-web param_loc=query

/**
 * CMDI-002-C: SAFE — hostname allowlist + escapeshellarg(); injected sleep
 * commands never reach the shell, so response timing stays flat.
 */

header('Content-Type: application/json');

$host = $_GET['host'] ?? '127.0.0.1';

if (!preg_match('/^[A-Za-z0-9.\-]{1,253}$/', $host)) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid host']);
    exit;
}

$start = microtime(true);
@shell_exec('echo ' . escapeshellarg($host) . ' >/dev/null 2>&1');
$elapsed = microtime(true) - $start;

echo json_encode(['host' => $host, 'status' => 'checked', 'elapsed' => round($elapsed, 3)]);
