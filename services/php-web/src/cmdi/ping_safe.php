<?php
// @control id=CMDI-001-C twin_of=CMDI-001 url=/php/cmdi/ping_safe.php method=GET param=host service=php-web param_loc=query

/**
 * CMDI-001-C: SAFE — input is validated against a hostname whitelist and then
 * escaped with escapeshellarg(). Shell metacharacters have no effect.
 */

header('Content-Type: application/json');

$host = $_GET['host'] ?? '127.0.0.1';

// SAFE: strict whitelist first, escaping second (defence in depth).
if (!preg_match('/^[A-Za-z0-9.\-]{1,253}$/', $host)) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid host']);
    exit;
}

$output = shell_exec('echo ' . escapeshellarg($host) . ' 2>&1');
echo json_encode(['host' => $host, 'output' => $output]);
