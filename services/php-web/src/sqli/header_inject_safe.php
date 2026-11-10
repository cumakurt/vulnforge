<?php
// @control id=SQLI-007-C twin_of=SQLI-007 url=/php/sqli/header_inject_safe.php method=GET param=X-Forwarded-For service=php-web param_loc=header

/**
 * SQLI-007-C: SAFE — the header value is validated and written with a prepared
 * statement. No part of the header reaches the SQL text.
 */

require_once __DIR__ . '/../common/db.php';
header('Content-Type: application/json');

$ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

// Only a literal IPv4/IPv6 address is accepted.
if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid forwarding address']);
    exit;
}

$pdo  = get_pdo();
$stmt = $pdo->prepare('INSERT INTO sessions (id, data) VALUES (:id, :data) ON DUPLICATE KEY UPDATE data = :data2');
$stmt->execute([
    ':id'    => bin2hex(random_bytes(16)),
    ':data'  => 'ip=' . $ip,
    ':data2' => 'ip=' . $ip,
]);

echo json_encode(['logged' => true, 'ip' => $ip]);
