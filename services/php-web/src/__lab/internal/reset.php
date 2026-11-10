<?php
/**
 * Internal reset endpoint — called by lab-control, never exposed through the
 * scanner-facing gateway (the gateway has no /__lab/ location).
 *
 * Restores every mutable table to the baseline defined by db/seed.sql.
 */

require_once __DIR__ . '/../../common/db.php';

header('Content-Type: application/json');

$seed_file = '/var/www/db/seed.sql';

if (!is_readable($seed_file)) {
    http_response_code(500);
    echo json_encode(['error' => 'seed file not available']);
    exit;
}

$sql = file_get_contents($seed_file);

// The baseline file is written for MySQL's init hook, which runs as root.
// The application user cannot create databases, so strip those statements.
$sql = preg_replace('/^\s*(?:CREATE\s+DATABASE|USE)\b[^;]*;\s*$/mi', '', $sql);

$conn = get_db();

$tables = [
    'comments', 'orders', 'uploads', 'sessions', 'password_resets',
    'csrf_tokens', 'products', 'users',
];

$conn->query('SET FOREIGN_KEY_CHECKS = 0');
foreach ($tables as $table) {
    if (!$conn->query("TRUNCATE TABLE `$table`")) {
        http_response_code(500);
        echo json_encode(['error' => "truncate failed for $table", 'detail' => $conn->error]);
        exit;
    }
}
$conn->query('SET FOREIGN_KEY_CHECKS = 1');

if (!$conn->multi_query($sql)) {
    http_response_code(500);
    echo json_encode(['error' => 'seed execution failed', 'detail' => $conn->error]);
    exit;
}
while ($conn->more_results() && $conn->next_result()) {
    // Drain result sets produced by multi_query.
}

echo json_encode(['reset' => true, 'tables' => $tables]);
