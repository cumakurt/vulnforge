<?php
// Health check endpoint
header('Content-Type: application/json');

$db_ok = false;
try {
    $pdo = new PDO(
        "mysql:host={$_ENV['MYSQL_HOST']};dbname={$_ENV['MYSQL_DATABASE']}",
        $_ENV['MYSQL_USER'],
        $_ENV['MYSQL_PASSWORD']
    );
    $pdo->query("SELECT 1");
    $db_ok = true;
} catch (Exception $e) {
    // ignore
}

http_response_code($db_ok ? 200 : 503);
echo json_encode([
    'status'  => $db_ok ? 'ok' : 'degraded',
    'service' => 'php-web',
    'db'      => $db_ok ? 'up' : 'down',
]);
