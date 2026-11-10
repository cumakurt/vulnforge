<?php
// @control id=SQLI-004-C twin_of=SQLI-004 url=/php/sqli/time_blind_safe.php method=GET param=id service=php-web param_loc=query

/**
 * SQLI-004-C: SAFE — prepared statement; injected SLEEP() is treated as data
 * and cannot introduce a delay.
 */

require_once __DIR__ . '/../common/db.php';
header('Content-Type: application/json');

$id   = $_GET['id'] ?? '1';
$pdo  = get_pdo();
$stmt = $pdo->prepare('SELECT id, name FROM products WHERE id = :id');
$stmt->execute([':id' => (int) $id]);

echo json_encode(['product' => $stmt->fetch() ?: null]);
