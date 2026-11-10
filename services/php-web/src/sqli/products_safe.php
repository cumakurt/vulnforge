<?php
// @control id=SQLI-001-C twin_of=SQLI-001 url=/php/sqli/products_safe.php method=GET param=id service=php-web param_loc=query

/**
 * SQLI-001-C: SAFE CONTROL TWIN — Parameterized query, no error disclosure
 * Demonstrates correct implementation: prepared statement + generic errors.
 */

require_once __DIR__ . '/../common/db.php';

header('Content-Type: application/json');

$id = $_GET['id'] ?? '1';

// SAFE: Parameterized query via PDO
$pdo  = get_pdo();
$stmt = $pdo->prepare("SELECT id, name, description, price, category, stock FROM products WHERE id = :id");
$stmt->execute([':id' => (int)$id]);
$rows = $stmt->fetchAll();

echo json_encode(['products' => $rows]);
