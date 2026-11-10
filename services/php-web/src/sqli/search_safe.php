<?php
// @control id=SQLI-002-C twin_of=SQLI-002 url=/php/sqli/search_safe.php method=GET param=q service=php-web param_loc=query

/**
 * SQLI-002-C: SAFE — Parameterized LIKE search
 */

require_once __DIR__ . '/../common/db.php';
header('Content-Type: application/json');

$q = $_GET['q'] ?? '';

$pdo  = get_pdo();
$stmt = $pdo->prepare("SELECT id, name, description, price, category, stock FROM products WHERE name LIKE :q");
$stmt->execute([':q' => '%' . $q . '%']);
$rows = $stmt->fetchAll();

echo json_encode(['results' => $rows]);
