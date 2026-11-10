<?php
// @control id=SQLI-005-C twin_of=SQLI-005 url=/php/sqli/order_safe.php method=GET param=sort service=php-web param_loc=query

require_once __DIR__ . '/../common/db.php';
header('Content-Type: application/json');

// SAFE: Whitelist allowed sort columns
$allowed_sorts = ['id', 'name', 'price', 'category', 'stock'];
$sort = in_array($_GET['sort'] ?? 'id', $allowed_sorts) ? $_GET['sort'] : 'id';

$pdo  = get_pdo();
$stmt = $pdo->query("SELECT id, name, price, category FROM products ORDER BY $sort");
echo json_encode(['products' => $stmt->fetchAll()]);
