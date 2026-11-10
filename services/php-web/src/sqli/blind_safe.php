<?php
// @control id=SQLI-003-C twin_of=SQLI-003 url=/php/sqli/blind_safe.php method=GET param=id service=php-web param_loc=query

require_once __DIR__ . '/../common/db.php';
header('Content-Type: application/json');

$id  = $_GET['id'] ?? '1';
$pdo = get_pdo();
$stmt = $pdo->prepare("SELECT id, name, description, price FROM products WHERE id = :id");
$stmt->execute([':id' => (int)$id]);
echo json_encode(['product' => $stmt->fetch() ?: null]);
