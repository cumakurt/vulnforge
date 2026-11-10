<?php
// @control id=IDOR-001-C twin_of=IDOR-001 url=/php/idor/order_safe.php method=GET param=id service=php-web param_loc=query

/**
 * IDOR-001-C: SAFE — the query is scoped to the authenticated user, so foreign
 * order ids resolve to 404 instead of leaking another user's data.
 */

require_once __DIR__ . '/../common/auth.php';

header('Content-Type: application/json');

$user = require_login();
$id   = (int) ($_GET['id'] ?? 1);

$pdo  = get_pdo();
$stmt = $pdo->prepare(
    'SELECT id, user_id, product_id, quantity, total, status, created_at
       FROM orders
      WHERE id = :id AND user_id = :current_user'
);
$stmt->execute([':id' => $id, ':current_user' => (int) $user['id']]);
$order = $stmt->fetch();

if (!$order) {
    http_response_code(404);
    echo json_encode(['error' => 'order not found']);
    exit;
}

echo json_encode(['order' => $order, 'viewer' => $user['username']]);
