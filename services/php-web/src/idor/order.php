<?php
// @vuln id=IDOR-001 name="IDOR: any authenticated user can read any order" cwe=CWE-639 owasp=A01:2021 type=idor level=1 param=id method=GET service=php-web url=/php/idor/order.php param_loc=query needs_oob=false auth=true detection=active tags=access-control,idor,api proof_kind=marker proof_desc="Order belonging to another user is returned when its sequential id is requested"

/**
 * IDOR-001: Insecure Direct Object Reference on order lookup.
 * Level: L1 — object ownership is never checked.
 *
 * Precondition: valid session (any user).
 * Payload: ?id=5 (admin's order)
 */

require_once __DIR__ . '/../common/auth.php';
require_once __DIR__ . '/../common/lab.php';

header('Content-Type: application/json');

$user = require_login();
$id   = (int) ($_GET['id'] ?? 1);

$pdo  = get_pdo();
$stmt = $pdo->prepare(
    'SELECT o.id, o.user_id, o.product_id, o.quantity, o.total, o.status, o.created_at,
            u.username
       FROM orders o
       JOIN users u ON u.id = o.user_id
      WHERE o.id = :id'
);
// !! INTENTIONALLY VULNERABLE — no "AND o.user_id = :current_user" clause !!
$stmt->execute([':id' => $id]);
$order = $stmt->fetch();

if (!$order) {
    http_response_code(404);
    echo json_encode(['error' => 'order not found']);
    exit;
}

if ((int) $order['user_id'] !== (int) $user['id']) {
    lab_trigger('IDOR-001', get_request_id(), [
        'order_id' => $id,
        'owner_id' => $order['user_id'],
        'viewer_id' => $user['id'],
    ]);
}

echo json_encode(['order' => $order, 'viewer' => $user['username']]);
