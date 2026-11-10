<?php
// @control id=CSRF-001-C twin_of=CSRF-001 url=/php/csrf/change_password_safe.php method=POST param=new_password service=php-web param_loc=body

/**
 * CSRF-001-C: SAFE — a per-session token is required and verified with
 * hash_equals(). The token is issued by csrf_token() and must be sent in the
 * "csrf_token" form field.
 */

require_once __DIR__ . '/../common/auth.php';
require_once __DIR__ . '/../common/csrf.php';

header('Content-Type: application/json');

$user = require_login();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'POST required']);
    exit;
}

if (!csrf_is_valid($_POST['csrf_token'] ?? null)) {
    http_response_code(403);
    echo json_encode(['error' => 'invalid csrf token', 'expected_field' => 'csrf_token']);
    exit;
}

$new_password = (string) ($_POST['new_password'] ?? '');

if (strlen($new_password) < 6) {
    http_response_code(400);
    echo json_encode(['error' => 'password too short']);
    exit;
}

$pdo  = get_pdo();
$stmt = $pdo->prepare('UPDATE users SET password = :hash WHERE id = :id');
$stmt->execute([
    ':hash' => password_hash($new_password, PASSWORD_BCRYPT),
    ':id'   => (int) $user['id'],
]);

echo json_encode(['updated' => true, 'username' => $user['username']]);
