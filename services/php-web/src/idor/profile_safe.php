<?php
// @control id=IDOR-002-C twin_of=IDOR-002 url=/php/idor/profile_safe.php method=GET param=user_id service=php-web param_loc=query

/**
 * IDOR-002-C: SAFE — the object id is always derived from the session; any
 * client-supplied user_id is ignored.
 */

require_once __DIR__ . '/../common/auth.php';

header('Content-Type: application/json');

$user = require_login();

$pdo  = get_pdo();
$stmt = $pdo->prepare('SELECT id, username, email, role, created_at FROM users WHERE id = :id');
$stmt->execute([':id' => (int) $user['id']]);
$profile = $stmt->fetch();

echo json_encode(['profile' => $profile]);
