<?php
// @vuln id=IDOR-002 name="IDOR: profile endpoint exposes arbitrary user records" cwe=CWE-639 owasp=A01:2021 type=idor level=1 param=user_id method=GET service=php-web url=/php/idor/profile.php param_loc=query needs_oob=false auth=true detection=active tags=access-control,idor,data-exposure proof_kind=marker proof_desc="Requesting another user's id returns their email and role"

/**
 * IDOR-002: Insecure Direct Object Reference on user profiles.
 * Level: L1
 *
 * Payload: ?user_id=1 (admin profile)
 */

require_once __DIR__ . '/../common/auth.php';
require_once __DIR__ . '/../common/lab.php';

header('Content-Type: application/json');

$user    = require_login();
$user_id = (int) ($_GET['user_id'] ?? $user['id']);

$pdo  = get_pdo();
$stmt = $pdo->prepare('SELECT id, username, email, role, created_at FROM users WHERE id = :id');
// !! INTENTIONALLY VULNERABLE — caller controls the object id !!
$stmt->execute([':id' => $user_id]);
$profile = $stmt->fetch();

if (!$profile) {
    http_response_code(404);
    echo json_encode(['error' => 'user not found']);
    exit;
}

if ((int) $profile['id'] !== (int) $user['id']) {
    lab_trigger('IDOR-002', get_request_id(), [
        'target_user' => $profile['id'],
        'viewer_id'   => $user['id'],
    ]);
}

echo json_encode(['profile' => $profile]);
