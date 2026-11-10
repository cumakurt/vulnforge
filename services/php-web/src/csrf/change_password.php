<?php
// @vuln id=CSRF-001 name="Password change without CSRF token" cwe=CWE-352 owasp=A01:2021 type=missing-token level=1 param=new_password method=POST service=php-web url=/php/csrf/change_password.php param_loc=body needs_oob=false auth=true detection=active tags=csrf,session proof_kind=marker proof_desc="A cross-site POST changes the victim password because no anti-CSRF token is checked"

/**
 * CSRF-001: Cross-site request forgery on a state-changing action.
 * Level: L1 (no token, no Origin/Referer validation, session cookie accepted)
 *
 * Precondition: victim has an active session.
 */

require_once __DIR__ . '/../common/auth.php';
require_once __DIR__ . '/../common/lab.php';

header('Content-Type: application/json');

$user = require_login();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'POST required']);
    exit;
}

$new_password = (string) ($_POST['new_password'] ?? '');

if (strlen($new_password) < 6) {
    http_response_code(400);
    echo json_encode(['error' => 'password too short']);
    exit;
}

// !! INTENTIONALLY VULNERABLE — no CSRF token validation !!
$pdo  = get_pdo();
$stmt = $pdo->prepare('UPDATE users SET password = :hash WHERE id = :id');
$stmt->execute([
    ':hash' => md5($new_password),
    ':id'   => (int) $user['id'],
]);

lab_trigger('CSRF-001', get_request_id(), ['user_id' => $user['id']]);

echo json_encode(['updated' => true, 'username' => $user['username']]);
