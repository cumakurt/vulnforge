<?php
// @control id=AUTH-001-C twin_of=AUTH-001 url=/php/auth/login_safe.php method=POST param=username service=php-web param_loc=body
// @control id=AUTH-002-C twin_of=AUTH-002 url=/php/auth/login_safe.php method=POST param=PHPSESSID service=php-web param_loc=cookie
// @control id=AUTH-003-C twin_of=AUTH-003 url=/php/auth/login_safe.php method=POST param=username service=php-web param_loc=body

/**
 * AUTH-001-C/002-C/003-C: SAFE —
 *   * prepared statement (no SQL injection),
 *   * session_regenerate_id() after login (no fixation),
 *   * one generic error for both unknown user and wrong password.
 *
 * The seeded MD5 hashes are kept for lab compatibility; the twin still uses a
 * constant-time comparison and never concatenates user input into SQL.
 */

require_once __DIR__ . '/../common/auth.php';

lab_session_start();
header('Content-Type: application/json');

$username = (string) ($_POST['username'] ?? '');
$password = (string) ($_POST['password'] ?? '');

$pdo  = get_pdo();
$stmt = $pdo->prepare('SELECT id, username, role, password FROM users WHERE username = :username');
$stmt->execute([':username' => $username]);
$row = $stmt->fetch();

$valid = $row && (
    hash_equals($row['password'], md5($password))
    || password_verify($password, $row['password'])
);

if ($valid) {
    session_regenerate_id(true);
    $_SESSION['user_id'] = (int) $row['id'];
    echo json_encode(['authenticated' => true, 'username' => $row['username'], 'role' => $row['role']]);
    exit;
}

http_response_code(401);
echo json_encode(['authenticated' => false, 'error' => 'invalid credentials']);
