<?php
// @control id=AUTH-004-C twin_of=AUTH-004 url=/php/auth/logout_safe.php method=GET param=PHPSESSID service=php-web param_loc=cookie

/**
 * AUTH-004-C: SAFE — logout destroys the session data, expires the cookie and
 * rotates the session ID, so a replayed cookie no longer authenticates.
 */

require_once __DIR__ . '/../common/auth.php';

lab_session_start();
header('Content-Type: application/json');

$old_session_id = session_id();

$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 3600, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
}
session_destroy();

echo json_encode(['logged_out' => true, 'invalidated_session_id' => $old_session_id]);
