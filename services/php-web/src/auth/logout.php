<?php
// @vuln id=AUTH-004 name="Logout does not invalidate the server-side session" cwe=CWE-613 owasp=A07:2021 type=insufficient-logout level=2 param=PHPSESSID method=GET service=php-web url=/php/auth/logout.php param_loc=cookie needs_oob=false auth=true detection=passive tags=auth,session,logout proof_kind=marker proof_desc="Replaying the captured session cookie after logout still grants access"

/**
 * AUTH-004: Logout only clears the client-side identity flag; the session ID
 * stays valid on the server, so a stolen cookie can be replayed.
 * Level: L2
 */

require_once __DIR__ . '/../common/auth.php';
require_once __DIR__ . '/../common/lab.php';

lab_session_start();
header('Content-Type: application/json');

$user = current_user();

// !! INTENTIONALLY VULNERABLE — only the client-side cookie is cleared; the
// server-side session remains valid and can be replayed.
setcookie(session_name(), '', time() - 3600, '/');

if ($user !== null) {
    lab_trigger('AUTH-004', get_request_id(), ['user_id' => $user['id'], 'session_id' => session_id()]);
}

echo json_encode(['logged_out' => true, 'session_id' => session_id()]);
