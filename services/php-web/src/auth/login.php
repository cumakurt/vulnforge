<?php
// @vuln id=AUTH-001 name="SQL injection authentication bypass" cwe=CWE-89 owasp=A07:2021 type=auth-bypass level=2 param=username method=POST service=php-web url=/php/auth/login.php param_loc=body needs_oob=false auth=false detection=active tags=auth,sqli,login proof_kind=marker proof_desc="Username payload such as admin'-- logs in without the correct password"
// @vuln id=AUTH-002 name="Session fixation in login flow" cwe=CWE-384 owasp=A07:2021 type=session-fixation level=2 param=PHPSESSID method=POST service=php-web url=/php/auth/login.php param_loc=cookie needs_oob=false auth=false detection=passive tags=auth,session,fixation proof_kind=marker proof_desc="Pre-set session cookie remains valid after successful authentication"
// @vuln id=AUTH-003 name="Username enumeration through distinct login errors" cwe=CWE-204 owasp=A07:2021 type=user-enumeration level=1 param=username method=POST service=php-web url=/php/auth/login.php param_loc=body needs_oob=false auth=false detection=passive tags=auth,enumeration,info-leak proof_kind=marker proof_desc="'Unknown user' and 'wrong password' responses are distinguishable"

/**
 * AUTH-001: SQL injection in the login query.
 * AUTH-002: The session ID is never rotated after authentication.
 * AUTH-003: Error messages disclose whether a username exists.
 * Level: L1/L2
 *
 * Login:       username=alice&password=password1
 * SQLi bypass: username=admin'--&password=x
 */

require_once __DIR__ . '/../common/auth.php';
require_once __DIR__ . '/../common/lab.php';

lab_session_start();
header('Content-Type: application/json');

$username = (string) ($_POST['username'] ?? '');
$password = (string) ($_POST['password'] ?? '');
$conn     = get_db();

// !! INTENTIONALLY VULNERABLE — raw concatenation in the credential query !!
$sql    = "SELECT id, username, role FROM users WHERE username = '$username' AND password = MD5('$password')";
$result = @$conn->query($sql);

if ($conn->error) {
    lab_trigger('AUTH-001', get_request_id(), ['payload' => $username]);
    echo json_encode(['error' => 'database error']);
    exit;
}

$row = $result ? $result->fetch_assoc() : null;

if ($row) {
    // !! AUTH-002: session ID is not regenerated on privilege change !!
    $_SESSION['user_id'] = (int) $row['id'];
    echo json_encode(['authenticated' => true, 'username' => $row['username'], 'role' => $row['role']]);
    exit;
}

// !! AUTH-003: response distinguishes unknown user from wrong password !!
$exists = $conn->query("SELECT id FROM users WHERE username = '$username'")->num_rows > 0;
$message = $exists ? 'wrong password' : 'unknown user';

if (preg_match("/['\"]|\\bOR\\b|\\bUNION\\b/i", $username)) {
    lab_trigger('AUTH-001', get_request_id(), ['payload' => $username]);
}
if ($exists) {
    lab_trigger('AUTH-003', get_request_id(), ['payload' => $username]);
}

echo json_encode(['authenticated' => false, 'error' => $message]);
