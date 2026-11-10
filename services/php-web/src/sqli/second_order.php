<?php
// @vuln id=SQLI-006 name="Second-order SQL Injection in user password change" cwe=CWE-89 owasp=A03:2021 type=second-order level=3 param=username method=POST service=php-web url=/php/sqli/second_order.php param_loc=body needs_oob=false auth=false detection=active tags=injection,database,mysql,second-order proof_kind=marker proof_desc="Payload stored through a prepared INSERT is later spliced unescaped into an UPDATE"

/**
 * SQLI-006: Second-order SQL Injection
 * Level: L3 — the write path is safe; the read-then-write path is not.
 *
 * Step 1 (store):  POST ?action=register username=admin'-- password=x
 * Step 2 (trigger): POST ?action=change_password username=admin'-- new_password=owned
 *
 * Evidence: the UPDATE statement targets the admin account and the executed
 * query is echoed in the response.
 */

require_once __DIR__ . '/../common/db.php';
require_once __DIR__ . '/../common/lab.php';

header('Content-Type: application/json');

$action = $_GET['action'] ?? 'register';
$conn   = get_db();

if ($action === 'register') {
    $username = (string) ($_POST['username'] ?? 'newuser');
    $password = md5((string) ($_POST['password'] ?? 'password'));

    // Write path is safe: prepared statement stores the raw value.
    $stmt = $conn->prepare('INSERT INTO users (username, password, email) VALUES (?, ?, ?)');
    $email = 'second@order.test';
    $stmt->bind_param('sss', $username, $password, $email);

    if (!$stmt->execute()) {
        echo json_encode(['error' => $conn->error]);
        exit;
    }

    echo json_encode(['registered' => true, 'username_stored' => $username]);
    exit;
}

if ($action === 'change_password') {
    $username = (string) ($_POST['username'] ?? '');
    $new_pass = md5((string) ($_POST['new_password'] ?? 'newpass'));

    // Safe lookup by the exact stored username.
    $lookup = $conn->prepare('SELECT username FROM users WHERE username = ?');
    $lookup->bind_param('s', $username);
    $lookup->execute();
    $row = $lookup->get_result()->fetch_assoc();

    if (!$row) {
        echo json_encode(['error' => 'User not found']);
        exit;
    }

    // !! INTENTIONALLY VULNERABLE — stored value is trusted in a new query !!
    $stored_username = $row['username'];
    $sql = "UPDATE users SET password = '$new_pass' WHERE username = '$stored_username'";
    $conn->query($sql);

    lab_trigger('SQLI-006', get_request_id(), ['stored_username' => $stored_username]);
    echo json_encode(['updated' => $conn->affected_rows, 'executed_query' => $sql]);
    exit;
}

http_response_code(400);
echo json_encode(['error' => 'unknown action']);
