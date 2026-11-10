<?php
// @control id=SQLI-006-C twin_of=SQLI-006 url=/php/sqli/second_order_safe.php method=POST param=username service=php-web param_loc=body

/**
 * SQLI-006-C: SAFE — the same two-step flow, but both the INSERT and the later
 * UPDATE use prepared statements. Stored metacharacters stay inert.
 */

require_once __DIR__ . '/../common/db.php';
header('Content-Type: application/json');

$action = $_GET['action'] ?? 'register';
$pdo    = get_pdo();

if ($action === 'register') {
    $username = (string) ($_POST['username'] ?? 'newuser');
    $password = password_hash((string) ($_POST['password'] ?? 'password'), PASSWORD_BCRYPT);

    $stmt = $pdo->prepare("INSERT INTO users (username, password, email) VALUES (:username, :password, 'second@order.test')");
    $stmt->execute([':username' => $username, ':password' => $password]);

    echo json_encode(['registered' => true, 'username_stored' => $username]);
    exit;
}

if ($action === 'change_password') {
    $username = (string) ($_POST['username'] ?? '');
    $new_hash = password_hash((string) ($_POST['new_password'] ?? 'newpass'), PASSWORD_BCRYPT);

    $lookup = $pdo->prepare('SELECT id FROM users WHERE username = :username');
    $lookup->execute([':username' => $username]);
    $row = $lookup->fetch();

    if (!$row) {
        echo json_encode(['error' => 'User not found']);
        exit;
    }

    $update = $pdo->prepare('UPDATE users SET password = :password WHERE id = :id');
    $update->execute([':password' => $new_hash, ':id' => (int) $row['id']]);

    echo json_encode(['updated' => $update->rowCount()]);
    exit;
}

http_response_code(400);
echo json_encode(['error' => 'unknown action']);
