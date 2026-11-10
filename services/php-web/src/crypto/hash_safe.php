<?php
// @control id=CRYPTO-001-C twin_of=CRYPTO-001 url=/php/crypto/hash_safe.php method=POST param=password service=php-web param_loc=body

/**
 * CRYPTO-001-C: SAFE — bcrypt with a per-password random salt (cost 12).
 */

header('Content-Type: application/json');

$password = (string) ($_POST['password'] ?? '');

if ($password === '') {
    http_response_code(400);
    echo json_encode(['error' => 'password required']);
    exit;
}

$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

echo json_encode(['algorithm' => 'bcrypt', 'hash' => $hash]);
