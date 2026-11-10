<?php
// @vuln id=CRYPTO-001 name="Password hashing with unsalted MD5" cwe=CWE-916 owasp=A02:2021 type=weak-password-hash level=1 param=password method=POST service=php-web url=/php/crypto/hash.php param_loc=body needs_oob=false auth=false detection=config tags=crypto,password,hash proof_kind=marker proof_desc="The response contains a bare 32-character MD5 digest for the supplied password"

/**
 * CRYPTO-001: Unsalted MD5 password hashing.
 * Level: L1 (weak algorithm, no salt, no work factor)
 *
 * Payload: POST password=letmein
 * Evidence: response hash equals md5("letmein")
 */

require_once __DIR__ . '/../common/lab.php';

header('Content-Type: application/json');

$password = (string) ($_POST['password'] ?? '');

// !! INTENTIONALLY VULNERABLE — MD5 without salt or stretching !!
$hash = md5($password);

if ($password !== '') {
    lab_trigger('CRYPTO-001', get_request_id(), ['hash' => $hash]);
}

echo json_encode(['algorithm' => 'md5', 'hash' => $hash]);
