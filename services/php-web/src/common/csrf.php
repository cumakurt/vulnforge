<?php
/**
 * VulnForge Lab — CSRF token helpers used by the safe control twin.
 *
 * The token is kept in the session and compared in constant time. The
 * intentionally vulnerable CSRF endpoint (CSRF-001) deliberately skips both.
 */

require_once __DIR__ . '/auth.php';

function csrf_token(): string
{
    lab_session_start();

    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

function csrf_is_valid(?string $token): bool
{
    lab_session_start();

    return is_string($token)
        && !empty($_SESSION['csrf_token'])
        && hash_equals($_SESSION['csrf_token'], $token);
}
