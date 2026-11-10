<?php
/**
 * VulnForge Lab — session and identity helpers.
 *
 * The lab uses PHP's native session handler. Endpoints that require a logged-in
 * user call lab_session_start() + current_user(); endpoints that intentionally
 * fail to rotate the session ID (AUTH-002) must NOT use a helper that calls
 * session_regenerate_id().
 */

require_once __DIR__ . '/db.php';

function lab_session_start(): void
{
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
}

/**
 * Return the authenticated user row, or null when no session exists.
 */
function current_user(): ?array
{
    lab_session_start();

    if (empty($_SESSION['user_id'])) {
        return null;
    }

    $pdo  = get_pdo();
    $stmt = $pdo->prepare('SELECT id, username, email, role FROM users WHERE id = :id');
    $stmt->execute([':id' => (int) $_SESSION['user_id']]);

    return $stmt->fetch() ?: null;
}

/**
 * Abort the request with a JSON error when the caller is not authenticated.
 */
function require_login(): array
{
    $user = current_user();
    if ($user === null) {
        http_response_code(401);
        echo json_encode(['error' => 'authentication required']);
        exit;
    }

    return $user;
}
