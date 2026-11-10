<?php
// @control id=REDIR-001-C twin_of=REDIR-001 url=/php/redirect/redirect_safe.php method=GET param=next service=php-web param_loc=query

/**
 * REDIR-001-C: SAFE — only relative paths on a fixed allowlist are accepted.
 * Absolute URLs, protocol-relative URLs and javascript: schemes are rejected.
 */

$allowed = ['/php/', '/php/xss/reflected.php', '/php/auth/login.php'];
$next    = $_GET['next'] ?? '/php/';

if (!in_array($next, $allowed, true)) {
    http_response_code(400);
    echo 'Invalid redirect target.';
    exit;
}

header('Location: ' . $next, true, 302);
echo 'Redirecting to ' . htmlspecialchars($next, ENT_QUOTES, 'UTF-8');
