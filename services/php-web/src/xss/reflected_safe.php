<?php
// @control id=XSS-001-C twin_of=XSS-001 url=/php/xss/reflected_safe.php method=GET param=name service=php-web param_loc=query

/**
 * XSS-001-C: SAFE — context-aware output encoding with ENT_QUOTES.
 */

$name = $_GET['name'] ?? 'guest';
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Greeting</title></head>
<body>
<h1>Hello, <?= htmlspecialchars($name, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>!</h1>
<p>Welcome to the VulnForge greeting page.</p>
</body>
</html>
