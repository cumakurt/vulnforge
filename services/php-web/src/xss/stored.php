<?php
// @vuln id=XSS-002 name="Stored XSS in product comments" cwe=CWE-79 owasp=A03:2021 type=stored level=1 param=body method=POST service=php-web url=/php/xss/stored.php param_loc=body needs_oob=false auth=false detection=active tags=xss,client,stored proof_kind=marker proof_desc="Comment markup is rendered without encoding on subsequent GET requests"

/**
 * XSS-002: Stored XSS — comment body is persisted and rendered raw.
 * Level: L1
 *
 * Step 1 (store): POST body=<script>alert(1)</script>
 * Step 2 (read):  GET /php/xss/stored.php
 */

require_once __DIR__ . '/../common/db.php';
require_once __DIR__ . '/../common/lab.php';

header('Content-Type: text/html; charset=utf-8');
$pdo = get_pdo();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $body = (string) ($_POST['body'] ?? '');

    // Prepared statement: injection is not the point of this endpoint.
    $stmt = $pdo->prepare(
        'INSERT INTO comments (product_id, user_id, username, body) VALUES (1, 0, :username, :body)'
    );
    $stmt->execute([':username' => 'guest', ':body' => $body]);

    if (preg_match('/<\s*script|onerror\s*=|onload\s*=/i', $body)) {
        lab_trigger('XSS-002', get_request_id(), ['payload' => $body]);
    }

    header('Location: /php/xss/stored.php');
    exit;
}

$comments = $pdo->query('SELECT username, body FROM comments ORDER BY id DESC LIMIT 50')->fetchAll();
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Product comments</title></head>
<body>
<h1>Comments</h1>
<form method="post">
    <textarea name="body" rows="4" cols="60"></textarea><br>
    <button type="submit">Post comment</button>
</form>
<ul>
<?php foreach ($comments as $comment): ?>
    <li><strong><?= $comment['username'] ?>:</strong> <?= $comment['body'] ?></li>
<?php endforeach; ?>
</ul>
</body>
</html>
