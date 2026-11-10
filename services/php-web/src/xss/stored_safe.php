<?php
// @control id=XSS-002-C twin_of=XSS-002 url=/php/xss/stored_safe.php method=POST param=body service=php-web param_loc=body

/**
 * XSS-002-C: SAFE — same storage flow, but every comment body is HTML-encoded
 * at render time. Stored markup therefore never becomes active content.
 */

require_once __DIR__ . '/../common/db.php';

header('Content-Type: text/html; charset=utf-8');
$pdo = get_pdo();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $body = (string) ($_POST['body'] ?? '');

    $stmt = $pdo->prepare(
        'INSERT INTO comments (product_id, user_id, username, body) VALUES (1, 0, :username, :body)'
    );
    $stmt->execute([':username' => 'guest', ':body' => $body]);

    header('Location: /php/xss/stored_safe.php');
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
    <li><strong><?= htmlspecialchars($comment['username'], ENT_QUOTES, 'UTF-8') ?>:</strong>
        <?= htmlspecialchars($comment['body'], ENT_QUOTES | ENT_HTML5, 'UTF-8') ?></li>
<?php endforeach; ?>
</ul>
</body>
</html>
