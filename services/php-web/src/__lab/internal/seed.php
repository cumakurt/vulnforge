<?php
/**
 * Internal seed endpoint — called by lab-control.
 *
 * profile=small  → baseline reset only
 * profile=large  → baseline plus deterministic bulk rows
 */

require_once __DIR__ . '/../../common/db.php';

header('Content-Type: application/json');

$profile = $_GET['profile'] ?? 'small';

if (!in_array($profile, ['small', 'large'], true)) {
    http_response_code(400);
    echo json_encode(['error' => 'profile must be small or large']);
    exit;
}

// Reset first so repeated seed calls are idempotent.
$reset_url = 'http://localhost/__lab/internal/reset';
$reset_body = @file_get_contents($reset_url, false, stream_context_create([
    'http' => ['method' => 'POST', 'timeout' => 30, 'ignore_errors' => true],
]));

if ($reset_body === false) {
    http_response_code(500);
    echo json_encode(['error' => 'baseline reset failed']);
    exit;
}

$inserted = ['users' => 0, 'products' => 0];

if ($profile === 'large') {
    $pdo = get_pdo();

    $user_stmt = $pdo->prepare(
        'INSERT INTO users (username, password, email, role) VALUES (:username, :password, :email, :role)'
    );
    for ($i = 1; $i <= 200; $i++) {
        $user_stmt->execute([
            ':username' => sprintf('bulk-user-%04d', $i),
            ':password' => md5('password-' . $i),
            ':email'    => sprintf('bulk-user-%04d@vulnforge.lab', $i),
            ':role'     => 'user',
        ]);
        $inserted['users']++;
    }

    $product_stmt = $pdo->prepare(
        'INSERT INTO products (name, description, price, category, stock) VALUES (:name, :description, :price, :category, :stock)'
    );
    for ($i = 1; $i <= 1000; $i++) {
        $product_stmt->execute([
            ':name'        => sprintf('Bulk product %04d', $i),
            ':description' => 'Synthetic catalogue row for crawl and pagination tests',
            ':price'       => number_format(($i % 500) + 0.99, 2, '.', ''),
            ':category'    => ['widgets', 'gadgets', 'misc'][$i % 3],
            ':stock'       => $i % 250,
        ]);
        $inserted['products']++;
    }
}

echo json_encode(['seeded' => true, 'profile' => $profile, 'inserted' => $inserted]);
