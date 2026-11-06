<?php
declare(strict_types=1);

// Issue 8: credentials come only from the environment. No hard-coded
// 'root' / empty-password fallback; missing config fails closed.
function db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $host = getenv('LAB_DB_HOST') ?: 'localhost';
    $name = getenv('LAB_DB_NAME') ?: 'notes_lab';
    $user = getenv('LAB_DB_USER');
    $pass = getenv('LAB_DB_PASSWORD');

    if ($user === false || $user === '' || $pass === false || $pass === '') {
        throw new RuntimeException('Database credentials unavailable.');
    }

    $pdo = new PDO(
        "mysql:host=$host;dbname=$name;charset=utf8mb4",
        $user,
        $pass,
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,   // native prepared statements
            PDO::MYSQL_ATTR_FOUND_ROWS   => true,    // rowCount = matched rows
        ]
    );
    return $pdo;
}
