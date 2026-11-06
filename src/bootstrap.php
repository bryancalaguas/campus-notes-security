<?php
declare(strict_types=1);

// Shared setup for every entry point (index.php, api.php).
// Order matters: error handling first, then session, then helpers.

// Issue 8: never show errors to visitors; log them instead.
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

require __DIR__ . '/db.php';
require __DIR__ . '/security.php';
require __DIR__ . '/notes.php';
require __DIR__ . '/auth.php';

/**
 * Fail securely: log a diagnostic with a correlation id, show a generic message.
 * $json selects the response format for the API.
 */
function install_error_handler(bool $json): void
{
    set_exception_handler(function (Throwable $e) use ($json): void {
        $ref = bin2hex(random_bytes(6));
        error_log(sprintf('[ref %s] %s in %s:%d', $ref, get_class($e), $e->getFile(), $e->getLine()));
        if (!headers_sent()) {
            http_response_code(500);
        }
        if ($json) {
            if (!headers_sent()) {
                header('Content-Type: application/json; charset=utf-8');
            }
            echo json_encode(['error' => 'Server error', 'ref' => $ref]);
        } else {
            echo 'Something went wrong. Reference: ' . $ref;
        }
    });
}

// Issue 6: secure session cookie settings, set BEFORE session_start().
function start_secure_session(): void
{
    $https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_trans_sid', '0');
    session_name('CAMPUSNOTESID');
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'secure'   => $https,   // true in production (HTTPS); local lab runs on HTTP
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    if (!session_start()) {
        throw new RuntimeException('Session could not start.');
    }

    // Idle (30 min) and absolute (8 h) expiry for signed-in sessions.
    if (isset($_SESSION['user_id'])) {
        $now = time();
        $idle = $now - ($_SESSION['last_activity'] ?? 0) > 1800;
        $old  = $now - ($_SESSION['authenticated_at'] ?? 0) > 28800;
        if ($idle || $old) {
            end_session();
            session_start();
        } else {
            $_SESSION['last_activity'] = $now;
        }
    }
}

/** Issue 6: log out fully — clear data, expire the cookie, destroy server session. */
function end_session(): void
{
    $_SESSION = [];
    $p = session_get_cookie_params();
    setcookie(session_name(), '', [
        'expires'  => time() - 3600,
        'path'     => $p['path'],
        'domain'   => $p['domain'],
        'secure'   => $p['secure'],
        'httponly' => $p['httponly'],
        'samesite' => $p['samesite'],
    ]);
    session_destroy();
}
