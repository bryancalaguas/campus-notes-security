<?php
declare(strict_types=1);

// Account registration and login.

/**
 * Issue 2 + 7: hash with an adaptive algorithm; role is always set on the
 * server ('student'), never taken from the form.
 * Returns an error message, or null on success.
 */
function register_user(mixed $emailIn, mixed $passwordIn): ?string
{
    $email = is_string($emailIn) ? trim($emailIn) : '';
    if (strlen($email) > 254 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return 'Enter a valid email address.';
    }
    if (!is_string($passwordIn) || strlen($passwordIn) < 12) {
        return 'Password must be at least 12 characters.';
    }
    // bcrypt (the fallback) silently ignores bytes past 72; refuse instead.
    $max = defined('PASSWORD_ARGON2ID') ? 1024 : 72;
    if (strlen($passwordIn) > $max) {
        return "Password must be at most $max bytes.";
    }

    $hash = password_hash($passwordIn, password_algo());
    try {
        $stmt = db()->prepare('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)');
        $stmt->execute([$email, $hash, 'student']);
    } catch (PDOException $e) {
        if ($e->getCode() === '23000') {           // duplicate email
            return 'Could not create the account.';
        }
        throw $e;
    }
    return null;
}

/**
 * Issue 1 + 2 + 6: prepared lookup by email, password_verify, then a fresh
 * session id. Returns true on success.
 */
function login_user(mixed $emailIn, mixed $passwordIn): bool
{
    if (!is_string($emailIn) || !is_string($passwordIn) || strlen($passwordIn) > 1024) {
        return false;
    }
    $email = trim($emailIn);
    if (strlen($email) > 254 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }

    $stmt = db()->prepare('SELECT id, password_hash, role FROM users WHERE email = ?');
    $stmt->execute([$email]);
    $user = $stmt->fetch();
    if (!$user) {
        // Spend similar time as a real check so timing reveals less.
        password_verify($passwordIn, '$2y$10$1nbKLfycQ2cVtws.zWwRXuqDucPAzC1I2hVOBUH39wOet/RwVaI2K');
        return false;
    }

    $stored = $user['password_hash'];
    $ok = password_verify($passwordIn, $stored);

    // Transitional: the seeded starter accounts still hold MD5. Accept that
    // once, then replace it with a modern hash. Remove after migration.
    $legacy = !$ok && preg_match('/^[a-f0-9]{32}$/', $stored) === 1
        && hash_equals($stored, md5($passwordIn));

    if (!$ok && !$legacy) {
        return false;
    }
    if ($legacy || password_needs_rehash($stored, password_algo())) {
        $up = db()->prepare('UPDATE users SET password_hash = ? WHERE id = ?');
        $up->execute([password_hash($passwordIn, password_algo()), $user['id']]);
    }

    if (!session_regenerate_id(true)) {             // prevent session fixation
        throw new RuntimeException('Session rotation failed.');
    }
    $_SESSION['user_id'] = (int) $user['id'];
    $_SESSION['role'] = (string) $user['role'];
    $_SESSION['authenticated_at'] = time();
    $_SESSION['last_activity'] = time();
    unset($_SESSION['csrf']);                       // new token for the new session
    return true;
}
