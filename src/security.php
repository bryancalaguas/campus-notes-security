<?php
declare(strict_types=1);

// Issue 4: encode untrusted values for HTML text and quoted attributes.
function html(string|int|null $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// Issue 5 / 11: one unpredictable CSRF token per session.
function csrf_token(): string
{
    if (empty($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_valid(mixed $submitted): bool
{
    return is_string($submitted)
        && isset($_SESSION['csrf'])
        && is_string($_SESSION['csrf'])
        && hash_equals($_SESSION['csrf'], $submitted);
}

function current_user_id(): ?int
{
    return isset($_SESSION['user_id']) ? (int) $_SESSION['user_id'] : null;
}

/** Positive integer from untrusted input, or null. */
function positive_int(mixed $value): ?int
{
    if (is_int($value)) {
        return $value > 0 ? $value : null;
    }
    if (!is_string($value)) {
        return null;
    }
    $n = filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
    return $n === false ? null : $n;
}

/** Trimmed string within length limits, or null. */
function bounded_string(mixed $value, int $min, int $max): ?string
{
    if (!is_string($value)) {
        return null;
    }
    $value = trim($value);
    $len = mb_strlen($value, 'UTF-8');
    return ($len >= $min && $len <= $max) ? $value : null;
}

/** Choose the strongest available adaptive password hash. */
function password_algo(): string|int|null
{
    return defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
}

function send_security_headers(): void
{
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
}
