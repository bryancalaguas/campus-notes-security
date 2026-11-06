<?php
declare(strict_types=1);

require __DIR__ . '/src/bootstrap.php';

install_error_handler(true);
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');
// Issue 11: no Access-Control-Allow-* headers. The API is same-origin only;
// browsers block other sites from reading its responses.

function respond(int $status, array $payload): never
{
    http_response_code($status);
    echo json_encode($payload);
    exit;
}

start_secure_session();

// Issue 9: authentication comes from the session for every request.
$userId = current_user_id();
if ($userId === null) {
    respond(401, ['error' => 'Authentication required']);
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method === 'GET') {
    // Issue 9: the user_id query parameter is no longer trusted. A request for
    // someone else's notes is refused; the owner is always the session user.
    if (isset($_GET['user_id']) && positive_int($_GET['user_id']) !== $userId) {
        respond(403, ['error' => 'Forbidden']);
    }
    respond(200, ['notes' => notes_for_owner($userId)]);
}

if ($method === 'POST') {
    // Issue 11: reject cross-origin requests when the browser reports an Origin.
    $origin = $_SERVER['HTTP_ORIGIN'] ?? null;
    if ($origin !== null) {
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $self = $scheme . '://' . ($_SERVER['HTTP_HOST'] ?? '');
        if (!hash_equals($self, $origin)) {
            respond(403, ['error' => 'Cross-origin request rejected']);
        }
    }
    // Issue 11: cookie-authenticated state change needs the session CSRF token.
    if (!csrf_valid($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null)) {
        respond(403, ['error' => 'Invalid CSRF token']);
    }

    // Issue 10: strict request validation.
    $type = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
    if ($type !== 'application/json') {
        respond(415, ['error' => 'Content-Type must be application/json']);
    }
    $raw = file_get_contents('php://input', false, null, 0, 20001);
    if ($raw === false || strlen($raw) > 20000) {
        respond(413, ['error' => 'Request too large']);
    }
    try {
        $data = json_decode($raw, true, 4, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        respond(400, ['error' => 'Malformed JSON']);
    }
    if (!is_array($data) || array_is_list($data)) {
        respond(400, ['error' => 'Expected a JSON object']);
    }

    $id    = is_int($data['id'] ?? null) ? positive_int($data['id']) : null;
    $title = bounded_string($data['title'] ?? null, 1, 120);
    $body  = bounded_string($data['body'] ?? null, 1, 5000);
    if ($id === null || $title === null || $body === null) {
        respond(422, ['error' => 'id (positive integer), title (1-120) and body (1-5000) are required']);
    }

    // Issue 9: per-record authorization; another user's note looks "not found".
    if (!update_note($id, $userId, $title, $body)) {
        respond(404, ['error' => 'Note not found']);
    }
    respond(200, ['updated' => 1]);
}

header('Allow: GET, POST');
respond(405, ['error' => 'Method not supported']);
