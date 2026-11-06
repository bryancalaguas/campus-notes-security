<?php
declare(strict_types=1);

require __DIR__ . '/src/bootstrap.php';

install_error_handler(false);
start_secure_session();
send_security_headers();

function flash(string $text): void
{
    $_SESSION['flash'] = $text;
}

function redirect_home(): never
{
    header('Location: /', true, 303);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$userId = current_user_id();

// Issue 5: every state change must be POST and carry a valid CSRF token.
if ($method === 'POST') {
    if (!csrf_valid($_POST['csrf'] ?? null)) {
        http_response_code(403);
        exit('Invalid request.');
    }
    $action = $_POST['action'] ?? '';

    if ($action === 'register') {
        $error = register_user($_POST['email'] ?? null, $_POST['password'] ?? null);
        flash($error ?? 'Account created. You can sign in now.');
        redirect_home();
    }

    if ($action === 'login') {
        if (login_user($_POST['email'] ?? null, $_POST['password'] ?? null)) {
            redirect_home();
        }
        flash('Invalid email or password.');   // generic; never echoes input
        redirect_home();
    }

    // Everything below requires a signed-in user.
    if ($userId === null) {
        http_response_code(401);
        exit('Please sign in.');
    }

    if ($action === 'logout') {
        end_session();
        redirect_home();
    }

    if ($action === 'save' || $action === 'update') {
        $title = bounded_string($_POST['title'] ?? null, 1, 120);
        $body  = bounded_string($_POST['body'] ?? null, 1, 5000);
        if ($title === null || $body === null) {
            flash('Title (1–120) and body (1–5000 characters) are required.');
            redirect_home();
        }
        if ($action === 'save') {
            // Issue 7: owner is the session user, not a form field.
            create_note($userId, $title, $body);
            flash('Note saved.');
        } else {
            $id = positive_int($_POST['id'] ?? null);
            $ok = $id !== null && update_note($id, $userId, $title, $body);
            flash($ok ? 'Note updated.' : 'Note not found.');
        }
        redirect_home();
    }

    if ($action === 'delete') {
        $id = positive_int($_POST['id'] ?? null);
        $ok = $id !== null && delete_note($id, $userId);
        flash($ok ? 'Note deleted.' : 'Note not found.');
        redirect_home();
    }

    http_response_code(400);
    exit('Invalid request.');
}

// GET: read-only page rendering.
$message = $_SESSION['flash'] ?? '';
unset($_SESSION['flash']);

$notes = [];
$editing = null;
if ($userId !== null) {
    $notes = notes_for_owner($userId);
    if (isset($_GET['edit'])) {
        $editId = positive_int($_GET['edit']);
        $editing = $editId !== null ? note_for_owner($editId, $userId) : null;
        if ($editing === null) {
            $message = 'Note not found.';
        }
    }
}
$csrf = csrf_token();

require __DIR__ . '/templates/page.php';
