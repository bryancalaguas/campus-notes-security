<?php
declare(strict_types=1);
// View only. Every dynamic value goes through html() (issue 4).
// Expects: $message, $userId, $notes, $editing, $csrf.
if (!isset($csrf)) {
    http_response_code(404);
    exit;
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="csrf-token" content="<?= html($csrf) ?>">
<title>Campus Notes</title>
<link rel="stylesheet" href="/assets/style.css">
</head>
<body>
<h1>Campus Notes</h1>
<?php if ($message !== ''): ?><p class="msg"><?= html($message) ?></p><?php endif; ?>

<?php if ($userId === null): ?>
<h2>Register or sign in</h2>
<form method="post">
  <input type="hidden" name="csrf" value="<?= html($csrf) ?>">
  <label>Email <input name="email" type="email" maxlength="254" required></label>
  <label>Password <input name="password" type="password" minlength="12" required></label>
  <button name="action" value="register">Register</button>
  <button name="action" value="login">Sign in</button>
</form>
<?php else: ?>
<p>Signed in as user <?= html($userId) ?> (<?= html($_SESSION['role'] ?? '') ?>)</p>
<form method="post" class="inline">
  <input type="hidden" name="csrf" value="<?= html($csrf) ?>">
  <button name="action" value="logout">Log out</button>
</form>

<?php if ($editing): ?>
<h2>Edit note</h2>
<form method="post">
  <input type="hidden" name="csrf" value="<?= html($csrf) ?>">
  <input type="hidden" name="id" value="<?= html($editing['id']) ?>">
  <label>Title <input name="title" maxlength="120" value="<?= html($editing['title']) ?>" required></label>
  <label>Body <textarea name="body" maxlength="5000" required><?= html($editing['body']) ?></textarea></label>
  <button name="action" value="update">Update</button>
  <a href="/">Cancel</a>
</form>
<?php endif; ?>

<h2>Create a note</h2>
<form method="post">
  <input type="hidden" name="csrf" value="<?= html($csrf) ?>">
  <label>Title <input name="title" maxlength="120" required></label>
  <label>Body <textarea name="body" maxlength="5000" required></textarea></label>
  <button name="action" value="save">Save</button>
</form>

<h2>Your notes</h2>
<?php foreach ($notes as $note): ?>
<article>
  <h3><?= html($note['title']) ?></h3>
  <p><?= nl2br(html($note['body'])) ?></p>
  <a href="/?edit=<?= html($note['id']) ?>">Edit</a>
  <form method="post" class="inline">
    <input type="hidden" name="csrf" value="<?= html($csrf) ?>">
    <input type="hidden" name="id" value="<?= html($note['id']) ?>">
    <button name="action" value="delete">Delete</button>
  </form>
</article>
<?php endforeach; ?>
<?php endif; ?>
</body>
</html>
