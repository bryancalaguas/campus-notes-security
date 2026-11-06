<?php
declare(strict_types=1);

// Issue 3 / 9: every note query is scoped to the signed-in owner.
// The owner id always comes from the server-side session, never the request.

function notes_for_owner(int $ownerId): array
{
    $stmt = db()->prepare('SELECT id, title, body FROM notes WHERE user_id = ? ORDER BY id DESC');
    $stmt->execute([$ownerId]);
    return $stmt->fetchAll();
}

function note_for_owner(int $noteId, int $ownerId): ?array
{
    $stmt = db()->prepare('SELECT id, title, body FROM notes WHERE id = ? AND user_id = ?');
    $stmt->execute([$noteId, $ownerId]);
    $note = $stmt->fetch();
    return $note ?: null;
}

function create_note(int $ownerId, string $title, string $body): void
{
    $stmt = db()->prepare('INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)');
    $stmt->execute([$ownerId, $title, $body]);
}

/** Returns true only if a note with this id belongs to the owner. */
function update_note(int $noteId, int $ownerId, string $title, string $body): bool
{
    $stmt = db()->prepare('UPDATE notes SET title = ?, body = ? WHERE id = ? AND user_id = ?');
    $stmt->execute([$title, $body, $noteId, $ownerId]);
    return $stmt->rowCount() === 1;
}

function delete_note(int $noteId, int $ownerId): bool
{
    $stmt = db()->prepare('DELETE FROM notes WHERE id = ? AND user_id = ?');
    $stmt->execute([$noteId, $ownerId]);
    return $stmt->rowCount() === 1;
}
