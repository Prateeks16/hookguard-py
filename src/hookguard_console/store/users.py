"""Users. Ported from web/internal/store/users.go."""

from __future__ import annotations

from ._base import _StoreBase
from .models import NotFoundError, User

__all__ = ["UsersMixin"]

_COLUMNS = "id, email, password_hash, role, active, created_at"


def _row_to_user(row: tuple) -> User:
    return User(
        id=row[0],
        email=row[1],
        password_hash=row[2],
        role=row[3],
        active=bool(row[4]),  # SQLite has no boolean type; the column is 0/1
        created_at=row[5],
    )


class UsersMixin(_StoreBase):
    def count_users(self) -> int:
        """Used to decide whether a new signup becomes the first (admin) user."""
        return int(self._scalar("SELECT COUNT(*) FROM users", default=0))

    def create_user(self, email: str, password_hash: str, role: str, created_at: int) -> int:
        return self._insert(
            "INSERT INTO users (email, password_hash, role, active, created_at)"
            " VALUES (?, ?, ?, 1, ?)",
            (email, password_hash, role, created_at),
        )

    def get_user_by_email(self, email: str) -> User:
        """Look up by email, case-insensitively.

        ``COLLATE NOCASE`` matches the column's own collation, so this cannot
        find a user the UNIQUE constraint would have rejected as a duplicate.
        """
        row = self._query_one(
            f"SELECT {_COLUMNS} FROM users WHERE email = ? COLLATE NOCASE", (email,)
        )
        if row is None:
            raise NotFoundError(f"no user with email {email!r}")
        return _row_to_user(row)

    def get_user_by_id(self, user_id: int) -> User:
        row = self._query_one(f"SELECT {_COLUMNS} FROM users WHERE id = ?", (user_id,))
        if row is None:
            raise NotFoundError(f"no user with id {user_id}")
        return _row_to_user(row)

    def update_password_hash(self, user_id: int, password_hash: str) -> None:
        self._execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))

    def list_users(self) -> list[User]:
        """Backs the admin-only Settings user list."""
        rows = self._query_all(f"SELECT {_COLUMNS} FROM users ORDER BY created_at")
        return [_row_to_user(r) for r in rows]

    def set_user_active(self, user_id: int, active: bool) -> None:
        self._execute("UPDATE users SET active = ? WHERE id = ?", (1 if active else 0, user_id))
