"""Sessions. Ported from web/internal/store/sessions.go.

Only ``sha256(token)`` is ever stored: someone with read access to the
database still cannot mint a cookie from it.
"""

from __future__ import annotations

from ._base import _StoreBase
from .models import NotFoundError, Session

__all__ = ["SessionsMixin"]

_COLUMNS = (
    "id, token_hash, user_id, csrf_token, created_at, last_seen_at, expires_at, ip, user_agent"
)


def _row_to_session(row: tuple) -> Session:
    return Session(
        id=row[0],
        token_hash=bytes(row[1]),
        user_id=row[2],
        csrf_token=row[3],
        created_at=row[4],
        last_seen_at=row[5],
        expires_at=row[6],
        # ip and user_agent are nullable in the schema; Go read them through
        # sql.NullString and flattened NULL to "". Same here.
        ip=row[7] or "",
        user_agent=row[8] or "",
    )


class SessionsMixin(_StoreBase):
    def create_session(self, session: Session) -> int:
        return self._insert(
            "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at,"
            " last_seen_at, expires_at, ip, user_agent)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                session.token_hash,
                session.user_id,
                session.csrf_token,
                session.created_at,
                session.last_seen_at,
                session.expires_at,
                session.ip,
                session.user_agent,
            ),
        )

    def get_session_by_token_hash(self, token_hash: bytes) -> Session:
        row = self._query_one(
            f"SELECT {_COLUMNS} FROM sessions WHERE token_hash = ?", (token_hash,)
        )
        if row is None:
            raise NotFoundError("no session for that token")
        return _row_to_session(row)

    def touch_session(self, session_id: int, last_seen_at: int) -> None:
        self._execute(
            "UPDATE sessions SET last_seen_at = ? WHERE id = ?", (last_seen_at, session_id)
        )

    def delete_session(self, session_id: int) -> None:
        self._execute("DELETE FROM sessions WHERE id = ?", (session_id,))

    def delete_session_by_token_hash(self, token_hash: bytes) -> None:
        self._execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    def delete_sessions_for_user_except(self, user_id: int, keep_id: int) -> int:
        """Revoke every session for a user except one. Returns the count."""
        return self._execute(
            "DELETE FROM sessions WHERE user_id = ? AND id != ?", (user_id, keep_id)
        )

    def list_sessions_for_user(self, user_id: int) -> list[Session]:
        rows = self._query_all(
            f"SELECT {_COLUMNS} FROM sessions WHERE user_id = ? ORDER BY last_seen_at DESC",
            (user_id,),
        )
        return [_row_to_session(r) for r in rows]
