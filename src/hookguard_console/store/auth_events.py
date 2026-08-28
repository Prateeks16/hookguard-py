"""The security log. Ported from web/internal/store/auth_events.go."""

from __future__ import annotations

from ._base import _StoreBase
from .models import AuthEvent

__all__ = ["AuthEventsMixin"]


class AuthEventsMixin(_StoreBase):
    def insert_auth_event(self, event: AuthEvent) -> None:
        self._execute(
            "INSERT INTO auth_events (at, user_id, email, kind, ip) VALUES (?, ?, ?, ?, ?)",
            (event.at, event.user_id, event.email, event.kind, event.ip),
        )

    def list_auth_events(self, limit: int) -> list[AuthEvent]:
        """The most recent events, newest first.

        Ordered by ``at`` then ``id`` so events sharing a millisecond -- which
        a burst of failed logins will -- still come back in a stable order
        rather than whatever the planner feels like.
        """
        rows = self._query_all(
            "SELECT id, at, user_id, email, kind, ip FROM auth_events"
            " ORDER BY at DESC, id DESC LIMIT ?",
            (limit,),
        )
        return [
            AuthEvent(id=r[0], at=r[1], user_id=r[2], email=r[3], kind=r[4], ip=r[5]) for r in rows
        ]
