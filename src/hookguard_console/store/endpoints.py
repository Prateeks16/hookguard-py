"""Endpoints. Ported from web/internal/store/endpoints.go.

An Endpoint is a Route with a database row behind it. The table's CHECK
constraint enforces the same per-provider shape the gateway's factories do:
PayPal carries a webhook_id and no secret_env, everything else the reverse.
"""

from __future__ import annotations

from ._base import _StoreBase
from .models import Endpoint, NotFoundError

__all__ = ["EndpointsMixin"]

_COLUMNS = (
    "id, path, provider, upstream_url, replay_window, secret_env, webhook_id,"
    " active, created_at, updated_at"
)


def _row_to_endpoint(row: tuple) -> Endpoint:
    return Endpoint(
        id=row[0],
        path=row[1],
        provider=row[2],
        upstream_url=row[3],
        replay_window=row[4],
        secret_env=row[5],
        webhook_id=row[6],
        active=bool(row[7]),
        created_at=row[8],
        updated_at=row[9],
    )


class EndpointsMixin(_StoreBase):
    def create_endpoint(self, endpoint: Endpoint) -> int:
        return self._insert(
            "INSERT INTO endpoints"
            " (path, provider, upstream_url, replay_window, secret_env, webhook_id,"
            "  active, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                endpoint.path,
                endpoint.provider,
                endpoint.upstream_url,
                endpoint.replay_window,
                endpoint.secret_env,
                endpoint.webhook_id,
                1 if endpoint.active else 0,
                endpoint.created_at,
                endpoint.updated_at,
            ),
        )

    def get_endpoint_by_id(self, endpoint_id: int) -> Endpoint:
        row = self._query_one(f"SELECT {_COLUMNS} FROM endpoints WHERE id = ?", (endpoint_id,))
        if row is None:
            raise NotFoundError(f"no endpoint with id {endpoint_id}")
        return _row_to_endpoint(row)

    def get_endpoint_by_path(self, path: str) -> Endpoint:
        row = self._query_one(f"SELECT {_COLUMNS} FROM endpoints WHERE path = ?", (path,))
        if row is None:
            raise NotFoundError(f"no endpoint at path {path!r}")
        return _row_to_endpoint(row)

    def list_endpoints(self) -> list[Endpoint]:
        """Every endpoint, ordered by path -- the same order the export uses."""
        rows = self._query_all(f"SELECT {_COLUMNS} FROM endpoints ORDER BY path")
        return [_row_to_endpoint(r) for r in rows]

    def list_active_endpoints(self) -> list[Endpoint]:
        """Backs the config export. Ordering is the store's job, not the
        caller's, so an exported file is stable between runs."""
        rows = self._query_all(f"SELECT {_COLUMNS} FROM endpoints WHERE active = 1 ORDER BY path")
        return [_row_to_endpoint(r) for r in rows]

    def update_endpoint(self, endpoint: Endpoint) -> None:
        """Update everything except ``active``, which has its own method so a
        toggle does not have to round-trip the whole row."""
        self._execute(
            "UPDATE endpoints SET path = ?, provider = ?, upstream_url = ?,"
            " replay_window = ?, secret_env = ?, webhook_id = ?, updated_at = ?"
            " WHERE id = ?",
            (
                endpoint.path,
                endpoint.provider,
                endpoint.upstream_url,
                endpoint.replay_window,
                endpoint.secret_env,
                endpoint.webhook_id,
                endpoint.updated_at,
                endpoint.id,
            ),
        )

    def set_endpoint_active(self, endpoint_id: int, active: bool, updated_at: int) -> None:
        self._execute(
            "UPDATE endpoints SET active = ?, updated_at = ? WHERE id = ?",
            (1 if active else 0, updated_at, endpoint_id),
        )

    def delete_endpoint(self, endpoint_id: int) -> None:
        self._execute("DELETE FROM endpoints WHERE id = ?", (endpoint_id,))
