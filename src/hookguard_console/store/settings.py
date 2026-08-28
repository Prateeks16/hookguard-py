"""Instance settings. Ported from web/internal/store/settings.go.

A key/value table. Password-reset tokens live here too, one row per pending
reset keyed ``pwreset:<user_id>`` -- the schema is fixed upfront and has no
dedicated table for a single-use, short-lived value.
"""

from __future__ import annotations

from ._base import _StoreBase
from .models import DEFAULT_RETENTION_DAYS, NotFoundError

__all__ = ["SettingsMixin"]

_RETENTION_DAYS = "retention_days"


class SettingsMixin(_StoreBase):
    def get_setting(self, key: str) -> str:
        row = self._query_one("SELECT value FROM settings WHERE key = ?", (key,))
        if row is None:
            raise NotFoundError(f"no setting {key!r}")
        return row[0]

    def set_setting(self, key: str, value: str) -> None:
        self._execute(
            "INSERT INTO settings (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def delete_setting(self, key: str) -> None:
        self._execute("DELETE FROM settings WHERE key = ?", (key,))

    def get_retention_days(self) -> int:
        """The configured retention window, falling back to the default.

        A blank or corrupt value falls back rather than raising: a bad row
        should not disable retention, which would silently let the events
        table grow forever.
        """
        try:
            raw = self.get_setting(_RETENTION_DAYS)
        except NotFoundError:
            return DEFAULT_RETENTION_DAYS
        try:
            return int(raw)
        except ValueError:
            return DEFAULT_RETENTION_DAYS

    def set_retention_days(self, days: int) -> None:
        self.set_setting(_RETENTION_DAYS, str(days))
