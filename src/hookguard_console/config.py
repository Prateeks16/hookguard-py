"""The Console's runtime configuration.

Read from the environment once at startup, the same names the Go build used so
an existing deployment's compose file keeps working unchanged.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

__all__ = ["VERSION", "ConsoleConfig"]

#: Reported in the UI and by /healthz.
VERSION = "1.0.0"

DEFAULT_PORT = 7000


@dataclass(frozen=True, slots=True)
class ConsoleConfig:
    port: int = DEFAULT_PORT
    host: str = "0.0.0.0"  # noqa: S104  (containers publish a port; loopback would hide it)
    data_dir: Path = Path()
    allow_signup: bool = False

    #: The same shared secret the gateway uses -- it authenticates the same
    #: Gateway signature on both sides of the ingest POST.
    #:
    #: Unset is a safe default rather than a startup failure: the ingest route
    #: then rejects everything, because no request could ever verify against an
    #: empty key, and the Console is still useful as an auth and routes admin
    #: UI without it. There is deliberately no "accept everything" mode.
    internal_secret: bytes = b""

    @property
    def database_path(self) -> Path:
        return self.data_dir / "console.db"

    @classmethod
    def from_env(cls) -> ConsoleConfig:
        return cls(
            port=int(os.getenv("CONSOLE_PORT") or DEFAULT_PORT),
            host=os.getenv("CONSOLE_HOST") or "0.0.0.0",  # noqa: S104
            data_dir=Path(os.getenv("CONSOLE_DATA_DIR") or "."),
            allow_signup=os.getenv("CONSOLE_ALLOW_SIGNUP") == "true",
            internal_secret=(os.getenv("INTERNAL_SECRET") or "").encode("utf-8"),
        )
