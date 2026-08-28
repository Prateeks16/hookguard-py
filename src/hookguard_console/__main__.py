"""Console entrypoint and operator subcommands.

``reset-password`` and ``seed-config`` are commands rather than pages on
purpose: both are things an operator does from the host, one of them while
locked out of the very UI a page would live in.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

import uvicorn

from . import gwconfig
from .auth import RESET_TOKEN_TTL, new_reset_token
from .config import ConsoleConfig
from .gwconfig import ConfigValidationError
from .store import NotFoundError, open_store

__all__ = ["main"]

#: Must stay above the ingest batcher's flush interval so a shutdown drains
#: queued events rather than dropping verdicts the gateway already handed over.
SHUTDOWN_TIMEOUT = 15


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="hookguard-console", description="The HookGuard console.")
    sub = parser.add_subparsers(dest="command")

    reset = sub.add_parser("reset-password", help="mint a one-time password-reset link for a user")
    reset.add_argument("email")

    seed = sub.add_parser("seed-config", help="import routes from a gateway config.json")
    seed.add_argument("path")

    args = parser.parse_args(argv)
    logging.basicConfig(level="INFO", format="%(asctime)s %(name)s %(levelname)s %(message)s")
    config = ConsoleConfig.from_env()

    if args.command == "reset-password":
        _reset_password(config, args.email)
    elif args.command == "seed-config":
        _seed_config(config, Path(args.path))
    else:
        _serve(config)


def _serve(config: ConsoleConfig) -> None:
    uvicorn.run(
        "hookguard_console.app:create_app",
        factory=True,
        host=config.host,
        port=config.port,
        timeout_graceful_shutdown=SHUTDOWN_TIMEOUT,
        access_log=False,
        log_config=None,
    )


def _reset_password(config: ConsoleConfig, email: str) -> None:
    """Print a one-time reset URL for the operator to hand over.

    Only the token's hash is stored, so this output is the only copy: losing
    it means minting another, not recovering this one.
    """
    store = open_store(config.database_path)
    try:
        user = store.get_user_by_email(email.strip().lower())
    except NotFoundError:
        sys.exit(f"no such user: {email}")

    token, token_hash = new_reset_token()
    expires_at = datetime.now(UTC) + RESET_TOKEN_TTL
    store.set_setting(
        f"pwreset:{user.id}",
        f"{token_hash.hex()}:{int(expires_at.timestamp() * 1000)}",
    )
    store.close()

    minutes = int(RESET_TOKEN_TTL.total_seconds() // 60)
    print(f"Reset link for {user.email} (valid {minutes} minutes, single use):")
    print(f"  /reset-password?token={token}&uid={user.id}")
    print("Hand this to the user over a channel you already trust.")


def _seed_config(config: ConsoleConfig, path: Path) -> None:
    """Import a gateway config.json as routes.

    Lets an operator point a fresh Console at an existing deployment instead
    of re-entering every route by hand. Existing paths are skipped rather than
    overwritten: the file is a starting point, not the source of truth.
    """
    try:
        endpoints = gwconfig.import_config(path.read_text(encoding="utf-8"))
    except OSError as e:
        sys.exit(f"read {path}: {e}")
    except ConfigValidationError as e:
        sys.exit(f"parse {path}: {e}")

    store = open_store(config.database_path)
    now_ms = int(datetime.now(UTC).timestamp() * 1000)
    created = 0
    for endpoint in endpoints:
        try:
            existing = store.get_endpoint_by_path(endpoint.path)
        except NotFoundError:
            pass
        else:
            print(f"skip {endpoint.path}: already exists (id {existing.id})")
            continue
        endpoint.created_at = endpoint.updated_at = now_ms
        store.create_endpoint(endpoint)
        created += 1
        print(f"added {endpoint.path} [{endpoint.provider}] -> {endpoint.upstream_url}")
    store.close()
    print(f"{created} route(s) added from {path}")


if __name__ == "__main__":
    main()
