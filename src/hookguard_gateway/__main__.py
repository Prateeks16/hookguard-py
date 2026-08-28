"""Gateway entrypoint.

Go's ``main`` set explicit timeouts on every phase of the HTTP server, because
the default ``http.Server`` has none and this is the one internet-facing
surface: without them a client can open a connection and then dribble, or never
send, its request. uvicorn's equivalents are passed here for the same reason.

Graceful shutdown lives in the app's lifespan rather than a signal handler --
uvicorn catches SIGTERM and SIGINT itself, and unwinds the lifespan on the way
out, which is what drains the event queue.
"""

from __future__ import annotations

import argparse
import logging
import os

import uvicorn

__all__ = ["main"]

LISTEN_HOST = "0.0.0.0"  # noqa: S104  (containers publish a port; binding loopback would hide it)
LISTEN_PORT = 9000
UPSTREAM_PORT = 8080

#: Must stay above the ingest emitter's delivery timeout so a shutdown flushes
#: queued events rather than discarding them.
SHUTDOWN_TIMEOUT = 15

#: A slow client must not hold a connection open indefinitely.
KEEP_ALIVE_TIMEOUT = 5


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="hookguard-gateway", description="The HookGuard gateway.")
    parser.add_argument(
        "--upstream",
        action="store_true",
        help="run the sample protected application instead of the gateway",
    )
    parser.add_argument("--host", default=os.getenv("HOST", LISTEN_HOST))
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    if args.upstream:
        target = "hookguard_gateway.upstream:create_app"
        port = args.port or int(os.getenv("PORT", str(UPSTREAM_PORT)))
    else:
        target = "hookguard_gateway.app:create_app"
        port = args.port or int(os.getenv("PORT", str(LISTEN_PORT)))

    uvicorn.run(
        target,
        factory=True,
        host=args.host,
        port=port,
        timeout_graceful_shutdown=SHUTDOWN_TIMEOUT,
        timeout_keep_alive=KEEP_ALIVE_TIMEOUT,
        access_log=False,
        log_config=None,
    )


if __name__ == "__main__":
    main()
