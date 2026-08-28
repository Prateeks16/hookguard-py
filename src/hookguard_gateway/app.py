"""The Gateway's HTTP surface.

One route per configured path. Each buffers the raw request body, verifies the
Provider signature, and forwards the unaltered bytes upstream with a Gateway
signature attached.

The body stays the exact bytes received -- never parsed, never re-serialized --
so the HMAC computed here is over what the Upstream will see. This is why the
handlers take the request object rather than a typed body model: letting the
framework parse the payload would reorder keys and normalize whitespace, and
the signature is over bytes, not meaning.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Coroutine
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

from hookguard_core import gatewaysig

from .config import Config, Route, config_path, load_config
from .emitter import EventEmitter, classify_reason
from .verifier import VerificationError, Verifier, VerifierDeps, build_verifier

__all__ = ["build_app", "create_app"]

log = logging.getLogger("hookguard.gateway")

#: Caps an inbound webhook body. The gateway is the only internet-facing
#: surface and must buffer each body whole to HMAC the exact bytes received,
#: so without a cap a single request could ask it to allocate without bound.
#: 5MB is far above every supported provider's largest documented payload.
MAX_BODY_BYTES = 5 << 20

#: Bounds the synchronous forward.
UPSTREAM_TIMEOUT = httpx.Timeout(30.0)


def create_app() -> FastAPI:
    """Build the app from the environment. This is the production entrypoint."""
    config = load_config(config_path())

    internal_secret = os.getenv("INTERNAL_SECRET", "").encode("utf-8")
    if not internal_secret:
        raise SystemExit("INTERNAL_SECRET not set")

    return build_app(
        config,
        internal_secret=internal_secret,
        secret_lookup=lambda name: os.getenv(name, ""),
        events_url=os.getenv("EVENTS_URL", ""),
    )


def build_app(
    config: Config,
    *,
    internal_secret: bytes,
    secret_lookup: Callable[[str], str],
    events_url: str = "",
    client: httpx.AsyncClient | None = None,
) -> FastAPI:
    """Wire routes, verifiers and the emitter into an app.

    Everything the app needs is passed in rather than read from the
    environment, so tests construct a real app without touching the process
    environment or the filesystem. ``create_app`` is the thin wrapper that does
    read the environment.

    Raises:
        SystemExit: a route names an unknown provider, or config that provider
            cannot use. Failing at construction is deliberate: a gateway that
            starts with a broken route would silently accept traffic on it.
    """
    emitter = EventEmitter(events_url, internal_secret)
    owns_client = client is None
    forward_client = client or httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await emitter.start()
        try:
            yield
        finally:
            # Drains queued events. Ordered after the server has stopped
            # accepting, so the queue being drained here is the complete one.
            await emitter.aclose()
            if owns_client:
                await forward_client.aclose()

    app = FastAPI(
        title="HookGuard",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.emitter = emitter

    # PayPal's factory needs a synchronous client for its certificate fetch.
    deps = VerifierDeps(client=httpx.Client(timeout=UPSTREAM_TIMEOUT))

    for route in config.routes:
        try:
            verifier = build_verifier(route, secret_lookup(route.secret_env), deps)
        except ValueError as e:
            raise SystemExit(f"route {route.path} (secret env {route.secret_env}): {e}") from e

        app.add_api_route(
            route.path,
            _make_handler(route, verifier, internal_secret, forward_client, emitter),
            methods=["POST"],
            include_in_schema=False,
        )
        log.info("route %s [%s] -> %s", route.path, route.provider, route.upstream)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> Response:
        return PlainTextResponse("ok\n")

    return app


def _make_handler(
    route: Route,
    verifier: Verifier,
    internal_secret: bytes,
    client: httpx.AsyncClient,
    emitter: EventEmitter,
) -> Callable[[Request], Coroutine[Any, Any, Response]]:
    async def handler(request: Request) -> Response:
        started = datetime.now(UTC)

        body = await _read_capped_body(request)
        if body is None:
            return PlainTextResponse("body too large\n", status_code=413)

        try:
            verifier.verify(body, request.headers, datetime.now(UTC))
        except VerificationError as e:
            emitter.record(
                route,
                body,
                request,
                "rejected",
                classify_reason(e),
                0,
                datetime.now(UTC) - started,
            )
            # Deliberately opaque: the caller learns the request was rejected,
            # not which check rejected it.
            return PlainTextResponse("unauthorized\n", status_code=401)

        response, status = await _forward(route, body, internal_secret, client)
        emitter.record(route, body, request, "accepted", "", status, datetime.now(UTC) - started)
        return response

    handler.__name__ = f"hook_{route.provider}"
    return handler


async def _read_capped_body(request: Request) -> bytes | None:
    """Buffer the body, or return ``None`` if it exceeds the cap.

    Streamed rather than awaited whole so an oversized body is abandoned as
    soon as it crosses the limit, instead of being buffered entirely and then
    judged.
    """
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


async def _forward(
    route: Route, body: bytes, internal_secret: bytes, client: httpx.AsyncClient
) -> tuple[Response, int]:
    """POST the unchanged bytes upstream with the Gateway signature attached.

    Returns the response to send back and the upstream's status code, or 0 if
    the request never completed against the upstream.
    """
    headers = {
        "Content-Type": "application/json",
        gatewaysig.PROVIDER_HEADER: route.provider,
        gatewaysig.HEADER: gatewaysig.sign(internal_secret, route.provider, body),
    }
    try:
        upstream = await client.post(route.upstream, content=body, headers=headers)
    except httpx.HTTPError as e:
        log.warning("upstream %s unreachable: %s", route.upstream, e)
        return PlainTextResponse("upstream unreachable\n", status_code=502), 0

    return (
        Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type"),
        ),
        upstream.status_code,
    )
