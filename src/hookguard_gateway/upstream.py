"""A sample protected application.

It trusts nothing on the network: a request is accepted only if the Gateway
signature verifies against the shared ``INTERNAL_SECRET``. A real upstream
reimplements this one check, in any language -- replacing the four bespoke
Provider verifications it would otherwise need.

This is the whole point of the gateway, in about thirty lines.
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

from hookguard_core import gatewaysig

__all__ = ["build_app", "create_app"]

log = logging.getLogger("hookguard.upstream")


def create_app() -> FastAPI:
    secret = os.getenv("INTERNAL_SECRET", "").encode("utf-8")
    if not secret:
        raise SystemExit("INTERNAL_SECRET not set")
    return build_app(secret)


def build_app(secret: bytes) -> FastAPI:
    app = FastAPI(
        title="HookGuard sample upstream", docs_url=None, redoc_url=None, openapi_url=None
    )

    @app.post("/{path:path}", include_in_schema=False)
    async def receive(request: Request, path: str) -> Response:
        body = await request.body()
        provider = request.headers.get(gatewaysig.PROVIDER_HEADER, "")
        signature = request.headers.get(gatewaysig.HEADER, "")

        try:
            gatewaysig.verify(secret, provider, body, signature)
        except gatewaysig.GatewaySignatureError as e:
            log.warning("REJECT /%s: %s", path, e)
            return PlainTextResponse("gateway signature invalid\n", status_code=401)

        log.info("ACCEPT /%s [%s] %d bytes", path, provider, len(body))
        return PlainTextResponse("ok\n")

    return app
