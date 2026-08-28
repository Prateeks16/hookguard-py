"""Provider signers and the recording upstream, for the gateway suite.

These build each header by hand from the documented algorithm rather than
calling our own verifier's internals. A helper that reused production code
would make every test that depends on it tautological.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass, field

from starlette.datastructures import Headers


def stripe_header(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return f"t={timestamp},v1={mac.hexdigest()}"


def github_header(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def shopify_header(secret: str, body: bytes) -> str:
    return base64.b64encode(hmac.new(secret.encode(), body, hashlib.sha256).digest()).decode()


def headers(**kwargs: str) -> Headers:
    """Case-insensitive headers, as Starlette hands a real request's to us."""
    return Headers({k.replace("_", "-"): v for k, v in kwargs.items()})


@dataclass
class RecordingUpstream:
    """An ASGI app standing in for the protected application.

    Records exactly what it received so a test can assert on the bytes rather
    than on a re-serialization of them.
    """

    status: int = 200
    body: bytes = b"ok\n"
    received_body: bytes | None = None
    received_headers: dict[str, str] = field(default_factory=dict)
    calls: int = 0

    async def __call__(self, scope, receive, send) -> None:
        assert scope["type"] == "http"
        chunks = []
        while True:
            message = await receive()
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        self.received_body = b"".join(chunks)
        self.received_headers = {k.decode(): v.decode() for k, v in scope["headers"]}
        self.calls += 1
        await send(
            {
                "type": "http.response.start",
                "status": self.status,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": self.body})
