"""The ingest endpoint the gateway posts verdicts to.

Authenticated by the Gateway signature, not by a session: the caller is the
gateway's event emitter, not a browser, and it has no cookie.

The order is deliberate and load-bearing: check the claimed identity, then the
signature, then decode, then enqueue. A bad signature must never cause a
write, and a malformed body carrying a valid signature over those exact bytes
must be refused without one either -- otherwise a gateway with the right
secret could still corrupt the log by sending nonsense.
"""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

from ..deps import console_of
from ..ingest import (
    PROVIDER_HEADER,
    SIGNATURE_HEADER,
    IngestError,
    check_provider_header,
    decode,
    to_row,
    verify,
)

__all__ = ["handle_ingest"]


async def handle_ingest(request: Request) -> Response:
    console = console_of(request)
    body = await request.body()

    try:
        check_provider_header(request.headers.get(PROVIDER_HEADER, ""))
        # An unset INTERNAL_SECRET rejects everything here, because no request
        # could verify against an empty key. That is the safe default -- there
        # is no accept-everything mode.
        verify(console.internal_secret, body, request.headers.get(SIGNATURE_HEADER, ""))
    except IngestError:
        # Deliberately opaque: the sender learns it was refused, not which
        # check refused it.
        return PlainTextResponse("unauthorized", status_code=401)

    try:
        event = decode(body)
    except IngestError:
        return PlainTextResponse("malformed event", status_code=400)

    if console.batcher is not None:
        console.batcher.enqueue(to_row(event))

    # Accepted, not OK: the write has been queued, not performed. Telling the
    # gateway otherwise would be a lie it might act on.
    return PlainTextResponse("", status_code=202)
