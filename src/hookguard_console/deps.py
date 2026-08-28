"""Route guards and the per-request application handle.

Go wrapped each protected handler with ``requireAuth``/``requireAdmin`` at the
router. These are the same checks as small helpers a handler calls first,
which keeps the redirect and the 403 page in one place instead of every
handler re-implementing "who is this and are they allowed".
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from jinja2 import Environment
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response

from .auth import Limiter
from .middleware import check_request_csrf
from .store import Session, Store, User
from .templating import render

if TYPE_CHECKING:
    from .batcher import Batcher
    from .retention import RetentionJob

__all__ = [
    "Console",
    "Redirect",
    "console_of",
    "require_admin",
    "require_auth",
    "require_csrf",
    "too_many_requests",
]


@dataclass
class Console:
    """Everything the handlers need, hung off ``app.state``."""

    store: Store
    env: Environment
    version: str
    allow_signup: bool
    internal_secret: bytes
    data_dir: str
    login_limiter: Limiter
    signup_limiter: Limiter
    batcher: Batcher | None = None
    retention: RetentionJob | None = None

    #: Injected so tests can pin the clock rather than sleep. Required
    #: rather than defaulted: a Console built with a real clock by accident
    #: would make time-dependent tests flaky in a way that is hard to trace.
    now: Callable[[], datetime] = field(default_factory=lambda: lambda: datetime.now(UTC))

    def render(self, name: str, context: dict[str, Any], status_code: int = 200) -> Response:
        return render(self.env, name, context, status_code)


def console_of(request: Request) -> Console:
    return request.app.state.console


class Redirect(Exception):
    """Raised by a guard to send the caller somewhere else.

    An exception rather than a returned response because the guards are called
    at the top of a handler: returning would need every call site to check and
    forward the result, which is exactly the boilerplate the guards exist to
    remove.
    """

    def __init__(self, response: Response) -> None:
        super().__init__()
        self.response = response


def require_auth(request: Request) -> User:
    """The signed-in user, or a redirect to the login page.

    The ``next`` parameter carries the path so signing in returns the operator
    where they were going. It is sanitized on the way back out, not here.
    """
    user = request.state.user
    if user is None:
        raise Redirect(RedirectResponse(f"/login?next={request.url.path}", status_code=303))
    return user


def require_admin(request: Request) -> User:
    """Additionally require the admin role.

    Server-side, independent of whether the UI hides the link: hiding a
    control is presentation, not authorization.
    """
    user = require_auth(request)
    if user.role != "admin":
        console = console_of(request)
        raise Redirect(
            console.render("403.html", {"user": user, "error": "Admins only."}, status_code=403)
        )
    return user


def require_csrf(request: Request, form: dict[str, str]) -> Session:
    """Verify the synchronizer token on a state-changing request.

    Mandatory on every non-GET route. SameSite=Lax on the cookie helps but is
    a backstop, not the mechanism -- it depends on browser behaviour we do not
    control and does not cover every request shape.
    """
    session = request.state.session
    if not check_request_csrf(request, session, form):
        raise Redirect(PlainTextResponse("invalid or missing CSRF token", status_code=403))
    return session


def too_many_requests(retry_after_seconds: float) -> Response:
    """The rate-limited response, with a Retry-After the client can act on."""
    seconds = max(1, int(retry_after_seconds))
    return PlainTextResponse(
        "Too many attempts. Try again later.",
        status_code=429,
        headers={"Retry-After": str(seconds)},
    )
