"""Session loading, CSRF, and the fixed security headers.

Session loading never blocks a request: it attaches the user when there is
one, and route-level dependencies decide what actually requires auth. Keeping
those separate means an anonymous request to a public page costs one cookie
check, and every protected route shares one implementation of "who is this".
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from .auth import CSRF_FORM_FIELD, CSRF_HEADER, SESSION_COOKIE_NAME, check_csrf, hash_token
from .auth.session import SESSION_IDLE_TIMEOUT
from .store import NotFoundError, Session, Store, User

__all__ = [
    "SECURITY_HEADERS",
    "SessionMiddleware",
    "check_request_csrf",
    "safe_next",
    "security_headers_middleware",
]

#: Applied to every response. The CSP has no exceptions: htmx is configured
#: through attributes and the theme toggle is an external file, so nothing in
#: this application needs inline script.
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
}

#: A session's last-seen timestamp is only written this often, rather than on
#: every request -- otherwise every page view is a database write against a
#: single-writer database.
TOUCH_INTERVAL = timedelta(minutes=1)


async def security_headers_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    response = await call_next(request)
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response


class SessionMiddleware:
    """Attaches ``request.state.user`` and ``request.state.session``.

    Both are ``None`` for an anonymous request. Expired sessions are deleted
    on sight rather than merely ignored, so a stolen cookie stops being useful
    at the same moment it stops being valid.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        store: Store,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.app = app
        self._store = store
        self._now = now

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        user, session = self._load(request)
        scope["state"] = {**scope.get("state", {}), "user": user, "session": session}
        await self.app(scope, receive, send)

    def _load(self, request: Request) -> tuple[User | None, Session | None]:
        token = request.cookies.get(SESSION_COOKIE_NAME)
        if not token:
            return None, None

        try:
            session = self._store.get_session_by_token_hash(hash_token(token))
        except NotFoundError:
            return None, None

        now = self._now()
        expires_at = datetime.fromtimestamp(session.expires_at / 1000, tz=UTC)
        last_seen = datetime.fromtimestamp(session.last_seen_at / 1000, tz=UTC)

        # Two independent limits: an absolute cap, and an idle window that
        # slides. Either one lapsing ends the session.
        if now > expires_at or now > last_seen + SESSION_IDLE_TIMEOUT:
            self._store.delete_session(session.id)
            return None, None

        if now - last_seen > TOUCH_INTERVAL:
            self._store.touch_session(session.id, int(now.timestamp() * 1000))

        try:
            user = self._store.get_user_by_id(session.user_id)
        except NotFoundError:
            return None, None

        # A deactivated user's existing sessions stop working immediately,
        # rather than lingering until they happen to expire.
        if not user.active:
            return None, None

        return user, session


def check_request_csrf(request: Request, session: Session | None, form: dict[str, str]) -> bool:
    """Whether the request carries the session's CSRF token.

    Accepts it from the header htmx sends or from a form field, so the
    no-JavaScript path is protected identically rather than exempted.
    """
    got = request.headers.get(CSRF_HEADER) or form.get(CSRF_FORM_FIELD, "")
    if session is None:
        return False
    return check_csrf(session.csrf_token, got)


def safe_next(next_path: str | None) -> str:
    """Sanitize a ``?next=`` redirect target.

    Only a local absolute path is allowed. Rejecting a leading ``//`` matters
    as much as rejecting a scheme: browsers read ``//evil.example`` as
    protocol-relative and would leave the site, which is an open redirect and
    a ready-made phishing step off a real login page.
    """
    if not next_path or not next_path.startswith("/") or next_path.startswith("//"):
        return "/dashboard"
    # A backslash is treated as a slash by some browsers in URL parsing, so
    # "/\evil.example" can escape the origin the same way "//" does.
    if next_path.startswith("/\\"):
        return "/dashboard"
    return next_path
