"""Session loading, security headers and the redirect guard.

Ported from web/internal/server/middleware.go.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from hookguard_console.auth import (
    SESSION_COOKIE_NAME,
    hash_token,
    new_csrf_token,
    new_session_token,
)
from hookguard_console.auth.session import SESSION_IDLE_TIMEOUT
from hookguard_console.middleware import (
    SECURITY_HEADERS,
    SessionMiddleware,
    safe_next,
    security_headers_middleware,
)
from hookguard_console.store import NotFoundError, Session, Store, open_store

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def ms(moment: datetime) -> int:
    return int(moment.timestamp() * 1000)


@pytest.fixture
def store(tmp_path: Path) -> Store:
    st = open_store(tmp_path / "console.db")
    yield st
    st.close()


def build_client(store: Store, now: datetime = NOW) -> TestClient:
    async def whoami(request: Request) -> JSONResponse:
        user = request.state.user
        session = request.state.session
        return JSONResponse(
            {
                "email": user.email if user else None,
                "session_id": session.id if session else None,
            }
        )

    app = Starlette(
        routes=[Route("/whoami", whoami)],
        middleware=[
            Middleware(BaseHTTPMiddleware, dispatch=security_headers_middleware),
            Middleware(SessionMiddleware, store=store, now=lambda: now),
        ],
    )
    return TestClient(app)


def seed_session(store: Store, *, last_seen: datetime, expires: datetime, active: bool = True):
    uid = store.create_user("a@example.com", "$argon2id$x", "admin", ms(NOW))
    if not active:
        store.set_user_active(uid, False)
    token, token_hash = new_session_token()
    sid = store.create_session(
        Session(
            token_hash=token_hash,
            user_id=uid,
            csrf_token=new_csrf_token(),
            created_at=ms(NOW),
            last_seen_at=ms(last_seen),
            expires_at=ms(expires),
        )
    )
    return token, sid


# --------------------------------------------------------------------------
# Security headers
# --------------------------------------------------------------------------


def test_every_response_carries_the_security_headers(store: Store) -> None:
    response = build_client(store).get("/whoami")
    for header, value in SECURITY_HEADERS.items():
        assert response.headers[header] == value


def test_the_csp_has_no_exceptions(store: Store) -> None:
    """htmx is configured through attributes and the theme toggle is an
    external file, so nothing here needs inline script."""
    csp = build_client(store).get("/whoami").headers["Content-Security-Policy"]
    assert csp == "default-src 'self'"
    assert "unsafe-inline" not in csp


# --------------------------------------------------------------------------
# Session loading
# --------------------------------------------------------------------------


def test_no_cookie_is_anonymous_not_an_error(store: Store) -> None:
    """Session loading never blocks a request -- route dependencies decide
    what needs auth."""
    body = build_client(store).get("/whoami").json()
    assert body == {"email": None, "session_id": None}


def test_a_valid_session_attaches_the_user(store: Store) -> None:
    token, sid = seed_session(store, last_seen=NOW, expires=NOW + timedelta(days=1))
    client = build_client(store)
    client.cookies.set(SESSION_COOKIE_NAME, token)
    assert client.get("/whoami").json() == {"email": "a@example.com", "session_id": sid}


def test_an_unknown_token_is_anonymous(store: Store) -> None:
    client = build_client(store)
    client.cookies.set(SESSION_COOKIE_NAME, "not-a-real-token")
    assert client.get("/whoami").json()["email"] is None


def test_an_expired_session_is_deleted_not_merely_ignored(store: Store) -> None:
    """A stolen cookie must stop being useful at the moment it stops being
    valid, rather than lingering as a row until something cleans it up."""
    token, _ = seed_session(store, last_seen=NOW, expires=NOW - timedelta(seconds=1))
    client = build_client(store)
    client.cookies.set(SESSION_COOKIE_NAME, token)

    assert client.get("/whoami").json()["email"] is None
    with pytest.raises(NotFoundError):
        store.get_session_by_token_hash(hash_token(token))


def test_an_idle_session_expires_even_within_its_absolute_cap(store: Store) -> None:
    """Two independent limits: either lapsing ends the session."""
    token, _ = seed_session(
        store,
        last_seen=NOW - SESSION_IDLE_TIMEOUT - timedelta(minutes=1),
        expires=NOW + timedelta(days=365),
    )
    client = build_client(store)
    client.cookies.set(SESSION_COOKIE_NAME, token)
    assert client.get("/whoami").json()["email"] is None


def test_a_deactivated_user_loses_their_session_immediately(store: Store) -> None:
    """Deactivation must take effect now, not whenever the session happens to
    expire -- otherwise removing someone's access does nothing for a week."""
    token, _ = seed_session(store, last_seen=NOW, expires=NOW + timedelta(days=1), active=False)
    client = build_client(store)
    client.cookies.set(SESSION_COOKIE_NAME, token)
    assert client.get("/whoami").json()["email"] is None


def test_last_seen_is_touched_when_stale(store: Store) -> None:
    token, sid = seed_session(
        store, last_seen=NOW - timedelta(minutes=5), expires=NOW + timedelta(days=1)
    )
    client = build_client(store)
    client.cookies.set(SESSION_COOKIE_NAME, token)
    client.get("/whoami")

    session = store.list_sessions_for_user(1)[0]
    assert session.id == sid
    assert session.last_seen_at == ms(NOW)


def test_last_seen_is_not_written_on_every_request(store: Store) -> None:
    """Every page view becoming a database write would be a needless load on a
    single-writer database."""
    token, _ = seed_session(
        store, last_seen=NOW - timedelta(seconds=5), expires=NOW + timedelta(days=1)
    )
    original = store.list_sessions_for_user(1)[0].last_seen_at

    client = build_client(store)
    client.cookies.set(SESSION_COOKIE_NAME, token)
    client.get("/whoami")

    assert store.list_sessions_for_user(1)[0].last_seen_at == original


# --------------------------------------------------------------------------
# The redirect guard
# --------------------------------------------------------------------------


def test_a_local_path_is_allowed() -> None:
    assert safe_next("/dashboard/logs") == "/dashboard/logs"
    assert safe_next("/dashboard/logs?provider=stripe") == "/dashboard/logs?provider=stripe"


@pytest.mark.parametrize(
    ("hostile", "why"),
    [
        ("//evil.example", "protocol-relative: the browser leaves the site"),
        ("/\\evil.example", "backslash is read as a slash by some browsers"),
        ("https://evil.example", "absolute URL"),
        ("http://evil.example", "absolute URL"),
        ("evil.example", "not absolute"),
        ("", "empty"),
        (None, "absent"),
    ],
)
def test_the_redirect_guard_rejects_anything_off_site(hostile: str | None, why: str) -> None:
    """An open redirect off a real login page is a ready-made phishing step."""
    assert safe_next(hostile) == "/dashboard", why
