"""Settings: profile, sessions, users, instance configuration, security log."""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from typing import Any

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from ..auth import (
    PasswordPolicyError,
    hash_password,
    validate_password,
    verify_password,
)
from ..deps import console_of, require_admin, require_auth, require_csrf
from ..store import AuthEventKind, NotFoundError
from ..views import client_ip, format_timestamp_ms, normalize_email, page_context
from .auth import _record

__all__ = [
    "handle_password_change",
    "handle_retention_change",
    "handle_session_revoke",
    "handle_session_revoke_others",
    "handle_settings",
    "handle_user_create",
    "handle_user_deactivate",
]

log = logging.getLogger("hookguard.console.settings")

AUTH_LOG_LIMIT = 50


@dataclass(frozen=True, slots=True)
class SessionRow:
    id: int
    created_at: str
    last_seen_at: str
    ip: str
    user_agent: str


@dataclass(frozen=True, slots=True)
class UserRow:
    id: int
    email: str
    role: str
    active: bool
    created_at: str


@dataclass(frozen=True, slots=True)
class AuthEventRow:
    at: str
    kind: str
    email: str
    ip: str


def _render(request: Request, **messages: str) -> Response:
    """The Settings page. Every action redisplays it, so building it lives here.

    The admin-only sections are gated on the user's role rather than on which
    route was hit, so a member who somehow reaches this handler still sees a
    member's page.
    """
    console = console_of(request)
    user = request.state.user
    session = request.state.session

    context: dict[str, Any] = {
        "sessions": [
            SessionRow(
                id=s.id,
                created_at=format_timestamp_ms(s.created_at),
                last_seen_at=format_timestamp_ms(s.last_seen_at),
                ip=s.ip,
                user_agent=s.user_agent,
            )
            for s in console.store.list_sessions_for_user(user.id)
        ],
        "current_session_id": session.id if session else 0,
        "retention_days": console.store.get_retention_days(),
        "data_dir": console.data_dir,
        "auth_events": [
            AuthEventRow(at=format_timestamp_ms(e.at), kind=e.kind, email=e.email, ip=e.ip)
            for e in console.store.list_auth_events(AUTH_LOG_LIMIT)
        ],
        "users": [],
        **messages,
    }

    if user.role == "admin":
        context["users"] = [
            UserRow(
                id=u.id,
                email=u.email,
                role=u.role,
                active=u.active,
                created_at=format_timestamp_ms(u.created_at),
            )
            for u in console.store.list_users()
        ]

    return console.render(
        "settings.html",
        page_context(
            request,
            store=console.store,
            version=console.version,
            now=console.now(),
            nav_active="settings",
            **context,
        ),
    )


async def handle_settings(request: Request) -> Response:
    require_auth(request)
    return _render(request)


async def handle_password_change(request: Request) -> Response:
    console = console_of(request)
    user = require_auth(request)
    form = {k: str(v) for k, v in (await request.form()).items()}
    session = require_csrf(request, form)

    current = form.get("current_password", "")
    new = form.get("new_password", "")
    confirm = form.get("new_password_confirm", "")

    # Requiring the current password is what stops a borrowed, unlocked
    # browser from becoming permanent access.
    if not verify_password(current, user.password_hash):
        return _render(request, password_error="Current password is incorrect.")
    if new != confirm:
        return _render(request, password_error="New passwords do not match.")
    try:
        validate_password(new)
    except PasswordPolicyError as e:
        return _render(request, password_error=str(e))

    console.store.update_password_hash(user.id, hash_password(new))
    # Every other session predates the change; the usual reason to change a
    # password is that someone else may have had it.
    console.store.delete_sessions_for_user_except(user.id, session.id)
    _record(
        console,
        AuthEventKind.PASSWORD_CHANGE,
        email=user.email,
        ip=client_ip(request),
        user_id=user.id,
    )
    return _render(request, password_ok="Password changed. Other sessions were signed out.")


async def handle_session_revoke(request: Request) -> Response:
    console = console_of(request)
    user = require_auth(request)
    form = {k: str(v) for k, v in (await request.form()).items()}
    require_csrf(request, form)

    try:
        target = int(request.path_params["session_id"])
    except ValueError:
        return RedirectResponse("/dashboard/settings", status_code=303)

    # Only your own sessions: the id comes from the page, and the page only
    # lists yours, but the check belongs here rather than in the template.
    if any(s.id == target for s in console.store.list_sessions_for_user(user.id)):
        console.store.delete_session(target)
        _record(
            console,
            AuthEventKind.SESSION_REVOKE,
            email=user.email,
            ip=client_ip(request),
            user_id=user.id,
        )
    return RedirectResponse("/dashboard/settings", status_code=303)


async def handle_session_revoke_others(request: Request) -> Response:
    console = console_of(request)
    user = require_auth(request)
    form = {k: str(v) for k, v in (await request.form()).items()}
    session = require_csrf(request, form)

    console.store.delete_sessions_for_user_except(user.id, session.id)
    _record(
        console,
        AuthEventKind.SESSION_REVOKE,
        email=user.email,
        ip=client_ip(request),
        user_id=user.id,
    )
    return RedirectResponse("/dashboard/settings", status_code=303)


async def handle_retention_change(request: Request) -> Response:
    console = console_of(request)
    require_auth(request)
    form = {k: str(v) for k, v in (await request.form()).items()}
    require_csrf(request, form)

    try:
        days = int(form.get("retention_days", ""))
    except ValueError:
        return _render(request, retention_error="Retention must be a whole number of days.")
    if days < 1:
        return _render(request, retention_error="Retention must be at least one day.")

    console.store.set_retention_days(days)
    return _render(request)


async def handle_user_create(request: Request) -> Response:
    console = console_of(request)
    admin = require_admin(request)
    form = {k: str(v) for k, v in (await request.form()).items()}
    require_csrf(request, form)

    email = normalize_email(form.get("email", ""))
    password = form.get("password", "")
    role = form.get("role", "member")

    if not email:
        return _render(request, user_error="Email is required.")
    if role not in {"admin", "member"}:
        return _render(request, user_error="Unknown role.")
    try:
        validate_password(password)
    except PasswordPolicyError as e:
        return _render(request, user_error=str(e))

    try:
        user_id = console.store.create_user(
            email, hash_password(password), role, int(console.now().timestamp() * 1000)
        )
    except sqlite3.IntegrityError:
        # Admin-only page, so naming the conflict leaks nothing an admin
        # cannot already see on the user list above.
        return _render(request, user_error="A user with that email already exists.")

    _record(
        console,
        AuthEventKind.USER_CREATE,
        email=email,
        ip=client_ip(request),
        user_id=user_id,
    )
    _ = admin
    return RedirectResponse("/dashboard/settings", status_code=303)


async def handle_user_deactivate(request: Request) -> Response:
    console = console_of(request)
    admin = require_admin(request)
    form = {k: str(v) for k, v in (await request.form()).items()}
    require_csrf(request, form)

    try:
        target_id = int(request.path_params["user_id"])
        target = console.store.get_user_by_id(target_id)
    except (NotFoundError, ValueError):
        return RedirectResponse("/dashboard/settings", status_code=303)

    # Locking yourself out of your own instance is not a recoverable mistake
    # on a single-admin install.
    if target_id == admin.id:
        return _render(request, user_error="You cannot deactivate your own account.")

    console.store.set_user_active(target_id, not target.active)
    return RedirectResponse("/dashboard/settings", status_code=303)
