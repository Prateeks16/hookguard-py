"""Login, signup, logout and password reset.

Two properties shape almost every decision in this file.

An attacker must not learn which email addresses have accounts. Every failure
path returns the same message, and an unknown address still pays for an Argon2
verification against a dummy hash, so the response is neither distinguishable
by content nor by a stopwatch.

And a session token is minted fresh on every login, including a re-login by an
already-authenticated browser. Reusing one would leave a token an attacker
planted before the login still valid after it -- session fixation.
"""

from __future__ import annotations

import binascii
import hmac
import logging

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from ..auth import (
    SESSION_ABSOLUTE_TIMEOUT,
    PasswordPolicyError,
    dummy_hash,
    hash_password,
    hash_token,
    new_csrf_token,
    new_session_token,
    validate_password,
    verify_password,
)
from ..auth.session import SESSION_COOKIE_NAME
from ..deps import Console, console_of, require_csrf, too_many_requests
from ..middleware import safe_next
from ..store import AuthEvent, AuthEventKind, NotFoundError, Session
from ..views import client_ip, normalize_email

__all__ = [
    "handle_login",
    "handle_logout",
    "handle_reset_password",
    "handle_reset_password_form",
    "handle_signup",
]

log = logging.getLogger("hookguard.console.auth")

#: One message for every authentication failure. Distinguishing "no such user"
#: from "wrong password" turns the login form into an account enumerator.
GENERIC_AUTH_ERROR = "Invalid email or password."


def _record(console: Console, kind: str, *, email: str, ip: str, user_id: int | None) -> None:
    console.store.insert_auth_event(
        AuthEvent(
            at=int(console.now().timestamp() * 1000),
            user_id=user_id,
            email=email,
            kind=kind,
            ip=ip,
        )
    )


def _start_session(console: Console, request: Request, response: Response, user_id: int) -> None:
    """Mint a session and set its cookie."""
    token, token_hash = new_session_token()
    now = console.now()
    console.store.create_session(
        Session(
            token_hash=token_hash,
            user_id=user_id,
            csrf_token=new_csrf_token(),
            created_at=int(now.timestamp() * 1000),
            last_seen_at=int(now.timestamp() * 1000),
            expires_at=int((now + SESSION_ABSOLUTE_TIMEOUT).timestamp() * 1000),
            ip=client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
        )
    )
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=int(SESSION_ABSOLUTE_TIMEOUT.total_seconds()),
        path="/",
        httponly=True,
        # TLS is terminated by a reverse proxy ahead of the Console
        # (PRODUCTION.md). Over plain HTTP on a non-localhost host the browser
        # will not send this back and login will appear to silently fail --
        # that is the intended trade, not an oversight.
        secure=True,
        samesite="lax",
    )


async def handle_login(request: Request) -> Response:
    console = console_of(request)
    form = dict(await request.form())
    email = normalize_email(str(form.get("email", "")))
    password = str(form.get("password", ""))
    ip = client_ip(request)
    next_path = safe_next(str(form.get("next", "")))

    # Keyed on both, so one attacker cannot lock out an account by guessing at
    # it, and one address cannot be hammered from a single host.
    allowed, retry_after = console.login_limiter.allow(f"{ip}|{email}", console.now())
    if not allowed:
        return too_many_requests(retry_after.total_seconds())

    def rejected() -> Response:
        return console.render(
            "login.html",
            {
                "version": console.version,
                "error": GENERIC_AUTH_ERROR,
                "next": next_path,
                "allow_signup": console.allow_signup,
            },
        )

    try:
        user = console.store.get_user_by_email(email)
    except NotFoundError:
        # Still hash, so an unknown address costs the same as a wrong password.
        verify_password(password, dummy_hash())
        _record(console, AuthEventKind.LOGIN_FAIL, email=email, ip=ip, user_id=None)
        return rejected()

    if not user.active or not verify_password(password, user.password_hash):
        _record(console, AuthEventKind.LOGIN_FAIL, email=email, ip=ip, user_id=user.id)
        return rejected()

    _record(console, AuthEventKind.LOGIN_OK, email=email, ip=ip, user_id=user.id)
    response = RedirectResponse(next_path, status_code=303)
    _start_session(console, request, response, user.id)
    return response


async def handle_signup(request: Request) -> Response:
    console = console_of(request)
    if not console.allow_signup:
        return console.render(
            "403.html",
            {"version": console.version, "error": "Ask your admin for an invite."},
            status_code=403,
        )

    ip = client_ip(request)
    allowed, retry_after = console.signup_limiter.allow(ip, console.now())
    if not allowed:
        return too_many_requests(retry_after.total_seconds())

    form = dict(await request.form())
    email = normalize_email(str(form.get("email", "")))
    password = str(form.get("password", ""))
    confirm = str(form.get("password_confirm", ""))

    def rejected(message: str = GENERIC_AUTH_ERROR) -> Response:
        return console.render("signup.html", {"version": console.version, "error": message})

    if not email or password != confirm:
        return rejected()
    try:
        validate_password(password)
    except PasswordPolicyError as e:
        # The policy is public and stated on the form, so echoing it leaks
        # nothing -- unlike the existence of an account.
        return rejected(str(e))

    # An address that already exists returns the same generic failure as any
    # other, so signup cannot be used to enumerate accounts either.
    try:
        console.store.get_user_by_email(email)
    except NotFoundError:
        pass
    else:
        return rejected()

    # The first account is the admin: someone has to be, and asking a
    # single-operator install to bootstrap a role is friction for nothing.
    role = "admin" if console.store.count_users() == 0 else "member"

    try:
        user_id = console.store.create_user(
            email, hash_password(password), role, int(console.now().timestamp() * 1000)
        )
    except Exception:
        # Most likely the UNIQUE constraint losing a race with another signup.
        log.warning("signup failed for %r", email, exc_info=True)
        return rejected()

    _record(console, AuthEventKind.USER_CREATE, email=email, ip=ip, user_id=user_id)
    response = RedirectResponse("/dashboard", status_code=303)
    _start_session(console, request, response, user_id)
    return response


async def handle_logout(request: Request) -> Response:
    console = console_of(request)
    form = dict(await request.form())
    session = require_csrf(request, {k: str(v) for k, v in form.items()})

    console.store.delete_session(session.id)
    user = request.state.user
    _record(
        console,
        AuthEventKind.LOGOUT,
        email=user.email if user else "",
        ip=client_ip(request),
        user_id=session.user_id,
    )

    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------
#
# Operator-run: `hookguard-console reset-password <email>` prints a one-time
# URL handed over out of band. There is no SMTP in this system, which removes
# a whole category of deployment and deliverability problems from a
# self-hosted tool.


def _reset_key(user_id: int) -> str:
    return f"pwreset:{user_id}"


def _consume_reset_token(console: Console, user_id: int, token: str) -> bool:
    """Validate a reset token and burn it.

    Deleted whether or not the password change then succeeds: a token that
    survived a failed attempt would be reusable, and the operator can always
    mint another.
    """
    try:
        stored = console.store.get_setting(_reset_key(user_id))
    except NotFoundError:
        return False

    digest_hex, _, expires_raw = stored.partition(":")
    try:
        stored_digest = bytes.fromhex(digest_hex)
        expires_at_ms = int(expires_raw)
    except (ValueError, binascii.Error):
        return False

    if console.now().timestamp() * 1000 > expires_at_ms:
        console.store.delete_setting(_reset_key(user_id))
        return False

    if not hmac.compare_digest(hash_token(token), stored_digest):
        return False

    console.store.delete_setting(_reset_key(user_id))
    return True


async def handle_reset_password_form(request: Request) -> Response:
    console = console_of(request)
    token = request.query_params.get("token", "")
    uid = request.query_params.get("uid", "")
    if not token or not uid:
        return console.render("404.html", {"version": console.version}, status_code=404)
    return console.render(
        "reset_password.html",
        {"version": console.version, "reset_token": token, "reset_uid": uid},
    )


async def handle_reset_password(request: Request) -> Response:
    console = console_of(request)
    form = dict(await request.form())
    token = str(form.get("token", ""))
    password = str(form.get("password", ""))
    confirm = str(form.get("password_confirm", ""))

    def rejected(message: str) -> Response:
        return console.render(
            "reset_password.html",
            {
                "version": console.version,
                "error": message,
                "reset_token": token,
                "reset_uid": str(form.get("uid", "")),
            },
            status_code=400,
        )

    try:
        user_id = int(str(form.get("uid", "")))
    except ValueError:
        return rejected("Invalid reset link.")

    if not _consume_reset_token(console, user_id, token):
        return rejected("This reset link is invalid or has expired.")
    if password != confirm:
        return rejected("Passwords do not match.")
    try:
        validate_password(password)
    except PasswordPolicyError as e:
        return rejected(str(e))

    console.store.update_password_hash(user_id, hash_password(password))
    # Every existing session is a session opened with the old password, and
    # the usual reason to reset one is that it was compromised.
    console.store.delete_sessions_for_user_except(user_id, keep_id=0)
    _record(
        console,
        AuthEventKind.PASSWORD_CHANGE,
        email="",
        ip=client_ip(request),
        user_id=user_id,
    )
    return RedirectResponse("/login", status_code=303)
