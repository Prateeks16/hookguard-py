"""Public pages: the landing page, the playground, health, and 404."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..deps import console_of
from ..middleware import safe_next

__all__ = ["handle_healthz", "handle_landing", "handle_not_found", "handle_playground"]


async def handle_landing(request: Request) -> Response:
    console = console_of(request)
    return console.render("landing.html", {"version": console.version})


async def handle_playground(request: Request) -> Response:
    """The client-side signature-verification demo.

    No gateway call and no backend logic -- the page's own JavaScript holds
    canned scenarios. Public, same as the landing page, because its whole
    purpose is explaining the product to someone who has not deployed it.
    """
    console = console_of(request)
    return console.render("playground.html", {"version": console.version})


async def handle_healthz(request: Request) -> Response:
    return JSONResponse({"status": "ok", "version": console_of(request).version})


async def handle_login_form(request: Request) -> Response:
    console = console_of(request)
    return console.render(
        "login.html",
        {
            "version": console.version,
            "next": safe_next(request.query_params.get("next")),
            "allow_signup": console.allow_signup,
        },
    )


async def handle_signup_form(request: Request) -> Response:
    console = console_of(request)
    if not console.allow_signup:
        return console.render(
            "403.html",
            {"version": console.version, "error": "Ask your admin for an invite."},
            status_code=403,
        )
    return console.render("signup.html", {"version": console.version})


async def handle_not_found(request: Request, exc: Exception) -> Response:
    console = console_of(request)
    return console.render(
        "404.html", {"version": console.version, "user": request.state.user}, status_code=404
    )
