"""Route (endpoint) management and the config.json export.

Form submissions are validated against the same rules the Gateway's verifier
factories apply, before anything touches the database. A bad submission comes
back as a form error rather than as a database constraint violation, which is
both a better message and the difference between a 400 and a 500.
"""

from __future__ import annotations

import logging
import sqlite3

from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response

from .. import gwconfig
from ..deps import console_of, require_auth, require_csrf
from ..gwconfig import ConfigValidationError
from ..store import Endpoint, NotFoundError
from ..views import page_context

__all__ = [
    "handle_endpoint_create",
    "handle_endpoint_delete",
    "handle_endpoint_edit_form",
    "handle_endpoint_export_download",
    "handle_endpoint_export_preview",
    "handle_endpoint_new_form",
    "handle_endpoint_toggle_active",
    "handle_endpoint_update",
    "handle_endpoints_list",
]

log = logging.getLogger("hookguard.console.endpoints")


def _form_endpoint(form: dict[str, str], endpoint_id: int = 0) -> Endpoint:
    return Endpoint(
        id=endpoint_id,
        path=str(form.get("path", "")).strip(),
        provider=str(form.get("provider", "")).strip(),
        upstream_url=str(form.get("upstream_url", "")).strip(),
        replay_window=str(form.get("replay_window", "")).strip(),
        secret_env=str(form.get("secret_env", "")).strip(),
        webhook_id=str(form.get("webhook_id", "")).strip(),
    )


def _validate(endpoint: Endpoint) -> str:
    """Return a human message, or "" when the route is usable.

    Delegates the provider-shape rules to gwconfig so this and the export
    cannot disagree about what a valid route is, and adds the two checks that
    are about the form rather than the gateway.
    """
    if not endpoint.path:
        return "Path is required."
    if not endpoint.path.startswith("/"):
        return "Path must start with /."
    if not endpoint.upstream_url:
        return "Upstream URL is required."

    try:
        gwconfig.validate(gwconfig.from_endpoint(endpoint))
    except ConfigValidationError as e:
        message = str(e)
        if "requires secret_env" in message:
            return "This provider requires the name of a secret environment variable."
        if "requires webhook_id" in message:
            return "PayPal requires a webhook ID."
        if "replay_window" in message:
            return 'Replay window must be a Go duration like "5m" (or left blank).'
        if "unknown provider" in message:
            return "Unknown provider."
        return message
    return ""


def _db_error_message(error: Exception) -> str:
    text = str(error).lower()
    if "unique" in text and "path" in text:
        return "A route with that path already exists."
    if "check" in text:
        return "That combination of provider and fields is not allowed."
    log.warning("unexpected database error saving a route", exc_info=error)
    return "Could not save the route."


def _render_form(
    request: Request, endpoint: Endpoint, *, is_new: bool, error: str = "", status: int = 200
) -> Response:
    console = console_of(request)
    return console.render(
        "endpoint_form.html",
        page_context(
            request,
            store=console.store,
            version=console.version,
            now=console.now(),
            nav_active="endpoints",
            endpoint=endpoint,
            is_new=is_new,
            form_error=error,
        ),
        status_code=status,
    )


async def handle_endpoints_list(request: Request) -> Response:
    console = console_of(request)
    require_auth(request)
    return console.render(
        "endpoints.html",
        page_context(
            request,
            store=console.store,
            version=console.version,
            now=console.now(),
            nav_active="endpoints",
            endpoints=console.store.list_endpoints(),
        ),
    )


async def handle_endpoint_new_form(request: Request) -> Response:
    require_auth(request)
    # Pre-selecting stripe means the provider-specific fields are consistent
    # with the select on first paint.
    return _render_form(request, Endpoint(provider="stripe", replay_window="5m"), is_new=True)


async def handle_endpoint_edit_form(request: Request) -> Response:
    console = console_of(request)
    require_auth(request)
    try:
        endpoint = console.store.get_endpoint_by_id(int(request.path_params["endpoint_id"]))
    except (NotFoundError, ValueError):
        return console.render("404.html", {"version": console.version}, status_code=404)
    return _render_form(request, endpoint, is_new=False)


async def handle_endpoint_create(request: Request) -> Response:
    console = console_of(request)
    require_auth(request)
    form = {k: str(v) for k, v in (await request.form()).items()}
    require_csrf(request, form)

    endpoint = _form_endpoint(form)
    error = _validate(endpoint)
    if error:
        return _render_form(request, endpoint, is_new=True, error=error, status=400)

    now_ms = int(console.now().timestamp() * 1000)
    endpoint.created_at = endpoint.updated_at = now_ms
    endpoint.active = True
    try:
        console.store.create_endpoint(endpoint)
    except sqlite3.Error as e:
        return _render_form(request, endpoint, is_new=True, error=_db_error_message(e), status=400)

    return RedirectResponse("/dashboard/endpoints", status_code=303)


async def handle_endpoint_update(request: Request) -> Response:
    console = console_of(request)
    require_auth(request)
    form = {k: str(v) for k, v in (await request.form()).items()}
    require_csrf(request, form)

    try:
        endpoint_id = int(request.path_params["endpoint_id"])
        existing = console.store.get_endpoint_by_id(endpoint_id)
    except (NotFoundError, ValueError):
        return console.render("404.html", {"version": console.version}, status_code=404)

    endpoint = _form_endpoint(form, endpoint_id)
    error = _validate(endpoint)
    if error:
        return _render_form(request, endpoint, is_new=False, error=error, status=400)

    endpoint.updated_at = int(console.now().timestamp() * 1000)
    endpoint.created_at = existing.created_at
    # active is not in the form: editing a route must not silently re-enable a
    # disabled one. Toggling is its own action.
    endpoint.active = existing.active
    try:
        console.store.update_endpoint(endpoint)
    except sqlite3.Error as e:
        return _render_form(request, endpoint, is_new=False, error=_db_error_message(e), status=400)

    return RedirectResponse("/dashboard/endpoints", status_code=303)


async def handle_endpoint_delete(request: Request) -> Response:
    console = console_of(request)
    require_auth(request)
    form = (
        {k: str(v) for k, v in (await request.form()).items()} if request.method == "POST" else {}
    )
    require_csrf(request, form)

    try:
        console.store.delete_endpoint(int(request.path_params["endpoint_id"]))
    except ValueError:
        return console.render("404.html", {"version": console.version}, status_code=404)
    return RedirectResponse("/dashboard/endpoints", status_code=303)


async def handle_endpoint_toggle_active(request: Request) -> Response:
    console = console_of(request)
    require_auth(request)
    form = {k: str(v) for k, v in (await request.form()).items()}
    require_csrf(request, form)

    try:
        endpoint_id = int(request.path_params["endpoint_id"])
        endpoint = console.store.get_endpoint_by_id(endpoint_id)
    except (NotFoundError, ValueError):
        return console.render("404.html", {"version": console.version}, status_code=404)

    console.store.set_endpoint_active(
        endpoint_id, not endpoint.active, int(console.now().timestamp() * 1000)
    )
    return RedirectResponse("/dashboard/endpoints", status_code=303)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def _export_json(request: Request) -> str:
    console = console_of(request)
    return gwconfig.marshal(gwconfig.export(console.store.list_active_endpoints()))


async def handle_endpoint_export_preview(request: Request) -> Response:
    console = console_of(request)
    require_auth(request)
    return console.render(
        "endpoint_export.html",
        page_context(
            request,
            store=console.store,
            version=console.version,
            now=console.now(),
            nav_active="endpoints",
            config_json=_export_json(request),
        ),
    )


async def handle_endpoint_export_download(request: Request) -> Response:
    """The same bytes as the preview, as a file.

    Safe to hand out to anyone who can already see the routes page: the export
    carries the *name* of each secret's environment variable, never a secret.
    """
    require_auth(request)
    return PlainTextResponse(
        _export_json(request),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="config.json"'},
    )
