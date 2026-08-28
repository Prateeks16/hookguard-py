"""The Jinja2 environment.

Autoescaping is enabled explicitly. Jinja2's default ``Environment`` does NOT
autoescape -- unlike Go's ``html/template``, which always does -- so leaving it
to the default would turn every template value into an XSS vector silently.
It is on for ``.html``, and the one place a template bypasses it
(``chart_svg``) is markup this application builds from integers.

Note the escaping difference that survives even with autoescape on: Go escapes
per context, so a value in an ``href`` gets URL escaping. Jinja2's is
HTML-only. That is fine here because no template interpolates request input
into a URL attribute -- an invariant the route tests pin, since nothing in the
templating layer can enforce it.
"""

from __future__ import annotations

from importlib import resources
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.responses import HTMLResponse

__all__ = ["build_environment", "render"]


def build_environment() -> Environment:
    templates = resources.files("hookguard_console.ui").joinpath("templates")
    env = Environment(
        loader=FileSystemLoader(str(templates)),
        autoescape=select_autoescape(default_for_string=True, default=True),
        trim_blocks=False,
        lstrip_blocks=False,
        auto_reload=False,
    )
    return env


def render(
    env: Environment, name: str, context: dict[str, Any], status_code: int = 200
) -> HTMLResponse:
    """Render a page template to a response.

    Every page gets the same defaults so a handler that forgets one renders a
    missing chrome element rather than raising -- Jinja2 treats an undefined
    name as empty, and a half-rendered dashboard is easier to spot in a test
    than a 500.
    """
    defaults: dict[str, Any] = {
        "user": None,
        "csrf_token": "",
        "version": "",
        "connected": False,
        "last_event_ago": "",
        "nav_active": "",
        "error": "",
        "next": "",
    }
    template = env.get_template(f"pages/{name}")
    return HTMLResponse(
        template.render({**defaults, **context}),
        status_code=status_code,
        media_type="text/html; charset=utf-8",
    )
