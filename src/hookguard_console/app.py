"""The Console's HTTP surface: routing, middleware and lifecycle."""

from __future__ import annotations

import logging
from collections.abc import Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from importlib import resources

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .auth import Limiter
from .batcher import Batcher
from .config import VERSION, ConsoleConfig
from .deps import Console, Redirect
from .middleware import SessionMiddleware, security_headers_middleware
from .retention import RetentionJob
from .routes import api, auth, dashboard, endpoints, logs, providers, public, settings
from .store import Store, open_store
from .templating import build_environment

__all__ = ["build_app", "create_app"]

log = logging.getLogger("hookguard.console")

#: Ten attempts per quarter hour, keyed on address-and-host: enough that a
#: person mistyping a password is never locked out, few enough that online
#: guessing against an Argon2 hash is hopeless.
LOGIN_LIMIT = (10, timedelta(minutes=15))

#: Tighter, because signup is the one endpoint that creates rows.
SIGNUP_LIMIT = (5, timedelta(hours=1))


def create_app() -> Starlette:
    """Build from the environment. The production entrypoint."""
    config = ConsoleConfig.from_env()
    return build_app(open_store(config.database_path), config=config)


def build_app(
    store: Store,
    *,
    config: ConsoleConfig | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Starlette:
    """Wire an app around an already-open store.

    The store is passed in rather than opened here so tests get a temporary
    database without touching the environment, and so the CLI subcommands can
    share one connection with the server.
    """
    config = config or ConsoleConfig()

    console = Console(
        store=store,
        env=build_environment(),
        version=VERSION,
        allow_signup=config.allow_signup,
        internal_secret=config.internal_secret,
        data_dir=str(config.data_dir),
        login_limiter=Limiter(*LOGIN_LIMIT),
        signup_limiter=Limiter(*SIGNUP_LIMIT),
        now=now,
    )

    @asynccontextmanager
    async def lifespan(app: Starlette):
        console.batcher = Batcher(store)
        console.retention = RetentionJob(
            store, limiters=[console.login_limiter, console.signup_limiter], now=now
        )
        await console.batcher.start()
        await console.retention.start()
        try:
            yield
        finally:
            # Ordered: stop accepting, flush what was accepted, then stop the
            # sweeper. Dropping queued events on shutdown would lose verdicts
            # the gateway already handed over.
            await console.batcher.aclose()
            await console.retention.aclose()

    static_dir = resources.files("hookguard_console.ui").joinpath("static")

    app = Starlette(
        routes=[
            Route("/", public.handle_landing),
            Route("/playground", public.handle_playground),
            Route("/healthz", public.handle_healthz),
            Route("/login", public.handle_login_form),
            Route("/login", auth.handle_login, methods=["POST"]),
            Route("/signup", public.handle_signup_form),
            Route("/signup", auth.handle_signup, methods=["POST"]),
            Route("/logout", auth.handle_logout, methods=["POST"]),
            Route("/reset-password", auth.handle_reset_password_form),
            Route("/reset-password", auth.handle_reset_password, methods=["POST"]),
            Route("/dashboard", dashboard.handle_overview),
            Route("/dashboard/endpoints", endpoints.handle_endpoints_list),
            Route("/dashboard/endpoints", endpoints.handle_endpoint_create, methods=["POST"]),
            Route("/dashboard/endpoints/new", endpoints.handle_endpoint_new_form),
            Route("/dashboard/endpoints/export", endpoints.handle_endpoint_export_preview),
            Route(
                "/dashboard/endpoints/export/download",
                endpoints.handle_endpoint_export_download,
            ),
            Route(
                "/dashboard/endpoints/{endpoint_id:int}/edit",
                endpoints.handle_endpoint_edit_form,
            ),
            # PUT is the documented route and htmx issues a real one. The POST
            # to the same path is the no-JavaScript fallback -- a <form> cannot
            # emit PUT -- so both exist deliberately and both are tested.
            Route(
                "/dashboard/endpoints/{endpoint_id:int}",
                endpoints.handle_endpoint_update,
                methods=["PUT", "POST"],
            ),
            Route(
                "/dashboard/endpoints/{endpoint_id:int}",
                endpoints.handle_endpoint_delete,
                methods=["DELETE"],
            ),
            Route(
                "/dashboard/endpoints/{endpoint_id:int}/delete",
                endpoints.handle_endpoint_delete,
                methods=["POST"],
            ),
            Route(
                "/dashboard/endpoints/{endpoint_id:int}/toggle-active",
                endpoints.handle_endpoint_toggle_active,
                methods=["POST"],
            ),
            Route("/dashboard/logs", logs.handle_logs_list),
            Route("/dashboard/logs/stream", logs.handle_logs_stream),
            Route("/dashboard/providers", providers.handle_providers),
            Route("/dashboard/settings", settings.handle_settings),
            Route(
                "/dashboard/settings/password",
                settings.handle_password_change,
                methods=["POST"],
            ),
            Route(
                "/dashboard/settings/retention",
                settings.handle_retention_change,
                methods=["POST"],
            ),
            Route(
                "/dashboard/settings/sessions/{session_id:int}/revoke",
                settings.handle_session_revoke,
                methods=["POST"],
            ),
            Route(
                "/dashboard/settings/sessions/revoke-others",
                settings.handle_session_revoke_others,
                methods=["POST"],
            ),
            Route("/dashboard/settings/users", settings.handle_settings),
            Route("/dashboard/settings/users", settings.handle_user_create, methods=["POST"]),
            Route(
                "/dashboard/settings/users/{user_id:int}/deactivate",
                settings.handle_user_deactivate,
                methods=["POST"],
            ),
            Route("/api/v1/ingest", api.handle_ingest, methods=["POST"]),
            Route("/api/v1/stats/summary", dashboard.handle_stats_summary),
            Mount("/static", StaticFiles(directory=str(static_dir)), name="static"),
        ],
        middleware=[
            Middleware(BaseHTTPMiddleware, dispatch=security_headers_middleware),
            Middleware(SessionMiddleware, store=store, now=now),
            Middleware(BaseHTTPMiddleware, dispatch=_redirect_middleware),
        ],
        exception_handlers={404: public.handle_not_found},
        lifespan=lifespan,
    )
    app.state.console = console
    return app


async def _redirect_middleware(request: Request, call_next) -> Response:
    """Turn a guard's :class:`Redirect` into its response.

    The guards raise rather than return so a handler can call them as a
    statement; something has to catch that, and doing it once here beats a
    try/except in every handler.
    """
    try:
        return await call_next(request)
    except Redirect as redirect:
        return redirect.response
