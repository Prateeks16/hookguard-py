"""The Providers page: four setup guides, each with its recent traffic."""

from __future__ import annotations

from dataclasses import dataclass

from starlette.requests import Request
from starlette.responses import Response

from ..deps import console_of, require_auth
from ..providers_catalog import PROVIDER_CATALOG, ProviderGuide
from ..store import ProviderStats
from ..views import format_accept_rate, page_context, window_from_request

__all__ = ["handle_providers"]


@dataclass(frozen=True, slots=True)
class ProviderCard:
    """A catalog entry plus this window's numbers."""

    guide: ProviderGuide
    stats: ProviderStats
    accept_rate: str
    has_traffic: bool
    logs_url: str

    # Flattened for the template, which has no attribute-chaining needs
    # beyond this and reads better without guide.guide.name.
    @property
    def id(self) -> str:
        return self.guide.id

    @property
    def name(self) -> str:
        return self.guide.name

    @property
    def algorithm(self) -> str:
        return self.guide.algorithm

    @property
    def headers(self) -> tuple[str, ...]:
        return self.guide.headers

    @property
    def secret_source(self) -> str:
        return self.guide.secret_source

    @property
    def config_field(self) -> str:
        return self.guide.config_field

    @property
    def replay_window(self) -> str:
        return self.guide.replay_window

    @property
    def reject_reasons(self) -> tuple[str, ...]:
        return self.guide.reject_reasons

    @property
    def checklist(self) -> tuple[str, ...]:
        return self.guide.checklist


async def handle_providers(request: Request) -> Response:
    console = console_of(request)
    require_auth(request)

    hours, window = window_from_request(request)
    now = console.now()
    stats = console.store.provider_stats_window(int(now.timestamp()), hours)

    cards = []
    for guide in PROVIDER_CATALOG:
        provider_stats = stats.get(guide.id, ProviderStats())
        cards.append(
            ProviderCard(
                guide=guide,
                stats=provider_stats,
                accept_rate=format_accept_rate(provider_stats),
                has_traffic=provider_stats.total > 0,
                # Built from the catalog's own id, never from request input --
                # the template puts this straight into an href, and Jinja2's
                # autoescaping is HTML-only.
                logs_url=f"/dashboard/logs?provider={guide.id}",
            )
        )

    return console.render(
        "providers.html",
        page_context(
            request,
            store=console.store,
            version=console.version,
            now=now,
            nav_active="providers",
            providers=cards,
            window=window,
        ),
    )
