"""Config export/import, ingest decoding, batching and retention.

Ported from web/internal/{gwconfig,ingest,retention}. These are the pieces
between the gateway and the database, so most of what matters here is what
happens when the gateway misbehaves or the database is busy.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from hookguard_console import gwconfig
from hookguard_console.auth import Limiter
from hookguard_console.batcher import Batcher, hour_bucket, rollup_deltas
from hookguard_console.gwconfig import ConfigValidationError
from hookguard_console.ingest import (
    EXPECTED_PROVIDER,
    IngestError,
    check_provider_header,
    decode,
    to_row,
    verify,
)
from hookguard_console.retention import RetentionJob, sweep
from hookguard_console.store import Endpoint, Event, EventFilter, Store, open_store
from hookguard_core import gatewaysig
from hookguard_core.events import VerifyEvent
from hookguard_gateway.config import Route

REPO_ROOT = Path(__file__).resolve().parents[2]
BASE = datetime(2026, 1, 1, tzinfo=UTC)
BASE_MS = int(BASE.timestamp() * 1000)
SECRET = b"internal-console"


@pytest.fixture
def store(tmp_path: Path) -> Store:
    st = open_store(tmp_path / "console.db")
    yield st
    st.close()


def make_event(**kw) -> Event:
    base = {
        "received_at": BASE_MS,
        "path": "/hook/stripe",
        "provider": "stripe",
        "verdict": "accepted",
        "latency_ms": 5,
    }
    return Event(**{**base, **kw})


# ==========================================================================
# gwconfig
# ==========================================================================


def endpoint(**kw) -> Endpoint:
    base = {
        "path": "/hook/stripe",
        "provider": "stripe",
        "upstream_url": "http://app:8080/stripe",
        "replay_window": "5m",
        "secret_env": "STRIPE_SECRET",
        "active": True,
    }
    return Endpoint(**{**base, **kw})


def test_export_round_trips_through_the_gateways_own_loader(tmp_path: Path) -> None:
    """The real contract: what the Console writes, the Gateway must read. This
    goes through the gateway's actual loader rather than comparing strings."""
    from hookguard_gateway.config import load_config

    rendered = gwconfig.marshal(
        gwconfig.export(
            [
                endpoint(),
                endpoint(path="/hook/paypal", provider="paypal", secret_env="", webhook_id="WH-1"),
            ]
        )
    )
    path = tmp_path / "config.json"
    path.write_text(rendered, encoding="utf-8")

    loaded = load_config(path)
    assert [r.path for r in loaded.routes] == ["/hook/stripe", "/hook/paypal"]
    assert loaded.routes[0].replay_window == "5m"
    assert loaded.routes[1].webhook_id == "WH-1"


def test_export_omits_an_empty_webhook_id() -> None:
    """Go's struct tag carries omitempty, and an exported file that differed
    from a hand-written one would be a confusing diff for no reason."""
    rendered = json.loads(gwconfig.marshal(gwconfig.export([endpoint()])))
    assert "webhook_id" not in rendered["routes"][0]


def test_export_uses_two_space_indent() -> None:
    rendered = gwconfig.marshal(gwconfig.export([endpoint()]))
    assert '\n  "routes": [' in rendered
    assert rendered.endswith("\n")


def test_the_shipped_config_survives_import_then_export(tmp_path: Path) -> None:
    """The committed config.json came from the Go repo. Importing and
    re-exporting it must give the Gateway the same routes, or the Console
    would mangle an operator's existing deployment on first use.

    Compared through the gateway's loader rather than as text: only
    `webhook_id` carries omitempty in the Go struct tags, so a re-export
    legitimately spells out `"replay_window": ""` where a hand-written file
    left it off. Byte-identical round-tripping was never the contract --
    loading to the same routes is.
    """
    from hookguard_gateway.config import load_config

    original_path = REPO_ROOT / "config.json"
    endpoints = gwconfig.import_config(original_path.read_text(encoding="utf-8"))

    reexported_path = tmp_path / "config.json"
    reexported_path.write_text(gwconfig.marshal(gwconfig.export(endpoints)), encoding="utf-8")

    assert load_config(reexported_path).routes == load_config(original_path).routes


def test_export_spells_out_empty_optional_fields() -> None:
    """Pins the omitempty behaviour that the round-trip test above depends on:
    webhook_id is dropped when empty, replay_window and secret_env are not."""
    exported = gwconfig.export([endpoint(replay_window="", secret_env="S")])
    rendered = json.loads(gwconfig.marshal(exported))["routes"][0]
    assert rendered["replay_window"] == ""
    assert rendered["secret_env"] == "S"
    assert "webhook_id" not in rendered


def test_import_rejects_a_bad_route_without_importing_any_of_it() -> None:
    """All-or-nothing: a half-imported config is worse than a rejected one."""
    data = json.dumps(
        {
            "routes": [
                {
                    "path": "/hook/stripe",
                    "provider": "stripe",
                    "upstream": "http://u",
                    "secret_env": "S",
                },
                {"path": "/hook/x", "provider": "nope", "upstream": "http://u"},
            ]
        }
    )
    with pytest.raises(ConfigValidationError, match="route 1"):
        gwconfig.import_config(data)


@pytest.mark.parametrize(
    ("route", "match"),
    [
        (Route(path="", provider="stripe", upstream="http://u", secret_env="S"), "path"),
        (Route(path="/h", provider="stripe", upstream="", secret_env="S"), "upstream"),
        (Route(path="/h", provider="stripe", upstream="http://u"), "requires secret_env"),
        (
            Route(
                path="/h", provider="stripe", upstream="http://u", secret_env="S", webhook_id="W"
            ),
            "must not set webhook_id",
        ),
        (Route(path="/h", provider="paypal", upstream="http://u"), "requires webhook_id"),
        (
            Route(
                path="/h", provider="paypal", upstream="http://u", webhook_id="W", secret_env="S"
            ),
            "must not set secret_env",
        ),
        (Route(path="/h", provider="nope", upstream="http://u"), "unknown provider"),
        (
            Route(
                path="/h",
                provider="stripe",
                upstream="http://u",
                secret_env="S",
                replay_window="5 minutes",
            ),
            "replay_window",
        ),
    ],
)
def test_validation_mirrors_the_gateways_rules(route: Route, match: str) -> None:
    with pytest.raises(ConfigValidationError, match=match):
        gwconfig.validate(route)


def test_endpoint_conversion_round_trips() -> None:
    original = endpoint()
    back = gwconfig.to_endpoint(gwconfig.from_endpoint(original))
    assert (back.path, back.provider, back.upstream_url) == (
        original.path,
        original.provider,
        original.upstream_url,
    )
    assert back.replay_window == original.replay_window
    assert back.secret_env == original.secret_env


def test_export_of_nothing_is_valid_config() -> None:
    assert json.loads(gwconfig.marshal(gwconfig.export([]))) == {"routes": []}


# ==========================================================================
# ingest
# ==========================================================================


def signed(body: bytes) -> str:
    return gatewaysig.sign(SECRET, EXPECTED_PROVIDER, body)


def test_verifies_a_signed_body() -> None:
    body = b'{"ts":"2026-01-01T00:00:00Z"}'
    verify(SECRET, body, signed(body))


def test_rejects_a_tampered_body() -> None:
    body = b'{"ts":"2026-01-01T00:00:00Z"}'
    with pytest.raises(IngestError):
        verify(SECRET, body + b"x", signed(body))


def test_rejects_the_wrong_secret() -> None:
    body = b"{}"
    with pytest.raises(IngestError):
        verify(b"other-secret", body, signed(body))


def test_rejects_a_signature_for_a_different_provider_label() -> None:
    """The label binds this signature to the ingest route. A gateway signature
    minted for a webhook must not be replayable here."""
    body = b"{}"
    webhook_sig = gatewaysig.sign(SECRET, "stripe", body)
    with pytest.raises(IngestError):
        verify(SECRET, body, webhook_sig)


def test_provider_header_is_checked_before_the_hmac() -> None:
    check_provider_header(EXPECTED_PROVIDER)
    with pytest.raises(IngestError, match="unexpected provider"):
        check_provider_header("stripe")
    with pytest.raises(IngestError):
        check_provider_header("")


def test_decodes_a_full_event() -> None:
    event = VerifyEvent(
        timestamp=BASE,
        path="/hook/stripe",
        provider="stripe",
        verdict="rejected",
        reason="signature mismatch",
        upstream_status=0,
        latency_ms=7,
        body_bytes=42,
        body_sha256="ab" * 32,
        remote_ip="203.0.113.1",
    )
    decoded = decode(event.to_json_bytes())
    assert decoded == event


@pytest.mark.parametrize("bad", [b"", b"not json", b"[]", b'{"no":"ts"}', b"\xff\xfe"])
def test_malformed_bodies_are_rejected(bad: bytes) -> None:
    with pytest.raises(IngestError):
        decode(bad)


def test_row_conversion_uses_unix_milliseconds() -> None:
    """The wire carries RFC 3339; every query buckets and orders on unix ms."""
    row = to_row(VerifyEvent(timestamp=BASE, path="/h", provider="stripe", verdict="accepted"))
    assert row.received_at == BASE_MS


def test_row_conversion_preserves_every_field() -> None:
    event = VerifyEvent(
        timestamp=BASE,
        path="/hook/github",
        provider="github",
        verdict="rejected",
        reason="stale timestamp",
        upstream_status=502,
        latency_ms=13,
        body_bytes=99,
        body_sha256="cd" * 32,
        remote_ip="198.51.100.4",
    )
    row = to_row(event)
    assert (row.path, row.provider, row.verdict, row.reason) == (
        event.path,
        event.provider,
        event.verdict,
        event.reason,
    )
    assert (row.upstream_status, row.latency_ms, row.body_bytes) == (502, 13, 99)
    assert (row.body_sha256, row.remote_ip) == (event.body_sha256, event.remote_ip)


# ==========================================================================
# batcher
# ==========================================================================


def test_hour_bucket_converts_ms_to_unix_hours() -> None:
    assert hour_bucket(BASE_MS) == BASE_MS // 1000 // 3600
    assert hour_bucket(0) == 0


def test_rollup_deltas_sum_same_bucket_events() -> None:
    """Three same-bucket events become one upsert of n=3, not three racing
    each other for the same row."""
    deltas = rollup_deltas([make_event() for _ in range(3)])
    assert len(deltas) == 1
    assert deltas[0].n == 3


def test_rollup_deltas_split_by_every_dimension() -> None:
    deltas = rollup_deltas(
        [
            make_event(provider="stripe", verdict="accepted"),
            make_event(provider="stripe", verdict="rejected"),
            make_event(provider="github", verdict="accepted"),
            make_event(provider="stripe", verdict="accepted", received_at=BASE_MS + 3600_000),
        ]
    )
    assert len(deltas) == 4
    assert all(d.n == 1 for d in deltas)


async def test_flush_persists_everything_enqueued_before_it(store: Store) -> None:
    """Tests wait on flush rather than sleeping on the ticker -- an event
    sitting in the queue right now was enqueued before the call and must be
    included, so sleeping would be a race."""
    batcher = Batcher(store)
    for _ in range(5):
        batcher.enqueue(make_event())
    await batcher.flush()
    assert store.count_events() == 5
    assert store.rollup_count(hour_bucket(BASE_MS), "stripe", "accepted") == 5


async def test_the_ticker_persists_without_an_explicit_flush(store: Store) -> None:
    batcher = Batcher(store, tick=0.01)
    await batcher.start()
    try:
        batcher.enqueue(make_event())
        for _ in range(100):
            await asyncio.sleep(0.01)
            if store.count_events():
                break
    finally:
        await batcher.aclose()
    assert store.count_events() == 1


async def test_close_drains_what_is_queued(store: Store) -> None:
    """Shutdown must flush rather than discard: those events were already
    accepted from the gateway."""
    batcher = Batcher(store, tick=3600)  # never ticks during the test
    await batcher.start()
    for _ in range(10):
        batcher.enqueue(make_event())
    await batcher.aclose()
    assert store.count_events() == 10


async def test_overflow_drops_the_oldest_and_stays_bounded(store: Store) -> None:
    """Ingest must never apply backpressure: the sender is the gateway, and
    slowing it down would slow webhook verification itself."""
    batcher = Batcher(store, queue_size=10)
    for i in range(100):
        batcher.enqueue(make_event(body_bytes=i))
    assert batcher.dropped == 90

    await batcher.flush()
    assert store.count_events() == 10
    kept = {e.body_bytes for e in store.list_events(EventFilter(), 100)}
    assert 99 in kept, "the newest survived"
    assert 0 not in kept, "the oldest were dropped"


async def test_a_failing_store_does_not_kill_the_batcher(store: Store, caplog) -> None:
    """An exception escaping the background task would stop ingest silently
    and permanently -- far worse than a logged write error."""
    batcher = Batcher(store)
    store.close()  # every write from here on raises

    batcher.enqueue(make_event())
    await batcher.flush()  # must not raise

    batcher_still_works = Batcher(open_store(":memory:"))
    batcher_still_works.enqueue(make_event())
    await batcher_still_works.flush()


async def test_last_ingest_time_is_recorded(store: Store) -> None:
    """A silent gateway and a healthy one look identical without this."""
    from hookguard_console.batcher import LAST_INGEST_SETTING

    batcher = Batcher(store)
    batcher.enqueue(make_event(received_at=BASE_MS + 5000))
    await batcher.flush()
    assert store.get_setting(LAST_INGEST_SETTING) == str(BASE_MS + 5000)


async def test_flushing_nothing_is_harmless(store: Store) -> None:
    await Batcher(store).flush()
    assert store.count_events() == 0


# ==========================================================================
# retention
# ==========================================================================


def test_sweep_deletes_only_events_past_the_window(store: Store) -> None:
    store.set_retention_days(30)
    store.insert_events(
        [
            make_event(received_at=int((BASE - timedelta(days=31)).timestamp() * 1000)),
            make_event(received_at=int((BASE - timedelta(days=29)).timestamp() * 1000)),
        ]
    )
    assert sweep(store, BASE) == 1
    assert store.count_events() == 1


def test_sweep_leaves_rollups_alone(store: Store) -> None:
    """Rollups are why a one-hour retention window can still show a month of
    trend."""
    from hookguard_console.store import RollupDelta

    store.set_retention_days(1)
    store.insert_events(
        [make_event(received_at=int((BASE - timedelta(days=5)).timestamp() * 1000))]
    )
    store.upsert_rollups(
        [RollupDelta(hour=hour_bucket(BASE_MS), provider="stripe", verdict="accepted", n=9)]
    )

    sweep(store, BASE)
    assert store.count_events() == 0
    assert store.rollup_count(hour_bucket(BASE_MS), "stripe", "accepted") == 9


def test_sweep_reads_the_setting_every_time(store: Store) -> None:
    """Caching the window at construction would mean an admin's change only
    took effect after a restart."""
    old = int((BASE - timedelta(days=10)).timestamp() * 1000)
    store.insert_events([make_event(received_at=old)])

    store.set_retention_days(30)
    assert sweep(store, BASE) == 0  # inside the window

    store.set_retention_days(5)
    assert sweep(store, BASE) == 1  # now outside it


def test_sweep_uses_the_default_when_unset(store: Store) -> None:
    store.insert_events(
        [make_event(received_at=int((BASE - timedelta(days=31)).timestamp() * 1000))]
    )
    assert sweep(store, BASE) == 1  # default is 30 days


async def test_the_job_sweeps_at_startup(store: Store) -> None:
    """A freshly deployed instance should not wait a full day for its first
    prune."""
    store.set_retention_days(1)
    store.insert_events(
        [make_event(received_at=int((BASE - timedelta(days=5)).timestamp() * 1000))]
    )

    job = RetentionJob(store, interval=timedelta(hours=1), now=lambda: BASE)
    await job.start()
    try:
        for _ in range(100):
            await asyncio.sleep(0.01)
            if store.count_events() == 0:
                break
    finally:
        await job.aclose()
    assert store.count_events() == 0


async def test_the_job_prunes_the_rate_limiters(store: Store) -> None:
    """The limiter key is attacker-supplied, so an unbounded map is a slow
    leak someone can drive."""
    limiter = Limiter(5, timedelta(minutes=15))
    for i in range(50):
        limiter.allow(f"user{i}@example.com", BASE - timedelta(hours=1))
    assert limiter.tracked_keys == 50

    job = RetentionJob(store, limiters=[limiter], now=lambda: BASE)
    await job.run_once()
    assert limiter.tracked_keys == 0


async def test_a_failing_sweep_does_not_kill_the_job(store: Store) -> None:
    store.close()
    job = RetentionJob(store, now=lambda: BASE)
    assert await job.run_once() == 0  # logged, not raised
