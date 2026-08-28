"""Store unit tests, ported from web/internal/store/*_test.go.

Covers the behaviour the Go-fixture test cannot reach: edge cases, boundaries,
and the queries whose correctness depends on how they are written rather than
on what is in the database.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from hookguard_console.store import (
    DEFAULT_RETENTION_DAYS,
    AuthEvent,
    AuthEventKind,
    Endpoint,
    Event,
    EventFilter,
    NotFoundError,
    RollupDelta,
    Store,
    open_store,
)

BASE_MS = 1767225600000  # 2026-01-01T00:00:00Z
BASE_S = BASE_MS // 1000
HOUR = BASE_MS // 3600000


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
        "latency_ms": 10,
    }
    return Event(**{**base, **kw})


# --------------------------------------------------------------------------
# Schema and lifecycle
# --------------------------------------------------------------------------


def test_a_fresh_database_gets_the_schema(store: Store) -> None:
    tables = {r[0] for r in store._query_all("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {
        "users",
        "sessions",
        "endpoints",
        "events",
        "event_rollups",
        "auth_events",
        "settings",
    } <= tables


def test_wal_mode_is_on(store: Store) -> None:
    """The dashboard reads while the batcher writes; without WAL those block
    each other."""
    assert store._query_one("PRAGMA journal_mode")[0].lower() == "wal"


def test_foreign_keys_are_on(store: Store) -> None:
    assert store._query_one("PRAGMA foreign_keys")[0] == 1


def test_open_creates_missing_parent_directories(tmp_path: Path) -> None:
    st = open_store(tmp_path / "nested" / "deeper" / "console.db")
    assert st.count_users() == 0
    st.close()


# --------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------


def test_duplicate_email_is_rejected_case_insensitively(store: Store) -> None:
    """The UNIQUE constraint is COLLATE NOCASE, so two users cannot differ
    only by case -- otherwise a login would be ambiguous."""
    store.create_user("a@example.com", "h", "admin", BASE_MS)
    with pytest.raises(sqlite3.IntegrityError):
        store.create_user("A@EXAMPLE.COM", "h", "member", BASE_MS)


def test_role_is_constrained(store: Store) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        store.create_user("a@example.com", "h", "superuser", BASE_MS)


def test_count_drives_the_first_user_becoming_admin(store: Store) -> None:
    assert store.count_users() == 0
    store.create_user("a@example.com", "h", "admin", BASE_MS)
    assert store.count_users() == 1


def test_password_hash_update(store: Store) -> None:
    uid = store.create_user("a@example.com", "old", "admin", BASE_MS)
    store.update_password_hash(uid, "new")
    assert store.get_user_by_id(uid).password_hash == "new"


def test_deactivating_and_reactivating(store: Store) -> None:
    uid = store.create_user("a@example.com", "h", "member", BASE_MS)
    store.set_user_active(uid, False)
    assert store.get_user_by_id(uid).active is False
    store.set_user_active(uid, True)
    assert store.get_user_by_id(uid).active is True


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------


def test_revoke_all_others_keeps_the_current_session(store: Store) -> None:
    from hookguard_console.store import Session

    uid = store.create_user("a@example.com", "h", "admin", BASE_MS)
    ids = [
        store.create_session(
            Session(
                token_hash=bytes([i]) * 32,
                user_id=uid,
                csrf_token="c",
                created_at=BASE_MS,
                last_seen_at=BASE_MS + i,
                expires_at=BASE_MS + 100000,
            )
        )
        for i in range(3)
    ]
    removed = store.delete_sessions_for_user_except(uid, ids[1])
    assert removed == 2
    remaining = store.list_sessions_for_user(uid)
    assert [s.id for s in remaining] == [ids[1]]


def test_sessions_are_listed_most_recently_seen_first(store: Store) -> None:
    from hookguard_console.store import Session

    uid = store.create_user("a@example.com", "h", "admin", BASE_MS)
    for i in range(3):
        store.create_session(
            Session(
                token_hash=bytes([i]) * 32,
                user_id=uid,
                csrf_token="c",
                created_at=BASE_MS,
                last_seen_at=BASE_MS + i * 1000,
                expires_at=BASE_MS + 100000,
            )
        )
    seen = [s.last_seen_at for s in store.list_sessions_for_user(uid)]
    assert seen == sorted(seen, reverse=True)


def test_touch_updates_last_seen(store: Store) -> None:
    from hookguard_console.store import Session

    uid = store.create_user("a@example.com", "h", "admin", BASE_MS)
    sid = store.create_session(
        Session(
            token_hash=b"x" * 32,
            user_id=uid,
            csrf_token="c",
            created_at=BASE_MS,
            last_seen_at=BASE_MS,
            expires_at=BASE_MS + 1000,
        )
    )
    store.touch_session(sid, BASE_MS + 500)
    assert store.list_sessions_for_user(uid)[0].last_seen_at == BASE_MS + 500


def test_missing_session_raises(store: Store) -> None:
    with pytest.raises(NotFoundError):
        store.get_session_by_token_hash(b"nope" * 8)


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------


def make_endpoint(**kw) -> Endpoint:
    base = {
        "path": "/hook/stripe",
        "provider": "stripe",
        "upstream_url": "http://app/stripe",
        "secret_env": "STRIPE_SECRET",
        "active": True,
        "created_at": BASE_MS,
        "updated_at": BASE_MS,
    }
    return Endpoint(**{**base, **kw})


def test_paths_are_unique(store: Store) -> None:
    store.create_endpoint(make_endpoint())
    with pytest.raises(sqlite3.IntegrityError):
        store.create_endpoint(make_endpoint())


def test_provider_is_constrained(store: Store) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        store.create_endpoint(make_endpoint(provider="squarespace"))


def test_paypal_must_carry_a_webhook_id_and_no_secret_env(store: Store) -> None:
    """The CHECK constraint mirrors the gateway's per-provider factory rules,
    so a row the gateway could not build is rejected at write time."""
    with pytest.raises(sqlite3.IntegrityError):
        store.create_endpoint(
            make_endpoint(path="/hook/paypal", provider="paypal", secret_env="X", webhook_id="")
        )
    with pytest.raises(sqlite3.IntegrityError):
        store.create_endpoint(
            make_endpoint(path="/hook/pp2", provider="paypal", secret_env="X", webhook_id="WH-1")
        )
    store.create_endpoint(
        make_endpoint(path="/hook/pp3", provider="paypal", secret_env="", webhook_id="WH-1")
    )


def test_hmac_providers_must_carry_a_secret_env_and_no_webhook_id(store: Store) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        store.create_endpoint(make_endpoint(secret_env=""))
    with pytest.raises(sqlite3.IntegrityError):
        store.create_endpoint(make_endpoint(webhook_id="WH-1"))


def test_toggling_active_updates_the_timestamp(store: Store) -> None:
    eid = store.create_endpoint(make_endpoint())
    store.set_endpoint_active(eid, False, BASE_MS + 5000)
    got = store.get_endpoint_by_id(eid)
    assert got.active is False
    assert got.updated_at == BASE_MS + 5000


def test_update_does_not_clobber_active(store: Store) -> None:
    """Update and toggle are separate methods precisely so editing a row does
    not silently re-enable a disabled endpoint."""
    eid = store.create_endpoint(make_endpoint())
    store.set_endpoint_active(eid, False, BASE_MS)
    endpoint = store.get_endpoint_by_id(eid)
    endpoint.upstream_url = "http://app/changed"
    store.update_endpoint(endpoint)
    assert store.get_endpoint_by_id(eid).active is False


def test_delete_endpoint(store: Store) -> None:
    eid = store.create_endpoint(make_endpoint())
    store.delete_endpoint(eid)
    with pytest.raises(NotFoundError):
        store.get_endpoint_by_id(eid)


# --------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------


def test_insert_events_is_a_no_op_for_an_empty_batch(store: Store) -> None:
    store.insert_events([])
    assert store.count_events() == 0


def test_verdict_is_constrained(store: Store) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        store.insert_events([make_event(verdict="maybe")])


def test_empty_database_states(store: Store) -> None:
    assert store.has_any_event() is False
    assert store.latest_event_id() == 0
    assert store.count_events() == 0
    with pytest.raises(NotFoundError):
        store.latest_event()


def test_events_since_is_a_cursor_not_a_window(store: Store) -> None:
    """The SSE tail uses the autoincrement id, so events sharing a timestamp
    are still delivered exactly once."""
    store.insert_events([make_event(received_at=BASE_MS) for _ in range(5)])
    first_batch = store.events_since(0, 10)
    assert len(first_batch) == 5
    assert [e.id for e in first_batch] == sorted(e.id for e in first_batch)

    cursor = first_batch[-1].id
    assert store.events_since(cursor, 10) == []

    store.insert_events([make_event()])
    assert len(store.events_since(cursor, 10)) == 1


def test_events_since_respects_the_limit(store: Store) -> None:
    store.insert_events([make_event() for _ in range(10)])
    assert len(store.events_since(0, 3)) == 3


def test_list_events_is_newest_first(store: Store) -> None:
    for i in range(5):
        store.insert_events([make_event(received_at=BASE_MS + i, body_bytes=i)])
    got = store.list_events(EventFilter(), 10)
    assert [e.body_bytes for e in got] == [4, 3, 2, 1, 0]


def test_like_metacharacters_in_a_filter_are_literal(store: Store) -> None:
    """A filter of "100%" must not match everything. Without escaping, '%'
    would be a wildcard and the log would look broken in a very confusing
    way."""
    store.insert_events([make_event(reason="100% failure"), make_event(reason="ordinary")])
    assert len(store.list_events(EventFilter(reason="100%"), 10)) == 1

    # Searching for "%" finds the row that literally contains one -- and only
    # that row. Unescaped it would be a wildcard and match both.
    literal_percent = store.list_events(EventFilter(reason="%"), 10)
    assert len(literal_percent) == 1
    assert literal_percent[0].reason == "100% failure"


def test_underscore_in_a_filter_is_literal(store: Store) -> None:
    store.insert_events([make_event(path="/hook/a_b"), make_event(path="/hook/axb")])
    assert len(store.list_events(EventFilter(path="a_b"), 10)) == 1


def test_time_bounds_are_inclusive(store: Store) -> None:
    for i in range(5):
        store.insert_events([make_event(received_at=BASE_MS + i * 1000)])
    got = store.list_events(EventFilter(from_ms=BASE_MS + 1000, to_ms=BASE_MS + 3000), 10)
    assert len(got) == 3


def test_filters_combine(store: Store) -> None:
    store.insert_events(
        [
            make_event(provider="stripe", verdict="accepted"),
            make_event(provider="stripe", verdict="rejected", reason="signature mismatch"),
            make_event(provider="github", verdict="rejected", reason="signature mismatch"),
        ]
    )
    got = store.list_events(EventFilter(provider="stripe", verdict="rejected"), 10)
    assert len(got) == 1


def test_recent_rejected_excludes_accepted(store: Store) -> None:
    store.insert_events(
        [make_event(verdict="accepted"), make_event(verdict="rejected", reason="r")]
    )
    got = store.recent_rejected(10)
    assert len(got) == 1
    assert got[0].verdict == "rejected"


def test_delete_events_older_than_leaves_rollups_alone(store: Store) -> None:
    """Rollups are the aggregate the dashboard reads and are kept far longer
    than raw events -- pruning must not touch them."""
    store.insert_events([make_event(received_at=BASE_MS - 100000), make_event(received_at=BASE_MS)])
    store.upsert_rollups([RollupDelta(hour=HOUR, provider="stripe", verdict="accepted", n=5)])

    deleted = store.delete_events_older_than(BASE_MS)
    assert deleted == 1
    assert store.count_events() == 1
    assert store.rollup_count(HOUR, "stripe", "accepted") == 5


# --------------------------------------------------------------------------
# Rollups and aggregates
# --------------------------------------------------------------------------


def test_upsert_accumulates_rather_than_replacing(store: Store) -> None:
    """Each flush adds onto the bucket. Replacing would lose every tick but
    the last."""
    for _ in range(3):
        store.upsert_rollups([RollupDelta(hour=HOUR, provider="stripe", verdict="accepted", n=2)])
    assert store.rollup_count(HOUR, "stripe", "accepted") == 6


def test_upsert_is_a_no_op_for_an_empty_batch(store: Store) -> None:
    store.upsert_rollups([])
    assert store.rollup_count(HOUR, "stripe", "accepted") == 0


def test_buckets_are_independent(store: Store) -> None:
    store.upsert_rollups(
        [
            RollupDelta(hour=HOUR, provider="stripe", verdict="accepted", n=1),
            RollupDelta(hour=HOUR, provider="stripe", verdict="rejected", n=2),
            RollupDelta(hour=HOUR, provider="github", verdict="accepted", n=3),
            RollupDelta(hour=HOUR - 1, provider="stripe", verdict="accepted", n=4),
        ]
    )
    assert store.rollup_count(HOUR, "stripe", "accepted") == 1
    assert store.rollup_count(HOUR, "stripe", "rejected") == 2
    assert store.rollup_count(HOUR, "github", "accepted") == 3
    assert store.rollup_count(HOUR - 1, "stripe", "accepted") == 4


def test_summary_of_an_empty_window(store: Store) -> None:
    summary = store.summary_window(BASE_S, 24)
    assert summary.accepted == 0
    assert summary.rejected == 0
    assert summary.accept_rate == 0.0, "no traffic reports 0, not a division error"
    assert summary.p50_latency_ms == 0


def test_summary_excludes_buckets_outside_the_window(store: Store) -> None:
    store.upsert_rollups(
        [
            RollupDelta(hour=HOUR, provider="stripe", verdict="accepted", n=1),
            RollupDelta(hour=HOUR - 100, provider="stripe", verdict="accepted", n=99),
        ]
    )
    assert store.summary_window(BASE_S, 24).accepted == 1


def test_the_window_includes_the_current_partial_hour(store: Store) -> None:
    """A 1-hour window is the current bucket only, not the previous one."""
    store.upsert_rollups(
        [
            RollupDelta(hour=HOUR, provider="stripe", verdict="accepted", n=1),
            RollupDelta(hour=HOUR - 1, provider="stripe", verdict="accepted", n=1),
        ]
    )
    assert store.summary_window(BASE_S, 1).accepted == 1
    assert store.summary_window(BASE_S, 2).accepted == 2


@pytest.mark.parametrize(
    ("latencies", "expected"),
    [
        ([5], 5),
        ([1, 2, 3], 2),
        ([1, 2, 3, 4], 2),  # even count takes the LOWER middle, not the average
        ([10, 1], 1),
        ([7, 7, 7], 7),
    ],
)
def test_p50_tie_break_is_the_lower_middle(
    store: Store, latencies: list[int], expected: int
) -> None:
    """Documented and deterministic. Averaging would produce a non-integer
    for a column that is an integer, and picking the upper middle is equally
    defensible -- what matters is that it never drifts."""
    store.insert_events([make_event(latency_ms=latency) for latency in latencies])
    assert store.summary_window(BASE_S, 24).p50_latency_ms == expected


def test_hourly_counts_are_dense(store: Store) -> None:
    series = store.hourly_counts_window(BASE_S, 12)
    assert len(series) == 12, "gaps must be zero-filled, or the chart's x-axis lies"
    assert all(h.accepted == 0 for h in series)
    assert [h.hour for h in series] == list(range(HOUR - 11, HOUR + 1))


def test_provider_stats_omit_untouched_providers(store: Store) -> None:
    store.upsert_rollups([RollupDelta(hour=HOUR, provider="stripe", verdict="accepted", n=1)])
    stats = store.provider_stats_window(BASE_S, 24)
    assert set(stats) == {"stripe"}


def test_provider_stats_accept_rate_of_an_all_rejected_provider(store: Store) -> None:
    store.upsert_rollups([RollupDelta(hour=HOUR, provider="stripe", verdict="rejected", n=4)])
    stats = store.provider_stats_window(BASE_S, 24)["stripe"]
    assert stats.total == 4
    assert stats.accept_rate == 0.0, "distinguishable from 'no traffic' by total"


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------


def test_retention_falls_back_when_unset(store: Store) -> None:
    assert store.get_retention_days() == DEFAULT_RETENTION_DAYS


@pytest.mark.parametrize("bad", ["", "abc", "3.5", " "])
def test_retention_falls_back_on_a_corrupt_value(store: Store, bad: str) -> None:
    """A bad row must not disable retention -- that would silently let the
    events table grow without bound."""
    store.set_setting("retention_days", bad)
    assert store.get_retention_days() == DEFAULT_RETENTION_DAYS


def test_setting_upsert_replaces(store: Store) -> None:
    store.set_setting("k", "one")
    store.set_setting("k", "two")
    assert store.get_setting("k") == "two"


def test_missing_setting_raises(store: Store) -> None:
    with pytest.raises(NotFoundError):
        store.get_setting("absent")


def test_delete_setting(store: Store) -> None:
    store.set_setting("k", "v")
    store.delete_setting("k")
    with pytest.raises(NotFoundError):
        store.get_setting("k")


# --------------------------------------------------------------------------
# Auth events
# --------------------------------------------------------------------------


def test_auth_events_are_capped_by_limit(store: Store) -> None:
    for i in range(10):
        store.insert_auth_event(
            AuthEvent(at=BASE_MS + i, email="a@example.com", kind=AuthEventKind.LOGIN_OK)
        )
    assert len(store.list_auth_events(3)) == 3


def test_auth_events_sharing_a_timestamp_are_ordered_stably(store: Store) -> None:
    """A burst of failed logins lands in the same millisecond; ordering by id
    as a tiebreak keeps the log deterministic."""
    for _ in range(5):
        store.insert_auth_event(
            AuthEvent(at=BASE_MS, email="a@example.com", kind=AuthEventKind.LOGIN_FAIL)
        )
    ids = [e.id for e in store.list_auth_events(10)]
    assert ids == sorted(ids, reverse=True)
