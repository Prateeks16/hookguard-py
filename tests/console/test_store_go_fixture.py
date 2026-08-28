"""Phase 4 exit check: a database written by the Go console reads here.

``tests/fixtures/go-console.db`` was produced by a program linking the Go
console's own ``store`` and ``auth`` packages -- not by hand, and not by this
implementation -- so these assertions are about interoperability rather than
self-consistency. Every table is populated.

The fixture is copied to a temp path before opening: SQLite would otherwise
create ``-wal`` and ``-shm`` siblings next to the committed file and mutate it
in place, and a test suite that edits its own fixture stops proving anything on
the second run.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from hookguard_console.store import (
    AuthEventKind,
    EventFilter,
    NotFoundError,
    Store,
    open_store,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
MANIFEST = json.loads((FIXTURES / "go-console.json").read_text(encoding="utf-8"))


@pytest.fixture
def go_store(tmp_path: Path) -> Store:
    copy = tmp_path / "go-console.db"
    shutil.copy(FIXTURES / "go-console.db", copy)
    store = open_store(copy)
    yield store
    store.close()


def test_the_committed_fixture_is_untouched_by_the_suite() -> None:
    """Guards the copy-first discipline above: no stray WAL siblings should
    ever appear beside the committed fixture."""
    strays = [p.name for p in FIXTURES.glob("go-console.db-*")]
    assert not strays, f"the suite wrote next to the committed fixture: {strays}"


# --------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------


def test_reads_users_written_by_go(go_store: Store) -> None:
    assert go_store.count_users() == 2
    admin = go_store.get_user_by_id(MANIFEST["admin_id"])
    assert admin.email == MANIFEST["admin_email"]
    assert admin.role == "admin"
    assert admin.active is True
    assert admin.created_at == MANIFEST["base_ms"]


def test_email_lookup_is_case_insensitive_across_implementations(go_store: Store) -> None:
    """Go stored ``Admin@Example.com``; the column is COLLATE NOCASE, so a
    lowercase login must still find it."""
    user = go_store.get_user_by_email("admin@example.com")
    assert user.id == MANIFEST["admin_id"]
    assert user.email == "Admin@Example.com"  # stored casing is preserved


def test_reads_the_go_argon2_hash_verbatim(go_store: Store) -> None:
    """The hash is a PHC string, and phase 5 depends on it verifying
    unchanged. Here we only assert it survived the round trip intact and
    carries the parameters the schema documents."""
    admin = go_store.get_user_by_id(MANIFEST["admin_id"])
    assert admin.password_hash == MANIFEST["admin_hash"]
    assert admin.password_hash.startswith("$argon2id$v=19$m=65536,t=3,p=2$")


def test_inactive_flag_round_trips(go_store: Store) -> None:
    """SQLite has no boolean type; Go wrote 0/1 and we must read it as a
    bool rather than a truthy integer."""
    member = go_store.get_user_by_id(MANIFEST["member_id"])
    assert member.active is False
    assert member.role == "member"


def test_listing_users_preserves_go_ordering(go_store: Store) -> None:
    emails = [u.email for u in go_store.list_users()]
    assert emails == [MANIFEST["admin_email"], MANIFEST["member_email"]]


def test_unknown_user_raises_not_found(go_store: Store) -> None:
    with pytest.raises(NotFoundError):
        go_store.get_user_by_email("nobody@example.com")


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------


def test_reads_a_session_by_its_go_written_token_hash(go_store: Store) -> None:
    """The stored value is sha256(token) as raw bytes. Reading it back by
    hashing the manifest's token proves the BLOB survived unchanged -- a
    text/bytes confusion here would silently log everyone out."""
    import hashlib

    token_hash = hashlib.sha256(MANIFEST["session_token"].encode()).digest()
    session = go_store.get_session_by_token_hash(token_hash)
    assert session.id == MANIFEST["session_id"]
    assert session.user_id == MANIFEST["admin_id"]
    assert session.csrf_token == MANIFEST["session_csrf"]
    assert session.ip == "203.0.113.7"
    assert session.user_agent == "Mozilla/5.0 (fixture)"


def test_session_token_hash_is_bytes_not_text(go_store: Store) -> None:
    session = go_store.list_sessions_for_user(MANIFEST["admin_id"])[0]
    assert isinstance(session.token_hash, bytes)
    assert len(session.token_hash) == 32


def test_cascade_delete_is_enabled(go_store: Store) -> None:
    """The schema relies on ON DELETE CASCADE for sessions, and SQLite
    disables foreign keys unless the pragma is set -- so this is really a
    test that we set it."""
    go_store._execute("DELETE FROM users WHERE id = ?", (MANIFEST["admin_id"],))
    assert go_store.list_sessions_for_user(MANIFEST["admin_id"]) == []


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------


def test_reads_endpoints_written_by_go(go_store: Store) -> None:
    endpoints = go_store.list_endpoints()
    assert [e.path for e in endpoints] == ["/hook/github", "/hook/paypal", "/hook/stripe"]

    stripe = go_store.get_endpoint_by_path("/hook/stripe")
    assert stripe.provider == "stripe"
    assert stripe.upstream_url == "http://app:8080/stripe"
    assert stripe.replay_window == "5m"
    assert stripe.secret_env == "STRIPE_SECRET"
    assert stripe.webhook_id == ""
    assert stripe.active is True


def test_paypal_endpoint_carries_a_webhook_id_and_no_secret_env(go_store: Store) -> None:
    """The table's CHECK constraint enforces the same per-provider shape the
    gateway's factories do."""
    paypal = go_store.get_endpoint_by_path("/hook/paypal")
    assert paypal.webhook_id == "WH-FIXTURE-1"
    assert paypal.secret_env == ""
    assert paypal.active is False


def test_active_filter_matches_go(go_store: Store) -> None:
    active = [e.path for e in go_store.list_active_endpoints()]
    assert active == ["/hook/github", "/hook/stripe"]  # paypal is inactive


# --------------------------------------------------------------------------
# Events and rollups
# --------------------------------------------------------------------------


def test_reads_events_written_by_go(go_store: Store) -> None:
    assert go_store.count_events() == 4
    assert go_store.has_any_event() is True

    latest = go_store.latest_event()
    assert latest.provider == "github"
    assert latest.verdict == "rejected"
    assert latest.reason == "stale timestamp"
    assert latest.latency_ms == 7


def test_event_filters_match_go_rows(go_store: Store) -> None:
    rejected = go_store.list_events(EventFilter(verdict="rejected"), 10)
    assert len(rejected) == 2
    assert {e.reason for e in rejected} == {"signature mismatch", "stale timestamp"}

    stripe_only = go_store.list_events(EventFilter(provider="stripe"), 10)
    assert len(stripe_only) == 2

    by_substring = go_store.list_events(EventFilter(reason="mismatch"), 10)
    assert len(by_substring) == 1


def test_reads_rollups_written_by_go(go_store: Store) -> None:
    hour = MANIFEST["hour"]
    assert go_store.rollup_count(hour, "stripe", "accepted") == 1
    assert go_store.rollup_count(hour, "github", "rejected") == 1
    assert go_store.rollup_count(hour, "shopify", "accepted") == 0  # absent bucket


def test_summary_over_go_written_rollups(go_store: Store) -> None:
    now_unix = MANIFEST["base_ms"] // 1000
    summary = go_store.summary_window(now_unix, 24)
    assert summary.accepted == 2
    assert summary.rejected == 2
    assert summary.accept_rate == 0.5
    # Latencies are 12, 3, 30, 7 -> sorted 3, 7, 12, 30 -> lower middle is 7.
    assert summary.p50_latency_ms == 7


def test_provider_stats_over_go_written_rollups(go_store: Store) -> None:
    stats = go_store.provider_stats_window(MANIFEST["base_ms"] // 1000, 24)
    assert set(stats) == {"stripe", "github"}
    assert stats["stripe"].accepted == 1
    assert stats["stripe"].total == 2
    assert stats["stripe"].accept_rate == 0.5
    assert "shopify" not in stats, "a provider with no traffic is absent, not zeroed"


def test_hourly_counts_zero_fill_around_the_go_bucket(go_store: Store) -> None:
    series = go_store.hourly_counts_window(MANIFEST["base_ms"] // 1000, 6)
    assert len(series) == 6
    assert [h.hour for h in series] == list(range(MANIFEST["hour"] - 5, MANIFEST["hour"] + 1))
    assert series[-1].accepted == 2  # the populated bucket
    assert all(h.accepted == 0 and h.rejected == 0 for h in series[:-1])


# --------------------------------------------------------------------------
# Settings and the security log
# --------------------------------------------------------------------------


def test_reads_settings_written_by_go(go_store: Store) -> None:
    assert go_store.get_retention_days() == MANIFEST["retention_days"]
    assert go_store.get_setting("fixture_marker") == "written-by-go"


def test_reads_auth_events_written_by_go(go_store: Store) -> None:
    events = go_store.list_auth_events(10)
    assert [e.kind for e in events] == [
        AuthEventKind.LOGIN_FAIL,
        AuthEventKind.LOGIN_OK,
        AuthEventKind.USER_CREATE,
    ]  # newest first


def test_a_failed_login_has_a_null_user_id(go_store: Store) -> None:
    """The column is nullable precisely so a failed login for an unknown
    address can still be recorded."""
    failed = next(e for e in go_store.list_auth_events(10) if e.kind == AuthEventKind.LOGIN_FAIL)
    assert failed.user_id is None
    assert failed.email == "nobody@example.com"


# --------------------------------------------------------------------------
# Writing back
# --------------------------------------------------------------------------


def test_python_can_write_into_a_go_created_database(go_store: Store) -> None:
    """Interoperability has to work in both directions: the console might be
    swapped over mid-deployment, leaving Python writing to a file Go made."""
    new_id = go_store.create_user("third@example.com", "$argon2id$x", "member", 1)
    assert go_store.count_users() == 3
    assert go_store.get_user_by_id(new_id).email == "third@example.com"

    go_store.set_retention_days(7)
    assert go_store.get_retention_days() == 7


def test_the_schema_is_not_reapplied_to_an_existing_database(tmp_path: Path) -> None:
    """Opening a populated database must not wipe it. The migration is gated
    on the users table existing, the same way Go gates it."""
    copy = tmp_path / "reopen.db"
    shutil.copy(FIXTURES / "go-console.db", copy)
    first = open_store(copy)
    assert first.count_users() == 2
    first.close()

    second = open_store(copy)
    assert second.count_users() == 2, "reopening re-ran the migration and lost data"
    second.close()
