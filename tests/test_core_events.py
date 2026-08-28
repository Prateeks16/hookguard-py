"""The verdict-event wire shape, pinned against Go.

The Console decodes this exact JSON, and during the port the two
implementations have to interoperate in both directions, so the field names and
the timestamp format are contract rather than preference.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from hookguard_core.events import (
    INGEST_PROVIDER_LABEL,
    VerifyEvent,
    format_timestamp,
    parse_timestamp,
)

VECTORS = json.loads((Path(__file__).parent / "vectors" / "core.json").read_text("utf-8"))

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def test_ingest_provider_label_matches_go() -> None:
    """Go's ingest package pins this string; the Console rejects any other
    value before it even checks the HMAC."""
    assert INGEST_PROVIDER_LABEL == "console-ingest"


@pytest.mark.parametrize("case", VECTORS["timestamps"], ids=lambda c: c["name"])
def test_parses_go_wire_timestamps(case: dict[str, Any]) -> None:
    """Every shape Go's RFC3339Nano actually emits parses to the right instant.

    RFC3339Nano strips trailing zeros, so the number of fractional digits
    varies with the clock -- nine, six, three, one, or none at all.
    """
    parsed = parse_timestamp(case["wire"])
    assert parsed.tzinfo is not None, "an aware datetime, or comparisons silently break"

    # Exact integer comparison against Go's own UnixNano, truncated to the
    # microsecond a datetime can actually hold. Going via float seconds would
    # need a tolerance, which is precisely what would hide a drift here.
    expected = _EPOCH + timedelta(microseconds=case["unix_ns"] // 1000)
    assert parsed.astimezone(UTC) == expected


def test_nanosecond_precision_truncates_not_rounds() -> None:
    """.123456789 must become 123456us, not 123457us -- the vector file carries
    the nanosecond case precisely so this cannot drift unnoticed."""
    case = next(c for c in VECTORS["timestamps"] if c["name"] == "nanosecond precision")
    assert case["wire"].endswith(".123456789Z"), "vector file changed shape"
    assert parse_timestamp(case["wire"]).microsecond == 123456


def test_non_utc_offset_is_preserved_as_an_instant() -> None:
    case = next(c for c in VECTORS["timestamps"] if c["name"] == "non-utc offset")
    parsed = parse_timestamp(case["wire"])
    assert parsed.utcoffset() == timedelta(hours=5, minutes=30)
    assert parsed.astimezone(UTC).hour == 6  # 12:00+05:30 is 06:30Z


def test_format_timestamp_uses_z_not_offset() -> None:
    """Go emits `Z`; isoformat() alone would emit `+00:00`."""
    t = datetime(2026, 8, 29, 12, 0, 0, tzinfo=UTC)
    assert format_timestamp(t) == "2026-08-29T12:00:00Z"


def test_format_timestamp_normalizes_to_utc() -> None:
    ist = timezone(timedelta(hours=5, minutes=30))
    t = datetime(2026, 8, 29, 12, 0, 0, tzinfo=ist)
    assert format_timestamp(t) == "2026-08-29T06:30:00Z"


def test_format_timestamp_treats_naive_as_utc() -> None:
    """A naive datetime must not be read as local time -- that would shift
    every event by the host's offset."""
    assert format_timestamp(datetime(2026, 8, 29, 12, 0, 0)) == "2026-08-29T12:00:00Z"


def test_round_trip_through_go_wire_format() -> None:
    for case in VECTORS["timestamps"]:
        parsed = parse_timestamp(case["wire"])
        assert parse_timestamp(format_timestamp(parsed)) == parsed


# --------------------------------------------------------------------------
# The event object itself
# --------------------------------------------------------------------------


def test_json_keys_match_the_go_struct_tags() -> None:
    """Field names are the contract. A rename here breaks the other
    implementation's decoder, in whichever language it happens to be."""
    ev = VerifyEvent(
        timestamp=datetime(2026, 8, 29, 12, 0, 0, tzinfo=UTC),
        path="/hook/stripe",
        provider="stripe",
        verdict="accepted",
    )
    assert set(ev.to_json_dict()) == {
        "ts",
        "path",
        "provider",
        "verdict",
        "reason",
        "upstream_status",
        "latency_ms",
        "body_bytes",
        "body_sha256",
        "remote_ip",
    }


def test_round_trip_preserves_every_field() -> None:
    ev = VerifyEvent(
        timestamp=datetime(2026, 8, 29, 12, 0, 0, 123456, tzinfo=UTC),
        path="/hook/github",
        provider="github",
        verdict="rejected",
        reason="signature mismatch",
        upstream_status=502,
        latency_ms=17,
        body_bytes=412,
        body_sha256="a" * 64,
        remote_ip="203.0.113.7",
    )
    assert VerifyEvent.from_json_dict(json.loads(json.dumps(ev.to_json_dict()))) == ev


def test_missing_fields_take_zero_values() -> None:
    """Go's decoder leaves absent fields at their zero value rather than
    failing; an event with a field omitted is not malformed."""
    ev = VerifyEvent.from_json_dict({"ts": "2026-08-29T12:00:00Z"})
    assert ev.path == ""
    assert ev.upstream_status == 0
    assert ev.verdict == ""


def test_missing_timestamp_is_an_error() -> None:
    """`ts` is the one field with no sensible zero -- an event with no time is
    not an event."""
    with pytest.raises(KeyError):
        VerifyEvent.from_json_dict({"path": "/hook/stripe"})
