"""Go's ``time.ParseDuration`` syntax, reimplemented.

``replay_window`` holds strings like ``"5m"``, ``"1h30m"`` and ``"300s"`` in
three places that all outlive the port: the committed ``config*.json`` files,
the ``endpoints.replay_window`` column, and the export/validate round-trip the
Console performs against the Gateway's config shape. Python has no stdlib
parser for that syntax, and this is the failure that stays quiet -- a parser
that returns zero on an input it does not understand disables the replay-window
check while every other test still passes. So the rule here is that anything
not accepted by Go is an error, never a default.

Precision: parsing is exact to the nanosecond via :func:`parse_go_duration_ns`,
which is what the cross-language tests compare. :func:`parse_go_duration`
returns a ``timedelta``, whose resolution is one microsecond -- irrelevant for
replay windows, which are minutes, but it is why the nanosecond function is the
one to reach for when comparing against Go.
"""

from __future__ import annotations

import re
from datetime import timedelta

__all__ = ["GoDurationError", "parse_go_duration", "parse_go_duration_ns"]


class GoDurationError(ValueError):
    """A duration string Go's ``time.ParseDuration`` would reject."""


# Nanoseconds per unit, matching Go's unitMap. Go accepts three spellings of
# microseconds because the sign it prints ("µs") is not the one most keyboards
# produce, and "µ" itself has two Unicode code points in common use.
_UNITS: dict[str, int] = {
    "ns": 1,
    "us": 1_000,
    "µs": 1_000,  # U+00B5 MICRO SIGN
    "μs": 1_000,  # U+03BC GREEK SMALL LETTER MU
    "ms": 1_000_000,
    "s": 1_000_000_000,
    "m": 60 * 1_000_000_000,
    "h": 3600 * 1_000_000_000,
}

# Longest first, so "ms" is never mis-read as bare "m" with a trailing "s".
_UNIT_NAMES = sorted(_UNITS, key=len, reverse=True)

_NUMBER = re.compile(r"\A(\d*)(?:\.(\d*))?")

# Go's Duration is an int64 count of nanoseconds; it reports an overflow rather
# than wrapping, and so do we.
_INT64_MAX = (1 << 63) - 1
_INT64_MIN = -(1 << 63)


def parse_go_duration_ns(s: str) -> int:
    """Parse a Go duration string to an exact integer count of nanoseconds.

    Accepts a possibly signed sequence of decimal numbers, each with an
    optional fraction and a required unit suffix -- ``"300ms"``, ``"-1.5h"``,
    ``"2h45m"``. As in Go, a bare ``"0"`` is the one number allowed to omit its
    unit.

    Raises:
        GoDurationError: on anything Go would reject, including the empty
            string, a missing or unknown unit, and int64 overflow.
    """
    if not isinstance(s, str):
        raise GoDurationError(f"expected a string, got {type(s).__name__}")

    orig = s
    neg = False
    if s and s[0] in "+-":
        neg = s[0] == "-"
        s = s[1:]

    # Go's one special case: "0" needs no unit. "0s" is also fine, and falls
    # through to the ordinary path below.
    if s == "0":
        return 0
    if s == "":
        raise GoDurationError(f"invalid duration {orig!r}")

    total = 0
    while s:
        # _NUMBER's parts are both optional, so it always matches -- possibly
        # empty, which is the "no digits at all" error below.
        m = _NUMBER.match(s)
        assert m is not None
        whole, frac = m.group(1), m.group(2)
        if not whole and not frac:
            raise GoDurationError(f"invalid duration {orig!r}")
        s = s[m.end() :]

        unit = next((u for u in _UNIT_NAMES if s.startswith(u)), None)
        if unit is None:
            raise GoDurationError(
                f"missing or unknown unit in duration {orig!r}"
                if s
                else f"missing unit in duration {orig!r}"
            )
        s = s[len(unit) :]

        scale = _UNITS[unit]
        total += int(whole or "0") * scale
        if frac:
            # Exact rather than floating point: 0.1s must be 100_000_000ns, and
            # float arithmetic does not promise that.
            total += int(frac) * scale // (10 ** len(frac))

        if total > _INT64_MAX:
            raise GoDurationError(f"duration {orig!r} overflows int64 nanoseconds")

    result = -total if neg else total
    if not (_INT64_MIN <= result <= _INT64_MAX):
        raise GoDurationError(f"duration {orig!r} overflows int64 nanoseconds")
    return result


def parse_go_duration(s: str) -> timedelta:
    """Parse a Go duration string to a ``timedelta``.

    Resolution is one microsecond; sub-microsecond input is truncated toward
    zero. Use :func:`parse_go_duration_ns` where the exact nanosecond value
    matters.
    """
    ns = parse_go_duration_ns(s)
    # Integer truncation toward zero. `ns // 1000` would floor (so -1500ns
    # would become -2us), and `ns / 1000` would lose precision on large values.
    us = abs(ns) // 1000
    return timedelta(microseconds=-us if ns < 0 else us)
