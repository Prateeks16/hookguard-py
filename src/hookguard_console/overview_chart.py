"""The Overview's events-per-hour chart, rendered server-side as inline SVG.

No charting library: the chart is bars over a fixed viewBox, and a dependency
that ships a canvas renderer to draw twenty-four rectangles would be the wrong
trade for a self-hosted console with a strict CSP.

Everything interpolated here is an integer or a float this module computed.
That matters: the template renders the result with ``| safe``, bypassing
autoescaping, so this function is the reason that bypass is sound. If it ever
needs to interpolate a string from the database, it must escape it.
"""

from __future__ import annotations

from collections.abc import Sequence

from .store import HourlyCounts

__all__ = ["render_hourly_chart"]

WIDTH = 720
HEIGHT = 160
BAR_GAP = 2
BOTTOM_PAD = 4
PLOT_HEIGHT = HEIGHT - BOTTOM_PAD


def render_hourly_chart(buckets: Sequence[HourlyCounts]) -> str:
    """Stacked accepted/rejected bars, one per hour.

    Rejected sits on top of accepted so an hour that was wholly rejected is
    still visible when the count is small. A ``<title>`` and an ``aria-label``
    carry a plain-text summary, so the chart is legible without colour.
    """
    if not buckets:
        return (
            f'<svg viewBox="0 0 {WIDTH} {HEIGHT}" xmlns="http://www.w3.org/2000/svg"'
            ' role="img" aria-label="No event data for this window"></svg>'
        )

    # Never zero: a window of all-zero buckets is still a valid chart, just a
    # flat baseline, and dividing by the max would fail on it.
    max_total = max(1, max(b.accepted + b.rejected for b in buckets))
    total_accepted = sum(b.accepted for b in buckets)
    total_rejected = sum(b.rejected for b in buckets)

    bar_width = max(1.0, (WIDTH / len(buckets)) - BAR_GAP)

    bars: list[str] = []
    for i, bucket in enumerate(buckets):
        x = i * (bar_width + BAR_GAP)
        accepted_h = bucket.accepted / max_total * PLOT_HEIGHT
        rejected_h = bucket.rejected / max_total * PLOT_HEIGHT
        accepted_y = PLOT_HEIGHT - accepted_h
        rejected_y = accepted_y - rejected_h

        if bucket.accepted:
            bars.append(
                f'<rect x="{x:.2f}" y="{accepted_y:.2f}" width="{bar_width:.2f}"'
                f' height="{accepted_h:.2f}" fill="var(--ok)">'
                f"<title>hour {bucket.hour}: {bucket.accepted} accepted</title></rect>"
            )
        if bucket.rejected:
            bars.append(
                f'<rect x="{x:.2f}" y="{rejected_y:.2f}" width="{bar_width:.2f}"'
                f' height="{rejected_h:.2f}" fill="var(--reject)">'
                f"<title>hour {bucket.hour}: {bucket.rejected} rejected</title></rect>"
            )

    label = (
        f"Events per hour over {len(buckets)} hours: "
        f"{total_accepted} accepted, {total_rejected} rejected total"
    )
    return (
        f'<svg viewBox="0 0 {WIDTH} {HEIGHT}" xmlns="http://www.w3.org/2000/svg"'
        f' role="img" aria-label="{label}"><title>{label}</title>{"".join(bars)}</svg>'
    )
