"""Primitives shared by the Gateway and the Console.

Stdlib-only by design, mirroring the Go `internal/gatewaysig` package this
replaces: both services import it, so anything heavier here would land in
both images.
"""
