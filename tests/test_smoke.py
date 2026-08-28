"""Phase 0 exit check: every shipped package imports on a clean install.

This is the Python counterpart to `go build ./...` -- it proves the packages
are wired into the build correctly, nothing more.
"""

import importlib

import pytest


@pytest.mark.parametrize(
    "module",
    [
        "hookguard_core",
        "hookguard_gateway",
        "hookguard_gateway.providers",
        "hookguard_console",
        "hookguard_console.auth",
        "hookguard_console.store",
        "hookguard_console.routes",
    ],
)
def test_package_imports(module: str) -> None:
    assert importlib.import_module(module) is not None
