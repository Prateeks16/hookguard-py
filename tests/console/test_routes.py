"""The Console's HTTP surface, ported from web/internal/server/handlers_*_test.go.

Note the base URL: ``https://testserver``. The session cookie is Secure, so a
plain-HTTP client never sends it back and every authenticated test would
silently exercise the logged-out path instead -- passing for the wrong reason
on the redirects and failing confusingly everywhere else. That is real
behaviour, not a test artifact: the Console cannot be used over plain HTTP.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from hookguard_console.app import build_app
from hookguard_console.config import ConsoleConfig
from hookguard_console.store import Event, RollupDelta, Store, open_store
from hookguard_core import gatewaysig
from hookguard_core.events import INGEST_PROVIDER_LABEL, VerifyEvent

SECRET = b"internal-console-test"
PASSWORD = "correct-horse-battery"
NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def store(tmp_path: Path) -> Store:
    st = open_store(tmp_path / "console.db")
    yield st
    st.close()


@pytest.fixture
def client(store: Store, tmp_path: Path) -> TestClient:
    app = build_app(
        store,
        config=ConsoleConfig(data_dir=tmp_path, allow_signup=True, internal_secret=SECRET),
        now=lambda: NOW,
    )
    with TestClient(app, base_url="https://testserver") as c:
        yield c


def csrf_of(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "no CSRF token in the rendered page"
    return match.group(1)


@pytest.fixture
def signed_in(client: TestClient) -> TestClient:
    client.post(
        "/signup",
        data={"email": "admin@example.com", "password": PASSWORD, "password_confirm": PASSWORD},
    )
    return client


def token(client: TestClient) -> str:
    return csrf_of(client.get("/dashboard").text)


# --------------------------------------------------------------------------
# Public surface
# --------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/", "/playground", "/healthz", "/login", "/signup"])
def test_public_pages_need_no_session(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 200


def test_healthz_reports_the_version(client: TestClient) -> None:
    body = client.get("/healthz").json()
    assert body["status"] == "ok"
    assert body["version"]


def test_unknown_paths_render_the_404_page(client: TestClient) -> None:
    response = client.get("/nope")
    assert response.status_code == 404
    assert "isn't in my config" in response.text


def test_security_headers_on_every_response(client: TestClient) -> None:
    headers = client.get("/").headers
    assert headers["Content-Security-Policy"] == "default-src 'self'"
    assert headers["X-Frame-Options"] == "DENY"


def test_signup_is_refused_when_disabled(store: Store, tmp_path: Path) -> None:
    app = build_app(store, config=ConsoleConfig(data_dir=tmp_path, allow_signup=False))
    with TestClient(app, base_url="https://testserver") as c:
        assert c.get("/signup").status_code == 403
        response = c.post(
            "/signup",
            data={"email": "a@example.com", "password": PASSWORD, "password_confirm": PASSWORD},
        )
        assert response.status_code == 403
        assert store.count_users() == 0


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/dashboard",
        "/dashboard/endpoints",
        "/dashboard/logs",
        "/dashboard/providers",
        "/dashboard/settings",
        "/api/v1/stats/summary",
    ],
)
def test_protected_routes_redirect_to_login(client: TestClient, path: str) -> None:
    response = client.get(path, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == f"/login?next={path}"


def test_signup_makes_the_first_user_an_admin(client: TestClient, store: Store) -> None:
    client.post(
        "/signup",
        data={"email": "first@example.com", "password": PASSWORD, "password_confirm": PASSWORD},
    )
    assert store.get_user_by_email("first@example.com").role == "admin"


def test_the_second_user_is_a_member(client: TestClient, store: Store) -> None:
    for email in ("first@example.com", "second@example.com"):
        client.post(
            "/signup",
            data={"email": email, "password": PASSWORD, "password_confirm": PASSWORD},
        )
    assert store.get_user_by_email("second@example.com").role == "member"


def test_login_succeeds_and_reaches_the_dashboard(signed_in: TestClient) -> None:
    signed_in.post("/logout", data={"csrf_token": token(signed_in)})
    response = signed_in.post(
        "/login", data={"email": "admin@example.com", "password": PASSWORD}, follow_redirects=False
    )
    assert response.status_code == 303
    assert signed_in.get("/dashboard").status_code == 200


@pytest.mark.parametrize(
    ("email", "password", "why"),
    [
        ("admin@example.com", "wrong-password-here", "wrong password"),
        ("nobody@example.com", PASSWORD, "unknown address"),
    ],
)
def test_failed_logins_are_indistinguishable(
    signed_in: TestClient, email: str, password: str, why: str
) -> None:
    """Same status and same message either way. Anything else turns the login
    form into an account enumerator."""
    signed_in.post("/logout", data={"csrf_token": token(signed_in)})
    response = signed_in.post("/login", data={"email": email, "password": password})
    assert response.status_code == 200, why
    assert "Invalid email or password." in response.text, why


def test_a_deactivated_user_cannot_log_in(signed_in: TestClient, store: Store) -> None:
    signed_in.post("/logout", data={"csrf_token": token(signed_in)})
    store.set_user_active(store.get_user_by_email("admin@example.com").id, False)
    response = signed_in.post("/login", data={"email": "admin@example.com", "password": PASSWORD})
    assert "Invalid email or password." in response.text


def test_login_rotates_the_session_token(signed_in: TestClient) -> None:
    """A fresh token on every login, so a token an attacker planted before it
    is not still valid after -- session fixation."""
    first = signed_in.cookies.get("hg_session")
    signed_in.post("/logout", data={"csrf_token": token(signed_in)})
    signed_in.post("/login", data={"email": "admin@example.com", "password": PASSWORD})
    assert signed_in.cookies.get("hg_session") != first


def test_next_is_honoured_but_sanitized(signed_in: TestClient) -> None:
    signed_in.post("/logout", data={"csrf_token": token(signed_in)})
    response = signed_in.post(
        "/login",
        data={"email": "admin@example.com", "password": PASSWORD, "next": "//evil.example"},
        follow_redirects=False,
    )
    assert response.headers["location"] == "/dashboard", "open redirect"


def test_logout_clears_the_session(signed_in: TestClient, store: Store) -> None:
    signed_in.post("/logout", data={"csrf_token": token(signed_in)})
    assert signed_in.get("/dashboard", follow_redirects=False).status_code == 303
    user = store.get_user_by_email("admin@example.com")
    assert store.list_sessions_for_user(user.id) == []


def test_logout_requires_csrf(signed_in: TestClient) -> None:
    assert signed_in.post("/logout", data={}).status_code == 403
    assert signed_in.get("/dashboard").status_code == 200, "still signed in"


def test_login_is_rate_limited(signed_in: TestClient) -> None:
    signed_in.post("/logout", data={"csrf_token": token(signed_in)})
    last = None
    for _ in range(15):
        last = signed_in.post(
            "/login", data={"email": "admin@example.com", "password": "wrong-password-x"}
        )
    assert last is not None
    assert last.status_code == 429
    assert int(last.headers["Retry-After"]) >= 1


# --------------------------------------------------------------------------
# CSRF
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/dashboard/endpoints",
        "/dashboard/settings/password",
        "/dashboard/settings/retention",
        "/dashboard/settings/sessions/revoke-others",
        "/logout",
    ],
)
def test_state_changing_routes_require_csrf(signed_in: TestClient, path: str) -> None:
    assert signed_in.post(path, data={}).status_code == 403


def test_a_wrong_csrf_token_is_refused(signed_in: TestClient) -> None:
    response = signed_in.post(
        "/dashboard/endpoints",
        data={
            "csrf_token": "not-the-token",
            "path": "/hook/x",
            "provider": "github",
            "upstream_url": "http://u",
            "secret_env": "S",
        },
    )
    assert response.status_code == 403


def test_the_csrf_token_is_accepted_from_a_header(signed_in: TestClient) -> None:
    """htmx sends it as a header; forms send it as a field. Both paths are
    protected, rather than the no-JavaScript one being exempt."""
    response = signed_in.post(
        "/dashboard/endpoints",
        data={
            "path": "/hook/gh",
            "provider": "github",
            "upstream_url": "http://u",
            "secret_env": "GITHUB_SECRET",
        },
        headers={"X-CSRF-Token": token(signed_in)},
        follow_redirects=False,
    )
    assert response.status_code == 303


# --------------------------------------------------------------------------
# Routes (endpoints) CRUD
# --------------------------------------------------------------------------


def create_route(client: TestClient, **overrides: str):
    data = {
        "csrf_token": token(client),
        "path": "/hook/stripe",
        "provider": "stripe",
        "upstream_url": "http://app:8080/stripe",
        "secret_env": "STRIPE_SECRET",
        "replay_window": "5m",
    }
    data.update(overrides)
    return client.post("/dashboard/endpoints", data=data, follow_redirects=False)


def test_create_and_list(signed_in: TestClient) -> None:
    assert create_route(signed_in).status_code == 303
    assert "/hook/stripe" in signed_in.get("/dashboard/endpoints").text


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"path": ""}, "Path is required."),
        ({"path": "hook/stripe"}, "must start with /"),
        ({"upstream_url": ""}, "Upstream URL is required."),
        ({"secret_env": ""}, "requires the name of a secret"),
        ({"provider": "nope"}, "Unknown provider."),
        ({"replay_window": "5 minutes"}, "Go duration"),
        ({"provider": "paypal", "secret_env": "", "webhook_id": ""}, "webhook ID"),
    ],
)
def test_invalid_submissions_come_back_as_form_errors(
    signed_in: TestClient, overrides: dict[str, str], message: str
) -> None:
    """Validated before anything touches the database, so a bad submission is
    a 400 with a readable message rather than a 500 from a constraint."""
    response = create_route(signed_in, **overrides)
    assert response.status_code == 400
    assert message in response.text


def test_a_duplicate_path_is_a_form_error(signed_in: TestClient) -> None:
    create_route(signed_in)
    response = create_route(signed_in)
    assert response.status_code == 400
    assert "already exists" in response.text


def test_editing_does_not_re_enable_a_disabled_route(signed_in: TestClient, store: Store) -> None:
    """The form has no active field. Editing a disabled route must leave it
    disabled rather than silently turning traffic back on."""
    create_route(signed_in)
    endpoint = store.get_endpoint_by_path("/hook/stripe")
    signed_in.post(
        f"/dashboard/endpoints/{endpoint.id}/toggle-active",
        data={"csrf_token": token(signed_in)},
    )
    assert store.get_endpoint_by_id(endpoint.id).active is False

    signed_in.post(
        f"/dashboard/endpoints/{endpoint.id}",
        data={
            "csrf_token": token(signed_in),
            "path": "/hook/stripe",
            "provider": "stripe",
            "upstream_url": "http://changed:8080/s",
            "secret_env": "STRIPE_SECRET",
            "replay_window": "5m",
        },
    )
    updated = store.get_endpoint_by_id(endpoint.id)
    assert updated.upstream_url == "http://changed:8080/s"
    assert updated.active is False


def test_delete(signed_in: TestClient, store: Store) -> None:
    create_route(signed_in)
    endpoint = store.get_endpoint_by_path("/hook/stripe")
    signed_in.post(
        f"/dashboard/endpoints/{endpoint.id}/delete", data={"csrf_token": token(signed_in)}
    )
    assert store.list_endpoints() == []


def test_editing_a_missing_route_is_a_404(signed_in: TestClient) -> None:
    assert signed_in.get("/dashboard/endpoints/999/edit").status_code == 404


def test_export_matches_what_the_gateway_would_load(signed_in: TestClient, tmp_path: Path) -> None:
    from hookguard_gateway.config import load_config

    create_route(signed_in)
    body = signed_in.get("/dashboard/endpoints/export/download").text
    path = tmp_path / "exported.json"
    path.write_text(body, encoding="utf-8")

    routes = load_config(path).routes
    assert [r.path for r in routes] == ["/hook/stripe"]
    assert routes[0].replay_window == "5m"


def test_export_omits_inactive_routes(signed_in: TestClient, store: Store) -> None:
    create_route(signed_in)
    endpoint = store.get_endpoint_by_path("/hook/stripe")
    signed_in.post(
        f"/dashboard/endpoints/{endpoint.id}/toggle-active",
        data={"csrf_token": token(signed_in)},
    )
    assert "/hook/stripe" not in signed_in.get("/dashboard/endpoints/export/download").text


def test_export_never_contains_a_secret(signed_in: TestClient) -> None:
    """It carries the NAME of each secret's environment variable. That is the
    whole design, and it is what makes the file safe to hand around."""
    create_route(signed_in)
    body = signed_in.get("/dashboard/endpoints/export/download").text
    assert "STRIPE_SECRET" in body
    assert PASSWORD not in body


# --------------------------------------------------------------------------
# The escaping invariant
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    ['"><script>alert(1)</script>', "javascript:alert(1)", "24h'\"><img src=x onerror=1>"],
)
def test_the_window_parameter_is_never_echoed(signed_in: TestClient, hostile: str) -> None:
    """The invariant the escaping audit turned up.

    Go's html/template escapes per context, so a value in a URL attribute got
    URL escaping; Jinja2's autoescape is HTML-only. Three templates interpolate
    into URL attributes, and this is the one whose value comes from a request.
    It is safe because ?window= selects one of two literals rather than being
    echoed -- an invariant nothing in the templating layer can enforce, so it
    is enforced here.
    """
    response = signed_in.get("/dashboard", params={"window": hostile})
    assert response.status_code == 200
    assert hostile not in response.text
    assert "window=24h" in response.text or "window={{" not in response.text


def test_the_window_parameter_only_ever_selects_a_known_value(
    signed_in: TestClient,
) -> None:
    for value, expected in [("7d", "7d"), ("24h", "24h"), ("nonsense", "24h"), ("", "24h")]:
        body = signed_in.get("/api/v1/stats/summary", params={"window": value}).json()
        assert body["window"] == expected


def test_hostile_values_are_escaped_where_they_are_displayed(
    signed_in: TestClient, store: Store
) -> None:
    """Reasons come from the gateway and are shown in the log table."""
    store.insert_events(
        [
            Event(
                received_at=int(NOW.timestamp() * 1000),
                path="/hook/stripe",
                provider="stripe",
                verdict="rejected",
                reason='<script>alert("xss")</script>',
            )
        ]
    )
    body = signed_in.get("/dashboard/logs").text
    assert "<script>alert" not in body
    assert "&lt;script&gt;" in body


# --------------------------------------------------------------------------
# Dashboard content
# --------------------------------------------------------------------------


def test_the_empty_state_rather_than_a_wall_of_zeros(signed_in: TestClient) -> None:
    body = signed_in.get("/dashboard").text
    assert "No traffic at the gate yet." in body


def test_the_overview_renders_real_numbers_once_events_exist(
    signed_in: TestClient, store: Store
) -> None:
    hour = int(NOW.timestamp()) // 3600
    store.insert_events(
        [
            Event(
                received_at=int(NOW.timestamp() * 1000),
                path="/h",
                provider="stripe",
                verdict="accepted",
                latency_ms=12,
            )
        ]
    )
    store.upsert_rollups([RollupDelta(hour=hour, provider="stripe", verdict="accepted", n=3)])
    body = signed_in.get("/dashboard").text
    assert "No traffic at the gate yet." not in body
    assert "<svg" in body, "the chart should render"


def test_providers_lists_all_four_with_setup_guides(signed_in: TestClient) -> None:
    body = signed_in.get("/dashboard/providers").text
    for provider in ("stripe", "github", "shopify", "paypal"):
        assert provider in body
    assert "X-Hub-Signature-256" in body
    assert "webhook_id" in body


def test_settings_shows_the_current_session(signed_in: TestClient) -> None:
    assert "this session" in signed_in.get("/dashboard/settings").text


# --------------------------------------------------------------------------
# Settings actions
# --------------------------------------------------------------------------


def test_changing_a_password_requires_the_current_one(signed_in: TestClient) -> None:
    response = signed_in.post(
        "/dashboard/settings/password",
        data={
            "csrf_token": token(signed_in),
            "current_password": "not-the-password",
            "new_password": "a-brand-new-passphrase",
            "new_password_confirm": "a-brand-new-passphrase",
        },
    )
    assert "Current password is incorrect." in response.text


def test_changing_a_password_signs_out_other_sessions(signed_in: TestClient, store: Store) -> None:
    """The usual reason to change a password is that someone else may have
    had it."""
    user = store.get_user_by_email("admin@example.com")
    from hookguard_console.store import Session

    store.create_session(
        Session(
            token_hash=b"other" * 8,
            user_id=user.id,
            csrf_token="c",
            created_at=1,
            last_seen_at=1,
            expires_at=9_999_999_999_999,
        )
    )
    assert len(store.list_sessions_for_user(user.id)) == 2

    signed_in.post(
        "/dashboard/settings/password",
        data={
            "csrf_token": token(signed_in),
            "current_password": PASSWORD,
            "new_password": "a-brand-new-passphrase",
            "new_password_confirm": "a-brand-new-passphrase",
        },
    )
    assert len(store.list_sessions_for_user(user.id)) == 1, "other sessions survived"
    assert signed_in.get("/dashboard").status_code == 200, "own session survived"


def test_retention_can_be_changed(signed_in: TestClient, store: Store) -> None:
    signed_in.post(
        "/dashboard/settings/retention",
        data={"csrf_token": token(signed_in), "retention_days": "7"},
    )
    assert store.get_retention_days() == 7


@pytest.mark.parametrize("bad", ["0", "-1", "abc", ""])
def test_invalid_retention_is_refused(signed_in: TestClient, store: Store, bad: str) -> None:
    signed_in.post(
        "/dashboard/settings/retention",
        data={"csrf_token": token(signed_in), "retention_days": bad},
    )
    assert store.get_retention_days() == 30, "the default should be untouched"


def test_an_admin_can_create_a_user(signed_in: TestClient, store: Store) -> None:
    signed_in.post(
        "/dashboard/settings/users",
        data={
            "csrf_token": token(signed_in),
            "email": "member@example.com",
            "password": "another-good-passphrase",
            "role": "member",
        },
    )
    assert store.get_user_by_email("member@example.com").role == "member"


def test_an_admin_cannot_deactivate_themselves(signed_in: TestClient, store: Store) -> None:
    """Not a recoverable mistake on a single-admin install."""
    admin = store.get_user_by_email("admin@example.com")
    response = signed_in.post(
        f"/dashboard/settings/users/{admin.id}/deactivate",
        data={"csrf_token": token(signed_in)},
    )
    assert "cannot deactivate your own account" in response.text
    assert store.get_user_by_id(admin.id).active is True


def test_a_member_cannot_reach_the_admin_actions(client: TestClient, store: Store) -> None:
    """Server-side authorization, independent of whether the UI hides it."""
    client.post(
        "/signup",
        data={"email": "first@example.com", "password": PASSWORD, "password_confirm": PASSWORD},
    )
    client.post("/logout", data={"csrf_token": token(client)})
    client.post(
        "/signup",
        data={"email": "member@example.com", "password": PASSWORD, "password_confirm": PASSWORD},
    )
    assert store.get_user_by_email("member@example.com").role == "member"

    response = client.post(
        "/dashboard/settings/users",
        data={
            "csrf_token": token(client),
            "email": "x@example.com",
            "password": "yet-another-passphrase",
            "role": "admin",
        },
    )
    assert response.status_code == 403
    assert "Admins only." in response.text


# --------------------------------------------------------------------------
# Ingest
# --------------------------------------------------------------------------


def ingest(
    client: TestClient, body: bytes, *, signature: str | None = None, provider: str | None = None
):
    return client.post(
        "/api/v1/ingest",
        content=body,
        headers={
            gatewaysig.PROVIDER_HEADER: provider or INGEST_PROVIDER_LABEL,
            gatewaysig.HEADER: signature
            if signature is not None
            else gatewaysig.sign(SECRET, INGEST_PROVIDER_LABEL, body),
        },
    )


def an_event() -> bytes:
    return VerifyEvent(
        timestamp=NOW,
        path="/hook/stripe",
        provider="stripe",
        verdict="accepted",
        latency_ms=9,
        body_bytes=12,
    ).to_json_bytes()


def test_a_signed_event_is_accepted(client: TestClient) -> None:
    assert ingest(client, an_event()).status_code == 202


def test_ingest_needs_no_session(client: TestClient) -> None:
    """The caller is the gateway, which has no cookie."""
    assert "hg_session" not in client.cookies
    assert ingest(client, an_event()).status_code == 202


@pytest.mark.parametrize(
    ("kwargs", "why"),
    [
        ({"signature": "00" * 32}, "forged signature"),
        ({"signature": "not-hex"}, "malformed signature"),
        ({"signature": ""}, "no signature"),
        ({"provider": "stripe"}, "a webhook's provider label, not the ingest one"),
    ],
)
def test_unauthenticated_ingest_is_refused(client: TestClient, kwargs: dict, why: str) -> None:
    assert ingest(client, an_event(), **kwargs).status_code == 401, why


def test_a_bad_signature_never_writes(client: TestClient, store: Store) -> None:
    ingest(client, an_event(), signature="00" * 32)
    assert store.count_events() == 0


def test_a_malformed_body_with_a_valid_signature_is_a_400(client: TestClient) -> None:
    """Signed by something holding the right secret, but still nonsense. It
    must not become a row."""
    assert ingest(client, b"not json at all").status_code == 400


def test_an_accepted_event_is_queued_not_written_synchronously(
    client: TestClient, store: Store
) -> None:
    """202, not 200: the write is queued, not performed. Telling the gateway
    otherwise would be a claim it might act on.

    That the queue actually reaches the database is asserted in
    test_pipeline.py, against the batcher directly, where a flush can be
    awaited rather than raced.
    """
    assert ingest(client, an_event()).status_code == 202
