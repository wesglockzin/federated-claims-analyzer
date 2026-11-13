import pytest
from fake_settings import CSRF


def test_health_is_public_and_ok(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_csp_directives_are_separated(client):
    csp = client.get("/health").headers["Content-Security-Policy"]
    directives = [d.strip() for d in csp.split(";") if d.strip()]
    names = [d.split()[0] for d in directives]
    assert names == [
        "default-src",
        "script-src",
        "style-src",
        "font-src",
        "img-src",
        "connect-src",
    ]


def test_gate_sends_anonymous_users_to_login(client):
    response = client.get("/")
    assert response.status_code == 302
    assert "/oidc/login" in response.headers["Location"]


def test_login_ignores_offsite_next(client):
    client.get("/login?next=//evil.invalid/x")
    with client.session_transaction() as sess:
        assert "post_login_redirect" not in sess


def test_login_keeps_relative_next(client):
    client.get("/login?next=/howto")
    with client.session_transaction() as sess:
        assert sess["post_login_redirect"] == "/howto"


def test_callback_ignores_offsite_stored_redirect(app_mod, client, monkeypatch):
    class FakeOAuthClient:
        def authorize_access_token(self):
            return {"userinfo": {"email": "someone@example.invalid"}}

    monkeypatch.setattr(app_mod.oauth, "okta", FakeOAuthClient(), raising=False)
    with client.session_transaction() as sess:
        sess["post_login_redirect"] = "//evil.invalid"
    response = client.get("/oidc/callback")
    assert response.status_code == 302
    assert "evil.invalid" not in response.headers["Location"]


def test_okta_callback_rejects_missing_state(client):
    response = client.get("/okta/oidc/callback?code=abc")
    assert b"Invalid state parameter." in response.data


def test_adfs_callback_rejects_missing_state(client):
    response = client.get("/adfs/oidc/callback?code=abc")
    assert b"Invalid state parameter." in response.data


def test_split_claims_separates_custom_from_standard(app_mod):
    important, detailed = app_mod.process_and_split_claims(
        {
            "email": "a@example.invalid",
            "iss": "https://idp.invalid",
            "groups": ["g1"],
            "exp": 1700000000,
        }
    )
    assert important["email"] == "a@example.invalid"
    assert important["groups"] == ["g1"]
    assert set(detailed) == {"iss", "exp"}
    assert detailed["exp"].endswith("(1700000000)")


def test_split_claims_keeps_bad_timestamp_and_handles_empty(app_mod):
    _, detailed = app_mod.process_and_split_claims({"exp": "not-a-number"})
    assert detailed["exp"] == "not-a-number"
    assert app_mod.process_and_split_claims(None) == ({}, {})


def test_refresh_passes_the_auth_server_type(app_mod, signed_in, monkeypatch):
    calls = []

    def fake_refresh(*args):
        calls.append(args)
        return {"access_token": "test-token-not-real"}

    monkeypatch.setattr(
        app_mod.sso_tester_logic, "oidc_perform_token_refresh", fake_refresh
    )
    with signed_in.session_transaction() as sess:
        sess["refresh_token"] = "test-refresh-not-real"
        sess["idp_context_for_refresh"] = {
            "idp": "okta",
            "env": "DEV",
            "auth_server_type": "default",
        }
    response = signed_in.post("/refresh_token", data={"csrf_token": CSRF})
    assert response.status_code == 200
    assert calls == [("test-refresh-not-real", "okta", "DEV", "default")]


def _fake_oauth(app_mod, monkeypatch, userinfo):
    class FakeOAuthClient:
        def authorize_access_token(self):
            if isinstance(userinfo, Exception):
                raise userinfo
            return {"userinfo": userinfo}

    monkeypatch.setattr(app_mod.oauth, "okta", FakeOAuthClient(), raising=False)


def test_callback_refuses_an_account_not_on_the_allow_list(
    app_mod, client, monkeypatch
):
    _fake_oauth(app_mod, monkeypatch, {"email": "stranger@example.invalid"})
    response = client.get("/oidc/callback")
    assert response.status_code == 302
    with client.session_transaction() as sess:
        assert "user" not in sess
        assert "not allowed" in sess["login_error"]


def test_callback_admits_an_account_in_an_allowed_group(app_mod, client, monkeypatch):
    monkeypatch.setattr(app_mod, "ALLOWED_GROUPS", ["staff"])
    _fake_oauth(
        app_mod, monkeypatch, {"email": "new@example.invalid", "groups": ["staff"]}
    )
    client.get("/oidc/callback")
    with client.session_transaction() as sess:
        assert sess["user"]["email"] == "new@example.invalid"


def test_login_page_never_shows_exception_text(app_mod, client, monkeypatch):
    _fake_oauth(app_mod, monkeypatch, RuntimeError("secret-detail-from-library"))
    client.get("/oidc/callback")
    page = client.get("/login").get_data(as_text=True)
    assert "secret-detail-from-library" not in page
    assert "Sign-in failed" in page


def test_callback_error_page_never_shows_exception_text(
    signed_in, monkeypatch, app_mod
):
    def boom(*args, **kwargs):
        raise RuntimeError("secret-detail-from-library")

    monkeypatch.setattr(app_mod.sso_tester_logic, "okta_oidc_get_endpoints", boom)
    with signed_in.session_transaction() as sess:
        sess["oauth_state"] = "abc"
        sess["okta_env_key"] = "DEV"
    page = signed_in.get("/okta/oidc/callback?code=c&state=abc").get_data(as_text=True)
    assert "secret-detail-from-library" not in page
    assert "request failed" in page


def test_refresh_error_page_shows_idp_status_and_body(app_mod, signed_in, monkeypatch):
    monkeypatch.setattr(
        app_mod.sso_tester_logic,
        "oidc_perform_token_refresh",
        lambda *args: {"error": "http_error", "error_description": "HTTP 502: bad"},
    )
    with signed_in.session_transaction() as sess:
        sess["refresh_token"] = "test-refresh-not-real"
        sess["idp_context_for_refresh"] = {"idp": "okta", "env": "DEV"}
    page = signed_in.post("/refresh_token", data={"csrf_token": CSRF}).get_data(
        as_text=True
    )
    assert "HTTP 502: bad" in page


@pytest.mark.parametrize(
    "path", ["/run_test", "/check_token_lifetimes", "/refresh_token"]
)
def test_post_without_csrf_token_is_rejected(signed_in, path):
    assert signed_in.post(path).status_code == 400
    assert signed_in.post(path, data={"csrf_token": "wrong"}).status_code == 400


def test_post_with_csrf_header_is_accepted(signed_in):
    response = signed_in.post(
        "/check_token_lifetimes",
        data={"idp_choice": "adfs", "environment": "DEV"},
        headers={"X-CSRF-Token": CSRF},
    )
    assert response.status_code == 200
    assert "only supported for Okta" in response.get_json()["error"]


def test_saml_callback_is_not_blocked_by_csrf(client):
    response = client.post("/okta/saml/callback")
    assert response.status_code == 200
    assert b"SAML context not found" in response.data


def test_form_carries_a_csrf_token_and_the_configured_environments(signed_in):
    page = signed_in.get("/").get_data(as_text=True)
    assert f'name="csrf_token" value="{CSRF}"' in page
    assert 'name="environment" value="DEV"' in page
    assert 'name="environment" value="QA"' in page
    assert 'name="environment" value="PROD"' not in page
    assert "Second app" in page


def test_session_cookie_is_lax_over_http(app_mod):
    assert app_mod.app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app_mod.app.config["SESSION_COOKIE_SECURE"] is False
