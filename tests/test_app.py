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
        {"email": "a@example.invalid", "iss": "https://idp.invalid", "groups": ["g1"], "exp": 1700000000}
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

    monkeypatch.setattr(app_mod.sso_tester_logic, "oidc_perform_token_refresh", fake_refresh)
    with signed_in.session_transaction() as sess:
        sess["refresh_token"] = "test-refresh-not-real"
        sess["idp_context_for_refresh"] = {"idp": "okta", "env": "DEV", "auth_server_type": "default"}
    response = signed_in.post("/refresh_token")
    assert response.status_code == 200
    assert calls == [("test-refresh-not-real", "okta", "DEV", "default")]
