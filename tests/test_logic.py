import logging

import pytest
import requests

import sso_tester_logic as logic

TOKEN_URL = "https://idp.invalid/token"
ISSUER = logic.OKTA_ENVIRONMENTS["DEV"]["custom"]["oidc_issuer_url"]
ADFS_ISSUER = logic.ADFS_ENVIRONMENTS["DEV"]
ENDPOINTS = {
    "auth": "https://idp.invalid/authorize",
    "token": TOKEN_URL,
    "jwks_uri": "https://idp.invalid/keys",
    "userinfo": "https://idp.invalid/userinfo",
}


def fake_response(status, body, content_type="application/json"):
    response = requests.Response()
    response.status_code = status
    response._content = body.encode()
    response.url = TOKEN_URL
    response.headers["Content-Type"] = content_type
    return response


@pytest.fixture
def idp(monkeypatch):
    """Make the Okta token endpoint answer with whatever the test sets."""
    logic._endpoints_cache[ISSUER] = ENDPOINTS
    answer = {}

    def fake_post(url, **kwargs):
        assert url == TOKEN_URL
        return answer["response"]

    monkeypatch.setattr(logic._session, "post", fake_post)
    return answer


def test_refresh_returns_the_idp_error_body(idp):
    idp["response"] = fake_response(
        400, '{"error": "invalid_grant", "error_description": "expired"}'
    )
    result = logic.oidc_perform_token_refresh("rt", "okta", "DEV")
    assert result["error"] == "invalid_grant"
    assert result["error_description"] == "expired"


def test_refresh_reports_status_and_body_of_non_json_error(idp):
    idp["response"] = fake_response(502, "gateway down", "text/plain")
    result = logic.oidc_perform_token_refresh("rt", "okta", "DEV")
    assert result["error"] == "http_error"
    assert "502" in result["error_description"]
    assert "gateway down" in result["error_description"]


def test_refresh_success_returns_tokens(idp):
    idp["response"] = fake_response(200, '{"access_token": "test-token-not-real"}')
    assert logic.oidc_perform_token_refresh("rt", "okta", "DEV") == {
        "access_token": "test-token-not-real"
    }


def test_refresh_without_endpoint_is_a_configuration_error(monkeypatch):
    monkeypatch.setattr(
        logic._session, "get", lambda url, **kw: fake_response(503, "down")
    )
    assert (
        logic.oidc_perform_token_refresh("rt", "okta", "DEV")["error"]
        == "configuration_error"
    )


def test_code_exchange_logs_the_error_body(idp, caplog):
    idp["response"] = fake_response(400, '{"error": "invalid_grant"}')
    config = logic.OKTA_ENVIRONMENTS["DEV"]["custom"]
    with caplog.at_level(logging.ERROR, logger=logic.logger.name):
        assert (
            logic.okta_oidc_exchange_code_for_tokens("code", config, "verifier") is None
        )
    assert "HTTP 400" in caplog.text
    assert "invalid_grant" in caplog.text


def test_describe_request_error_without_response():
    assert logic.describe_request_error(requests.ConnectionError("boom")) == "boom"


def test_pkce_pair_matches():
    import base64
    import hashlib

    verifier, challenge = logic.generate_pkce_pair()
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    assert challenge == base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def discovery_document(prefix):
    return (
        '{"authorization_endpoint": "%s/authorize", "token_endpoint": "%s/token",'
        ' "jwks_uri": "%s/keys", "userinfo_endpoint": "%s/userinfo"}'
    ) % (prefix, prefix, prefix, prefix)


def test_endpoints_of_two_issuers_do_not_overwrite_each_other(monkeypatch):
    def fake_get(url, **kwargs):
        prefix = url.removesuffix("/.well-known/openid-configuration")
        return fake_response(200, discovery_document(prefix))

    monkeypatch.setattr(logic._session, "get", fake_get)
    first = logic.okta_oidc_get_endpoints("https://first.invalid")
    second = logic.okta_oidc_get_endpoints("https://second.invalid")
    assert first["token"] == "https://first.invalid/token"
    assert second["token"] == "https://second.invalid/token"
    assert logic.endpoints_for("https://first.invalid", "Okta") == first


def test_refresh_discovers_when_this_worker_has_no_endpoints(monkeypatch):
    """A refresh served by a worker that never ran the sign-in must still work."""
    monkeypatch.setattr(
        logic._session,
        "get",
        lambda url, **kw: fake_response(200, discovery_document("https://idp.invalid")),
    )
    monkeypatch.setattr(
        logic._session,
        "post",
        lambda url, **kw: fake_response(200, '{"access_token": "test-token-not-real"}'),
    )
    result = logic.oidc_perform_token_refresh("rt", "okta", "DEV")
    assert result == {"access_token": "test-token-not-real"}


def test_adfs_refresh_for_a_removed_environment_is_a_configuration_error():
    result = logic.oidc_perform_token_refresh("rt", "adfs", "GONE")
    assert result["error"] == "configuration_error"


def test_incomplete_discovery_document_is_refused(monkeypatch):
    monkeypatch.setattr(
        logic._session,
        "get",
        lambda url, **kw: fake_response(200, '{"token_endpoint": "https://x.invalid"}'),
    )
    assert logic.okta_oidc_get_endpoints(ISSUER) is None
    assert ISSUER not in logic._endpoints_cache


def test_discovery_logs_the_error_status_and_body(monkeypatch, caplog):
    monkeypatch.setattr(
        logic._session, "get", lambda url, **kw: fake_response(403, "discovery-denied")
    )
    with caplog.at_level(logging.ERROR, logger=logic.logger.name):
        assert logic.okta_oidc_get_endpoints(ISSUER) is None
        assert logic.adfs_oidc_get_endpoints(ADFS_ISSUER) is None
    assert caplog.text.count("HTTP 403: discovery-denied") == 2


def test_jwks_fetch_logs_the_error_status_and_body(monkeypatch, caplog):
    monkeypatch.setattr(
        logic._session, "get", lambda url, **kw: fake_response(404, "no-such-keys")
    )
    with caplog.at_level(logging.ERROR, logger=logic.logger.name):
        assert logic.get_jwks_cached("https://idp.invalid/keys") is None
    assert "HTTP 404: no-such-keys" in caplog.text


@pytest.mark.parametrize("label", ["okta", "adfs"])
def test_userinfo_logs_the_error_status_and_body(monkeypatch, caplog, label):
    issuer = ISSUER if label == "okta" else ADFS_ISSUER
    logic._endpoints_cache[issuer] = ENDPOINTS
    monkeypatch.setattr(
        logic._session, "get", lambda url, **kw: fake_response(401, "bad-bearer")
    )
    config = logic.OKTA_ENVIRONMENTS["DEV"]["custom"]
    with caplog.at_level(logging.ERROR, logger=logic.logger.name):
        if label == "okta":
            result = logic.okta_oidc_get_userinfo_claims("t", config)
        else:
            result = logic.adfs_oidc_get_userinfo_claims("t", ADFS_ISSUER)
    assert result is None
    assert "HTTP 401: bad-bearer" in caplog.text


def test_session_user_agent_has_no_org_text():
    agent = logic._session.headers["User-Agent"]
    assert agent.startswith("FederatedClaimsAnalyzer/")
    assert "internal" not in agent
