import logging

import pytest
import requests

import sso_tester_logic as logic

TOKEN_URL = "https://idp.invalid/token"


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
    monkeypatch.setattr(logic, "OKTA_OIDC_TOKEN_ENDPOINT", TOKEN_URL)
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
    monkeypatch.setattr(logic, "OKTA_OIDC_TOKEN_ENDPOINT", None)
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


def test_session_user_agent_has_no_org_text():
    agent = logic._session.headers["User-Agent"]
    assert agent.startswith("FederatedClaimsAnalyzer/")
    assert "internal" not in agent
