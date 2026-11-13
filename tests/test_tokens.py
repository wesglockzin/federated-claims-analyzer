"""Token validation and SAML response processing, with fakes and no network."""

import json
import time

import pytest
from authlib.common.encoding import json_b64encode
from authlib.jose import JsonWebKey, JsonWebToken
from authlib.jose.errors import JoseError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import sso_tester_logic as logic
from guards import UserFacingError

ISSUER = logic.OKTA_ENVIRONMENTS["DEV"]["custom"]["oidc_issuer_url"]
ADFS_ISSUER = logic.ADFS_ENVIRONMENTS["DEV"]
CLIENT_ID = "test-client-not-real"
HMAC_SECRET = "test-hmac-key-not-real-0123456789abcdef"
KEY_ID = "test-kid"


@pytest.fixture(scope="module")
def private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def okta_config():
    return logic.OKTA_ENVIRONMENTS["DEV"]["custom"]


@pytest.fixture
def jwks(private_key, monkeypatch):
    """Serve this test key as the IdP's key set for both issuers."""
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    jwk = JsonWebKey.import_key(public_pem).as_dict()
    jwk.update(kid=KEY_ID, use="sig", alg="RS256")
    keys = {"keys": [jwk]}
    endpoints = {
        "auth": "https://idp.invalid/authorize",
        "token": "https://idp.invalid/token",
        "jwks_uri": "https://idp.invalid/keys",
        "userinfo": None,
    }
    logic._endpoints_cache[ISSUER] = endpoints
    logic._endpoints_cache[ADFS_ISSUER] = endpoints
    monkeypatch.setattr(logic, "get_jwks_cached", lambda uri: keys)
    return keys


def make_token(key, algorithm="RS256", kid=KEY_ID, **overrides):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "test-subject",
        "iat": now - 5,
        "exp": now + 300,
        "email": "someone@example.invalid",
    }
    claims.update(overrides)
    claims = {name: value for name, value in claims.items() if value is not None}
    header = {"alg": algorithm, "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    if algorithm == "none":
        # Hand-built unsigned token: header.payload. with an empty signature.
        return (
            json_b64encode(header).decode() + "." + json_b64encode(claims).decode() + "."
        )
    if algorithm == "RS256":
        key = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    return JsonWebToken([algorithm]).encode(header, claims, key).decode()


def test_okta_id_token_with_correct_claims_is_accepted(jwks, private_key, okta_config):
    claims = logic.okta_oidc_validate_id_token(make_token(private_key), okta_config)
    assert claims["email"] == "someone@example.invalid"


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "someone-else"},
        {"iss": "https://other.invalid"},
        {"exp": int(time.time()) - 3600},
        {"aud": None},
    ],
    ids=["wrong-aud", "wrong-iss", "expired", "no-aud"],
)
def test_okta_id_token_with_bad_claims_is_refused(
    jwks, private_key, okta_config, overrides
):
    token = make_token(private_key, **overrides)
    assert logic.okta_oidc_validate_id_token(token, okta_config) is None


def test_okta_id_token_not_signed_with_rs256_is_refused(jwks, okta_config):
    token = make_token(HMAC_SECRET, algorithm="HS256")
    assert logic.okta_oidc_validate_id_token(token, okta_config) is None


def test_okta_id_token_with_algorithm_none_is_refused(jwks, okta_config):
    token = make_token(None, algorithm="none")
    assert logic.okta_oidc_validate_id_token(token, okta_config) is None


def test_okta_id_token_signed_by_another_key_is_refused(jwks, okta_config):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert logic.okta_oidc_validate_id_token(make_token(other), okta_config) is None


def test_okta_id_token_with_unknown_key_id_is_refused(jwks, private_key, okta_config):
    token = make_token(private_key, kid="not-in-the-key-set")
    assert logic.okta_oidc_validate_id_token(token, okta_config) is None


def test_token_issued_slightly_in_the_future_is_accepted(
    jwks, private_key, okta_config
):
    """A container clock a few seconds behind the IdP must not refuse fresh tokens."""
    now = int(time.time())
    token = make_token(private_key, iat=now + 20, nbf=now + 20)
    assert logic.okta_oidc_validate_id_token(token, okta_config) is not None


def test_token_without_key_id_is_tried_against_every_key(
    jwks, private_key, okta_config
):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pem = other.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    other_jwk = JsonWebKey.import_key(other_pem).as_dict()
    other_jwk.update(kid="other-kid", use="sig", alg="RS256")
    jwks["keys"].insert(0, other_jwk)
    token = make_token(private_key, kid=None)
    assert logic.okta_oidc_validate_id_token(token, okta_config) is not None


def test_decode_jwt_raises_a_jose_error_for_a_wrong_algorithm(jwks):
    token = make_token(HMAC_SECRET, algorithm="HS256")
    with pytest.raises(JoseError):
        logic.decode_jwt(token, jwks, audience=CLIENT_ID, issuer=ISSUER)


def test_unverified_claims_are_read_without_a_key(private_key):
    claims = logic.decode_unverified_claims(make_token(private_key))
    assert claims["sub"] == "test-subject"


@pytest.mark.parametrize("token", ["opaque-token", "a.b.c", "a..c"])
def test_unverified_decode_of_a_non_jwt_raises(token):
    with pytest.raises(JoseError):
        logic.decode_unverified_claims(token)


def test_okta_id_token_that_is_not_a_jwt_is_refused(jwks, okta_config):
    assert logic.okta_oidc_validate_id_token("not-a-token", okta_config) is None


def test_okta_access_token_is_checked_against_the_audience(
    jwks, private_key, okta_config
):
    config = {**okta_config, "oidc_audience": "api://test"}
    good = make_token(private_key, aud="api://test")
    assert logic.okta_oidc_validate_access_token(good, config)["aud"] == "api://test"
    wrong = make_token(private_key, aud=CLIENT_ID)
    assert logic.okta_oidc_validate_access_token(wrong, config) is None


def test_adfs_id_token_with_correct_claims_is_accepted(jwks, private_key):
    token = make_token(private_key, iss=ADFS_ISSUER)
    claims = logic.adfs_oidc_validate_id_token(token, ADFS_ISSUER, "DEV")
    assert claims["sub"] == "test-subject"


@pytest.mark.parametrize(
    "overrides",
    [{"aud": "someone-else"}, {"iss": "https://other.invalid"}],
    ids=["wrong-aud", "wrong-iss"],
)
def test_adfs_id_token_with_bad_claims_is_refused(jwks, private_key, overrides):
    token = make_token(private_key, **{"iss": ADFS_ISSUER, **overrides})
    assert logic.adfs_oidc_validate_id_token(token, ADFS_ISSUER, "DEV") is None


def test_adfs_id_token_not_signed_with_rs256_is_refused(jwks):
    token = make_token(HMAC_SECRET, algorithm="HS256", iss=ADFS_ISSUER)
    assert logic.adfs_oidc_validate_id_token(token, ADFS_ISSUER, "DEV") is None


def test_adfs_id_token_for_unknown_environment_is_refused(jwks, private_key):
    token = make_token(private_key, iss=ADFS_ISSUER)
    assert logic.adfs_oidc_validate_id_token(token, ADFS_ISSUER, "GONE") is None


class FakeSamlAuth:
    """Stands in for OneLogin_Saml2_Auth after process_response()."""

    def __init__(self, errors=(), authenticated=True):
        self.errors = list(errors)
        self.authenticated = authenticated

    def process_response(self):
        pass

    def get_errors(self):
        return self.errors

    def get_last_error_reason(self):
        return "reason-only-for-the-log"

    def is_authenticated(self):
        return self.authenticated

    def get_attributes(self):
        return {"email": ["someone@example.invalid"]}

    def get_last_response_xml(self):
        return "<Response><Assertion>x</Assertion></Response>"


def use_saml_auth(monkeypatch, auth):
    monkeypatch.setattr(logic, "prepare_saml_request", lambda request, key: auth)


def test_saml_response_that_fails_validation_raises_a_user_facing_error(monkeypatch):
    use_saml_auth(monkeypatch, FakeSamlAuth(errors=["invalid_signature"]))
    with pytest.raises(UserFacingError) as raised:
        logic.process_saml_response(None, "okta_dev")
    assert "reason-only-for-the-log" not in str(raised.value)


def test_saml_response_that_is_not_authenticated_is_refused(monkeypatch):
    use_saml_auth(monkeypatch, FakeSamlAuth(authenticated=False))
    with pytest.raises(UserFacingError):
        logic.process_saml_response(None, "okta_dev")


def test_valid_saml_response_returns_claims_and_pretty_xml(monkeypatch):
    use_saml_auth(monkeypatch, FakeSamlAuth())
    result = logic.process_saml_response(None, "okta_dev")
    assert result["claims"] == {"email": ["someone@example.invalid"]}
    assert "<Assertion>x</Assertion>" in result["raw_xml"]
    assert "\n" in result["raw_xml"]
