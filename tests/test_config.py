import logging

import pytest
import requests
from fake_settings import FAKE_ENV

import idp_config
import saml_settings
import sso_tester_logic as logic
from guards import ConfigError


def test_okta_list_has_any_length_and_names_come_from_the_setting():
    env = {
        **FAKE_ENV,
        "OKTA_ENVIRONMENTS": "DEV,QA,EU_LAB",
        "OKTA_EU_LAB_ISSUER": "https://eu.invalid",
        "OKTA_EU_LAB_CLIENT_ID": "test-client-not-real",
        "OKTA_EU_LAB_OIDC_SECRET": "test-secret-not-real",
    }
    result = idp_config.load_okta_environments(env)
    assert list(result) == ["DEV", "QA", "EU_LAB"]
    assert result["EU_LAB"]["custom"]["oidc_issuer_url"] == "https://eu.invalid"
    # The audience defaults to the client id; "default" exists only when configured.
    assert result["EU_LAB"]["custom"]["oidc_audience"] == "test-client-not-real"
    assert "default" not in result["QA"]
    assert result["DEV"]["default"]["oidc_audience"] == "api://default"


def test_missing_okta_setting_is_named():
    env = {k: v for k, v in FAKE_ENV.items() if k != "OKTA_QA_OIDC_SECRET"}
    with pytest.raises(ConfigError, match="OKTA_QA_OIDC_SECRET"):
        idp_config.load_okta_environments(env)


def test_adfs_list_returns_issuers_and_clients():
    issuers, configs = idp_config.load_adfs_environments(FAKE_ENV)
    assert issuers == {"DEV": "https://adfs.invalid/adfs"}
    assert configs["DEV"]["client_secret"] == "test-secret-not-real"
    env = {k: v for k, v in FAKE_ENV.items() if k != "ADFS_DEV_ISSUER"}
    with pytest.raises(ConfigError, match="ADFS_DEV_ISSUER"):
        idp_config.load_adfs_environments(env)


def test_saml_entries_are_keyed_by_idp_and_target():
    idps = idp_config.load_saml_idps(FAKE_ENV)
    assert list(idps) == ["okta_dev", "okta_cucm"]
    assert idps["okta_dev"]["sp_entity_id"] == "sp.invalid"
    assert idps["okta_dev"]["idp"]["singleSignOnService"] == {
        "url": "https://idp.invalid/sso"
    }


def test_saml_entry_needs_its_settings_and_a_known_idp_prefix():
    env = {k: v for k, v in FAKE_ENV.items() if k != "SAML_OKTA_DEV_CERT"}
    with pytest.raises(ConfigError, match="SAML_OKTA_DEV_CERT"):
        idp_config.load_saml_idps(env)
    with pytest.raises(ConfigError, match="OKTA_<target>"):
        idp_config.load_saml_idps({**FAKE_ENV, "SAML_IDPS": "GOOGLE_DEV"})


def test_validate_needs_at_least_one_idp():
    with pytest.raises(ConfigError, match="OKTA_ENVIRONMENTS or ADFS_ENVIRONMENTS"):
        idp_config.validate({"SAML_IDPS": ""})
    idp_config.validate(FAKE_ENV)


def test_ui_config_groups_targets_by_environment():
    ui = idp_config.build_ui_config(
        idp_config.load_okta_environments(FAKE_ENV),
        idp_config.load_adfs_environments(FAKE_ENV)[0],
        idp_config.load_saml_idps(FAKE_ENV),
    )
    assert ui["environments"] == ["DEV", "QA"]
    assert ui["default_server_envs"] == ["DEV"]
    assert [o["value"] for o in ui["targets"]["DEV"]["saml"]] == ["dev", "cucm"]
    assert ui["targets"]["QA"]["saml"] == []
    assert ui["targets"]["QA"]["oidc"][0]["value"] == "default"


def test_api_base_url_is_derived_from_the_issuer():
    assert idp_config.api_base_url("https://idp.invalid/oauth2/x") == (
        "https://idp.invalid"
    )
    assert idp_config.api_base_url("not a url") is None


def test_missing_sp_file_is_logged_and_raised(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(saml_settings, "SCRIPT_DIR", tmp_path)
    with (
        caplog.at_level(logging.ERROR, logger=saml_settings.logger.name),
        pytest.raises(FileNotFoundError),
    ):
        saml_settings.read_file_content("absent.cert")
    assert "absent.cert" in caplog.text


def test_saml_settings_use_the_entry_and_its_sp_files(tmp_path, monkeypatch):
    (tmp_path / "saml_tester.cert").write_text("test-cert-not-real")
    (tmp_path / "saml_tester.key").write_text("test-key-not-real")
    monkeypatch.setattr(saml_settings, "SCRIPT_DIR", tmp_path)
    settings = saml_settings.get_saml_settings("okta_cucm")
    assert settings["idp"]["entityId"] == "https://idp.invalid/cucm"
    assert settings["sp"]["entityId"] == "sp.invalid"
    assert settings["sp"]["assertionConsumerService"]["url"].endswith(
        "/okta/saml/callback"
    )
    with pytest.raises(ValueError, match="okta_nope"):
        saml_settings.get_saml_settings("okta_nope")


def _lifetime_failure(monkeypatch, response_or_error):
    monkeypatch.setenv("OKTA_DEV_API_TOKEN", "test-token-not-real")

    def fake_get(url, **kwargs):
        if isinstance(response_or_error, Exception):
            raise response_or_error
        return response_or_error

    monkeypatch.setattr(logic._session, "get", fake_get)
    return logic.okta_check_token_lifetimes("DEV")


def test_lifetime_check_reports_idp_status_and_body(monkeypatch):
    response = requests.Response()
    response.status_code = 500
    response._content = b"upstream broke"
    result = _lifetime_failure(monkeypatch, response)
    assert result["success"] is False
    assert "HTTP 500" in result["error"]
    assert "upstream broke" in result["error"]


def test_lifetime_check_hides_raw_exception_text(monkeypatch):
    error = requests.ConnectionError("secret-detail-from-library")
    result = _lifetime_failure(monkeypatch, error)
    assert "secret-detail-from-library" not in result["error"]
