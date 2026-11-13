import os
import subprocess
import sys
from pathlib import Path

import pytest
from fake_settings import FAKE_ENV

from guards import (
    ConfigError,
    UserFacingError,
    auth_mode,
    bounded,
    check_startup_settings,
    cookie_policy,
    is_allowed,
    is_safe_redirect,
    public_error,
    states_match,
)

ROOT = Path(__file__).resolve().parent.parent
FULL = {
    "FLASK_SECRET_KEY": "test-key-not-real",
    "APP_BASE_URL": "https://app.invalid",
    "OIDC_ISSUER": "https://idp.invalid",
    "OIDC_CLIENT_ID": "test-client-not-real",
    "OIDC_CLIENT_SECRET": "test-secret-not-real",
    "ALLOWED_EMAILS": "someone@example.invalid",
}


def test_full_settings_start_in_oidc_mode():
    assert check_startup_settings(FULL) == "oidc"


@pytest.mark.parametrize("name", sorted(FULL))
def test_missing_setting_is_named(name):
    env = {k: v for k, v in FULL.items() if k != name}
    with pytest.raises(ConfigError, match=name):
        check_startup_settings(env)


def test_groups_alone_satisfy_the_allow_list_requirement():
    env = {k: v for k, v in FULL.items() if k != "ALLOWED_EMAILS"}
    env["ALLOWED_GROUPS"] = "admins"
    assert check_startup_settings(env) == "oidc"


def test_none_mode_needs_only_the_session_key_and_base_url():
    base = {"AUTH_MODE": "none", "FLASK_SECRET_KEY": "k", "APP_BASE_URL": "https://a"}
    assert check_startup_settings(base) == "none"
    with pytest.raises(ConfigError, match="FLASK_SECRET_KEY"):
        check_startup_settings({"AUTH_MODE": "none", "APP_BASE_URL": "https://a"})
    with pytest.raises(ConfigError, match="APP_BASE_URL"):
        check_startup_settings({"AUTH_MODE": "none", "FLASK_SECRET_KEY": "k"})


def test_allow_list_by_email_and_by_group():
    claims = {"email": "Someone@Example.invalid", "groups": ["staff"]}
    assert is_allowed(claims, ["someone@example.invalid"], [], "groups")
    assert is_allowed(claims, [], ["staff"], "groups")
    assert is_allowed({"email": "x@y", "teams": "staff"}, [], ["staff"], "teams")
    assert not is_allowed(claims, ["other@example.invalid"], ["admins"], "groups")
    assert not is_allowed({}, [], [], "groups")


def test_session_cookie_policy_follows_the_scheme():
    assert cookie_policy("https://app.invalid") == ("None", True)
    assert cookie_policy("http://app.invalid") == ("Lax", False)


def test_public_error_hides_raw_exception_text():
    assert public_error(UserFacingError("Invalid state parameter.")) == (
        "Invalid state parameter."
    )
    assert "secret-detail" not in public_error(RuntimeError("secret-detail"))
    assert len(bounded("x" * 5000)) == 300


def test_unknown_auth_mode_is_rejected():
    with pytest.raises(ConfigError, match="AUTH_MODE"):
        auth_mode({"AUTH_MODE": "off"})


def _import_app(env):
    base = {"PATH": os.environ.get("PATH", "")}
    return subprocess.run(
        [sys.executable, "-c", "import app"],
        cwd=ROOT,
        env={**base, **env},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_app_refuses_to_start_without_settings():
    result = _import_app({})
    assert result.returncode != 0
    assert "FLASK_SECRET_KEY" in result.stderr
    assert "APP_BASE_URL" in result.stderr


def test_app_starts_with_the_full_fake_settings():
    assert _import_app(FAKE_ENV).returncode == 0


def test_app_starts_without_login_only_when_asked():
    env = {**FAKE_ENV, "AUTH_MODE": "none"}
    for name in (
        "OIDC_ISSUER",
        "OIDC_CLIENT_ID",
        "OIDC_CLIENT_SECRET",
        "ALLOWED_EMAILS",
    ):
        del env[name]
    assert _import_app(env).returncode == 0
    env["AUTH_MODE"] = "oidc"
    assert _import_app(env).returncode != 0


@pytest.mark.parametrize(
    "name",
    ["APP_BASE_URL", "ALLOWED_EMAILS", "OKTA_QA_OIDC_SECRET", "ADFS_DEV_CLIENT_ID"],
)
def test_app_names_the_missing_setting_at_startup(name):
    env = {k: v for k, v in FAKE_ENV.items() if k != name}
    result = _import_app(env)
    assert result.returncode != 0
    assert name in result.stderr


@pytest.mark.parametrize("target", ["/", "/page?x=1", "/a/b#frag"])
def test_relative_paths_are_safe(target):
    assert is_safe_redirect(target)


@pytest.mark.parametrize(
    "target",
    [
        None,
        "",
        "//evil.invalid",
        "//evil.invalid/path",
        "/\\evil.invalid",
        "https://evil.invalid/",
        "http:evil.invalid",
        "javascript:alert(1)",
        "relative/path",
        "/ok\r\nSet-Cookie: x=1",
    ],
)
def test_other_targets_are_rejected(target):
    assert not is_safe_redirect(target)


def test_states_match_rules():
    assert states_match("abc", "abc")
    assert not states_match("abc", "abd")
    assert not states_match(None, None)
    assert not states_match("", "")
    assert not states_match("abc", None)
