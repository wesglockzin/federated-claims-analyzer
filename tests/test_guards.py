import os
import subprocess
import sys
from pathlib import Path

import pytest

from guards import (
    ConfigError,
    auth_mode,
    check_startup_settings,
    is_safe_redirect,
    states_match,
)

ROOT = Path(__file__).resolve().parent.parent
FULL = {
    "FLASK_SECRET_KEY": "test-key-not-real",
    "OIDC_ISSUER": "https://idp.invalid",
    "OIDC_CLIENT_ID": "test-client-not-real",
    "OIDC_CLIENT_SECRET": "test-secret-not-real",
}


def test_full_settings_start_in_oidc_mode():
    assert check_startup_settings(FULL) == "oidc"


@pytest.mark.parametrize("name", sorted(FULL))
def test_missing_setting_is_named(name):
    env = {k: v for k, v in FULL.items() if k != name}
    with pytest.raises(ConfigError, match=name):
        check_startup_settings(env)


def test_none_mode_needs_only_the_session_key():
    assert check_startup_settings({"AUTH_MODE": "none", "FLASK_SECRET_KEY": "k"}) == "none"
    with pytest.raises(ConfigError, match="FLASK_SECRET_KEY"):
        check_startup_settings({"AUTH_MODE": "none"})


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
    )


def test_app_refuses_to_start_without_settings():
    result = _import_app({})
    assert result.returncode != 0
    assert "FLASK_SECRET_KEY" in result.stderr


def test_app_starts_without_login_only_when_asked():
    env = {
        "AUTH_MODE": "none",
        "FLASK_SECRET_KEY": "test-key-not-real",
        "OKTA_DEV_OIDC_SECRET": "test-secret-not-real",
        "ADFS_DEV_CLIENT_SECRET": "test-secret-not-real",
        "ADFS_PROD_CLIENT_SECRET": "test-secret-not-real",
    }
    assert _import_app(env).returncode == 0


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
