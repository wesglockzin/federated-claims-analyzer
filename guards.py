"""Small, pure helpers for startup checks, redirect targets and OAuth state."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from urllib.parse import urlsplit

OIDC_GATE_SETTINGS = ("OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET")


class ConfigError(RuntimeError):
    """A required setting is missing or invalid."""


def auth_mode(env: Mapping[str, str]) -> str:
    """Return "oidc" or "none". "none" must be asked for explicitly."""
    mode = env.get("AUTH_MODE", "oidc").strip().lower()
    if mode not in {"oidc", "none"}:
        raise ConfigError(f"AUTH_MODE must be 'oidc' or 'none', got {mode!r}")
    return mode


def check_startup_settings(env: Mapping[str, str]) -> str:
    """Fail closed: refuse to start without a session key or login settings.

    Returns the auth mode. Raises ConfigError naming every missing setting.
    """
    mode = auth_mode(env)
    required = ["FLASK_SECRET_KEY"]
    if mode == "oidc":
        required += OIDC_GATE_SETTINGS
    missing = [name for name in required if not env.get(name)]
    if missing:
        raise ConfigError(
            "Missing required settings: "
            + ", ".join(missing)
            + ". Set them, or set AUTH_MODE=none to run without a login."
        )
    return mode


def is_safe_redirect(target: str | None) -> bool:
    """Accept only a same-site relative path such as /page?x=1."""
    if not target or not target.startswith("/"):
        return False
    if target.startswith("//") or "\\" in target:
        return False
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in target):
        return False
    parts = urlsplit(target)
    return not parts.scheme and not parts.netloc


def states_match(received: str | None, expected: str | None) -> bool:
    """Compare OAuth state values. Two missing values never match."""
    if not received or not expected:
        return False
    return hmac.compare_digest(received.encode(), expected.encode())
