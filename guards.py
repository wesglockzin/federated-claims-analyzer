"""Small, pure helpers for startup checks, redirect targets and OAuth state."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from urllib.parse import urlsplit

OIDC_GATE_SETTINGS = ("OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET")


GENERIC_ERROR = "The request failed. The details are in the server log."
MAX_DETAIL = 300


class ConfigError(RuntimeError):
    """A required setting is missing or invalid."""


class UserFacingError(Exception):
    """An error whose message was written to be shown to the user."""


def public_error(exc: BaseException) -> str:
    """Text safe to send to a client: our own messages, never raw exception text."""
    if isinstance(exc, UserFacingError):
        return str(exc)
    return GENERIC_ERROR


def bounded(text: object) -> str:
    """Cut IdP-supplied text to a length that is safe to show."""
    return str(text)[:MAX_DETAIL]


def split_list(value: str | None) -> list[str]:
    """Split a comma-separated setting into its non-empty items."""
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def auth_mode(env: Mapping[str, str]) -> str:
    """Return "oidc" or "none". "none" must be asked for explicitly."""
    mode = env.get("AUTH_MODE", "oidc").strip().lower()
    if mode not in {"oidc", "none"}:
        raise ConfigError(f"AUTH_MODE must be 'oidc' or 'none', got {mode!r}")
    return mode


def check_startup_settings(env: Mapping[str, str]) -> str:
    """Fail closed: refuse to start without a session key, base URL or login settings.

    Returns the auth mode. Raises ConfigError naming every missing setting.
    """
    mode = auth_mode(env)
    required = ["FLASK_SECRET_KEY", "APP_BASE_URL"]
    if mode == "oidc":
        required += OIDC_GATE_SETTINGS
    missing = [name for name in required if not env.get(name)]
    if mode == "oidc" and not (
        split_list(env.get("ALLOWED_EMAILS")) or split_list(env.get("ALLOWED_GROUPS"))
    ):
        missing.append("ALLOWED_EMAILS or ALLOWED_GROUPS")
    if missing:
        raise ConfigError(
            "Missing required settings: "
            + ", ".join(missing)
            + ". Set them, or set AUTH_MODE=none to run without a login."
        )
    return mode


def is_allowed(claims: Mapping, emails: list[str], groups: list[str], claim: str) -> bool:
    """Allow-list rule: the user's email is listed, or one of their groups is."""
    email = str(claims.get("email") or claims.get("preferred_username") or "").lower()
    if email and email in {item.lower() for item in emails}:
        return True
    user_groups = claims.get(claim) or []
    if isinstance(user_groups, str):
        user_groups = [user_groups]
    return bool(set(user_groups) & set(groups))


def cookie_policy(base_url: str) -> tuple[str, bool]:
    """Return (SameSite, Secure) for the session cookie.

    Over https the cookie is SameSite=None so the IdP's cross-site SAML POST
    carries it. Browsers drop SameSite=None without Secure, so over plain http
    the cookie is Lax and not Secure.
    """
    if base_url.startswith("https://"):
        return "None", True
    return "Lax", False


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
