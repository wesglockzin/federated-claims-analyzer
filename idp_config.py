"""Build the Okta, ADFS and SAML IdP lists from environment settings.

Each list is a comma-separated setting of any length. Every name in it needs
its own settings, and a missing one stops the app at startup.
"""

from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlsplit

from guards import ConfigError, split_list

SAML_PROTOCOL_PREFIXES = ("okta", "adfs")


def _names(env: Mapping[str, str], setting: str) -> list[str]:
    return [name.upper() for name in split_list(env.get(setting))]


def _raise_if_missing(env: Mapping[str, str], needed: list[str]) -> None:
    missing = [name for name in needed if not env.get(name)]
    if missing:
        raise ConfigError("Missing required settings: " + ", ".join(missing))


def load_okta_environments(env: Mapping[str, str]) -> dict[str, dict[str, dict]]:
    """Return {NAME: {"custom": cfg, "default": cfg (optional)}} from OKTA_ENVIRONMENTS."""
    result: dict[str, dict[str, dict]] = {}
    for name in _names(env, "OKTA_ENVIRONMENTS"):
        prefix = f"OKTA_{name}_"
        _raise_if_missing(
            env, [prefix + "ISSUER", prefix + "CLIENT_ID", prefix + "OIDC_SECRET"]
        )
        client_id = env[prefix + "CLIENT_ID"]
        custom = {
            "oidc_issuer_url": env[prefix + "ISSUER"],
            "oidc_client_id": client_id,
            "oidc_client_secret": env[prefix + "OIDC_SECRET"],
            "oidc_audience": env.get(prefix + "AUDIENCE") or client_id,
        }
        result[name] = {"custom": custom}
        if env.get(prefix + "DEFAULT_ISSUER"):
            result[name]["default"] = {
                **custom,
                "oidc_issuer_url": env[prefix + "DEFAULT_ISSUER"],
                "oidc_audience": env.get(prefix + "DEFAULT_AUDIENCE")
                or "api://default",
            }
    return result


def load_adfs_environments(
    env: Mapping[str, str],
) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    """Return ({NAME: issuer}, {NAME: {client_id, client_secret}}) from ADFS_ENVIRONMENTS."""
    issuers: dict[str, str] = {}
    configs: dict[str, dict[str, str]] = {}
    for name in _names(env, "ADFS_ENVIRONMENTS"):
        prefix = f"ADFS_{name}_"
        _raise_if_missing(
            env, [prefix + "ISSUER", prefix + "CLIENT_ID", prefix + "CLIENT_SECRET"]
        )
        issuers[name] = env[prefix + "ISSUER"]
        configs[name] = {
            "client_id": env[prefix + "CLIENT_ID"],
            "client_secret": env[prefix + "CLIENT_SECRET"],
        }
    return issuers, configs


def load_saml_idps(env: Mapping[str, str]) -> dict[str, dict]:
    """Return {key: entry} from SAML_IDPS, e.g. OKTA_DEV gives the key "okta_dev".

    The key is "<okta|adfs>_<target>", which is how the app names a SAML test.
    """
    names = _names(env, "SAML_IDPS")
    if names:
        _raise_if_missing(env, ["SAML_SP_ENTITY_ID"])
    result: dict[str, dict] = {}
    for name in names:
        prefix = f"SAML_{name}_"
        if name.split("_")[0].lower() not in SAML_PROTOCOL_PREFIXES or "_" not in name:
            raise ConfigError(
                f"SAML_IDPS entry {name} must look like OKTA_<target> or ADFS_<target>"
            )
        _raise_if_missing(
            env,
            [prefix + "ENTITY_ID", prefix + "SSO_URL", prefix + "CERT", prefix + "ENV"],
        )
        key = name.lower()
        result[key] = {
            "idp": {
                "entityId": env[prefix + "ENTITY_ID"],
                "singleSignOnService": {"url": env[prefix + "SSO_URL"]},
                "x509cert": env[prefix + "CERT"].replace("\\n", "\n"),
            },
            "env": env[prefix + "ENV"].upper(),
            "label": env.get(prefix + "LABEL") or f"SAML app {key.split('_', 1)[1]}",
            "sp_entity_id": env.get(prefix + "SP_ENTITY_ID") or env["SAML_SP_ENTITY_ID"],
            "sp_cert_file": env.get(prefix + "SP_CERT_FILE") or "saml_tester.cert",
            "sp_key_file": env.get(prefix + "SP_KEY_FILE") or "saml_tester.key",
        }
    return result


def validate(env: Mapping[str, str]) -> None:
    """Load every list now, so a missing setting stops the app at startup."""
    okta = load_okta_environments(env)
    adfs, _ = load_adfs_environments(env)
    load_saml_idps(env)
    if not okta and not adfs:
        raise ConfigError(
            "Missing required settings: OKTA_ENVIRONMENTS or ADFS_ENVIRONMENTS"
        )


def api_base_url(issuer_url: str) -> str | None:
    """The Okta org URL (scheme and host) of an issuer URL, or None."""
    parts = urlsplit(issuer_url)
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"


def build_ui_config(okta: Mapping, adfs: Mapping, saml: Mapping) -> dict:
    """What the form needs: environment names, target apps and default-server envs."""
    environments = list(dict.fromkeys([*okta, *adfs, *(s["env"] for s in saml.values())]))
    targets = {
        name: {
            "oidc": [{"label": f"Default OIDC App ({name})", "value": "default"}],
            "saml": [],
        }
        for name in environments
    }
    for key, entry in saml.items():
        target = key.split("_", 1)[1]
        options = targets[entry["env"]]["saml"]
        if all(option["value"] != target for option in options):
            options.append({"label": entry["label"], "value": target})
    return {
        "environments": environments,
        "targets": targets,
        "default_server_envs": [n for n, cfg in okta.items() if "default" in cfg],
    }
