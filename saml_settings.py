# -----------------------------------------------------------------------------
# Script Name : saml_settings.py
# Description : Builds the python3-saml settings for one configured SAML IdP.
# Author      : Wes Glockzin
# Version     : 4.0 (IdP list from environment settings)
# License     : MIT
# -----------------------------------------------------------------------------
import logging
import os
from pathlib import Path

import idp_config

# --- Base Directory ---
SCRIPT_DIR = Path(__file__).resolve().parent

# Child of the app logger, so these messages reach its stdout handler.
logger = logging.getLogger("sso_tester_logic.saml")

# --- Configuration: Base URL (required; must match the main app logic) ---
BASE_URL = os.environ["APP_BASE_URL"].rstrip("/")

# IdP entries come from the SAML_IDPS settings (see idp_config.py).
IDP_CONFIGS = idp_config.load_saml_idps(os.environ)


def read_file_content(file_name):
    """Read a file beside the app. A missing file is logged and raised."""
    try:
        return (SCRIPT_DIR / file_name).read_text()
    except FileNotFoundError:
        logger.error(
            "SAML signing file '%s' not found. Make sure it is in the app directory.",
            file_name,
        )
        raise


def get_saml_settings(idp_key):
    """
    Dynamically builds the settings dictionary required by the python3-saml library.
    """
    if idp_key not in IDP_CONFIGS:
        raise ValueError(f"Invalid IdP key provided: {idp_key}")
    entry = IDP_CONFIGS[idp_key]

    # The SP must know which IdP to contact for the ACS URL.
    idp_name = idp_key.split("_")[0]

    # Define settings for our application (the Service Provider)
    # Uses the dynamic BASE_URL
    sp_config = {
        "entityId": entry["sp_entity_id"],
        "assertionConsumerService": {
            "url": f"{BASE_URL}/{idp_name}/saml/callback",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        },
        "singleLogoutService": {
            "url": f"{BASE_URL}/{idp_name}/saml/sls",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        },
        "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        "x509cert": read_file_content(entry["sp_cert_file"]),
        "privateKey": read_file_content(entry["sp_key_file"]),
    }

    # --- CUSTOM SECURITY CONFIGURATION LOGIC ---
    # Define security settings
    security_config = {
        "authnRequestsSigned": True,
        "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        "wantAssertionsSigned": True,
    }

    # ADFS Quirk Fix: Add lowercase URL encoding flag to fix signature validation.
    # Also disable RequestedAuthnContext — ADFS returns NoAuthnContext if the session
    # auth context (e.g. WindowsAuthentication) doesn't exactly match the default
    # PasswordProtectedTransport that python3-saml sends when this is unset.
    if idp_name == "adfs":
        security_config["lowercase_urlencoding"] = True
        security_config["requestedAuthnContext"] = False

    # Combine all parts into the final settings dictionary
    settings = {
        "strict": True,
        "debug": True,
        "sp": sp_config,
        "idp": entry["idp"],
        "security": security_config,
    }

    return settings
