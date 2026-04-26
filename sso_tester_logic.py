#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Script Name : sso_tester_logic.py (Core Logic Module for Identity Analyzer)
# Description : Contains the IdP/Protocol specific test execution functions and
#               helpers.
# Author      : Wes Glockzin
# Version     : 7.0.1 (Container Apps + Multi-worker OIDC fix)
# License     : MIT
# -----------------------------------------------------------------------------

import os
import requests
import json
from urllib.parse import urlencode
from jose import jwt
from jose.exceptions import JWTError
import time
from datetime import datetime, timezone
import logging
import sys
from pathlib import Path
import base64
import hashlib
import xml.dom.minidom

from onelogin.saml2.auth import OneLogin_Saml2_Auth
import saml_settings

APP_VERSION = "7.2.0"

# --- Base Directory ---
SCRIPT_DIR = Path(__file__).resolve().parent

# --- Configuration: Base URL (Local vs Cloud) ---
# This allows the app to switch between localhost and Cloud Run automatically
# via the APP_BASE_URL environment variable.
BASE_URL = os.environ.get("APP_BASE_URL", "https://localhost:8080").rstrip('/')

# --- File Names and Directory for Output ---
LOG_DIRECTORY = SCRIPT_DIR / "logs"
LOG_FILENAME = "federated_claims_analyzer.log"
LOG_FILEPATH = LOG_DIRECTORY / LOG_FILENAME

# --- ADFS Environment Presets ---
ADFS_ENVIRONMENTS = {
    "DEV": "https://host.example.gov/[redacted-path]
    "PROD": "https://host.example.gov/[redacted-path]
}

# --- Okta Environment Configuration (Nested for Auth Server Toggle) ---
OKTA_ENVIRONMENTS = {
    "DEV": {
        "custom": {
            "oidc_issuer_url": "https://dev-your-org.okta.com/oauth2/aus192v0np74vqcQ50j7",
            "oidc_client_id": "0oaEXAMPLE00EXAMPLE0",
            "oidc_client_secret": os.environ.get("OKTA_DEV_OIDC_SECRET", ""),
            "oidc_audience": "https://dev-your-org.okta.com/oauth2/aus192v0np74vqcQ50j7",
        },
        "default": {
            "oidc_issuer_url": "https://host.example.gov/[redacted-path]
            "oidc_client_id": "0oaEXAMPLE00EXAMPLE0",
            "oidc_client_secret": os.environ.get("OKTA_DEV_OIDC_SECRET", ""),
            "oidc_audience": "api://default",
        },
    },
    "STG": {
        "custom": {
            "oidc_issuer_url": "https://host.example.gov",
            "oidc_client_id": "0oaEXAMPLE00EXAMPLE0",
            "oidc_client_secret": os.environ.get("OKTA_STG_OIDC_SECRET", ""),
            "oidc_audience": "0oaEXAMPLE00EXAMPLE0",
        },
    },
    "PROD": {
        "custom": {
            "oidc_issuer_url": "https://host.example.gov",
            "oidc_client_id": "0oaEXAMPLE00EXAMPLE0",
            "oidc_client_secret": os.environ.get("OKTA_PROD_OIDC_SECRET", ""),
            "oidc_audience": "0oaEXAMPLE00EXAMPLE0",
        },
    },
}

# Dynamic Redirect URI based on BASE_URL
OKTA_OIDC_REDIRECT_URI = f"{BASE_URL}/okta/oidc/callback"
OKTA_OIDC_SCOPES = "openid profile email offline_access"
OKTA_OIDC_AUTH_ENDPOINT, OKTA_OIDC_TOKEN_ENDPOINT, OKTA_OIDC_JWKS_URI, OKTA_OIDC_USERINFO_ENDPOINT = None, None, None, None

# --- ADFS OIDC Configuration ---
ADFS_OIDC_CONFIGS = {
    "DEV": {
        "client_id": "00000000-0000-0000-0000-000000000000",
        "client_secret": os.environ.get("ADFS_DEV_CLIENT_SECRET", "")
    },
    "PROD": {
        "client_id": "00000000-0000-0000-0000-000000000000",
        "client_secret": os.environ.get("ADFS_PROD_CLIENT_SECRET", "")
    }
}
ADFS_OIDC_SCOPES = "openid profile email offline_access"
# Dynamic Redirect URI based on BASE_URL
ADFS_OIDC_REDIRECT_URI = f"{BASE_URL}/adfs/oidc/callback"
ADFS_OIDC_AUTH_ENDPOINT, ADFS_OIDC_TOKEN_ENDPOINT, ADFS_OIDC_JWKS_URI, ADFS_OIDC_USERINFO_ENDPOINT = None, None, None, None

# --- Azure AD OIDC Configuration (App Login) ---
AZURE_OIDC_TENANT_ID = os.environ.get("AZURE_OIDC_TENANT_ID", "")
AZURE_OIDC_CLIENT_ID = os.environ.get("AZURE_OIDC_CLIENT_ID", "")
AZURE_OIDC_CLIENT_SECRET = os.environ.get("AZURE_OIDC_CLIENT_SECRET", "")
AZURE_OIDC_ISSUER = f"https://login.microsoftonline.com/{AZURE_OIDC_TENANT_ID}/v2.0" if AZURE_OIDC_TENANT_ID else ""
AZURE_OIDC_SCOPES = "openid email profile"
AZURE_OIDC_REDIRECT_URI = f"{BASE_URL}/azure/oidc/callback"
AZURE_OIDC_AUTH_ENDPOINT, AZURE_OIDC_TOKEN_ENDPOINT, AZURE_OIDC_JWKS_URI, AZURE_OIDC_USERINFO_ENDPOINT = None, None, None, None

# --- General Configuration ---
LISTEN_PORT = 8080
VERIFY_SSL = True
HTTP_TIMEOUT = 10  # Timeout in seconds for all HTTP requests to IdPs
JWKS_CACHE_TTL = 3600  # JWKS cache time-to-live in seconds (1 hour)

# SAML Certificate Paths (will be set after loading from Secret Manager in Cloud Run)
CERT_FILE = SCRIPT_DIR / 'saml_tester.cert'  # Default for local dev
KEY_FILE = SCRIPT_DIR / 'saml_tester.key'    # Default for local dev

# JWKS Cache: {jwks_uri: {"jwks": <data>, "timestamp": <time>}}
_jwks_cache = {}

STANDARD_CLAIMS = {
    'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti', 'auth_time', 'nonce', 'acr', 'amr', 'azp',
    'at_hash', 'c_hash', 'name', 'given_name', 'family_name', 'middle_name', 'nickname',
    'preferred_username', 'profile', 'picture', 'website', 'email', 'email_verified', 'gender',
    'birthdate', 'zoneinfo', 'locale', 'phone_number', 'phone_number_verified', 'address',
    'updated_at', 'scp', 'cid', 'uid', 'ver', 'sid', 'pwd_url', 'mfa_auth_time', 'apptype',
    'appid', 'authmethod', 'idsub'
}

# --- Logging Setup ---
# Cloud/Kubernetes best practice: Log to stdout/stderr (captured by logging infrastructure)
# Only use file logging in local development
IS_CLOUD_OR_K8S = bool(os.environ.get('K_SERVICE') or os.environ.get('KUBERNETES_SERVICE_HOST'))
# IS_CLOUD adds Azure Container Apps detection. Kept separate from
# IS_CLOUD_OR_K8S until SAML cert env-var loading is verified on ACA.
IS_CLOUD = IS_CLOUD_OR_K8S or bool(os.environ.get('CONTAINER_APP_NAME'))

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if logger.hasHandlers():
    logger.handlers.clear()

# File logging: Only in local dev (cloud platforms have ephemeral filesystems)
if not IS_CLOUD:
    if not os.path.exists(LOG_DIRECTORY):
        os.makedirs(LOG_DIRECTORY)
    file_handler = logging.FileHandler(LOG_FILEPATH, mode='a')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)

# Stdout logging: Always enabled (cloud platforms capture stdout)
stream_handler = logging.StreamHandler(sys.stdout)
if IS_CLOUD:
    # Structured format for Cloud Logging
    stream_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
else:
    stream_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(stream_handler)

# Reduce Flask/Werkzeug noise
logging.getLogger('werkzeug').setLevel(logging.WARNING)

# --- SAML Certificate Loading (Cloud/Kubernetes Support) ---
def load_saml_certs_from_secrets():
    """
    Load SAML certificates from environment variables (injected by K8s Secrets or Secret Manager).
    Writes them to /tmp/ files since OneLogin library requires file paths.
    Updates global CERT_FILE and KEY_FILE paths.
    """
    global CERT_FILE, KEY_FILE

    if not IS_CLOUD_OR_K8S:
        logger.info("Local dev mode: Using SAML certs from local files")
        return

    # Load from environment variables (Secret Manager injects these)
    cert_content = os.environ.get('SAML_TESTER_CERT')
    key_content = os.environ.get('SAML_TESTER_KEY')

    if not cert_content or not key_content:
        logger.warning("SAML certs not found in Secret Manager. SAML functionality may be unavailable.")
        return

    # Write to /tmp/ (Cloud Run's writable filesystem)
    import tempfile
    tmp_cert = Path('/tmp') / 'saml_tester.cert'
    tmp_key = Path('/tmp') / 'saml_tester.key'

    try:
        tmp_cert.write_text(cert_content)
        tmp_key.write_text(key_content)

        # Update permissions (read-only)
        os.chmod(tmp_cert, 0o400)
        os.chmod(tmp_key, 0o400)

        # Update global paths
        CERT_FILE = tmp_cert
        KEY_FILE = tmp_key

        logger.info(f"SAML certs loaded from Secret Manager and written to {tmp_cert} and {tmp_key}")
    except Exception as e:
        logger.error(f"Failed to write SAML certs to /tmp/: {e}")

# Load SAML certs at module import (happens once at startup)
load_saml_certs_from_secrets()

# --- PKCE Helper Functions ---
def generate_pkce_pair():
    code_verifier = base64.urlsafe_b64encode(os.urandom(64)).rstrip(b'=').decode('ascii')
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode('ascii')).digest()).rstrip(b'=').decode('ascii')
    return code_verifier, code_challenge

# --- JWKS Caching Helper ---
def get_jwks_cached(jwks_uri):
    """
    Fetch JWKS with caching to reduce calls to IdP.

    Args:
        jwks_uri: The JWKS endpoint URL

    Returns:
        dict: JWKS data or None on error
    """
    current_time = time.time()

    # Check if we have a cached version that's still valid
    if jwks_uri in _jwks_cache:
        cached_entry = _jwks_cache[jwks_uri]
        age = current_time - cached_entry["timestamp"]
        if age < JWKS_CACHE_TTL:
            logger.info(f"JWKS cache hit for {jwks_uri} (age: {int(age)}s)")
            return cached_entry["jwks"]
        else:
            logger.info(f"JWKS cache expired for {jwks_uri} (age: {int(age)}s, TTL: {JWKS_CACHE_TTL}s)")

    # Cache miss or expired - fetch fresh JWKS
    try:
        logger.info(f"Fetching JWKS from {jwks_uri}")
        response = requests.get(jwks_uri, verify=VERIFY_SSL, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        jwks = response.json()

        # Update cache
        _jwks_cache[jwks_uri] = {
            "jwks": jwks,
            "timestamp": current_time
        }

        return jwks
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch JWKS from {jwks_uri}: {e}")
        return None

# --- OIDC Helper Functions ---
def okta_oidc_get_endpoints(issuer_url):
    global OKTA_OIDC_AUTH_ENDPOINT, OKTA_OIDC_TOKEN_ENDPOINT, OKTA_OIDC_JWKS_URI, OKTA_OIDC_USERINFO_ENDPOINT
    discovery_url = f"{issuer_url}/.well-known/openid-configuration"
    logger.info(f"Okta OIDC: Discovering endpoints from: {discovery_url}")
    try:
        response = requests.get(discovery_url, verify=VERIFY_SSL, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        config = response.json()
        OKTA_OIDC_AUTH_ENDPOINT, OKTA_OIDC_TOKEN_ENDPOINT = config.get("authorization_endpoint"), config.get("token_endpoint")
        OKTA_OIDC_JWKS_URI, OKTA_OIDC_USERINFO_ENDPOINT = config.get("jwks_uri"), config.get("userinfo_endpoint")
        return all([OKTA_OIDC_AUTH_ENDPOINT, OKTA_OIDC_TOKEN_ENDPOINT, OKTA_OIDC_JWKS_URI])
    except requests.exceptions.RequestException as e:
        logger.error(f"Okta OIDC: Error during OIDC discovery: {e}")
        return False

def okta_oidc_exchange_code_for_tokens(code, okta_config, code_verifier):
    logger.info("--- Okta OIDC: Exchanging Authorization Code for Tokens ---")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = { "grant_type": "authorization_code", "client_id": okta_config["oidc_client_id"], "client_secret": okta_config["oidc_client_secret"], "redirect_uri": OKTA_OIDC_REDIRECT_URI, "code": code, "code_verifier": code_verifier }
    try:
        response = requests.post(OKTA_OIDC_TOKEN_ENDPOINT, data=payload, headers=headers, verify=VERIFY_SSL, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Okta OIDC: Error exchanging code for tokens: {e.response.text if e.response else e}")
        return None

def okta_oidc_validate_id_token(id_token, okta_config):
    logger.info("--- Okta OIDC: Validating ID Token ---")
    try:
        jwks = get_jwks_cached(OKTA_OIDC_JWKS_URI)
        if not jwks:
            raise RuntimeError("Failed to fetch JWKS")
        decoded_token = jwt.decode( token=id_token, key=jwks, algorithms=["RS256"], audience=okta_config["oidc_client_id"], issuer=okta_config["oidc_issuer_url"], options={"verify_at_hash": False} )
        logger.info("Okta OIDC: ID Token validation successful!")
        return decoded_token
    except (JWTError, requests.exceptions.RequestException) as e:
        logger.error(f"Okta OIDC: ID Token validation failed: {e}")
        return None

def okta_oidc_validate_access_token(access_token, okta_config):
    logger.info("--- Okta OIDC: Validating Access Token ---")
    try:
        jwks = get_jwks_cached(OKTA_OIDC_JWKS_URI)
        if not jwks:
            raise RuntimeError("Failed to fetch JWKS")
        decoded_token = jwt.decode( token=access_token, key=jwks, algorithms=["RS256"], audience=okta_config["oidc_audience"], issuer=okta_config["oidc_issuer_url"] )
        logger.info("Okta OIDC: Access Token validation successful!")
        return decoded_token
    except (JWTError, requests.exceptions.RequestException) as e:
        logger.error(f"Okta OIDC: Access Token validation failed: {e}")
        return None

def okta_oidc_get_userinfo_claims(access_token):
    logger.info("--- Okta OIDC: Fetching Userinfo Claims ---")
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        response = requests.get(OKTA_OIDC_USERINFO_ENDPOINT, headers=headers, verify=VERIFY_SSL, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Okta OIDC: Error fetching Userinfo claims: {e}")
        return None

def adfs_oidc_get_endpoints(adfs_issuer_url):
    global ADFS_OIDC_AUTH_ENDPOINT, ADFS_OIDC_TOKEN_ENDPOINT, ADFS_OIDC_JWKS_URI, ADFS_OIDC_USERINFO_ENDPOINT
    discovery_url = f"{adfs_issuer_url}/.well-known/openid-configuration"
    logger.info(f"ADFS OIDC: Discovering endpoints from: {discovery_url}")
    try:
        response = requests.get(discovery_url, verify=VERIFY_SSL, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        config = response.json()
        ADFS_OIDC_AUTH_ENDPOINT, ADFS_OIDC_TOKEN_ENDPOINT = config.get("authorization_endpoint"), config.get("token_endpoint")
        ADFS_OIDC_JWKS_URI, ADFS_OIDC_USERINFO_ENDPOINT = config.get("jwks_uri"), config.get("userinfo_endpoint")
        return all([ADFS_OIDC_AUTH_ENDPOINT, ADFS_OIDC_TOKEN_ENDPOINT, ADFS_OIDC_JWKS_URI])
    except requests.exceptions.RequestException as e:
        logger.error(f"ADFS OIDC: Error during OIDC discovery: {e}")
        return False

def azure_oidc_get_endpoints():
    global AZURE_OIDC_AUTH_ENDPOINT, AZURE_OIDC_TOKEN_ENDPOINT, AZURE_OIDC_JWKS_URI, AZURE_OIDC_USERINFO_ENDPOINT
    if not AZURE_OIDC_TENANT_ID:
        logger.error("Azure OIDC: AZURE_OIDC_TENANT_ID is not set")
        return False
    discovery_url = f"https://login.microsoftonline.com/{AZURE_OIDC_TENANT_ID}/v2.0/.well-known/openid-configuration"
    logger.info(f"Azure OIDC: Discovering endpoints from: {discovery_url}")
    try:
        response = requests.get(discovery_url, verify=VERIFY_SSL, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        config = response.json()
        AZURE_OIDC_AUTH_ENDPOINT, AZURE_OIDC_TOKEN_ENDPOINT = config.get("authorization_endpoint"), config.get("token_endpoint")
        AZURE_OIDC_JWKS_URI, AZURE_OIDC_USERINFO_ENDPOINT = config.get("jwks_uri"), config.get("userinfo_endpoint")
        return all([AZURE_OIDC_AUTH_ENDPOINT, AZURE_OIDC_TOKEN_ENDPOINT, AZURE_OIDC_JWKS_URI])
    except requests.exceptions.RequestException as e:
        logger.error(f"Azure OIDC: Error during OIDC discovery: {e}")
        return False

def adfs_oidc_exchange_code_for_tokens(code, adfs_env_key, code_verifier):
    logger.info("--- ADFS OIDC: Exchanging Authorization Code for Tokens ---")
    config = ADFS_OIDC_CONFIGS.get(adfs_env_key)
    if not config:
        logger.error(f"ADFS OIDC: No configuration found for environment '{adfs_env_key}'")
        return None
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = { "grant_type": "authorization_code", "client_id": config["client_id"], "client_secret": config["client_secret"], "redirect_uri": ADFS_OIDC_REDIRECT_URI, "code": code, "code_verifier": code_verifier }
    try:
        response = requests.post(ADFS_OIDC_TOKEN_ENDPOINT, data=payload, headers=headers, verify=VERIFY_SSL, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"ADFS OIDC: Error exchanging code for tokens: {e.response.text if e.response else e}")
        return None

def azure_oidc_exchange_code_for_tokens(code, code_verifier):
    logger.info("--- Azure OIDC: Exchanging Authorization Code for Tokens ---")
    # Ensure endpoints are discovered (needed for multi-worker setups where callback may hit different worker)
    if not AZURE_OIDC_TOKEN_ENDPOINT:
        if not azure_oidc_get_endpoints():
            logger.error("Azure OIDC: Failed to discover endpoints for token exchange")
            return None
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = {
        "grant_type": "authorization_code",
        "client_id": AZURE_OIDC_CLIENT_ID,
        "client_secret": AZURE_OIDC_CLIENT_SECRET,
        "redirect_uri": AZURE_OIDC_REDIRECT_URI,
        "code": code,
        "code_verifier": code_verifier
    }
    try:
        response = requests.post(AZURE_OIDC_TOKEN_ENDPOINT, data=payload, headers=headers, verify=VERIFY_SSL, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Azure OIDC: Error exchanging code for tokens: {e.response.text if e.response else e}")
        return None

def adfs_oidc_validate_id_token(id_token, adfs_issuer_url, adfs_env_key):
    logger.info("--- ADFS OIDC: Validating ID Token ---")
    config = ADFS_OIDC_CONFIGS.get(adfs_env_key)
    if not config:
        logger.error(f"ADFS OIDC: No configuration found for environment '{adfs_env_key}'")
        return None
    try:
        jwks = get_jwks_cached(ADFS_OIDC_JWKS_URI)
        if not jwks:
            raise RuntimeError("Failed to fetch JWKS")
        decoded_token = jwt.decode(token=id_token, key=jwks, algorithms=["RS256"], audience=config["client_id"], issuer=adfs_issuer_url)
        logger.info("ADFS OIDC: ID Token validation successful!")
        return decoded_token
    except (JWTError, requests.exceptions.RequestException) as e:
        logger.error(f"ADFS OIDC: ID Token validation failed: {e}")
        return None

def azure_oidc_validate_id_token(id_token):
    logger.info("--- Azure OIDC: Validating ID Token ---")
    # Ensure endpoints are discovered (needed for multi-worker setups)
    if not AZURE_OIDC_JWKS_URI:
        if not azure_oidc_get_endpoints():
            logger.error("Azure OIDC: Failed to discover endpoints for token validation")
            return None
    try:
        jwks = get_jwks_cached(AZURE_OIDC_JWKS_URI)
        if not jwks:
            raise RuntimeError("Failed to fetch JWKS")
        # Azure AD v2.0 tokens have issuer format: https://login.microsoftonline.com/{tenant}/v2.0
        decoded_token = jwt.decode(
            token=id_token,
            key=jwks,
            algorithms=["RS256"],
            audience=AZURE_OIDC_CLIENT_ID,
            issuer=AZURE_OIDC_ISSUER,
            options={"verify_at_hash": False}
        )
        logger.info("Azure OIDC: ID Token validation successful!")
        return decoded_token
    except (JWTError, requests.exceptions.RequestException) as e:
        logger.error(f"Azure OIDC: ID Token validation failed: {e}")
        return None

def adfs_oidc_get_userinfo_claims(access_token):
    logger.info("--- ADFS OIDC: Fetching Userinfo Claims ---")
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        response = requests.get(ADFS_OIDC_USERINFO_ENDPOINT, headers=headers, verify=VERIFY_SSL, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"ADFS OIDC: Error fetching Userinfo claims: {e}")
        return None

def azure_oidc_get_userinfo_claims(access_token):
    logger.info("--- Azure OIDC: Fetching Userinfo Claims ---")
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        # Azure's userinfo endpoint is at Microsoft Graph
        response = requests.get("https://graph.microsoft.com/oidc/userinfo", headers=headers, verify=VERIFY_SSL, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Azure OIDC: Error fetching Userinfo claims: {e}")
        return None

def oidc_perform_token_refresh(refresh_token, idp_choice, env_key, auth_server_type="custom"):
    logger.info(f"--- {idp_choice.upper()} OIDC: Performing Token Refresh ---")
    token_endpoint, client_id, client_secret, scopes = None, None, None, None

    if idp_choice == 'okta':
        env_config = OKTA_ENVIRONMENTS.get(env_key)
        if env_config:
            config = env_config.get(auth_server_type, env_config.get("custom"))
            token_endpoint, client_id, client_secret, scopes = OKTA_OIDC_TOKEN_ENDPOINT, config.get("oidc_client_id"), config.get("oidc_client_secret"), OKTA_OIDC_SCOPES
    elif idp_choice == 'adfs':
        config = ADFS_OIDC_CONFIGS.get(env_key)
        token_endpoint, client_id, client_secret, scopes = ADFS_OIDC_TOKEN_ENDPOINT, config.get("client_id"), config.get("client_secret"), ADFS_OIDC_SCOPES

    if not all([token_endpoint, client_id, client_secret]):
        error_msg = f"OIDC Refresh: Configuration incomplete for {idp_choice.upper()} {env_key}."
        logger.error(error_msg)
        return {"error": "configuration_error", "error_description": error_msg}

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = { "grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id, "client_secret": client_secret, "scope": scopes }
    try:
        response = requests.post(token_endpoint, data=payload, headers=headers, verify=VERIFY_SSL, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        logger.info(f"{idp_choice.upper()} OIDC: Token refresh successful.")
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"{idp_choice.upper()} OIDC: Error during token refresh: {e.response.text if e.response else e}")
        return e.response.json() if e.response else {"error": "request_error", "error_description": str(e)}

# --- SAML v2.0 Functions ---
def build_saml_request_data(req):
    # Cloud Run terminates SSL at the load balancer.
    # We must check X-Forwarded-Proto to see if the real request was HTTPS.
    forwarded_proto = req.headers.get('X-Forwarded-Proto', req.scheme)
    
    is_https = 'on' if forwarded_proto == 'https' else 'off'
    
    # If HTTPS, force port 443. If HTTP, use the actual server port (e.g. 8080)
    # This prevents the library from constructing URLs like https://site:8080/
    if is_https == 'on':
        server_port = '443'
    else:
        server_port = req.environ.get('SERVER_PORT', '80')

    host = req.host
    # If the host header includes a port (e.g. localhost:8080), strip it
    # so we don't accidentally double-port the URL.
    if ':' in host:
        host = host.split(':')[0]

    return {
        'https': is_https,
        'http_host': host,
        'server_port': server_port,
        'script_name': req.path,
        'get_data': req.args.copy(),
        'post_data': req.form.copy()
    }

def prepare_saml_request(request, idp_key):
    saml_req_data = build_saml_request_data(request)
    settings = saml_settings.get_saml_settings(idp_key)
    auth = OneLogin_Saml2_Auth(saml_req_data, settings)
    return auth

def run_sp_initiated_saml_flow(request, idp_key, force_fresh_login=True):
    logger.info(f"--- SAML SP-Initiated Flow Initialized for {idp_key} ---")
    auth = prepare_saml_request(request, idp_key)
    return auth.login(force_authn=force_fresh_login)

def process_saml_response(request, idp_key):
    logger.info("SAML: --- Processing and Validating SAML Response ---")
    auth = prepare_saml_request(request, idp_key)
    auth.process_response()
    errors = auth.get_errors()
    if errors:
        error_reason = auth.get_last_error_reason()
        logger.error(f"SAML Response validation failed: {error_reason}")
        raise RuntimeError(f"SAML Error: {error_reason}")
    if not auth.is_authenticated():
        raise RuntimeError("SAML authentication failed.")
    logger.info("SAML: Response validation successful!")
    
    claims = auth.get_attributes()
    raw_xml_string = auth.get_last_response_xml()
    dom = xml.dom.minidom.parseString(raw_xml_string)
    raw_xml = dom.toprettyxml()
    return {"claims": claims, "raw_xml": raw_xml}

# --- Test Execution Flow Functions (OIDC part) ---
def run_okta_oidc_flow(okta_config, auth_server_type="custom", force_fresh_login=True):
    logger.info(f"--- Okta OIDC Client Test Initiated (Auth Server: {auth_server_type}) ---")
    if not okta_oidc_get_endpoints(okta_config["oidc_issuer_url"]):
        return None, None, None, None
    state = os.urandom(16).hex()
    code_verifier, code_challenge = generate_pkce_pair()
    auth_params = { "response_type": "code", "client_id": okta_config["oidc_client_id"], "redirect_uri": OKTA_OIDC_REDIRECT_URI, "scope": OKTA_OIDC_SCOPES, "state": state, "code_challenge": code_challenge, "code_challenge_method": "S256" }
    if force_fresh_login:
        auth_params["prompt"] = "login"
        auth_params["max_age"] = 0
    authorization_url = f"{OKTA_OIDC_AUTH_ENDPOINT}?{urlencode(auth_params)}"
    logger.info(f"Okta OIDC: Generated authorization URL for redirect with PKCE (using {auth_server_type} auth server, force_fresh_login={force_fresh_login}).")
    return authorization_url, state, code_verifier, code_challenge

def run_adfs_oidc_flow(adfs_base_url, adfs_env_key, force_fresh_login=True):
    logger.info(f"--- ADFS OIDC Client Test Initiated on {adfs_base_url} ---")
    if not adfs_oidc_get_endpoints(adfs_base_url): return None, None, None, None
    state = os.urandom(16).hex()
    client_id = ADFS_OIDC_CONFIGS[adfs_env_key]["client_id"]
    code_verifier, code_challenge = generate_pkce_pair()
    auth_params = { "response_type": "code", "client_id": client_id, "redirect_uri": ADFS_OIDC_REDIRECT_URI, "scope": ADFS_OIDC_SCOPES, "state": state, "code_challenge": code_challenge, "code_challenge_method": "S256" }
    if force_fresh_login:
        auth_params["prompt"] = "login"
        auth_params["max_age"] = 0
    authorization_url = f"{ADFS_OIDC_AUTH_ENDPOINT}?{urlencode(auth_params)}"
    logger.info(f"ADFS OIDC: Generated authorization URL for redirect with PKCE (force_fresh_login={force_fresh_login}).")
    return authorization_url, state, code_verifier, code_challenge

def run_azure_oidc_flow():
    logger.info("--- Azure OIDC Login Initiated ---")
    if not azure_oidc_get_endpoints():
        return None, None, None, None
    state = os.urandom(16).hex()
    code_verifier, code_challenge = generate_pkce_pair()
    auth_params = {
        "response_type": "code",
        "client_id": AZURE_OIDC_CLIENT_ID,
        "redirect_uri": AZURE_OIDC_REDIRECT_URI,
        "scope": AZURE_OIDC_SCOPES,
        "state": state,
        "prompt": "select_account",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    authorization_url = f"{AZURE_OIDC_AUTH_ENDPOINT}?{urlencode(auth_params)}"
    logger.info("Azure OIDC: Generated authorization URL for redirect with PKCE.")
    return authorization_url, state, code_verifier, code_challenge

def okta_check_token_lifetimes(environment, auth_server_type="custom"):
    """
    Queries Okta Authorization Server API to retrieve token lifetime settings.

    Args:
        environment: "DEV" or "PROD"
        auth_server_type: "custom" or "default"

    Returns:
        dict with success status and data/error message
    """
    logger.info(f"--- Token Lifetime Check: Okta {environment} ({auth_server_type}) ---")

    # Get API token from environment
    api_token_key = f"OKTA_{environment}_API_TOKEN"
    api_token = os.environ.get(api_token_key)

    if not api_token:
        error_msg = f"API token not found for {environment}. Please set {api_token_key} in env.config"
        logger.error(error_msg)
        return {"success": False, "error": error_msg}

    # Get the configuration for this environment/auth server
    # Handle environments that only have one auth server type available
    env_options = OKTA_ENVIRONMENTS.get(environment, {})
    env_config = env_options.get(auth_server_type)

    if not env_config:
        # Requested type doesn't exist, try to find any available type
        if "custom" in env_options:
            auth_server_type = "custom"
            env_config = env_options["custom"]
            logger.info(f"{environment}: Using 'custom' auth server (fallback)")
        elif "default" in env_options:
            auth_server_type = "default"
            env_config = env_options["default"]
            logger.info(f"{environment}: Using 'default' auth server (fallback)")
        else:
            error_msg = f"No auth server configuration found for {environment}"
            logger.error(error_msg)
            return {"success": False, "error": error_msg}

    # Determine the authorization server ID from the issuer URL
    issuer_url = env_config.get("oidc_issuer_url", "")

    # Extract auth server ID from issuer URL
    # For custom: https://domain/oauth2/{authServerId}
    # For default: https://domain/oauth2/default
    if "/oauth2/" in issuer_url:
        auth_server_id = issuer_url.split("/oauth2/")[-1].rstrip("/")
    else:
        # For PROD custom server, the issuer is just the base domain
        auth_server_id = "default"

    # Determine base URL for API calls
    if "dev-your-org.okta.com" in issuer_url:
        base_url = "https://dev-your-org.okta.com"
    elif "login-dev.example.gov" in issuer_url:
        base_url = "https://host.example.gov"
    elif "staging-your-org.okta.com" in issuer_url:
        base_url = "https://staging-your-org.okta.com"
    elif "login-lab.example.gov" in issuer_url:
        base_url = "https://host.example.gov"
    elif "login.example.gov" in issuer_url:
        base_url = "https://host.example.gov"
    else:
        error_msg = f"Could not determine base URL from issuer: {issuer_url}"
        logger.error(error_msg)
        return {"success": False, "error": error_msg}

    logger.info(f"Using base URL: {base_url}, auth server ID: {auth_server_id}")

    # Step 1: Get policies
    policies_url = f"{base_url}/api/v1/authorizationServers/{auth_server_id}/policies"
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json"
    }

    try:
        logger.info(f"Fetching policies from: {policies_url}")
        policies_response = requests.get(policies_url, headers=headers, timeout=10)
        policies_response.raise_for_status()
        policies_data = policies_response.json()

        # Check for API errors
        if isinstance(policies_data, dict) and "errorCode" in policies_data:
            error_msg = policies_data.get("errorSummary", "Unknown API error")
            logger.error(f"Okta API Error: {error_msg}")
            return {"success": False, "error": f"Okta API Error: {error_msg}"}

        # Extract first policy ID
        if not policies_data or not isinstance(policies_data, list) or len(policies_data) == 0:
            error_msg = "No policies found in authorization server"
            logger.error(error_msg)
            return {"success": False, "error": error_msg}

        policy_id = policies_data[0].get("id")
        logger.info(f"Found policy ID: {policy_id}")

        # Step 2: Get policy rules (contains token lifetimes)
        rules_url = f"{base_url}/api/v1/authorizationServers/{auth_server_id}/policies/{policy_id}/rules"
        logger.info(f"Fetching rules from: {rules_url}")
        rules_response = requests.get(rules_url, headers=headers, timeout=10)
        rules_response.raise_for_status()
        rules_data = rules_response.json()

        # Check for API errors
        if isinstance(rules_data, dict) and "errorCode" in rules_data:
            error_msg = rules_data.get("errorSummary", "Unknown API error")
            logger.error(f"Okta API Error: {error_msg}")
            return {"success": False, "error": f"Okta API Error: {error_msg}"}

        # Extract token lifetime values from first rule
        if not rules_data or not isinstance(rules_data, list) or len(rules_data) == 0:
            error_msg = "No rules found in policy"
            logger.error(error_msg)
            return {"success": False, "error": error_msg}

        rule = rules_data[0]
        actions = rule.get("actions", {})
        token_settings = actions.get("token", {})

        access_token_minutes = token_settings.get("accessTokenLifetimeMinutes")
        refresh_token_minutes = token_settings.get("refreshTokenLifetimeMinutes")
        refresh_window_minutes = token_settings.get("refreshTokenWindowMinutes")

        if access_token_minutes is None:
            error_msg = "Could not extract token lifetime values from policy rules"
            logger.error(error_msg)
            return {"success": False, "error": error_msg}

        # Calculate human-readable values
        access_hours = access_token_minutes / 60
        refresh_days = refresh_token_minutes / 1440 if refresh_token_minutes else 0
        window_days = refresh_window_minutes / 1440 if refresh_window_minutes else 0

        result = {
            "success": True,
            "environment": environment,
            "auth_server_type": auth_server_type,
            "data": {
                "access_token": {
                    "minutes": access_token_minutes,
                    "human_readable": f"{access_hours:.1f} hours"
                },
                "refresh_token": {
                    "minutes": refresh_token_minutes,
                    "human_readable": f"{refresh_days:.1f} days"
                } if refresh_token_minutes else None,
                "refresh_token_idle": {
                    "minutes": refresh_window_minutes,
                    "human_readable": f"{window_days:.1f} days"
                } if refresh_window_minutes else None
            }
        }

        logger.info(f"Token lifetime check successful: Access={access_token_minutes}min, Refresh={refresh_token_minutes}min, Idle={refresh_window_minutes}min")
        return result

    except requests.exceptions.HTTPError as e:
        # Check for 401 Unauthorized - likely missing Custom AS SKU
        if e.response.status_code == 401:
            logger.warning(f"{environment} token lifetime check failed (401 Unauthorized - likely no Custom AS SKU): {str(e)}")
            return {
                "success": False,
                "error": f"Token lifetime checks require Custom Authorization Server SKU. {environment} environment does not have API access to authorization server settings.",
                "is_limitation": True,  # Flag to show as info instead of error
                "environment": environment,
                "assumed_defaults": {
                    "access_token": "60 minutes (1 hour)",
                    "refresh_token": "7776000 minutes (90 days)",
                    "note": "These are standard Okta org server defaults. Contact Okta support for exact settings in this environment."
                }
            }
        else:
            error_msg = f"HTTP error: {str(e)}"
            logger.error(error_msg)
            return {"success": False, "error": error_msg}
    except requests.exceptions.RequestException as e:
        error_msg = f"HTTP request failed: {str(e)}"
        logger.error(error_msg)
        return {"success": False, "error": error_msg}
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(error_msg)
        return {"success": False, "error": error_msg}
