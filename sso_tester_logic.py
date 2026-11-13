# -----------------------------------------------------------------------------
# Script Name : sso_tester_logic.py (Core Logic Module for Identity Analyzer)
# Description : Contains the IdP/Protocol specific test execution functions and
#               helpers.
# Author      : Wes Glockzin
# Version     : 7.0.1 (Container Apps + Multi-worker OIDC fix)
# License     : MIT
# -----------------------------------------------------------------------------

import base64
import hashlib
import logging
import os
import sys
import time
import xml.dom.minidom
from pathlib import Path
from urllib.parse import urlencode

import jwt
import requests
from onelogin.saml2.auth import OneLogin_Saml2_Auth

import idp_config
import saml_settings
from guards import GENERIC_ERROR, UserFacingError, bounded
from http_session import make_session

APP_VERSION = "7.3.8"

# --- Base Directory ---
SCRIPT_DIR = Path(__file__).resolve().parent

# --- Configuration: Base URL (Local vs Cloud) ---
# This allows the app to switch between localhost and Cloud Run automatically
# via the APP_BASE_URL environment variable.
BASE_URL = os.environ["APP_BASE_URL"].rstrip("/")

# --- Okta and ADFS environments: lists of any length, from environment settings ---
# (see idp_config.py). Okta entries are nested for the auth server toggle.
OKTA_ENVIRONMENTS = idp_config.load_okta_environments(os.environ)
ADFS_ENVIRONMENTS, ADFS_OIDC_CONFIGS = idp_config.load_adfs_environments(os.environ)

# Dynamic Redirect URI based on BASE_URL
OKTA_OIDC_REDIRECT_URI = f"{BASE_URL}/okta/oidc/callback"
OKTA_OIDC_SCOPES = "openid profile email offline_access"

# --- ADFS OIDC Configuration (ADFS_OIDC_CONFIGS is loaded above) ---
ADFS_OIDC_SCOPES = "openid profile email offline_access"
# Dynamic Redirect URI based on BASE_URL
ADFS_OIDC_REDIRECT_URI = f"{BASE_URL}/adfs/oidc/callback"

# Discovered endpoints, keyed by issuer URL: {issuer: {"auth", "token", "jwks_uri",
# "userinfo"}}. Each entry is written whole, never changed afterwards, and found by
# the issuer of the environment being tested, so concurrent users and workers
# cannot overwrite each other's endpoints. A worker that has no entry discovers it.
_endpoints_cache = {}


# --- General Configuration ---
def listen_port(env):
    """The port to listen on: the PORT setting, 8080 when it is not set."""
    return int(env.get("PORT", 8080))


LISTEN_PORT = listen_port(os.environ)
VERIFY_SSL = True
HTTP_TIMEOUT = 10  # Timeout in seconds for all HTTP requests to IdPs
JWKS_CACHE_TTL = 3600  # JWKS cache time-to-live in seconds (1 hour)

# Module-level HTTP session — centralizes the User-Agent so IdP-side audit
# logs can tell this tool apart from generic python-requests automation, and so each
# call site gets connection reuse for free.
_session = make_session("FederatedClaimsAnalyzer", APP_VERSION)
_session.verify = VERIFY_SSL

# SAML Certificate Paths (will be set after loading from Secret Manager in Cloud Run)
CERT_FILE = SCRIPT_DIR / "saml_tester.cert"  # Default for local dev
KEY_FILE = SCRIPT_DIR / "saml_tester.key"  # Default for local dev

# JWKS Cache: {jwks_uri: {"jwks": <data>, "timestamp": <time>}}
_jwks_cache = {}

STANDARD_CLAIMS = {
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "azp",
    "at_hash",
    "c_hash",
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "email",
    "email_verified",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "phone_number",
    "phone_number_verified",
    "address",
    "updated_at",
    "scp",
    "cid",
    "uid",
    "ver",
    "sid",
    "pwd_url",
    "mfa_auth_time",
    "apptype",
    "appid",
    "authmethod",
    "idsub",
}

# --- Logging Setup ---
# Cloud/Kubernetes best practice: Log to stdout/stderr (captured by logging infrastructure)
# Only use file logging in local development
IS_CLOUD_OR_K8S = bool(
    os.environ.get("K_SERVICE") or os.environ.get("KUBERNETES_SERVICE_HOST")
)
# IS_CLOUD adds Azure Container Apps detection. Kept separate from
# IS_CLOUD_OR_K8S until SAML cert env-var loading is verified on ACA.
IS_CLOUD = IS_CLOUD_OR_K8S or bool(os.environ.get("CONTAINER_APP_NAME"))

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if logger.hasHandlers():
    logger.handlers.clear()

# Logs go to stdout only (container platforms capture it)
stream_handler = logging.StreamHandler(sys.stdout)
if IS_CLOUD:
    # Structured format for Cloud Logging
    stream_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
else:
    stream_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    )
logger.addHandler(stream_handler)

# Reduce Flask/Werkzeug noise
logging.getLogger("werkzeug").setLevel(logging.WARNING)


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
    cert_content = os.environ.get("SAML_TESTER_CERT")
    key_content = os.environ.get("SAML_TESTER_KEY")

    if not cert_content or not key_content:
        logger.warning(
            "SAML certs not found in Secret Manager. SAML functionality may be unavailable."
        )
        return

    # Write to /tmp/ (Cloud Run's writable filesystem)
    tmp_cert = Path("/tmp") / "saml_tester.cert"
    tmp_key = Path("/tmp") / "saml_tester.key"

    try:
        tmp_cert.write_text(cert_content)
        tmp_key.write_text(key_content)

        # Update permissions (read-only)
        os.chmod(tmp_cert, 0o400)
        os.chmod(tmp_key, 0o400)

        # Update global paths
        CERT_FILE = tmp_cert
        KEY_FILE = tmp_key

        logger.info(
            f"SAML certs loaded from Secret Manager and written to {tmp_cert} and {tmp_key}"
        )
    except OSError as e:
        logger.error("Failed to write SAML certs to /tmp/: %s", e)


# Load SAML certs at module import (happens once at startup)
load_saml_certs_from_secrets()


def describe_request_error(exc):
    """Describe a requests error; an HTTP error keeps its status and body.

    A requests Response is falsy for 4xx/5xx, so test `is None`, not truthiness.
    """
    response = getattr(exc, "response", None)
    if response is None:
        return str(exc)
    return f"HTTP {response.status_code}: {response.text}"


# --- PKCE Helper Functions ---
def generate_pkce_pair():
    code_verifier = (
        base64.urlsafe_b64encode(os.urandom(64)).rstrip(b"=").decode("ascii")
    )
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
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
            logger.info(
                f"JWKS cache expired for {jwks_uri} (age: {int(age)}s, TTL: {JWKS_CACHE_TTL}s)"
            )

    # Cache miss or expired - fetch fresh JWKS
    try:
        logger.info(f"Fetching JWKS from {jwks_uri}")
        response = _session.get(jwks_uri, verify=VERIFY_SSL, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        jwks = response.json()

        # Update cache
        _jwks_cache[jwks_uri] = {"jwks": jwks, "timestamp": current_time}

        return jwks
    except requests.exceptions.RequestException as e:
        logger.error(
            f"Failed to fetch JWKS from {jwks_uri}: {describe_request_error(e)}"
        )
        return None


def decode_jwt(token, jwks, **checks):
    """Verify a token's signature (RS256 only) against a JWKS and return its claims.

    `checks` are PyJWT checks such as audience= and issuer=. Raises
    jwt.PyJWTError when the token or the key set is not acceptable.
    """
    key_id = jwt.get_unverified_header(token).get("kid")
    keys = jwt.PyJWKSet.from_dict(jwks).keys
    matching = [k for k in keys if key_id is None or k.key_id == key_id]
    if not matching:
        raise jwt.PyJWTError("No key in the JWKS matches the token's key id.")
    return jwt.decode(token, matching[0].key, algorithms=["RS256"], **checks)


# --- OIDC Helper Functions ---
def discover_endpoints(issuer_url, label):
    """Fetch the issuer's discovery document; return its endpoints, or None."""
    discovery_url = f"{issuer_url}/.well-known/openid-configuration"
    logger.info(f"{label} OIDC: Discovering endpoints from: {discovery_url}")
    try:
        response = _session.get(discovery_url, verify=VERIFY_SSL, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        config = response.json()
    except requests.exceptions.RequestException as e:
        logger.error(
            f"{label} OIDC: Error during OIDC discovery: {describe_request_error(e)}"
        )
        return None
    endpoints = {
        "auth": config.get("authorization_endpoint"),
        "token": config.get("token_endpoint"),
        "jwks_uri": config.get("jwks_uri"),
        "userinfo": config.get("userinfo_endpoint"),
    }
    if not all([endpoints["auth"], endpoints["token"], endpoints["jwks_uri"]]):
        logger.error(f"{label} OIDC: The discovery document is incomplete.")
        return None
    _endpoints_cache[issuer_url] = endpoints
    return endpoints


def endpoints_for(issuer_url, label):
    """The issuer's endpoints from this worker's cache, discovered when absent."""
    return _endpoints_cache.get(issuer_url) or discover_endpoints(issuer_url, label)


def okta_oidc_get_endpoints(issuer_url):
    return discover_endpoints(issuer_url, "Okta")


def okta_oidc_exchange_code_for_tokens(code, okta_config, code_verifier):
    logger.info("--- Okta OIDC: Exchanging Authorization Code for Tokens ---")
    endpoints = endpoints_for(okta_config["oidc_issuer_url"], "Okta")
    if not endpoints:
        return None
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = {
        "grant_type": "authorization_code",
        "client_id": okta_config["oidc_client_id"],
        "client_secret": okta_config["oidc_client_secret"],
        "redirect_uri": OKTA_OIDC_REDIRECT_URI,
        "code": code,
        "code_verifier": code_verifier,
    }
    try:
        response = _session.post(
            endpoints["token"],
            data=payload,
            headers=headers,
            verify=VERIFY_SSL,
            timeout=HTTP_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(
            f"Okta OIDC: Error exchanging code for tokens: {describe_request_error(e)}"
        )
        return None


def okta_oidc_validate_id_token(id_token, okta_config):
    logger.info("--- Okta OIDC: Validating ID Token ---")
    try:
        endpoints = endpoints_for(okta_config["oidc_issuer_url"], "Okta")
        jwks = endpoints and get_jwks_cached(endpoints["jwks_uri"])
        if not jwks:
            raise RuntimeError("Failed to fetch JWKS")
        decoded_token = decode_jwt(
            id_token,
            jwks,
            audience=okta_config["oidc_client_id"],
            issuer=okta_config["oidc_issuer_url"],
        )
        logger.info("Okta OIDC: ID Token validation successful!")
        return decoded_token
    except (jwt.PyJWTError, requests.exceptions.RequestException) as e:
        logger.error(f"Okta OIDC: ID Token validation failed: {e}")
        return None


def okta_oidc_validate_access_token(access_token, okta_config):
    logger.info("--- Okta OIDC: Validating Access Token ---")
    try:
        endpoints = endpoints_for(okta_config["oidc_issuer_url"], "Okta")
        jwks = endpoints and get_jwks_cached(endpoints["jwks_uri"])
        if not jwks:
            raise RuntimeError("Failed to fetch JWKS")
        decoded_token = decode_jwt(
            access_token,
            jwks,
            audience=okta_config["oidc_audience"],
            issuer=okta_config["oidc_issuer_url"],
        )
        logger.info("Okta OIDC: Access Token validation successful!")
        return decoded_token
    except (jwt.PyJWTError, requests.exceptions.RequestException) as e:
        logger.error(f"Okta OIDC: Access Token validation failed: {e}")
        return None


def fetch_userinfo(issuer_url, access_token, label):
    """Call the issuer's userinfo endpoint; return its claims, or None."""
    endpoints = endpoints_for(issuer_url, label)
    if not endpoints or not endpoints["userinfo"]:
        logger.error(f"{label} OIDC: No userinfo endpoint is known.")
        return None
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        response = _session.get(
            endpoints["userinfo"],
            headers=headers,
            verify=VERIFY_SSL,
            timeout=HTTP_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(
            f"{label} OIDC: Error fetching Userinfo claims: {describe_request_error(e)}"
        )
        return None


def okta_oidc_get_userinfo_claims(access_token, okta_config):
    logger.info("--- Okta OIDC: Fetching Userinfo Claims ---")
    return fetch_userinfo(okta_config["oidc_issuer_url"], access_token, "Okta")


def adfs_oidc_get_endpoints(adfs_issuer_url):
    return discover_endpoints(adfs_issuer_url, "ADFS")


def adfs_oidc_exchange_code_for_tokens(code, adfs_env_key, code_verifier):
    logger.info("--- ADFS OIDC: Exchanging Authorization Code for Tokens ---")
    config = ADFS_OIDC_CONFIGS.get(adfs_env_key)
    if not config:
        logger.error(
            f"ADFS OIDC: No configuration found for environment '{adfs_env_key}'"
        )
        return None
    endpoints = endpoints_for(ADFS_ENVIRONMENTS[adfs_env_key], "ADFS")
    if not endpoints:
        return None
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = {
        "grant_type": "authorization_code",
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "redirect_uri": ADFS_OIDC_REDIRECT_URI,
        "code": code,
        "code_verifier": code_verifier,
    }
    try:
        response = _session.post(
            endpoints["token"],
            data=payload,
            headers=headers,
            verify=VERIFY_SSL,
            timeout=HTTP_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(
            f"ADFS OIDC: Error exchanging code for tokens: {describe_request_error(e)}"
        )
        return None


def adfs_oidc_validate_id_token(id_token, adfs_issuer_url, adfs_env_key):
    logger.info("--- ADFS OIDC: Validating ID Token ---")
    config = ADFS_OIDC_CONFIGS.get(adfs_env_key)
    if not config:
        logger.error(
            f"ADFS OIDC: No configuration found for environment '{adfs_env_key}'"
        )
        return None
    try:
        endpoints = endpoints_for(adfs_issuer_url, "ADFS")
        jwks = endpoints and get_jwks_cached(endpoints["jwks_uri"])
        if not jwks:
            raise RuntimeError("Failed to fetch JWKS")
        decoded_token = decode_jwt(
            id_token,
            jwks,
            audience=config["client_id"],
            issuer=adfs_issuer_url,
        )
        logger.info("ADFS OIDC: ID Token validation successful!")
        return decoded_token
    except (jwt.PyJWTError, requests.exceptions.RequestException) as e:
        logger.error(f"ADFS OIDC: ID Token validation failed: {e}")
        return None


def adfs_oidc_get_userinfo_claims(access_token, adfs_issuer_url):
    logger.info("--- ADFS OIDC: Fetching Userinfo Claims ---")
    return fetch_userinfo(adfs_issuer_url, access_token, "ADFS")


def oidc_perform_token_refresh(
    refresh_token, idp_choice, env_key, auth_server_type="custom"
):
    logger.info(f"--- {idp_choice.upper()} OIDC: Performing Token Refresh ---")
    token_endpoint, client_id, client_secret, scopes = None, None, None, None

    if idp_choice == "okta":
        env_config = OKTA_ENVIRONMENTS.get(env_key)
        if env_config:
            config = env_config.get(auth_server_type, env_config.get("custom"))
            # Discover in this worker when it has not served this issuer yet.
            endpoints = endpoints_for(config["oidc_issuer_url"], "Okta")
            token_endpoint, client_id, client_secret, scopes = (
                endpoints and endpoints["token"],
                config.get("oidc_client_id"),
                config.get("oidc_client_secret"),
                OKTA_OIDC_SCOPES,
            )
    elif idp_choice == "adfs":
        config = ADFS_OIDC_CONFIGS.get(env_key)
        if config:
            endpoints = endpoints_for(ADFS_ENVIRONMENTS[env_key], "ADFS")
            token_endpoint, client_id, client_secret, scopes = (
                endpoints and endpoints["token"],
                config.get("client_id"),
                config.get("client_secret"),
                ADFS_OIDC_SCOPES,
            )

    if not all([token_endpoint, client_id, client_secret]):
        error_msg = f"OIDC Refresh: Configuration incomplete for {idp_choice.upper()} {env_key}."
        logger.error(error_msg)
        return {"error": "configuration_error", "error_description": error_msg}

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scopes,
    }
    try:
        response = _session.post(
            token_endpoint,
            data=payload,
            headers=headers,
            verify=VERIFY_SSL,
            timeout=HTTP_TIMEOUT,
        )
        response.raise_for_status()
        logger.info(f"{idp_choice.upper()} OIDC: Token refresh successful.")
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(
            f"{idp_choice.upper()} OIDC: Error during token refresh: {describe_request_error(e)}"
        )
        if e.response is None:
            return {
                "error": "request_error",
                "error_description": "The identity provider could not be reached.",
            }
        try:
            body = e.response.json()
        except ValueError:
            body = None
        if isinstance(body, dict) and body.get("error"):
            return body
        return {
            "error": "http_error",
            "error_description": f"HTTP {e.response.status_code}: {e.response.text}",
        }


# --- SAML v2.0 Functions ---
def build_saml_request_data(req):
    # Cloud Run terminates SSL at the load balancer.
    # We must check X-Forwarded-Proto to see if the real request was HTTPS.
    forwarded_proto = req.headers.get("X-Forwarded-Proto", req.scheme)

    is_https = "on" if forwarded_proto == "https" else "off"

    # If HTTPS, force port 443. If HTTP, use the actual server port (e.g. 8080)
    # This prevents the library from constructing URLs like https://host.example.invalid:8080
    if is_https == "on":
        server_port = "443"
    else:
        server_port = req.environ.get("SERVER_PORT", "80")

    host = req.host
    # If the host header includes a port (e.g. localhost:8080), strip it
    # so we don't accidentally double-port the URL.
    if ":" in host:
        host = host.split(":")[0]

    return {
        "https": is_https,
        "http_host": host,
        "server_port": server_port,
        "script_name": req.path,
        "get_data": req.args.copy(),
        "post_data": req.form.copy(),
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
        raise UserFacingError("SAML response validation failed.")
    if not auth.is_authenticated():
        raise UserFacingError("SAML authentication failed.")
    logger.info("SAML: Response validation successful!")

    claims = auth.get_attributes()
    raw_xml_string = auth.get_last_response_xml()
    dom = xml.dom.minidom.parseString(raw_xml_string)
    raw_xml = dom.toprettyxml()
    return {"claims": claims, "raw_xml": raw_xml}


# --- Test Execution Flow Functions (OIDC part) ---
def run_okta_oidc_flow(okta_config, auth_server_type="custom", force_fresh_login=True):
    logger.info(
        f"--- Okta OIDC Client Test Initiated (Auth Server: {auth_server_type}) ---"
    )
    endpoints = okta_oidc_get_endpoints(okta_config["oidc_issuer_url"])
    if not endpoints:
        return None, None, None, None
    state = os.urandom(16).hex()
    code_verifier, code_challenge = generate_pkce_pair()
    auth_params = {
        "response_type": "code",
        "client_id": okta_config["oidc_client_id"],
        "redirect_uri": OKTA_OIDC_REDIRECT_URI,
        "scope": OKTA_OIDC_SCOPES,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if force_fresh_login:
        auth_params["prompt"] = "login"
        auth_params["max_age"] = 0
    authorization_url = f"{endpoints['auth']}?{urlencode(auth_params)}"
    logger.info(
        f"Okta OIDC: Generated authorization URL for redirect with PKCE (using {auth_server_type} auth server, force_fresh_login={force_fresh_login})."
    )
    return authorization_url, state, code_verifier, code_challenge


def run_adfs_oidc_flow(adfs_base_url, adfs_env_key, force_fresh_login=True):
    logger.info(f"--- ADFS OIDC Client Test Initiated on {adfs_base_url} ---")
    endpoints = adfs_oidc_get_endpoints(adfs_base_url)
    if not endpoints:
        return None, None, None, None
    state = os.urandom(16).hex()
    client_id = ADFS_OIDC_CONFIGS[adfs_env_key]["client_id"]
    code_verifier, code_challenge = generate_pkce_pair()
    auth_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": ADFS_OIDC_REDIRECT_URI,
        "scope": ADFS_OIDC_SCOPES,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if force_fresh_login:
        auth_params["prompt"] = "login"
        auth_params["max_age"] = 0
    authorization_url = f"{endpoints['auth']}?{urlencode(auth_params)}"
    logger.info(
        f"ADFS OIDC: Generated authorization URL for redirect with PKCE (force_fresh_login={force_fresh_login})."
    )
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
    logger.info(
        f"--- Token Lifetime Check: Okta {environment} ({auth_server_type}) ---"
    )

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
    # For custom: https://host.example.invalid/oauth2/{authServerId}
    # For default: https://host.example.invalid
    if "/oauth2/" in issuer_url:
        auth_server_id = issuer_url.split("/oauth2/")[-1].rstrip("/")
    else:
        # For PROD custom server, the issuer is just the base domain
        auth_server_id = "default"

    # Determine base URL for API calls: the scheme and host of the issuer
    base_url = idp_config.api_base_url(issuer_url)
    if not base_url:
        error_msg = f"Could not determine base URL from issuer: {issuer_url}"
        logger.error(error_msg)
        return {"success": False, "error": error_msg}

    logger.info(f"Using base URL: {base_url}, auth server ID: {auth_server_id}")

    # Step 1: Get policies
    policies_url = f"{base_url}/api/v1/authorizationServers/{auth_server_id}/policies"
    headers = {"Authorization": f"SSWS {api_token}", "Accept": "application/json"}

    try:
        logger.info(f"Fetching policies from: {policies_url}")
        policies_response = _session.get(policies_url, headers=headers, timeout=10)
        policies_response.raise_for_status()
        policies_data = policies_response.json()

        # Check for API errors
        if isinstance(policies_data, dict) and "errorCode" in policies_data:
            error_msg = policies_data.get("errorSummary", "Unknown API error")
            logger.error(f"Okta API Error: {error_msg}")
            return {"success": False, "error": f"Okta API Error: {error_msg}"}

        # Extract first policy ID
        if (
            not policies_data
            or not isinstance(policies_data, list)
            or len(policies_data) == 0
        ):
            error_msg = "No policies found in authorization server"
            logger.error(error_msg)
            return {"success": False, "error": error_msg}

        policy_id = policies_data[0].get("id")
        logger.info(f"Found policy ID: {policy_id}")

        # Step 2: Get policy rules (contains token lifetimes)
        rules_url = f"{base_url}/api/v1/authorizationServers/{auth_server_id}/policies/{policy_id}/rules"
        logger.info(f"Fetching rules from: {rules_url}")
        rules_response = _session.get(rules_url, headers=headers, timeout=10)
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
                    "human_readable": f"{access_hours:.1f} hours",
                },
                "refresh_token": {
                    "minutes": refresh_token_minutes,
                    "human_readable": f"{refresh_days:.1f} days",
                }
                if refresh_token_minutes
                else None,
                "refresh_token_idle": {
                    "minutes": refresh_window_minutes,
                    "human_readable": f"{window_days:.1f} days",
                }
                if refresh_window_minutes
                else None,
            },
        }

        logger.info(
            f"Token lifetime check successful: Access={access_token_minutes}min, Refresh={refresh_token_minutes}min, Idle={refresh_window_minutes}min"
        )
        return result

    except requests.exceptions.HTTPError as e:
        # Check for 401 Unauthorized - likely missing Custom AS SKU
        if e.response.status_code == 401:
            logger.warning(
                f"{environment} token lifetime check failed (401 Unauthorized - likely no Custom AS SKU): {describe_request_error(e)}"
            )
            return {
                "success": False,
                "error": f"Token lifetime checks require Custom Authorization Server SKU. {environment} environment does not have API access to authorization server settings.",
                "is_limitation": True,  # Flag to show as info instead of error
                "environment": environment,
                "assumed_defaults": {
                    "access_token": "60 minutes (1 hour)",
                    "refresh_token": "7776000 minutes (90 days)",
                    "note": "These are standard Okta org server defaults. Contact Okta support for exact settings in this environment.",
                },
            }
        else:
            # The caller is signed in; show the IdP's status and a bounded body.
            logger.error(f"Okta API error: {describe_request_error(e)}")
            return {
                "success": False,
                "error": f"Okta API returned HTTP {e.response.status_code}: {bounded(e.response.text)}",
            }
    except requests.exceptions.RequestException:
        logger.exception("Okta API request failed")
        return {"success": False, "error": "The Okta API could not be reached."}
    except Exception:
        logger.exception("Unexpected error in token lifetime check")
        return {"success": False, "error": GENERIC_ERROR}
