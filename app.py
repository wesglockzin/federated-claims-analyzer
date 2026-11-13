# -----------------------------------------------------------------------------
# Script Name : app.py (Web UI for Federated Identity & Claims Analyzer)
# Description : Provides a Flask-based web interface for running SSO tests
#               against Okta and ADFS.
# Author      : Wes Glockzin
# Version     : 6.0 (Kubernetes Migration: Azure AD OIDC, removed GCP dependencies)
# License     : MIT
# -----------------------------------------------------------------------------

import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

import jwt
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import (
    Flask,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix

import idp_config
from guards import (
    ConfigError,
    UserFacingError,
    bounded,
    check_startup_settings,
    cookie_policy,
    is_allowed,
    is_safe_redirect,
    public_error,
    split_list,
    states_match,
)

APP_DIR = Path(__file__).resolve().parent
# Try to load local env file for development (secrets come from Secret Manager in production)
CONFIG_PATH = APP_DIR / "env.config.DO_NOT_SHARE"
if CONFIG_PATH.exists():
    load_dotenv(dotenv_path=CONFIG_PATH)
else:
    # Fallback for old filename (for backward compatibility during transition)
    CONFIG_PATH = APP_DIR / "env.config"
    if CONFIG_PATH.exists():
        load_dotenv(dotenv_path=CONFIG_PATH)


def env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


FORCE_FRESH_LOGIN_DEFAULT = env_flag("FORCE_FRESH_LOGIN_DEFAULT", True)

# Fail closed: without a session key, the base URL, the login settings and an
# allow-list the app refuses to start, unless AUTH_MODE=none is set explicitly.
# The environment lists (Okta, ADFS, SAML) are checked the same way.
try:
    AUTH_MODE = check_startup_settings(os.environ)
    idp_config.validate(os.environ)
except ConfigError as exc:
    sys.exit(f"FATAL: {exc}")

AUTH_GATE_ENABLED = AUTH_MODE == "oidc"
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "").rstrip("/")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
APP_BASE_URL = os.environ["APP_BASE_URL"].rstrip("/")
OIDC_SCOPES = os.environ.get("OIDC_SCOPES", "openid email profile")
OIDC_GROUPS_CLAIM = os.environ.get("OIDC_GROUPS_CLAIM", "groups")
ALLOWED_EMAILS = split_list(os.environ.get("ALLOWED_EMAILS"))
ALLOWED_GROUPS = split_list(os.environ.get("ALLOWED_GROUPS"))
OIDC_GATE_READY = AUTH_GATE_ENABLED


# These imports read settings at import time, so they must follow the dotenv load.
import sso_tester_logic
from howto_page import register_howto

logger = sso_tester_logic.logger
if not AUTH_GATE_ENABLED:
    logger.warning("AUTH_MODE=none: the app serves every route without a login.")
ADFS_ENVIRONMENTS = sso_tester_logic.ADFS_ENVIRONMENTS
OKTA_ENVIRONMENTS = sso_tester_logic.OKTA_ENVIRONMENTS
UI_CONFIG = idp_config.build_ui_config(
    OKTA_ENVIRONMENTS, ADFS_ENVIRONMENTS, sso_tester_logic.saml_settings.IDP_CONFIGS
)
logger.info(f"App auth gate enabled: {AUTH_GATE_ENABLED}")
logger.info(f"Force fresh login default: {FORCE_FRESH_LOGIN_DEFAULT}")

app = Flask(__name__, template_folder=".", static_folder="static")
app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# --- Configure Secure Cookie Sessions (Stateless) ---
# Uses Flask's built-in signed cookies - no filesystem, Redis, or database needed
# Perfect for Cloud Run: stateless, scales to multiple instances, no shared storage required
app.config["SESSION_PERMANENT"] = False  # Session expires when browser closes
# SAML callbacks come back as cross-site POSTs from the IdP, and Lax would make
# the browser drop the session cookie on them. So over https the cookie is
# SameSite=None; Secure. Browsers reject SameSite=None without Secure, so over
# plain http it is Lax: sign-in works, but SAML callbacks need https. Every
# other POST route carries a CSRF token; the SAML callbacks are signature-checked.
_SAMESITE, _SECURE = cookie_policy(APP_BASE_URL)
app.config["SESSION_COOKIE_SAMESITE"] = _SAMESITE
app.config["SESSION_COOKIE_SECURE"] = _SECURE
app.config["SESSION_COOKIE_HTTPONLY"] = True  # JavaScript can't access (XSS protection)
# Flask will use app.secret_key (set above) to sign session cookies
# ---

# --- Auth-gate OIDC (the tool's own OIDC client: OIDC_CLIENT_ID) ---
# Authlib drives the auth-code+PKCE flow AND validates the id_token.
oauth = OAuth(app)
if OIDC_GATE_READY:
    oauth.register(
        name="okta",
        client_id=OIDC_CLIENT_ID,
        client_secret=OIDC_CLIENT_SECRET,
        server_metadata_url=f"{OIDC_ISSUER}/.well-known/openid-configuration",
        client_kwargs={"scope": OIDC_SCOPES, "code_challenge_method": "S256"},
    )

PUBLIC_PATHS = {
    # Auth gate's own routes
    "/health",
    "/login",
    "/oidc/login",
    "/oidc/callback",
    "/logout",
    # SSO TESTER callbacks — must bypass the auth gate. SAML callbacks come in
    # as cross-site POSTs from the IdP; SameSite=Lax drops the session cookie
    # on those, so the auth gate would 302 to /login and the SAML response
    # would be lost. OIDC GET callbacks are unaffected by SameSite=Lax but are
    # listed here for symmetry. Each callback validates internally
    # (python3-saml signature check; OIDC state token).
    "/okta/saml/callback",
    "/adfs/saml/callback",
    "/okta/oidc/callback",
    "/adfs/oidc/callback",
}


# --- Security Headers ---
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Prevent clickjacking attacks
    response.headers["X-Frame-Options"] = "DENY"

    # Force HTTPS (only in cloud, not local dev with self-signed certs)
    if (
        os.environ.get("K_SERVICE")
        or os.environ.get("KUBERNETES_SERVICE_HOST")
        or os.environ.get("CONTAINER_APP_NAME")
    ):
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    # XSS Protection (legacy header, but still good to have)
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Content Security Policy (restrictive for security)
    # Allow inline styles for Pico CSS and scripts for AJAX
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )

    return response


@app.before_request
def require_login():
    if not AUTH_GATE_ENABLED:
        return
    if request.path.startswith("/static/"):
        return
    if request.path in PUBLIC_PATHS:
        return
    if not session.get("user"):
        # Go straight to the IdP — no intermediate "Sign in with Okta" landing
        # page (fleet-uniform direct redirect). /login is kept for logout landing
        # and auth-error display only.
        return redirect(url_for("oidc_login", next=request.path))


# --- CSRF protection ---
# Every POST carries the session's token as a form field or an X-CSRF-Token
# header. The SAML callbacks are POSTed by the IdP, so they cannot carry it;
# python3-saml checks their signature instead.
CSRF_EXEMPT_PATHS = {"/okta/saml/callback", "/adfs/saml/callback"}


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def require_csrf_token():
    if request.method != "POST" or request.path in CSRF_EXEMPT_PATHS:
        return None
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not states_match(sent, session.get("csrf_token")):
        logger.warning(
            "Rejected a POST to %s: missing or wrong CSRF token", request.path
        )
        return jsonify(success=False, error="Missing or invalid CSRF token."), 400
    return None


def start_flask_dev_server():
    if not os.path.exists(sso_tester_logic.CERT_FILE) or not os.path.exists(
        sso_tester_logic.KEY_FILE
    ):
        logger.error(
            f"SSL files not found! Ensure '{sso_tester_logic.CERT_FILE.name}' and '{sso_tester_logic.KEY_FILE.name}' are present."
        )
        return False
    try:
        logger.info(
            f"Flask App: Starting local HTTPS server on https://localhost:{sso_tester_logic.LISTEN_PORT}..."
        )
        app.run(
            host="127.0.0.1",  # local dev only; the container binds 0.0.0.0 (Dockerfile)
            port=sso_tester_logic.LISTEN_PORT,
            debug=False,
            use_reloader=False,
            ssl_context=(
                str(sso_tester_logic.CERT_FILE),
                str(sso_tester_logic.KEY_FILE),
            ),
        )
        return True
    except OSError as e:
        logger.error(f"Error starting Flask app: {e}")
        return False


def idp_error_text(provider, error):
    """Message for an error the IdP sent back. Its text is shown to signed-in users only."""
    message = f"{provider} returned an error."
    if AUTH_GATE_ENABLED and not session.get("user"):
        return message
    description = request.args.get("error_description", "")
    return f"{message} {bounded(error)} - {bounded(description)}"


def get_full_template_context():
    user = session.get("user")
    user_email = user.get("email") if user else None
    return {
        "app_version": sso_tester_logic.APP_VERSION,
        "environments": UI_CONFIG["environments"],
        "ui_targets": UI_CONFIG["targets"],
        "default_server_envs": UI_CONFIG["default_server_envs"],
        "user_email": user_email,
        "force_fresh_login": FORCE_FRESH_LOGIN_DEFAULT,
        "auth_gate_enabled": AUTH_GATE_ENABLED,
    }


def process_and_split_claims(claims_dict):
    if not claims_dict:
        return {}, {}

    important_claims, detailed_claims = {}, {}
    essential_standard_claims = {
        "email",
        "name",
        "given_name",
        "family_name",
        "preferred_username",
    }
    timestamp_claims = {"iat", "nbf", "exp", "auth_time", "mfa_auth_time"}

    for claim, value in claims_dict.items():
        if claim in timestamp_claims:
            try:
                value = f"{datetime.fromtimestamp(int(value)).strftime('%Y-%m-%d %H:%M:%S')} ({value})"
            except (ValueError, TypeError):
                logger.debug("Claim %s is not a timestamp: %r", claim, value)
        is_custom = claim not in sso_tester_logic.STANDARD_CLAIMS
        is_essential = claim in essential_standard_claims
        if is_custom or is_essential:
            important_claims[claim] = value
        else:
            detailed_claims[claim] = value
    return important_claims, detailed_claims


# In-tool documentation page (/howto), rendered from HOWTO.md via the shared
# howto_page module. Inherits the auth gate from the @before_request hook.
register_howto(app, tool_name="Federated Identity & Claims Analyzer")


@app.route("/")
def index():
    context = get_full_template_context()
    context.update(
        {
            "idp_choice": "okta",
            "protocol_choice": "oidc",
            "selected_env": UI_CONFIG["environments"][0],
            "selected_target_app": "default",
            "auth_server_type": "custom",
        }
    )
    return render_template("index.html", **context)


@app.route("/login")
def login():
    if not AUTH_GATE_ENABLED:
        return redirect(url_for("index"))
    if session.get("user"):
        return redirect(url_for("index"))
    next_url = request.args.get("next")
    if is_safe_redirect(next_url):
        session["post_login_redirect"] = next_url
    context = {
        "app_version": sso_tester_logic.APP_VERSION,
        "login_error": session.pop("login_error", None),
    }
    return render_template("login.html", **context)


@app.route("/health")
def health():
    return jsonify(status="ok", version=sso_tester_logic.APP_VERSION), 200


@app.route("/oidc/login")
def oidc_login():
    if not AUTH_GATE_ENABLED:
        return redirect(url_for("index"))
    next_url = request.args.get("next")
    if is_safe_redirect(next_url):
        session["post_login_redirect"] = next_url
    redirect_uri = url_for("oidc_callback", _external=True)
    return oauth.okta.authorize_redirect(redirect_uri)


@app.route("/oidc/callback")
def oidc_callback():
    if not AUTH_GATE_ENABLED:
        return redirect(url_for("index"))
    if request.args.get("error"):
        logger.warning(
            "Sign-in returned an error: %s: %s",
            bounded(request.args.get("error")),
            bounded(request.args.get("error_description", "")),
        )
        session["login_error"] = "The identity provider returned an error."
        return redirect(url_for("login"))
    try:
        token = oauth.okta.authorize_access_token()
    except Exception:
        logger.exception("OIDC token exchange failed")
        session["login_error"] = "Sign-in failed. The details are in the server log."
        return redirect(url_for("login"))

    claims = token.get("userinfo") or {}
    email = claims.get("email") or claims.get("preferred_username")
    if not email:
        session["login_error"] = "Email claim missing in id_token."
        return redirect(url_for("login"))
    if not is_allowed(claims, ALLOWED_EMAILS, ALLOWED_GROUPS, OIDC_GROUPS_CLAIM):
        logger.warning("Sign-in refused: the account is not on the allow-list")
        session["login_error"] = "Your account is not allowed to use this tool."
        return redirect(url_for("login"))

    session["user"] = {
        "email": email,
        "name": claims.get("name"),
        "idp": "okta",
        "login_time": datetime.now(timezone.utc).isoformat(),
    }
    redirect_to = session.pop("post_login_redirect", None)
    if not is_safe_redirect(redirect_to):
        redirect_to = url_for("index")
    return redirect(redirect_to)


@app.route("/logout")
def logout():
    session.clear()
    if AUTH_GATE_ENABLED:
        return redirect(url_for("login"))
    return redirect(url_for("index"))


@app.route("/run_test", methods=["POST"])
def run_test():
    user = session.get("user")
    session.clear()
    if user:
        session["user"] = user
    environment = request.form.get("environment")  # DEV or PROD
    idp_choice = request.form.get("idp_choice")  # okta or adfs
    protocol_choice = request.form.get("protocol_choice")  # oidc or saml
    target_app = request.form.get("target_app")  # e.g. 'default', 'dev', 'prod', 'cucm'
    auth_server_type = request.form.get(
        "auth_server_type", "custom"
    )  # custom or default
    force_fresh_login = request.form.get("force_fresh_login", "1").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    auth_url = None

    # Store context for UI restoration
    session["ui_context"] = {
        "environment": environment,
        "idp_choice": idp_choice,
        "protocol_choice": protocol_choice,
        "target_app": target_app,
        "auth_server_type": auth_server_type,
        "force_fresh_login": force_fresh_login,
    }

    if protocol_choice == "oidc":
        state, code_verifier, code_challenge = None, None, None

        # OIDC Logic uses the Environment variable directly
        env_key = environment

        if idp_choice == "okta":
            env_config = OKTA_ENVIRONMENTS.get(env_key)
            if env_config:
                # Get the specific auth server config (custom or default)
                okta_config = env_config.get(auth_server_type, env_config.get("custom"))
                session["okta_env_key"] = env_key
                session["auth_server_type"] = auth_server_type
                auth_url, state, code_verifier, code_challenge = (
                    sso_tester_logic.run_okta_oidc_flow(
                        okta_config,
                        auth_server_type,
                        force_fresh_login=force_fresh_login,
                    )
                )
        elif idp_choice == "adfs":
            adfs_base_url = ADFS_ENVIRONMENTS.get(env_key)
            if adfs_base_url:
                session["adfs_env_key"] = env_key
                session["adfs_issuer"] = adfs_base_url
                auth_url, state, code_verifier, code_challenge = (
                    sso_tester_logic.run_adfs_oidc_flow(
                        adfs_base_url, env_key, force_fresh_login=force_fresh_login
                    )
                )

        if state:
            session["oauth_state"] = state
            session["code_verifier"] = code_verifier
            session["code_challenge"] = code_challenge

    else:  # SAML Flow
        # Construct the idp_key expected by saml_settings.py
        # Format: {idp}_{app_value} (e.g., okta_dev, okta_prod, okta_cucm)
        idp_key = f"{idp_choice}_{target_app}"

        # Determine the user-friendly app name for the session
        session["saml_app_selection"] = target_app
        session["saml_idp_key"] = idp_key

        try:
            auth_url = sso_tester_logic.run_sp_initiated_saml_flow(
                request, idp_key, force_fresh_login=force_fresh_login
            )
        except Exception:
            logger.exception("Error generating SAML request for %s", idp_key)
            auth_url = None

    if auth_url:
        response = make_response(redirect(auth_url))
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    else:
        context = get_full_template_context()
        context.update(
            {
                "message": "Failed to generate auth URL.",
                "color": "#dc3545",
                "selected_env": environment,
                "idp_choice": idp_choice,
                "protocol_choice": protocol_choice,
                "selected_target_app": target_app,
                "auth_server_type": auth_server_type,
                "force_fresh_login": force_fresh_login,
            }
        )
        return render_template("index.html", **context)


@app.route("/check_token_lifetimes", methods=["POST"])
def check_token_lifetimes():
    """
    Endpoint to check Okta token lifetime settings without performing SSO.
    Returns JSON with token lifetime data.
    """
    user = session.get("user")
    if not user:
        return jsonify({"success": False, "error": "Not authenticated"}), 401

    environment = request.form.get("environment")  # DEV or PROD
    idp_choice = request.form.get("idp_choice")  # okta or adfs
    auth_server_type = request.form.get(
        "auth_server_type", "custom"
    )  # custom or default

    # Only support Okta for token lifetime checks
    if idp_choice != "okta":
        return jsonify(
            {
                "success": False,
                "error": "Token lifetime checks are only supported for Okta",
            }
        )

    if not environment:
        return jsonify({"success": False, "error": "Environment parameter is required"})

    # Call the token lifetime check function
    result = sso_tester_logic.okta_check_token_lifetimes(environment, auth_server_type)

    return jsonify(result)


@app.route("/okta/saml/callback", methods=["POST"])
def okta_saml_callback():
    webpage_message, webpage_color, saml_error = "", "", None
    result_data = {"saml_imp_claims": {}, "saml_det_claims": {}, "raw_saml_xml": None}
    test_timestamp = (
        datetime.now(timezone.utc).astimezone().strftime("%b %d %Y, %I:%M:%S %p %Z")
    )
    idp_key = session.get("saml_idp_key")

    try:
        if not idp_key:
            raise UserFacingError(
                "SAML context not found in session. Session may have expired or cookie was blocked by the browser."
            )
        saml_data = sso_tester_logic.process_saml_response(request, idp_key)
        result_data["raw_saml_xml"] = saml_data.get("raw_xml")
        imp, det = process_and_split_claims(saml_data.get("claims"))
        result_data["saml_imp_claims"], result_data["saml_det_claims"] = imp, det
        webpage_message, webpage_color = (
            "✅ Okta SAML Flow Completed! Signature Validated.",
            "#28a745",
        )
    except Exception as e:
        logger.exception("Okta SAML Callback Error")
        webpage_message, webpage_color, saml_error = (
            "❌ Okta SAML Error!",
            "#dc3545",
            public_error(e),
        )
    finally:
        session["last_result"] = result_data
        context = get_full_template_context()
        ui = session.get("ui_context", {})
        context.update(
            {
                "message": webpage_message,
                "color": webpage_color,
                "saml_error": saml_error,
                **result_data,
                "idp_choice": "okta",
                "protocol_choice": "saml",
                "selected_env": ui.get("environment"),
                "selected_target_app": ui.get("target_app"),
                "auth_server_type": ui.get("auth_server_type", "custom"),
                "force_fresh_login": ui.get(
                    "force_fresh_login", FORCE_FRESH_LOGIN_DEFAULT
                ),
                "test_timestamp": test_timestamp,
            }
        )
    return render_template("index.html", **context)


@app.route("/adfs/saml/callback", methods=["POST"])
def adfs_saml_callback():
    webpage_message, webpage_color, saml_error = "", "", None
    result_data = {"saml_imp_claims": {}, "saml_det_claims": {}, "raw_saml_xml": None}
    test_timestamp = (
        datetime.now(timezone.utc).astimezone().strftime("%b %d %Y, %I:%M:%S %p %Z")
    )
    idp_key = session.get("saml_idp_key")

    try:
        if not idp_key:
            raise UserFacingError(
                "SAML context not found in session. Session may have expired or cookie was blocked by the browser."
            )
        saml_data = sso_tester_logic.process_saml_response(request, idp_key)
        result_data["raw_saml_xml"] = saml_data.get("raw_xml")
        imp, det = process_and_split_claims(saml_data.get("claims"))
        result_data["saml_imp_claims"], result_data["saml_det_claims"] = imp, det
        webpage_message, webpage_color = (
            "✅ ADFS SAML Flow Completed! Signature Validated.",
            "#28a745",
        )
    except Exception as e:
        logger.exception("ADFS SAML Callback Error")
        webpage_message, webpage_color, saml_error = (
            "❌ ADFS SAML Error!",
            "#dc3545",
            public_error(e),
        )
    finally:
        session["last_result"] = result_data
        context = get_full_template_context()
        ui = session.get("ui_context", {})
        context.update(
            {
                "message": webpage_message,
                "color": webpage_color,
                "saml_error": saml_error,
                **result_data,
                "idp_choice": "adfs",
                "protocol_choice": "saml",
                "selected_env": ui.get("environment"),
                "selected_target_app": ui.get("target_app"),
                "auth_server_type": ui.get("auth_server_type", "custom"),
                "force_fresh_login": ui.get(
                    "force_fresh_login", FORCE_FRESH_LOGIN_DEFAULT
                ),
                "test_timestamp": test_timestamp,
            }
        )
    return render_template("index.html", **context)


@app.route("/okta/oidc/callback")
def okta_oidc_callback():
    webpage_message, webpage_color, oidc_error = "", "", None
    result_data = {
        "oidc_imp_claims": {},
        "oidc_det_claims": {},
        "access_imp_claims": {},
        "access_det_claims": {},
        "userinfo_imp_claims": {},
        "userinfo_det_claims": {},
        "raw_id_token": None,
        "raw_access_token": None,
        "raw_refresh_token": None,
    }
    test_timestamp = (
        datetime.now(timezone.utc).astimezone().strftime("%b %d %Y, %I:%M:%S %p %Z")
    )
    selected_env = session.get("okta_env_key")
    auth_server_type = session.get("auth_server_type", "custom")

    # Get the nested config
    env_config = OKTA_ENVIRONMENTS.get(selected_env)
    okta_config = (
        env_config.get(auth_server_type, env_config.get("custom"))
        if env_config
        else None
    )

    try:
        if not states_match(
            request.args.get("state"), session.pop("oauth_state", None)
        ):
            raise UserFacingError("Invalid state parameter.")
        if not okta_config:
            raise UserFacingError("Okta context not found in session.")
        code, error = request.args.get("code"), request.args.get("error")
        if error:
            raise UserFacingError(idp_error_text("Okta", error))
        if not code:
            raise UserFacingError("No authorization code received.")

        # Re-discover endpoints in this worker (multi-worker safety)
        if not sso_tester_logic.okta_oidc_get_endpoints(okta_config["oidc_issuer_url"]):
            raise UserFacingError("Failed to discover Okta OIDC endpoints")

        tokens = sso_tester_logic.okta_oidc_exchange_code_for_tokens(
            code, okta_config, session.get("code_verifier")
        )
        if not tokens:
            raise UserFacingError("Token exchange failed.")

        result_data.update(
            {
                "raw_id_token": tokens.get("id_token"),
                "raw_access_token": tokens.get("access_token"),
                "raw_refresh_token": tokens.get("refresh_token"),
                "code_verifier": session.get("code_verifier"),
                "code_challenge": session.get("code_challenge"),
            }
        )
        if tokens.get("refresh_token"):
            session["refresh_token"] = tokens.get("refresh_token")
            session["idp_context_for_refresh"] = {
                "idp": "okta",
                "env": selected_env,
                "auth_server_type": auth_server_type,
            }
        if result_data["raw_id_token"]:
            imp, det = process_and_split_claims(
                sso_tester_logic.okta_oidc_validate_id_token(
                    result_data["raw_id_token"], okta_config
                )
            )
            result_data["oidc_imp_claims"], result_data["oidc_det_claims"] = imp, det
        if result_data["raw_access_token"]:
            imp, det = process_and_split_claims(
                sso_tester_logic.okta_oidc_validate_access_token(
                    result_data["raw_access_token"], okta_config
                )
            )
            result_data["access_imp_claims"], result_data["access_det_claims"] = (
                imp,
                det,
            )
            imp, det = process_and_split_claims(
                sso_tester_logic.okta_oidc_get_userinfo_claims(
                    result_data["raw_access_token"], okta_config
                )
            )
            result_data["userinfo_imp_claims"], result_data["userinfo_det_claims"] = (
                imp,
                det,
            )

        webpage_message, webpage_color = "✅ Okta OIDC Flow Completed!", "#28a745"
    except Exception as e:
        logger.exception("Okta OIDC Callback Error")
        webpage_message, webpage_color, oidc_error = (
            "❌ Okta OIDC Error!",
            "#dc3545",
            public_error(e),
        )
    finally:
        session["last_result"] = result_data
        context = get_full_template_context()
        ui = session.get("ui_context", {})
        context.update(
            {
                "message": webpage_message,
                "color": webpage_color,
                "oidc_error": oidc_error,
                **result_data,
                "idp_choice": "okta",
                "protocol_choice": "oidc",
                "selected_env": ui.get("environment"),
                "selected_target_app": ui.get("target_app"),
                "auth_server_type": ui.get("auth_server_type", "custom"),
                "force_fresh_login": ui.get(
                    "force_fresh_login", FORCE_FRESH_LOGIN_DEFAULT
                ),
                "test_timestamp": test_timestamp,
            }
        )
    return render_template("index.html", **context)


@app.route("/adfs/oidc/callback")
def adfs_oidc_callback():
    webpage_message, webpage_color, oidc_error = "", "", None
    result_data = {
        "oidc_imp_claims": {},
        "oidc_det_claims": {},
        "access_imp_claims": {},
        "access_det_claims": {},
        "userinfo_imp_claims": {},
        "userinfo_det_claims": {},
        "raw_id_token": None,
        "raw_access_token": None,
        "raw_refresh_token": None,
    }
    test_timestamp = (
        datetime.now(timezone.utc).astimezone().strftime("%b %d %Y, %I:%M:%S %p %Z")
    )
    try:
        if not states_match(
            request.args.get("state"), session.pop("oauth_state", None)
        ):
            raise UserFacingError("Invalid state parameter.")
        code, error = request.args.get("code"), request.args.get("error")
        if error:
            raise UserFacingError(idp_error_text("ADFS", error))
        if not code:
            raise UserFacingError("No authorization code received.")
        adfs_env_key = session.get("adfs_env_key")
        adfs_issuer = session.get("adfs_issuer")
        if not adfs_env_key or not adfs_issuer:
            raise UserFacingError("ADFS context not found in session.")

        # Re-discover endpoints in this worker (multi-worker safety)
        if not sso_tester_logic.adfs_oidc_get_endpoints(adfs_issuer):
            raise UserFacingError("Failed to discover ADFS OIDC endpoints")

        tokens = sso_tester_logic.adfs_oidc_exchange_code_for_tokens(
            code, adfs_env_key, session.get("code_verifier")
        )
        if not tokens:
            raise UserFacingError("Token exchange failed.")

        result_data.update(
            {
                "raw_id_token": tokens.get("id_token"),
                "raw_access_token": tokens.get("access_token"),
                "raw_refresh_token": tokens.get("refresh_token"),
                "code_verifier": session.get("code_verifier"),
                "code_challenge": session.get("code_challenge"),
            }
        )
        if tokens.get("refresh_token"):
            session["refresh_token"] = tokens.get("refresh_token")
            session["idp_context_for_refresh"] = {"idp": "adfs", "env": adfs_env_key}

        if result_data["raw_id_token"]:
            imp, det = process_and_split_claims(
                sso_tester_logic.adfs_oidc_validate_id_token(
                    result_data["raw_id_token"], adfs_issuer, adfs_env_key
                )
            )
            result_data["oidc_imp_claims"], result_data["oidc_det_claims"] = imp, det
        if result_data["raw_access_token"]:
            try:
                imp, det = process_and_split_claims(
                    jwt.decode(
                        result_data["raw_access_token"],
                        options={"verify_signature": False},
                    )
                )
                result_data["access_imp_claims"], result_data["access_det_claims"] = (
                    imp,
                    det,
                )
            except jwt.PyJWTError:
                logger.info("ADFS Access Token is not a JWT.")
                result_data["access_imp_claims"] = {"token_type": "Opaque or non-JWT"}
            imp, det = process_and_split_claims(
                sso_tester_logic.adfs_oidc_get_userinfo_claims(
                    result_data["raw_access_token"], adfs_issuer
                )
            )
            result_data["userinfo_imp_claims"], result_data["userinfo_det_claims"] = (
                imp,
                det,
            )

        webpage_message, webpage_color = "✅ ADFS OIDC Flow Completed!", "#28a745"
    except Exception as e:
        logger.exception("ADFS OIDC Callback Error")
        webpage_message, webpage_color, oidc_error = (
            "❌ ADFS OIDC Error!",
            "#dc3545",
            public_error(e),
        )
    finally:
        session["last_result"] = result_data
        context = get_full_template_context()
        ui = session.get("ui_context", {})
        context.update(
            {
                "message": webpage_message,
                "color": webpage_color,
                "oidc_error": oidc_error,
                **result_data,
                "idp_choice": "adfs",
                "protocol_choice": "oidc",
                "selected_env": ui.get("environment"),
                "selected_target_app": ui.get("target_app"),
                "auth_server_type": ui.get("auth_server_type", "custom"),
                "force_fresh_login": ui.get(
                    "force_fresh_login", FORCE_FRESH_LOGIN_DEFAULT
                ),
                "test_timestamp": test_timestamp,
            }
        )
    return render_template("index.html", **context)


@app.route("/refresh_token", methods=["POST"])
def refresh_token():
    logger.info("--- OIDC Token Refresh Test Initiated ---")
    refresh_token_val = session.get("refresh_token")
    idp_context = session.get("idp_context_for_refresh")
    original_result_data = session.get("last_result", {})

    webpage_message, webpage_color, refresh_error, refresh_result_data = (
        "",
        "",
        None,
        {},
    )
    test_timestamp = (
        datetime.now(timezone.utc).astimezone().strftime("%b %d %Y, %I:%M:%S %p %Z")
    )

    try:
        if not refresh_token_val or not idp_context:
            raise UserFacingError("Refresh token or IdP context not found in session.")

        refresh_response = sso_tester_logic.oidc_perform_token_refresh(
            refresh_token_val,
            idp_context["idp"],
            idp_context["env"],
            idp_context.get("auth_server_type", "custom"),
        )

        if refresh_response.get("error"):
            raise UserFacingError(
                "IdP Error: "
                + bounded(
                    refresh_response.get("error_description")
                    or refresh_response.get("error")
                )
            )

        webpage_message, webpage_color = "✅ Token Refresh Successful!", "#28a745"
        refresh_result_data["refreshed_access_token"] = refresh_response.get(
            "access_token"
        )
        refresh_result_data["refreshed_id_token"] = refresh_response.get("id_token")

    except Exception as e:
        logger.exception("Token Refresh Error")
        webpage_message, webpage_color, refresh_error = (
            "❌ Token Refresh Failed!",
            "#dc3545",
            public_error(e),
        )

    finally:
        context = get_full_template_context()
        context.update(original_result_data)
        ui = session.get("ui_context", {})
        context.update(
            {
                "message": webpage_message,
                "color": webpage_color,
                "refresh_error": refresh_error,
                "idp_choice": idp_context.get("idp") if idp_context else "okta",
                "protocol_choice": "oidc",
                "selected_env": ui.get("environment")
                if ui
                else UI_CONFIG["environments"][0],
                "selected_target_app": ui.get("target_app") if ui else "default",
                "auth_server_type": ui.get("auth_server_type", "custom"),
                "force_fresh_login": ui.get(
                    "force_fresh_login", FORCE_FRESH_LOGIN_DEFAULT
                ),
                "test_timestamp": test_timestamp,
            }
        )
        context.update(refresh_result_data)
        # The template reads these even when no earlier test result is stored.
        context.setdefault("oidc_imp_claims", {})
        context.setdefault("oidc_det_claims", {})
    return render_template("index.html", **context)


if __name__ == "__main__":
    logger.info("--- Starting Federated Identity & Claims Analyzer Web UI ---")
    if not start_flask_dev_server():
        sys.exit(1)
