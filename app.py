#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Script Name : app.py (Web UI for Federated Identity & Claims Analyzer)
# Description : Provides a Flask-based web interface for running SSO tests
#               against Okta and ADFS.
# Author      : Wes Glockzin
# Version     : 6.0 (Kubernetes Migration: Azure AD OIDC, removed GCP dependencies)
# License     : MIT
# -----------------------------------------------------------------------------

import os
import sys
from flask import Flask, render_template, request, redirect, url_for, make_response, session, jsonify
import logging
from pathlib import Path
from jose.exceptions import JWTError
from datetime import datetime, timezone
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix

APP_DIR = Path(__file__).resolve().parent
# Try to load local env file for development (secrets come from Secret Manager in production)
CONFIG_PATH = APP_DIR / 'env.config.DO_NOT_SHARE'
if CONFIG_PATH.exists():
    load_dotenv(dotenv_path=CONFIG_PATH)
else:
    # Fallback for old filename (for backward compatibility during transition)
    CONFIG_PATH = APP_DIR / 'env.config'
    if CONFIG_PATH.exists():
        load_dotenv(dotenv_path=CONFIG_PATH)

def env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


AUTH_GATE_ENABLED = env_flag("APP_AUTH_GATE_ENABLED", True)
FORCE_FRESH_LOGIN_DEFAULT = env_flag("FORCE_FRESH_LOGIN_DEFAULT", True)

REQUIRED_SECRETS = [
    "OKTA_DEV_OIDC_SECRET",
    "ADFS_DEV_CLIENT_SECRET",
    "ADFS_PROD_CLIENT_SECRET",
    "FLASK_SECRET_KEY"
]
if AUTH_GATE_ENABLED:
    REQUIRED_SECRETS.extend([
        "AZURE_OIDC_CLIENT_ID",
        "AZURE_OIDC_CLIENT_SECRET",
        "AZURE_OIDC_TENANT_ID"
    ])
# Optional checks for STG and PROD secrets
if "OKTA_STG_OIDC_SECRET" not in os.environ:
    print("⚠️  WARNING: OKTA_STG_OIDC_SECRET is missing. Staging Okta OIDC tests will fail.")
if "OKTA_PROD_OIDC_SECRET" not in os.environ:
    print("⚠️  WARNING: OKTA_PROD_OIDC_SECRET is missing. Production Okta OIDC tests will fail.")

missing_secrets = [secret for secret in REQUIRED_SECRETS if secret not in os.environ]
if missing_secrets:
    print(f"❌ FATAL ERROR: The following required environment variables are not set: {', '.join(missing_secrets)}")
    print(f"Please ensure secrets are configured in Kubernetes or env.config file is in the '{APP_DIR}' directory.")
    sys.exit(1)


sys.path.append(str(Path(__file__).resolve().parent))
import sso_tester_logic

logger = sso_tester_logic.logger
ADFS_ENVIRONMENTS = sso_tester_logic.ADFS_ENVIRONMENTS
OKTA_ENVIRONMENTS = sso_tester_logic.OKTA_ENVIRONMENTS
logger.info(f"App auth gate enabled: {AUTH_GATE_ENABLED}")
logger.info(f"Force fresh login default: {FORCE_FRESH_LOGIN_DEFAULT}")

app = Flask(__name__, template_folder='.', static_folder='static')
app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# --- Configure Secure Cookie Sessions (Stateless) ---
# Uses Flask's built-in signed cookies - no filesystem, Redis, or database needed
# Perfect for Cloud Run: stateless, scales to multiple instances, no shared storage required
app.config["SESSION_PERMANENT"] = False  # Session expires when browser closes
app.config["SESSION_COOKIE_SAMESITE"] = "None"  # Required for cross-site OAuth callbacks
app.config["SESSION_COOKIE_SECURE"] = True  # HTTPS only
app.config["SESSION_COOKIE_HTTPONLY"] = True  # JavaScript can't access (XSS protection)
# Flask will use app.secret_key (set above) to sign session cookies
# ---

PUBLIC_PATHS = {"/login", "/azure/oidc/login", "/azure/oidc/callback", "/logout"}

# --- Security Headers ---
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Prevent clickjacking attacks
    response.headers['X-Frame-Options'] = 'DENY'

    # Force HTTPS (only in cloud, not local dev with self-signed certs)
    if os.environ.get('K_SERVICE') or os.environ.get('KUBERNETES_SERVICE_HOST') or os.environ.get('CONTAINER_APP_NAME'):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # XSS Protection (legacy header, but still good to have)
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Content Security Policy (restrictive for security)
    # Allow inline styles for Pico CSS and scripts for AJAX
    response.headers['Content-Security-Policy'] = (
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
        return redirect(url_for("login", next=request.path))

def start_flask_dev_server():
    if not os.path.exists(sso_tester_logic.CERT_FILE) or not os.path.exists(sso_tester_logic.KEY_FILE):
        logger.error(f"SSL files not found! Ensure '{sso_tester_logic.CERT_FILE.name}' and '{sso_tester_logic.KEY_FILE.name}' are present.")
        return False
    cucm_cert_path = sso_tester_logic.SCRIPT_DIR / 'saml_tester_cucm.cert'
    cucm_key_path = sso_tester_logic.SCRIPT_DIR / 'saml_tester_cucm.key'
    if not os.path.exists(cucm_cert_path) or not os.path.exists(cucm_key_path):
        logger.warning(f"CUCM SAML certs not found! Expected files: {cucm_cert_path.name} and {cucm_key_path.name}. CUCM SAML tests will fail.")
        
    try:
        logger.info(f"Flask App: Starting local HTTPS server on https://localhost:{sso_tester_logic.LISTEN_PORT}...")
        app.run(port=sso_tester_logic.LISTEN_PORT, debug=False, use_reloader=False, ssl_context=(str(sso_tester_logic.CERT_FILE), str(sso_tester_logic.KEY_FILE)))
        return True
    except OSError as e:
        logger.error(f"Error starting Flask app: {e}")
        return False

def get_full_template_context():
    user = session.get('user')
    user_email = user.get('email') if user else None
    return {
        'app_version': sso_tester_logic.APP_VERSION,
        'okta_environments': sso_tester_logic.OKTA_ENVIRONMENTS,
        'adfs_environments': sso_tester_logic.ADFS_ENVIRONMENTS,
        'user_email': user_email,
        'force_fresh_login': FORCE_FRESH_LOGIN_DEFAULT,
        'auth_gate_enabled': AUTH_GATE_ENABLED,
    }

def process_and_split_claims(claims_dict):
    if not claims_dict:
        return {}, {}
    
    important_claims, detailed_claims = {}, {}
    essential_standard_claims = {'email', 'name', 'given_name', 'family_name', 'preferred_username'}
    timestamp_claims = {'iat', 'nbf', 'exp', 'auth_time', 'mfa_auth_time'}

    for claim, value in claims_dict.items():
        if claim in timestamp_claims:
            try:
                value = f"{datetime.fromtimestamp(int(value)).strftime('%Y-%m-%d %H:%M:%S')} ({value})"
            except (ValueError, TypeError): pass 
        is_custom = claim not in sso_tester_logic.STANDARD_CLAIMS
        is_essential = claim in essential_standard_claims
        if is_custom or is_essential:
            important_claims[claim] = value
        else:
            detailed_claims[claim] = value
    return important_claims, detailed_claims

@app.route("/")
def index():
    context = get_full_template_context()
    context.update({ 'idp_choice': 'okta', 'protocol_choice': 'oidc', 'selected_env': 'DEV', 'selected_target_app': 'default', 'auth_server_type': 'custom' })
    return render_template('index.html', **context)

@app.route("/login")
def login():
    if not AUTH_GATE_ENABLED:
        return redirect(url_for("index"))
    if session.get("user"):
        return redirect(url_for("index"))
    next_url = request.args.get("next")
    if next_url:
        session["post_login_redirect"] = next_url
    context = {
        "app_version": sso_tester_logic.APP_VERSION,
        "login_error": session.pop("login_error", None)
    }
    return render_template("login.html", **context)

@app.route("/azure/oidc/login")
def azure_oidc_login():
    if not AUTH_GATE_ENABLED:
        return redirect(url_for("index"))
    auth_url, state, code_verifier, code_challenge = sso_tester_logic.run_azure_oidc_flow()
    if not auth_url:
        session["login_error"] = "Azure AD OIDC discovery failed. Check network access and configuration."
        return redirect(url_for("login"))
    session["azure_oauth_state"] = state
    session["azure_code_verifier"] = code_verifier
    session["azure_code_challenge"] = code_challenge
    return redirect(auth_url)

@app.route("/azure/oidc/callback")
def azure_oidc_callback():
    if not AUTH_GATE_ENABLED:
        return redirect(url_for("index"))
    error = request.args.get("error")
    error_description = request.args.get("error_description", "")
    if error:
        session["login_error"] = f"Azure AD login failed: {error} - {error_description}"
        return redirect(url_for("login"))

    if request.args.get("state") != session.pop("azure_oauth_state", None):
        session["login_error"] = "Invalid state parameter."
        return redirect(url_for("login"))

    code = request.args.get("code")
    if not code:
        session["login_error"] = "No authorization code received."
        return redirect(url_for("login"))

    tokens = sso_tester_logic.azure_oidc_exchange_code_for_tokens(code, session.get("azure_code_verifier"))
    if not tokens or not tokens.get("id_token"):
        session["login_error"] = "Token exchange failed."
        return redirect(url_for("login"))

    claims = sso_tester_logic.azure_oidc_validate_id_token(tokens.get("id_token"))
    if not claims:
        session["login_error"] = "ID token validation failed."
        return redirect(url_for("login"))

    # Azure AD uses 'preferred_username' or 'email' for the email claim
    email = claims.get("email") or claims.get("preferred_username")
    if not email:
        session["login_error"] = "Email claim missing in ID token."
        return redirect(url_for("login"))

    # No allowlist check - all authenticated Azure AD users in the tenant are allowed
    session["user"] = {
        "email": email,
        "name": claims.get("name"),
        "idp": "azure_ad",
        "login_time": datetime.now(timezone.utc).isoformat()
    }
    redirect_to = session.pop("post_login_redirect", None) or url_for("index")
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
    environment = request.form.get("environment") # DEV or PROD
    idp_choice = request.form.get("idp_choice")   # okta or adfs
    protocol_choice = request.form.get("protocol_choice") # oidc or saml
    target_app = request.form.get("target_app") # e.g. 'default', 'dev', 'prod', 'cucm'
    auth_server_type = request.form.get("auth_server_type", "custom") # custom or default
    force_fresh_login = request.form.get("force_fresh_login", "1").lower() in {"1", "true", "yes", "on"}
    
    auth_url = None
    
    # Store context for UI restoration
    session['ui_context'] = {
        'environment': environment,
        'idp_choice': idp_choice,
        'protocol_choice': protocol_choice,
        'target_app': target_app,
        'auth_server_type': auth_server_type,
        'force_fresh_login': force_fresh_login
    }

    if protocol_choice == 'oidc':
        state, code_verifier, code_challenge = None, None, None
        
        # OIDC Logic uses the Environment variable directly
        env_key = environment 
        
        if idp_choice == 'okta':
            env_config = OKTA_ENVIRONMENTS.get(env_key)
            if env_config:
                # Get the specific auth server config (custom or default)
                okta_config = env_config.get(auth_server_type, env_config.get("custom"))
                session['okta_env_key'] = env_key
                session['auth_server_type'] = auth_server_type
                auth_url, state, code_verifier, code_challenge = sso_tester_logic.run_okta_oidc_flow(okta_config, auth_server_type, force_fresh_login=force_fresh_login)
        elif idp_choice == 'adfs':
            adfs_base_url = ADFS_ENVIRONMENTS.get(env_key)
            if adfs_base_url:
                session['adfs_env_key'] = env_key
                session['adfs_issuer'] = adfs_base_url
                auth_url, state, code_verifier, code_challenge = sso_tester_logic.run_adfs_oidc_flow(adfs_base_url, env_key, force_fresh_login=force_fresh_login)
        
        if state:
            session['oauth_state'] = state
            session['code_verifier'] = code_verifier
            session['code_challenge'] = code_challenge
    
    else: # SAML Flow
        # Construct the idp_key expected by saml_settings.py
        # Format: {idp}_{app_value} (e.g., okta_dev, okta_prod, okta_cucm)
        idp_key = f"{idp_choice}_{target_app}"
        
        # Determine the user-friendly app name for the session
        session['saml_app_selection'] = target_app
        session['saml_idp_key'] = idp_key
        
        try:
            auth_url = sso_tester_logic.run_sp_initiated_saml_flow(request, idp_key, force_fresh_login=force_fresh_login)
        except Exception as e:
            logger.error(f"Error generating SAML request for {idp_key}: {e}")
            auth_url = None

    if auth_url:
        response = make_response(redirect(auth_url))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    else:
        context = get_full_template_context()
        context.update({'message': 'Failed to generate auth URL.', 'color': '#dc3545', 'selected_env': environment, 'idp_choice': idp_choice, 'protocol_choice': protocol_choice, 'selected_target_app': target_app, 'auth_server_type': auth_server_type, 'force_fresh_login': force_fresh_login})
        return render_template('index.html', **context)

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
    idp_choice = request.form.get("idp_choice")    # okta or adfs
    auth_server_type = request.form.get("auth_server_type", "custom")  # custom or default

    # Only support Okta for token lifetime checks
    if idp_choice != "okta":
        return jsonify({
            "success": False,
            "error": "Token lifetime checks are only supported for Okta"
        })

    if not environment:
        return jsonify({
            "success": False,
            "error": "Environment parameter is required"
        })

    # Call the token lifetime check function
    result = sso_tester_logic.okta_check_token_lifetimes(environment, auth_server_type)

    return jsonify(result)

@app.route("/okta/saml/callback", methods=['POST'])
def okta_saml_callback():
    webpage_message, webpage_color, saml_error = "", "", None
    result_data = { 'saml_imp_claims': {}, 'saml_det_claims': {}, 'raw_saml_xml': None }
    test_timestamp = datetime.now(timezone.utc).astimezone().strftime('%b %d %Y, %I:%M:%S %p %Z')
    idp_key = session.get('saml_idp_key')
    
    try:
        if not idp_key: raise RuntimeError("SAML context not found in session. Session may have expired or cookie was blocked by the browser.")
        saml_data = sso_tester_logic.process_saml_response(request, idp_key)
        result_data['raw_saml_xml'] = saml_data.get("raw_xml")
        imp, det = process_and_split_claims(saml_data.get("claims"))
        result_data['saml_imp_claims'], result_data['saml_det_claims'] = imp, det
        webpage_message, webpage_color = "✅ Okta SAML Flow Completed! Signature Validated.", "#28a745"
    except Exception as e:
        logger.error(f"Okta SAML Callback Error: {e}", exc_info=True)
        webpage_message, webpage_color, saml_error = "❌ Okta SAML Error!", "#dc3545", str(e)
    finally:
        session['last_result'] = result_data
        context = get_full_template_context()
        ui = session.get('ui_context', {})
        context.update({'message': webpage_message, 'color': webpage_color, 'saml_error': saml_error, **result_data, 'idp_choice': 'okta', 'protocol_choice': 'saml', 'selected_env': ui.get('environment'), 'selected_target_app': ui.get('target_app'), 'auth_server_type': ui.get('auth_server_type', 'custom'), 'force_fresh_login': ui.get('force_fresh_login', FORCE_FRESH_LOGIN_DEFAULT), 'test_timestamp': test_timestamp})
    return render_template('index.html', **context)

@app.route("/adfs/saml/callback", methods=['POST'])
def adfs_saml_callback():
    webpage_message, webpage_color, saml_error = "", "", None
    result_data = { 'saml_imp_claims': {}, 'saml_det_claims': {}, 'raw_saml_xml': None }
    test_timestamp = datetime.now(timezone.utc).astimezone().strftime('%b %d %Y, %I:%M:%S %p %Z')
    idp_key = session.get('saml_idp_key')
    
    try:
        if not idp_key: raise RuntimeError("SAML context not found in session. Session may have expired or cookie was blocked by the browser.")
        saml_data = sso_tester_logic.process_saml_response(request, idp_key)
        result_data['raw_saml_xml'] = saml_data.get("raw_xml")
        imp, det = process_and_split_claims(saml_data.get("claims"))
        result_data['saml_imp_claims'], result_data['saml_det_claims'] = imp, det
        webpage_message, webpage_color = "✅ ADFS SAML Flow Completed! Signature Validated.", "#28a745"
    except Exception as e:
        logger.error(f"ADFS SAML Callback Error: {e}", exc_info=True)
        webpage_message, webpage_color, saml_error = "❌ ADFS SAML Error!", "#dc3545", str(e)
    finally:
        session['last_result'] = result_data
        context = get_full_template_context()
        ui = session.get('ui_context', {})
        context.update({'message': webpage_message, 'color': webpage_color, 'saml_error': saml_error, **result_data, 'idp_choice': 'adfs', 'protocol_choice': 'saml', 'selected_env': ui.get('environment'), 'selected_target_app': ui.get('target_app'), 'auth_server_type': ui.get('auth_server_type', 'custom'), 'force_fresh_login': ui.get('force_fresh_login', FORCE_FRESH_LOGIN_DEFAULT), 'test_timestamp': test_timestamp})
    return render_template('index.html', **context)

@app.route("/okta/oidc/callback")
def okta_oidc_callback():
    webpage_message, webpage_color, oidc_error = "", "", None
    result_data = { 'oidc_imp_claims': {}, 'oidc_det_claims': {}, 'access_imp_claims': {}, 'access_det_claims': {}, 'userinfo_imp_claims': {}, 'userinfo_det_claims': {}, 'raw_id_token': None, 'raw_access_token': None, 'raw_refresh_token': None }
    test_timestamp = datetime.now(timezone.utc).astimezone().strftime('%b %d %Y, %I:%M:%S %p %Z')
    selected_env = session.get('okta_env_key')
    auth_server_type = session.get('auth_server_type', 'custom')
    
    # Get the nested config
    env_config = OKTA_ENVIRONMENTS.get(selected_env)
    okta_config = env_config.get(auth_server_type, env_config.get("custom")) if env_config else None
    
    try:
        if request.args.get('state') != session.pop('oauth_state', None): raise RuntimeError("Invalid state parameter.")
        if not okta_config: raise RuntimeError("Okta context not found in session.")
        code, error = request.args.get("code"), request.args.get("error")
        if error: raise RuntimeError(f"Okta error: {error} - {request.args.get('error_description')}")
        if not code: raise ValueError("No authorization code received.")

        # Re-discover endpoints in this worker (multi-worker safety)
        if not sso_tester_logic.okta_oidc_get_endpoints(okta_config["oidc_issuer_url"]):
            raise RuntimeError("Failed to discover Okta OIDC endpoints")

        tokens = sso_tester_logic.okta_oidc_exchange_code_for_tokens(code, okta_config, session.get('code_verifier'))
        if not tokens: raise ConnectionError("Token exchange failed.")
        
        result_data.update({ 'raw_id_token': tokens.get("id_token"), 'raw_access_token': tokens.get("access_token"), 'raw_refresh_token': tokens.get("refresh_token"), 'code_verifier': session.get('code_verifier'), 'code_challenge': session.get('code_challenge') })
        if tokens.get("refresh_token"):
            session['refresh_token'] = tokens.get("refresh_token")
            session['idp_context_for_refresh'] = {'idp': 'okta', 'env': selected_env, 'auth_server_type': auth_server_type}

        if result_data['raw_id_token']:
            imp, det = process_and_split_claims(sso_tester_logic.okta_oidc_validate_id_token(result_data['raw_id_token'], okta_config))
            result_data['oidc_imp_claims'], result_data['oidc_det_claims'] = imp, det
        if result_data['raw_access_token']:
            imp, det = process_and_split_claims(sso_tester_logic.okta_oidc_validate_access_token(result_data['raw_access_token'], okta_config))
            result_data['access_imp_claims'], result_data['access_det_claims'] = imp, det
            imp, det = process_and_split_claims(sso_tester_logic.okta_oidc_get_userinfo_claims(result_data['raw_access_token']))
            result_data['userinfo_imp_claims'], result_data['userinfo_det_claims'] = imp, det
            
        webpage_message, webpage_color = "✅ Okta OIDC Flow Completed!", "#28a745"
    except Exception as e:
        logger.error(f"Okta OIDC Callback Error: {e}", exc_info=True)
        webpage_message, webpage_color, oidc_error = "❌ Okta OIDC Error!", "#dc3545", str(e)
    finally:
        session['last_result'] = result_data
        context = get_full_template_context()
        ui = session.get('ui_context', {})
        context.update({'message': webpage_message, 'color': webpage_color, 'oidc_error': oidc_error, **result_data, 'idp_choice': 'okta', 'protocol_choice': 'oidc', 'selected_env': ui.get('environment'), 'selected_target_app': ui.get('target_app'), 'auth_server_type': ui.get('auth_server_type', 'custom'), 'force_fresh_login': ui.get('force_fresh_login', FORCE_FRESH_LOGIN_DEFAULT), 'test_timestamp': test_timestamp})
    return render_template('index.html', **context)

@app.route("/adfs/oidc/callback")
def adfs_oidc_callback():
    webpage_message, webpage_color, oidc_error = "", "", None
    result_data = { 'oidc_imp_claims': {}, 'oidc_det_claims': {}, 'access_imp_claims': {}, 'access_det_claims': {}, 'userinfo_imp_claims': {}, 'userinfo_det_claims': {}, 'raw_id_token': None, 'raw_access_token': None, 'raw_refresh_token': None }
    test_timestamp = datetime.now(timezone.utc).astimezone().strftime('%b %d %Y, %I:%M:%S %p %Z')
    selected_env = session.get('adfs_env_key')
    try:
        if request.args.get('state') != session.pop('oauth_state', None): raise RuntimeError("Invalid state parameter.")
        code, error = request.args.get("code"), request.args.get("error")
        if error: raise RuntimeError(f"ADFS error: {error} - {request.args.get('error_description')}")
        if not code: raise ValueError("No authorization code received.")
        adfs_env_key = session.get('adfs_env_key')
        adfs_issuer = session.get('adfs_issuer')
        if not adfs_env_key or not adfs_issuer: raise RuntimeError("ADFS context not found in session.")

        # Re-discover endpoints in this worker (multi-worker safety)
        if not sso_tester_logic.adfs_oidc_get_endpoints(adfs_issuer):
            raise RuntimeError("Failed to discover ADFS OIDC endpoints")

        tokens = sso_tester_logic.adfs_oidc_exchange_code_for_tokens(code, adfs_env_key, session.get('code_verifier'))
        if not tokens: raise ConnectionError("Token exchange failed.")
        
        result_data.update({ 'raw_id_token': tokens.get("id_token"), 'raw_access_token': tokens.get("access_token"), 'raw_refresh_token': tokens.get("refresh_token"), 'code_verifier': session.get('code_verifier'), 'code_challenge': session.get('code_challenge') })
        if tokens.get("refresh_token"):
            session['refresh_token'] = tokens.get("refresh_token")
            session['idp_context_for_refresh'] = {'idp': 'adfs', 'env': adfs_env_key}

        if result_data['raw_id_token']:
            imp, det = process_and_split_claims(sso_tester_logic.adfs_oidc_validate_id_token(result_data['raw_id_token'], adfs_issuer, adfs_env_key))
            result_data['oidc_imp_claims'], result_data['oidc_det_claims'] = imp, det
        if result_data['raw_access_token']:
            try:
                imp, det = process_and_split_claims(sso_tester_logic.jwt.decode(token=result_data['raw_access_token'], key="", options={"verify_signature": False, "verify_aud": False, "verify_exp": False}))
                result_data['access_imp_claims'], result_data['access_det_claims'] = imp, det
            except JWTError: logger.info("ADFS Access Token is not a JWT."); result_data['access_imp_claims'] = {"token_type": "Opaque or non-JWT"}
            imp, det = process_and_split_claims(sso_tester_logic.adfs_oidc_get_userinfo_claims(result_data['raw_access_token']))
            result_data['userinfo_imp_claims'], result_data['userinfo_det_claims'] = imp, det

        webpage_message, webpage_color = "✅ ADFS OIDC Flow Completed!", "#28a745"
    except Exception as e:
        logger.error(f"ADFS OIDC Callback Error: {e}", exc_info=True)
        webpage_message, webpage_color, oidc_error = "❌ ADFS OIDC Error!", "#dc3545", str(e)
    finally:
        session['last_result'] = result_data
        context = get_full_template_context()
        ui = session.get('ui_context', {})
        context.update({'message': webpage_message, 'color': webpage_color, 'oidc_error': oidc_error, **result_data, 'idp_choice': 'adfs', 'protocol_choice': 'oidc', 'selected_env': ui.get('environment'), 'selected_target_app': ui.get('target_app'), 'auth_server_type': ui.get('auth_server_type', 'custom'), 'force_fresh_login': ui.get('force_fresh_login', FORCE_FRESH_LOGIN_DEFAULT), 'test_timestamp': test_timestamp})
    return render_template('index.html', **context)

@app.route("/refresh_token", methods=['POST'])
def refresh_token():
    logger.info("--- OIDC Token Refresh Test Initiated ---")
    refresh_token_val = session.get('refresh_token')
    idp_context = session.get('idp_context_for_refresh')
    original_result_data = session.get('last_result', {})
    
    webpage_message, webpage_color, refresh_error, refresh_result_data = "", "", None, {}
    test_timestamp = datetime.now(timezone.utc).astimezone().strftime('%b %d %Y, %I:%M:%S %p %Z')

    try:
        if not refresh_token_val or not idp_context:
            raise RuntimeError("Refresh token or IdP context not found in session.")

        refresh_response = sso_tester_logic.oidc_perform_token_refresh(refresh_token_val, idp_context['idp'], idp_context['env'])
        
        if refresh_response.get("error"):
            raise RuntimeError(f"IdP Error: {refresh_response.get('error_description') or refresh_response.get('error')}")
        
        webpage_message, webpage_color = "✅ Token Refresh Successful!", "#28a745"
        refresh_result_data['refreshed_access_token'] = refresh_response.get('access_token')
        refresh_result_data['refreshed_id_token'] = refresh_response.get('id_token')
        
    except Exception as e:
        logger.error(f"Token Refresh Error: {e}", exc_info=True)
        webpage_message, webpage_color, refresh_error = "❌ Token Refresh Failed!", "#dc3545", str(e)

    finally:
        context = get_full_template_context()
        context.update(original_result_data)
        ui = session.get('ui_context', {})
        context.update({
            'message': webpage_message, 'color': webpage_color, 'refresh_error': refresh_error,
            'idp_choice': idp_context.get('idp') if idp_context else 'okta', 
            'protocol_choice': 'oidc',
            'selected_env': ui.get('environment') if ui else list(OKTA_ENVIRONMENTS.keys())[0],
            'selected_target_app': ui.get('target_app') if ui else 'default',
            'auth_server_type': ui.get('auth_server_type', 'custom'),
            'force_fresh_login': ui.get('force_fresh_login', FORCE_FRESH_LOGIN_DEFAULT),
            'test_timestamp': test_timestamp
        })
        context.update(refresh_result_data)
    return render_template('index.html', **context)

if __name__ == "__main__":
    logger.info("--- Starting Federated Identity & Claims Analyzer Web UI ---")
    if not start_flask_dev_server():
        sys.exit(1)
