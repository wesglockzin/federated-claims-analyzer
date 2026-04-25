#!/usr/bin/env python3
"""
smoke_test.py — Federated Claims Analyzer deployment validation.

Pre-deploy  (default):
    Static analysis only — syntax, Dockerfile, requirements, project structure.
    Zero external dependencies. No secrets or env vars required.
    Runs on any machine with Python 3.6+.

Post-deploy (--post-deploy <url>):
    HTTP checks against the live Container App. Verifies the container is up
    and Azure AD OIDC redirect is functional.
    Also zero external dependencies (uses urllib, stdlib only).

Exit code 0 = all checks passed.
Exit code 1 = one or more checks failed.

Usage:
    python3 smoke_test.py                          # pre-deploy
    python3 smoke_test.py --post-deploy <url>      # post-deploy
"""

from __future__ import annotations

import argparse
import py_compile
import sys
import urllib.request
import urllib.error
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

APP_URL = "https://federated-claims-analyzer.your-env.eastus.azurecontainerapps.io"

# ---------------------------------------------------------------------------
# Terminal output helpers
# ---------------------------------------------------------------------------

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"

def _ok(msg: str)   -> None: print(f"{GREEN}✓ {msg}{RESET}")
def _fail(msg: str) -> None: print(f"{RED}✗ {msg}{RESET}")
def _warn(msg: str) -> None: print(f"{YELLOW}⚠ {msg}{RESET}")
def _info(msg: str) -> None: print(f"  {msg}")


# ---------------------------------------------------------------------------
# Pre-deploy checks
# ---------------------------------------------------------------------------

def check_syntax() -> bool:
    """
    Compile every .py file in the project directory without executing it.
    Uses py_compile — catches SyntaxError with zero runtime side effects
    and zero dependency on installed packages or environment variables.
    """
    _info("Compiling .py files (py_compile, no execution)...")
    errors = []
    for pyfile in sorted(SCRIPT_DIR.glob("*.py")):
        if pyfile.name == "smoke_test.py":
            continue  # Skip self
        try:
            py_compile.compile(str(pyfile), doraise=True)
        except py_compile.PyCompileError as e:
            errors.append(str(e))
    if errors:
        for e in errors:
            _fail(e)
        return False
    _ok("All .py files compile without syntax errors")
    return True


def check_requirements() -> bool:
    """
    Verify requirements.txt exists and lists the packages this app depends on.
    Does NOT check whether packages are installed locally — the Docker build
    (az acr build) is the authoritative test for that.
    """
    _info("Checking requirements.txt content...")
    req = SCRIPT_DIR / "requirements.txt"
    if not req.exists():
        _fail("requirements.txt not found")
        return False

    content = req.read_text().lower()
    expected = ["flask", "requests", "python3-saml", "gunicorn", "python-dotenv"]
    missing = [p for p in expected if p not in content]
    if missing:
        _fail(f"requirements.txt missing entries: {', '.join(missing)}")
        return False

    _ok("requirements.txt contains all expected packages")
    return True


def check_dockerfile() -> bool:
    """
    Verify Dockerfile exists and contains the minimum expected directives.
    Accepts any base image (including ACR-hosted mirrors like
    my-acr.azurecr.io/python:3.11-slim).
    """
    _info("Checking Dockerfile...")
    dockerfile = SCRIPT_DIR / "Dockerfile"
    if not dockerfile.exists():
        _fail("Dockerfile not found")
        return False

    content = dockerfile.read_text()
    issues = []

    if not any(line.strip().startswith("FROM") for line in content.splitlines()):
        issues.append("no FROM directive found")
    if "gunicorn" not in content:
        issues.append("gunicorn not referenced (expected in CMD or ENTRYPOINT)")

    if issues:
        _fail(f"Dockerfile issues: {'; '.join(issues)}")
        return False

    _ok("Dockerfile is structurally valid")
    return True


def check_structure() -> bool:
    """
    Verify all required project files exist and are non-trivially sized.
    Catches accidental deletions or zero-byte writes before they ship.
    """
    _info("Checking project structure...")
    required = {
        "app.py":              50,
        "sso_tester_logic.py": 50,
        "saml_settings.py":    50,
        "requirements.txt":    10,
        "Dockerfile":          10,
        "deploy.sh":           10,
        "AGENTS.md":           20,
        "SESSION_NOTES.md":    20,
    }
    issues = []
    for name, min_bytes in required.items():
        f = SCRIPT_DIR / name
        if not f.exists():
            issues.append(f"{name}: missing")
        elif f.stat().st_size < min_bytes:
            issues.append(f"{name}: suspiciously small ({f.stat().st_size} bytes)")

    if issues:
        for i in issues:
            _fail(i)
        return False

    _ok("All required project files present")
    return True


# ---------------------------------------------------------------------------
# Post-deploy checks
# ---------------------------------------------------------------------------

def _ssl_context():
    """
    Build an SSL context for post-deploy health checks.

    Senate AnyConnect performs TLS inspection and Python 3.12+ enforces stricter
    certificate validation (requires Authority Key Identifier extension) that
    intercept certificates may not satisfy. For a reachability health check this
    isn't the security boundary — the app's own TLS is managed by Azure Container
    Apps. We disable verification here and warn so the operator knows why.
    """
    import ssl
    _warn("SSL verification disabled for post-deploy checks (VPN/TLS inspection environment)")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_get(url: str, follow_redirects: bool = True, timeout: int = 15) -> tuple[int, str]:
    """
    Minimal HTTP GET using stdlib urllib. Returns (status_code, location_header).
    No third-party dependencies required.
    """
    import ssl

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # Suppress redirect

    https_handler = urllib.request.HTTPSHandler(context=_ssl_context())

    if follow_redirects:
        opener = urllib.request.build_opener(https_handler)
    else:
        opener = urllib.request.build_opener(https_handler, _NoRedirect)

    try:
        resp = opener.open(url, timeout=timeout)
        return resp.status, ""
    except urllib.error.HTTPError as e:
        location = e.headers.get("Location", "")
        return e.code, location
    except Exception as e:
        raise


def check_app_reachable(base_url: str) -> bool:
    """
    GET / on the live Container App.
    Healthy responses: 200 (login page rendered) or 302 (OIDC redirect).
    Anything else indicates the container failed to start or is misconfigured.
    """
    _info(f"Checking app is reachable: {base_url}")
    try:
        status, _ = _http_get(base_url, follow_redirects=False)
        if status in (200, 302):
            _ok(f"App responded HTTP {status}")
            return True
        _fail(f"Unexpected HTTP {status} — container may not have started cleanly")
        return False
    except Exception as e:
        _fail(f"Could not reach app: {e}")
        return False


def check_oidc_redirect(base_url: str) -> bool:
    """
    GET /login on the live Container App.
    Must return 302 → login.microsoftonline.com.
    Verifies that Azure AD OIDC is configured and the app loaded its secrets.

    /azure/oidc/login is the unauthenticated OIDC initiation endpoint — hitting it
    directly triggers the authorization redirect without requiring an existing session.
    """
    url = f"{base_url.rstrip('/')}/azure/oidc/login"
    _info(f"Checking Azure AD OIDC redirect: {url}")
    try:
        status, location = _http_get(url, follow_redirects=False)
        if status == 302 and "microsoftonline.com" in location:
            _ok("Azure AD OIDC redirect is functional")
            return True
        _fail(
            f"Expected 302 → microsoftonline.com, "
            f"got HTTP {status} → {location or '(no Location header)'}"
        )
        return False
    except Exception as e:
        _fail(f"OIDC redirect check failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _run_suite(label: str, checks: list[tuple[str, object]]) -> bool:
    print()
    print("=" * 60)
    print(f"  {label}")
    print("=" * 60)

    results: list[tuple[str, bool]] = []
    for name, fn in checks:
        print()
        try:
            passed = fn()
        except Exception as e:
            _fail(f"{name}: unhandled exception — {e}")
            passed = False
        results.append((name, passed))

    print()
    print("=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    for name, passed in results:
        ((_ok if passed else _fail)(f"{name}: {'PASS' if passed else 'FAIL'}"))

    passed_count = sum(1 for _, p in results if p)
    total = len(results)
    print()
    print(f"  {passed_count}/{total} checks passed")
    return passed_count == total


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Federated Claims Analyzer — pre- and post-deployment smoke tests"
    )
    parser.add_argument(
        "--post-deploy",
        metavar="URL",
        nargs="?",
        const=APP_URL,
        help=(
            f"Run post-deployment HTTP checks against the live Container App. "
            f"Defaults to {APP_URL} if URL is omitted."
        ),
    )
    args = parser.parse_args()

    if args.post_deploy:
        url = args.post_deploy.rstrip("/")
        checks = [
            ("App reachable",       lambda: check_app_reachable(url)),
            ("Azure AD OIDC redirect", lambda: check_oidc_redirect(url)),
        ]
        success = _run_suite("POST-DEPLOY CHECKS", checks)
    else:
        checks = [
            ("Python syntax",      check_syntax),
            ("requirements.txt",   check_requirements),
            ("Dockerfile",         check_dockerfile),
            ("Project structure",  check_structure),
        ]
        success = _run_suite("PRE-DEPLOY CHECKS", checks)

    print()
    if success:
        _ok("Done.")
    else:
        _fail("One or more checks failed — see details above.")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
