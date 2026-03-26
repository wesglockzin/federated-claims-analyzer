#!/usr/bin/env python3
"""
Pre-Deployment Smoke Test
Validates the application can start and access required services before deploying.
Exit code 0 = all checks passed, non-zero = deployment should abort.
"""

import sys
import os
from pathlib import Path

# Colors for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'

def print_status(message, status="info"):
    """Print colored status messages."""
    if status == "pass":
        print(f"{GREEN}✓ {message}{RESET}")
    elif status == "fail":
        print(f"{RED}✗ {message}{RESET}")
    elif status == "warn":
        print(f"{YELLOW}⚠ {message}{RESET}")
    else:
        print(f"  {message}")

def test_python_syntax():
    """Test 1: Verify Python files have valid syntax."""
    print_status("Testing Python syntax and imports...", "info")
    try:
        import app
        import sso_tester_logic
        import saml_settings
        print_status("All Python modules import successfully", "pass")
        return True
    except SyntaxError as e:
        print_status(f"Syntax error in Python files: {e}", "fail")
        return False
    except ImportError as e:
        print_status(f"Import error: {e}", "fail")
        return False
    except Exception as e:
        print_status(f"Unexpected error importing modules: {e}", "fail")
        return False

def test_dependencies():
    """Test 2: Verify all required dependencies are installed."""
    print_status("Checking dependencies...", "info")
    # If Python syntax test passes (imports app modules), dependencies are good
    # This test is mainly for explicit verification
    core_packages = [
        'flask',
        'requests',
        'jose',
        'dotenv'
    ]

    missing = []
    for package in core_packages:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)

    if missing:
        print_status(f"Missing core dependencies: {', '.join(missing)}", "fail")
        return False
    else:
        print_status("Core dependencies installed", "pass")
        return True

def test_azure_container_apps_env():
    """Test 3: Verify Azure Container Apps environment detection."""
    print_status("Checking Azure Container Apps environment...", "info")

    # Check for Kubernetes/Container Apps environment indicators
    is_cloud_or_k8s = os.environ.get('KUBERNETES_SERVICE_HOST') or os.environ.get('K_SERVICE')

    if is_cloud_or_k8s:
        print_status("Running in cloud/container environment", "pass")
        return True
    else:
        print_status("Running in local development environment", "warn")
        return True  # Not a failure, just informational

def test_flask_app_creation():
    """Test 5: Verify Flask app can be instantiated."""
    print_status("Testing Flask app instantiation...", "info")
    try:
        import app
        if hasattr(app, 'app') and app.app is not None:
            print_status("Flask app created successfully", "pass")
            return True
        else:
            print_status("Flask app object not found", "fail")
            return False
    except Exception as e:
        print_status(f"Flask app creation failed: {e}", "fail")
        return False

def test_required_env_vars():
    """Test 4: Verify required environment variables (in cloud environments)."""
    print_status("Checking required environment variables...", "info")

    # Check if we're in a cloud environment
    is_cloud = os.environ.get('KUBERNETES_SERVICE_HOST') or os.environ.get('K_SERVICE')

    if not is_cloud:
        print_status("Not in cloud environment, skipping env var checks", "warn")
        return True

    required_vars = [
        'FLASK_SECRET_KEY',
        'AZURE_OIDC_CLIENT_ID',
        'AZURE_OIDC_CLIENT_SECRET',
        'AZURE_OIDC_TENANT_ID',
    ]

    missing = [var for var in required_vars if not os.environ.get(var)]

    if missing:
        print_status(f"Missing environment variables: {', '.join(missing)}", "fail")
        return False
    else:
        print_status("Required environment variables present", "pass")
        return True

def test_documentation_files():
    """Test 5: Verify required documentation files exist and have content."""
    print_status("Checking documentation files...", "info")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    required_docs = {
        'AGENTS.md': ['Project Rules', 'File Management', 'Version Management'],
        'SESSION_NOTES.md': ['Session Notes', 'Last Updated'],
        'requirements.txt': ['flask', 'requests'],
        'AZURE_AD_SETUP.md': ['Azure AD', 'App Registration'],
        'Dockerfile': ['FROM python', 'gunicorn'],
    }

    issues = []
    for filename, expected_content in required_docs.items():
        filepath = os.path.join(script_dir, filename)

        if not os.path.exists(filepath):
            issues.append(f"{filename} missing")
            continue

        try:
            with open(filepath, 'r') as f:
                content = f.read()

            # Check for expected content markers
            missing_content = [marker for marker in expected_content if marker not in content]
            if missing_content:
                issues.append(f"{filename} missing: {', '.join(missing_content)}")

            # Check file is not empty
            if len(content.strip()) < 10:
                issues.append(f"{filename} appears empty or too small")

        except Exception as e:
            issues.append(f"{filename} read error: {e}")

    if issues:
        print_status(f"Documentation issues: {'; '.join(issues)}", "fail")
        return False
    else:
        print_status("All required documentation files present and valid", "pass")
        return True

def main():
    """Run all smoke tests."""
    print("=" * 60)
    print("FEDERATED CLAIMS ANALYZER - PRE-DEPLOYMENT SMOKE TEST")
    print("=" * 60)
    print()

    tests = [
        ("Dependencies", test_dependencies),
        ("Python Syntax", test_python_syntax),
        ("Flask App", test_flask_app_creation),
        ("Azure Environment", test_azure_container_apps_env),
        ("Environment Variables", test_required_env_vars),
        ("Documentation Files", test_documentation_files),
    ]

    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print_status(f"{test_name} test crashed: {e}", "fail")
            results.append((test_name, False))
        print()

    # Summary
    print("=" * 60)
    print("SMOKE TEST SUMMARY")
    print("=" * 60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        print_status(f"{test_name}: {status}", "pass" if result else "fail")

    print()
    print(f"Tests Passed: {passed}/{total}")

    if passed == total:
        print_status("All smoke tests passed! Deployment can proceed.", "pass")
        return 0
    else:
        print_status(f"Smoke tests failed! Fix errors before deploying.", "fail")
        return 1

if __name__ == "__main__":
    sys.exit(main())
