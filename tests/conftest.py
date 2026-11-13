import os

import pytest

# Plainly fake settings. They must be in place before `app` is imported,
# because the app reads its settings and checks them at import time.
os.environ.update(
    {
        "AUTH_MODE": "oidc",
        "FLASK_SECRET_KEY": "test-key-not-real",
        "OIDC_ISSUER": "https://idp.invalid",
        "OIDC_CLIENT_ID": "test-client-not-real",
        "OIDC_CLIENT_SECRET": "test-secret-not-real",
        "APP_BASE_URL": "http://localhost:8080",
        "OKTA_DEV_OIDC_SECRET": "test-secret-not-real",
        "ADFS_DEV_CLIENT_SECRET": "test-secret-not-real",
        "ADFS_PROD_CLIENT_SECRET": "test-secret-not-real",
    }
)

import app as app_module


@pytest.fixture
def app_mod():
    return app_module


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


@pytest.fixture
def signed_in(client):
    with client.session_transaction() as sess:
        sess["user"] = {"email": "someone@example.invalid"}
    return client
