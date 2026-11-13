import os

import pytest
from fake_settings import CSRF, FAKE_ENV

# Plainly fake settings. They must be in place before `app` is imported,
# because the app reads its settings and checks them at import time.
os.environ.update(FAKE_ENV)

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
        sess["csrf_token"] = CSRF
    return client
