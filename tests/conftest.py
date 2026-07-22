"""Test fixtures. Env vars must be set before backend.config is first
imported, since it reads them at module load time."""

import os
import sys

os.environ.setdefault("NETMON_USERNAME", "testuser")
os.environ.setdefault("NETMON_PASSWORD", "testpass")
os.environ.setdefault("NETMON_SECRET_KEY", "test-secret-key")
os.environ.setdefault("NETMON_SCAN_RATE_LIMIT", "1000 per minute")
os.environ.setdefault("NETMON_LOGIN_RATE_LIMIT", "1000 per minute")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from backend.app import app as flask_app  # noqa: E402


@pytest.fixture()
def app():
    flask_app.config.update(TESTING=True)
    yield flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def auth_client(client):
    client.post(
        "/api/auth/login",
        json={"username": os.environ["NETMON_USERNAME"], "password": os.environ["NETMON_PASSWORD"]},
    )
    return client
