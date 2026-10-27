"""Shared test fixtures.

The app reads DATABASE_URL at import time, so point it at a throwaway SQLite
file before importing app.main. Each test gets a fresh TestClient context so
the lifespan handler creates tables; the fixture removes targets afterwards.
"""
import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_tmpdir = tempfile.mkdtemp(prefix="leadline-tests-")
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{Path(_tmpdir) / 'test.db'}"
os.environ.setdefault(
    "ALLOWED_HOSTS",
    '["localhost","127.0.0.1","::1","backend","testserver"]',
)

from app.main import app  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client

        # Keep list_targets_empty deterministic regardless of test order.
        for target in test_client.get("/api/targets").json():
            test_client.delete(f"/api/targets/{target['id']}")
