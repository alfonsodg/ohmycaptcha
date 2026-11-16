"""Security tests for websiteURL SSRF validation."""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    _ = sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient  # noqa: E402


def _load_client() -> TestClient:
    os.environ.pop("CLIENT_KEY", None)
    config_mod = importlib.import_module("src.core.config")
    routes_mod = importlib.import_module("src.api.routes")
    task_mgr_mod = importlib.import_module("src.services.task_manager")
    main_mod = importlib.import_module("src.main")
    importlib.reload(config_mod)
    importlib.reload(task_mgr_mod)
    importlib.reload(routes_mod)
    main_mod = importlib.reload(main_mod)
    mgr = getattr(task_mgr_mod, "task_manager")
    mgr.register_solver("RecaptchaV3TaskProxyless", AsyncMock(return_value={"gRecaptchaResponse": "tok"}))
    return TestClient(getattr(main_mod, "app"))


@pytest.mark.parametrize(
    "bad_url",
    [
        "file:///etc/passwd",
        "http://127.0.0.1:8000/admin",
        "http://localhost:30000/v1",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/internal",
        "ftp://example.com/resource",
    ],
)
def test_create_task_rejects_ssrf_urls(bad_url: str) -> None:
    """Browser tasks must reject non-HTTP(S) schemes and private/loopback/link-local hosts."""
    client = _load_client()
    resp = client.post(
        "/createTask",
        json={
            "clientKey": "any",
            "task": {
                "type": "RecaptchaV3TaskProxyless",
                "websiteURL": bad_url,
                "websiteKey": "site-key",
            },
        },
    )
    body = resp.json()
    assert body["errorId"] == 1
    assert body["errorCode"] == "ERROR_TASK_PROPERTY_INVALID"


def test_create_task_allows_public_https_url() -> None:
    """Public HTTPS URLs continue to be accepted."""
    client = _load_client()
    resp = client.post(
        "/createTask",
        json={
            "clientKey": "any",
            "task": {
                "type": "RecaptchaV3TaskProxyless",
                "websiteURL": "https://example.com/login",
                "websiteKey": "site-key",
            },
        },
    )
    body = resp.json()
    assert body["errorId"] == 0
    assert body["taskId"]
