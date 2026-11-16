"""Security tests for clientKey authentication and constant-time comparison."""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    _ = sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient  # noqa: E402


def _load_client(*, client_key: str | None, require_key: str | None) -> TestClient:
    os.environ.pop("CLIENT_KEY", None)
    os.environ.pop("REQUIRE_CLIENT_KEY", None)
    if client_key is not None:
        os.environ["CLIENT_KEY"] = client_key
    if require_key is not None:
        os.environ["REQUIRE_CLIENT_KEY"] = require_key

    config_mod = importlib.import_module("src.core.config")
    routes_mod = importlib.import_module("src.api.routes")
    task_mgr_mod = importlib.import_module("src.services.task_manager")
    main_mod = importlib.import_module("src.main")
    importlib.reload(config_mod)
    importlib.reload(task_mgr_mod)
    importlib.reload(routes_mod)
    main_mod = importlib.reload(main_mod)
    return TestClient(getattr(main_mod, "app"))


def test_require_client_key_rejects_when_unset() -> None:
    """When REQUIRE_CLIENT_KEY=true and CLIENT_KEY is unset, all auth endpoints reject."""
    client = _load_client(client_key=None, require_key="true")
    try:
        res_create = client.post(
            "/createTask",
            json={"clientKey": "any", "task": {"type": "RecaptchaV3TaskProxyless"}},
        )
        res_result = client.post(
            "/getTaskResult",
            json={"clientKey": "any", "taskId": "missing"},
        )
        res_balance = client.post("/getBalance", json={"clientKey": "any"})
        assert res_create.json()["errorId"] == 1
        assert res_create.json()["errorCode"] == "ERROR_KEY_DOES_NOT_EXIST"
        assert res_result.json()["errorId"] == 1
        assert res_result.json()["errorCode"] == "ERROR_KEY_DOES_NOT_EXIST"
        assert res_balance.json()["errorId"] == 1
    finally:
        os.environ.pop("REQUIRE_CLIENT_KEY", None)


def test_client_key_uses_constant_time_compare_digest() -> None:
    """Client key verification must use hmac.compare_digest."""
    client = _load_client(client_key="top-secret", require_key="true")
    try:
        with patch("src.api.routes.hmac.compare_digest", return_value=True) as mock_cmp:
            resp = client.post("/getBalance", json={"clientKey": "top-secret"})
            assert resp.json()["errorId"] == 0
            mock_cmp.assert_called_once_with("top-secret", "top-secret")
    finally:
        os.environ.pop("CLIENT_KEY", None)
        os.environ.pop("REQUIRE_CLIENT_KEY", None)
