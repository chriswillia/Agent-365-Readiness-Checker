"""Shared test fixtures."""

from __future__ import annotations

import base64
import json as jsonlib
import os
import sys

import pytest

# Ensure repo root is importable.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


VALID_TENANT = "11111111-2222-3333-4444-555555555555"
VALID_CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _b64url(obj) -> str:
    raw = jsonlib.dumps(obj).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def make_jwt(roles=None) -> str:
    """Create an unsigned JWT-like string for payload-only inspection."""
    header = _b64url({"alg": "none", "typ": "JWT"})
    payload = _b64url({"roles": list(roles) if roles else []})
    return f"{header}.{payload}.sig"


@pytest.fixture
def valid_env(monkeypatch):
    monkeypatch.setenv("TENANT_ID", VALID_TENANT)
    monkeypatch.setenv("CLIENT_ID", VALID_CLIENT)
    monkeypatch.setenv("CLIENT_SECRET", "super-secret")
    monkeypatch.delenv("CLIENT_CERT_PATH", raising=False)
    monkeypatch.delenv("CLIENT_CERT_THUMBPRINT", raising=False)
    monkeypatch.setenv("FRONTIER_PREVIEW_ENABLED", "false")
    yield


@pytest.fixture
def clean_env(monkeypatch):
    for var in [
        "TENANT_ID",
        "CLIENT_ID",
        "CLIENT_SECRET",
        "CLIENT_CERT_PATH",
        "CLIENT_CERT_THUMBPRINT",
        "FRONTIER_PREVIEW_ENABLED",
    ]:
        monkeypatch.delenv(var, raising=False)
    yield
