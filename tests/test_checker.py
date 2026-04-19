"""Tests for checker.py core logic."""

from __future__ import annotations

import json

import pytest

import checker
from checker import (
    Agent365PreflightChecker,
    Printer,
    Severity,
    Status,
    decode_jwt_claims,
    extract_roles,
    load_client_credential,
)
from tests.conftest import make_jwt

# --- JWT helpers -------------------------------------------------------------

def test_decode_jwt_claims_valid():
    token = make_jwt(["Organization.Read.All"])
    claims = decode_jwt_claims(token)
    assert claims["roles"] == ["Organization.Read.All"]


def test_decode_jwt_claims_malformed():
    assert decode_jwt_claims("not-a-jwt") == {}
    assert decode_jwt_claims("a.b") == {}


def test_extract_roles_empty():
    assert extract_roles(make_jwt([])) == set()


def test_extract_roles_set():
    roles = extract_roles(make_jwt(["A", "B", "A"]))
    assert roles == {"A", "B"}


# --- Credential loader -------------------------------------------------------

def test_load_client_credential_prefers_cert(tmp_path):
    cert = tmp_path / "cert.pem"
    cert.write_text("PEM")
    cred = load_client_credential(str(cert), "THUMB", "secret")
    assert isinstance(cred, dict)
    assert cred["thumbprint"] == "THUMB"
    assert cred["private_key"] == "PEM"


def test_load_client_credential_falls_back_to_secret():
    assert load_client_credential(None, None, "secret") == "secret"


def test_load_client_credential_none():
    assert load_client_credential(None, None, None) is None


def test_load_client_credential_missing_cert_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_client_credential(str(tmp_path / "missing.pem"), "T", "s")


# --- Environment variable check ---------------------------------------------

def _make_checker(run_security=False, skip_graph=False):
    p = Printer(quiet=True, use_color=False)
    return Agent365PreflightChecker(
        printer=p,
        skip_graph=skip_graph,
        run_security=run_security,
    )


def test_env_check_pass(valid_env):
    c = _make_checker()
    assert c.check_environment_variables() is True
    assert all(r.status is Status.PASS for r in c.results)


def test_env_check_fail(clean_env):
    c = _make_checker()
    assert c.check_environment_variables() is False
    fails = [r for r in c.results if r.status is Status.FAIL]
    assert len(fails) == 3


# --- GUID validation ---------------------------------------------------------

def test_entra_app_registration_invalid_guids(clean_env, monkeypatch):
    monkeypatch.setenv("TENANT_ID", "not-a-guid")
    monkeypatch.setenv("CLIENT_ID", "also-bad")
    monkeypatch.setenv("CLIENT_SECRET", "x")
    c = _make_checker()
    assert c.check_entra_app_registration() is False
    assert any("Tenant ID" in r.name and r.status is Status.FAIL for r in c.results)
    assert any("Client" in r.name and r.status is Status.FAIL for r in c.results)


def test_entra_app_registration_valid(valid_env):
    c = _make_checker()
    assert c.check_entra_app_registration() is True


def test_cert_credential_reported(valid_env, monkeypatch, tmp_path):
    cert = tmp_path / "c.pem"
    cert.write_text("PEM")
    monkeypatch.setenv("CLIENT_CERT_PATH", str(cert))
    monkeypatch.setenv("CLIENT_CERT_THUMBPRINT", "THUMB")
    c = _make_checker()
    c.check_entra_app_registration()
    assert any("certificate" in r.name.lower() and r.status is Status.PASS
               for r in c.results)


def test_secret_credential_marked_warning(valid_env):
    c = _make_checker()
    c.check_entra_app_registration()
    secret_result = next(
        r for r in c.results if "secret" in r.name.lower()
    )
    assert secret_result.severity is Severity.WARNING


# --- Token roles check ------------------------------------------------------

def test_roles_check_pass(valid_env):
    c = _make_checker()
    token = make_jwt(["Organization.Read.All"])
    c._check_token_roles(token)
    assert c.results[-1].status is Status.PASS


def test_roles_check_missing(valid_env):
    c = _make_checker()
    token = make_jwt(["Something.Else"])
    c._check_token_roles(token)
    assert c.results[-1].status is Status.FAIL
    assert "Missing" in c.results[-1].message


def test_roles_check_no_roles_claim(valid_env):
    c = _make_checker()
    token = make_jwt([])
    c._check_token_roles(token)
    assert c.results[-1].status is Status.FAIL


def test_roles_check_security_mode_needs_more(valid_env):
    c = _make_checker(run_security=True)
    token = make_jwt(["Organization.Read.All"])
    c._check_token_roles(token)
    # Missing Policy.Read.All, AuditLog.Read.All, Directory.Read.All.
    assert c.results[-1].status is Status.FAIL


# --- Skip paths -------------------------------------------------------------

def test_graph_permissions_skipped_no_token(valid_env):
    c = _make_checker()
    c.check_graph_permissions(None)
    assert c.results[-1].status is Status.SKIP


def test_graph_permissions_skipped_flag(valid_env):
    c = _make_checker(skip_graph=True)
    c.check_graph_permissions("any-token")
    assert c.results[-1].status is Status.SKIP


# --- Summary exit code ------------------------------------------------------

def test_summary_success_true_when_no_critical_fails(valid_env):
    c = _make_checker()
    c.check_environment_variables()  # all pass
    assert c._summary() is True


def test_summary_success_false_on_critical_fail(clean_env):
    c = _make_checker()
    c.check_environment_variables()  # all fail
    assert c._summary() is False


def test_frontier_warning_does_not_fail_summary(valid_env):
    c = _make_checker()
    c.check_frontier_preview()  # emits warning (fail+severity=WARNING)
    assert c._summary() is True


# --- CLI --------------------------------------------------------------------

def test_parse_args_defaults():
    args = checker._parse_args([])
    assert args.as_json is False
    assert args.security is False
    assert args.fail_on_security is False


def test_parse_args_security_flags():
    args = checker._parse_args(["--security", "--fail-on-security"])
    assert args.security is True
    assert args.fail_on_security is True


def test_main_json_output(valid_env, monkeypatch, capsys):
    """End-to-end with MSAL + Graph mocked; --json emits valid JSON."""
    monkeypatch.setattr(
        checker, "ConfidentialClientApplication", _FakeMSAL
    )
    import security_checks as sc  # ensure same requests module patched

    class _FakeResp:
        def __init__(self, code=200, body=None):
            self.status_code = code
            self.reason = "OK"
            self._body = body or {"value": []}

        def json(self):
            return self._body

    monkeypatch.setattr(
        checker.requests, "get", lambda *a, **k: _FakeResp(200)
    )
    monkeypatch.setattr(
        sc.requests, "get", lambda *a, **k: _FakeResp(200)
    )

    rc = checker.main(["--json", "--no-color"])
    captured = capsys.readouterr()
    # rc is 0 (all critical pass) because FRONTIER is a WARNING only.
    assert rc == 0
    payload = json.loads(captured.out)
    assert payload["success"] is True
    assert isinstance(payload["results"], list)
    assert "security_findings" in payload


# --- Fakes ------------------------------------------------------------------

class _FakeMSAL:
    def __init__(self, *a, **k):
        pass

    def acquire_token_for_client(self, scopes):
        return {"access_token": make_jwt(["Organization.Read.All"])}
