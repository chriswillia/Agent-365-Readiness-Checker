"""Tests for security_checks.py."""

from __future__ import annotations

from unittest.mock import patch

import security_checks as sc
from security_checks import (
    Category,
    SecurityFinding,
    Verdict,
    _policy_targets_workload_identities,
    _rollup_risk,
    findings_to_markdown,
    run_security_checks,
)


class FakeResp:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self.reason = "OK"
        self._body = body or {}

    def json(self):
        return self._body


def _make_get(route_map):
    def _get(path, access_token, params=None):
        for route, resp in route_map.items():
            if route in path:
                return resp
        return FakeResp(404, {})
    return _get


# --- Policy heuristic -------------------------------------------------------

def test_policy_targets_workload_identities_true():
    policy = {"conditions": {"clientApplications": {"includeServicePrincipals": ["All"]}}}
    assert _policy_targets_workload_identities(policy) is True


def test_policy_targets_workload_identities_false_empty():
    assert _policy_targets_workload_identities({}) is False


def test_policy_targets_workload_identities_false_none_marker():
    policy = {"conditions": {"clientApplications": {"includeServicePrincipals": ["None"]}}}
    assert _policy_targets_workload_identities(policy) is False


# --- Rollup -----------------------------------------------------------------

def test_rollup_risk_priority():
    fail = SecurityFinding(Category.IDENTITY, "x", Verdict.FAIL, "s")
    warn = SecurityFinding(Category.IDENTITY, "x", Verdict.WARN, "s")
    passf = SecurityFinding(Category.IDENTITY, "x", Verdict.PASS, "s")
    assert _rollup_risk([fail, warn, passf]) is Verdict.FAIL
    assert _rollup_risk([warn, passf]) is Verdict.WARN
    assert _rollup_risk([passf]) is Verdict.PASS


# --- Full run with mocked Graph --------------------------------------------

def test_run_security_checks_ca_not_bound():
    """CA exists, enabled, but none target workload identities → WARN."""
    routes = {
        "/servicePrincipals": FakeResp(200, {"value": [{"id": "sp1"}]}),
        "/identity/conditionalAccess/policies": FakeResp(200, {
            "value": [{"id": "p1", "displayName": "All users MFA",
                       "state": "enabled", "conditions": {}}]
        }),
        "/policies/identitySecurityDefaultsEnforcementPolicy": FakeResp(200, {
            "isEnabled": False
        }),
        "/auditLogs/directoryAudits": FakeResp(200, {"value": []}),
        "/subscribedSkus": FakeResp(200, {"value": [
            {"servicePlans": [
                {"servicePlanName": "EXCHANGE_S_ENTERPRISE_E5"},
                {"servicePlanName": "INFORMATION_PROTECTION_COMPLIANCE"},
                {"servicePlanName": "MDI_TRIAL"},
            ]}
        ]}),
    }
    with patch.object(sc, "_graph_get", side_effect=_make_get(routes)):
        findings = run_security_checks("fake-token")

    # Audit reachability should PASS
    audit = next(f for f in findings if "audit log reachability" in f.name.lower())
    assert audit.verdict is Verdict.PASS

    # CA coverage should WARN
    coverage = next(f for f in findings if "coverage for agents" in f.name.lower())
    assert coverage.verdict is Verdict.WARN

    # Rollup present and at least WARN
    rollup = findings[-1]
    assert "Risk classification" in rollup.name
    assert rollup.verdict in (Verdict.WARN, Verdict.FAIL)


def test_run_security_checks_no_ca_policies():
    routes = {
        "/servicePrincipals": FakeResp(200, {"value": []}),
        "/identity/conditionalAccess/policies": FakeResp(200, {"value": []}),
        "/auditLogs/directoryAudits": FakeResp(200, {"value": []}),
        "/subscribedSkus": FakeResp(200, {"value": []}),
    }
    with patch.object(sc, "_graph_get", side_effect=_make_get(routes)):
        findings = run_security_checks("fake-token")

    ca = next(f for f in findings if f.name == "Conditional Access policies")
    assert ca.verdict is Verdict.FAIL

    # No licensing → DLP should FAIL
    dlp = next(f for f in findings if "DLP" in f.name)
    assert dlp.verdict is Verdict.FAIL

    # Rollup must be FAIL
    assert findings[-1].verdict is Verdict.FAIL


def test_run_security_checks_permission_denied_skips():
    routes = {
        "/servicePrincipals": FakeResp(403, {}),
        "/identity/conditionalAccess/policies": FakeResp(403, {}),
        "/auditLogs/directoryAudits": FakeResp(403, {}),
        "/subscribedSkus": FakeResp(403, {}),
    }
    with patch.object(sc, "_graph_get", side_effect=_make_get(routes)):
        findings = run_security_checks("fake-token")

    skipped = [f for f in findings if f.verdict is Verdict.SKIP]
    assert len(skipped) >= 3  # identity, policies, audit, licensing


# --- Markdown export --------------------------------------------------------

def test_findings_to_markdown_contains_sections():
    findings = [
        SecurityFinding(Category.IDENTITY, "Id check", Verdict.PASS, "good"),
        SecurityFinding(Category.POLICIES, "Pol check", Verdict.WARN, "meh"),
        SecurityFinding(Category.AUDIT_DLP, "Aud check", Verdict.FAIL, "bad"),
    ]
    md = findings_to_markdown(findings)
    assert "# Agent 365 Security" in md
    assert "Identity" in md
    assert "Policies" in md
    assert "Audit Dlp" in md
    assert "✅" in md and "⚠️" in md and "❌" in md
