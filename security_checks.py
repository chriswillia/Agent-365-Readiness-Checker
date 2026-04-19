"""
security_checks.py
------------------
Pre-flight security & governance checks for Microsoft Agent 365.

These checks are READ-ONLY and capability/heuristic-based. They answer:
  - Will agent activity be governed, audited and policy-enforced
    once onboarded?
  - Or would agents operate outside the tenant's security envelope?

Three categories are evaluated:
  1. Identity        - Is Microsoft Entra Agent ID available so agents can
                       be identity-anchored? Without a non-human identity
                       anchor, Conditional Access / audit / DLP cannot
                       reliably apply to agent actions.
  2. Policies        - Does the tenant have Conditional Access and identity
                       governance policies that COULD bind to agent
                       identities?
  3. Audit & DLP     - Are Microsoft Purview audit logs reachable, and does
                       the tenant have licensing that enables DLP / Defender
                       signals to be produced from agent activity?

For each finding we distinguish:
  - "policies exist but are not yet bound"   (WARNING)
  - "policies unavailable / not licensed"    (FAIL)
  - "capability ready"                        (PASS)

Graph endpoints used (all read-only):
  /identity/conditionalAccess/policies   (Policy.Read.All)
  /policies/identitySecurityDefaultsEnforcementPolicy (Policy.Read.All)
  /auditLogs/directoryAudits?$top=1      (AuditLog.Read.All)
  /subscribedSkus                        (Organization.Read.All)
  /servicePrincipals?$filter=...         (Directory.Read.All)

None of these endpoints mutate state.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
HTTP_TIMEOUT_SECONDS = 15

# SKU service-plan IDs that indicate governance capability.
# These are heuristics (licensing != binding), kept short on purpose.
PURVIEW_AUDIT_SKU_HINTS = {
    "e5",              # Microsoft 365 E5 family
    "audit",           # Purview Audit (Premium) add-ons
    "compliance",      # Compliance E5
    "information_protection_and_governance",
}
DLP_SKU_HINTS = {
    "dlp",
    "information_protection",
    "e5",
    "compliance",
}
DEFENDER_SKU_HINTS = {
    "defender",
    "atp",
    "threat_intelligence",
    "mdi",  # Defender for Identity
}


class Category(str, Enum):
    IDENTITY = "identity"
    POLICIES = "policies"
    AUDIT_DLP = "audit_dlp"


class Verdict(str, Enum):
    PASS = "pass"       # Capability ready & bindable to agents
    WARN = "warn"       # Exists but not yet bound / partial
    FAIL = "fail"       # Unavailable - agent activity would bypass control
    SKIP = "skip"       # Could not evaluate (permission / network)


@dataclass
class SecurityFinding:
    category: Category
    name: str
    verdict: Verdict
    statement: str          # Executive-readable one-liner
    detail: str = ""        # Technical detail / next step
    evidence: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["verdict"] = self.verdict.value
        return d


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _graph_get(
    path: str,
    access_token: str,
    params: dict[str, str] | None = None,
) -> requests.Response:
    """Issue a read-only Graph GET. Raises requests exceptions to caller."""
    return requests.get(
        f"{GRAPH_BASE}{path}",
        headers={"Authorization": f"Bearer {access_token}"},
        params=params,
        timeout=HTTP_TIMEOUT_SECONDS,
    )


# ---------------------------------------------------------------------------
# 1. IDENTITY-ANCHORED GOVERNANCE
# ---------------------------------------------------------------------------
#
# Why this matters: observability (logs, metrics) can exist WITHOUT Entra
# Agent ID, but audit, DLP, Defender correlation and Conditional Access
# enforcement all require a durable identity to bind to. If the tenant
# lacks Entra Agent ID (or its workload identity preview features), then
# even if policies exist they cannot target the agent.

def check_identity_anchoring(access_token: str) -> list[SecurityFinding]:
    """Determine whether agents can be identity-anchored in this tenant."""
    findings: list[SecurityFinding] = []

    # Heuristic: look for workload identity / agent service principals.
    # "Agent 365" agents surface as service principals once provisioned.
    # Absence doesn't prove lack of capability, but presence proves readiness.
    try:
        resp = _graph_get(
            "/servicePrincipals",
            access_token,
            params={
                "$top": "5",
                "$select": "id,displayName,servicePrincipalType,tags",
                "$filter": "servicePrincipalType eq 'Application'",
            },
        )
    except requests.RequestException as e:
        findings.append(SecurityFinding(
            category=Category.IDENTITY,
            name="Entra workload identity reachability",
            verdict=Verdict.SKIP,
            statement="Could not evaluate Entra identity surface for agents.",
            detail=f"Network/Graph error: {type(e).__name__}: {e}",
        ))
        return findings

    if resp.status_code == 403:
        findings.append(SecurityFinding(
            category=Category.IDENTITY,
            name="Entra workload identity visibility",
            verdict=Verdict.SKIP,
            statement=(
                "Cannot confirm identity-anchored governance: app lacks "
                "Directory.Read.All to enumerate workload identities."
            ),
            detail="Grant Directory.Read.All (application) to improve accuracy.",
        ))
        return findings

    if resp.status_code != 200:
        findings.append(SecurityFinding(
            category=Category.IDENTITY,
            name="Entra workload identity visibility",
            verdict=Verdict.SKIP,
            statement="Could not evaluate Entra workload identities.",
            detail=f"Graph returned {resp.status_code} {resp.reason}.",
        ))
        return findings

    sps = resp.json().get("value", [])
    findings.append(SecurityFinding(
        category=Category.IDENTITY,
        name="Entra workload identity surface",
        verdict=Verdict.PASS,
        statement=(
            "Tenant exposes Entra workload identities that Agent 365 can "
            "anchor to; audit, DLP and Conditional Access can target agents "
            "once provisioned."
        ),
        detail=(
            "Observability alone is insufficient. Agents MUST be provisioned "
            "with Entra Agent ID (or a dedicated service principal) for "
            "policy enforcement to apply."
        ),
        evidence={"sample_service_principal_count": len(sps)},
    ))

    # Governance gap statement - always emitted as a warning reminder.
    findings.append(SecurityFinding(
        category=Category.IDENTITY,
        name="Observability vs identity-anchored governance",
        verdict=Verdict.WARN,
        statement=(
            "Observability (telemetry) can exist without Entra Agent ID, "
            "but audit, DLP, Defender correlation and Conditional Access "
            "enforcement require identity anchoring."
        ),
        detail=(
            "Until each agent has a durable Entra identity, treat logs as "
            "informational - not as a governance control."
        ),
    ))

    return findings


# ---------------------------------------------------------------------------
# 2. DEFAULT POLICY TEMPLATE AWARENESS
# ---------------------------------------------------------------------------
#
# We check whether Conditional Access policies exist at all, and whether
# any of them could plausibly target workload / agent identities. We do
# NOT claim a policy is bound to a specific agent - we report capability.

def check_policy_readiness(access_token: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []

    # ---- Conditional Access inventory -----------------------------------
    try:
        resp = _graph_get(
            "/identity/conditionalAccess/policies",
            access_token,
            params={"$select": "id,displayName,state,conditions"},
        )
    except requests.RequestException as e:
        findings.append(SecurityFinding(
            category=Category.POLICIES,
            name="Conditional Access inventory",
            verdict=Verdict.SKIP,
            statement="Could not evaluate Conditional Access posture.",
            detail=f"Network/Graph error: {type(e).__name__}: {e}",
        ))
    else:
        if resp.status_code == 403:
            findings.append(SecurityFinding(
                category=Category.POLICIES,
                name="Conditional Access inventory",
                verdict=Verdict.SKIP,
                statement=(
                    "Cannot confirm Conditional Access coverage: app lacks "
                    "Policy.Read.All."
                ),
                detail="Grant Policy.Read.All (application) and admin consent.",
            ))
        elif resp.status_code != 200:
            findings.append(SecurityFinding(
                category=Category.POLICIES,
                name="Conditional Access inventory",
                verdict=Verdict.SKIP,
                statement="Conditional Access inventory unavailable.",
                detail=f"Graph returned {resp.status_code} {resp.reason}.",
            ))
        else:
            policies = resp.json().get("value", [])
            enabled = [p for p in policies if p.get("state") == "enabled"]
            workload_targeted = [
                p for p in enabled
                if _policy_targets_workload_identities(p)
            ]

            if not policies:
                findings.append(SecurityFinding(
                    category=Category.POLICIES,
                    name="Conditional Access policies",
                    verdict=Verdict.FAIL,
                    statement=(
                        "No Conditional Access policies exist; agent sign-ins "
                        "would not be gated by tenant policy."
                    ),
                    detail=(
                        "Create at least one CA policy that includes workload "
                        "identities (requires Entra Workload Identities "
                        "Premium)."
                    ),
                ))
            elif not enabled:
                findings.append(SecurityFinding(
                    category=Category.POLICIES,
                    name="Conditional Access policies",
                    verdict=Verdict.WARN,
                    statement=(
                        "Conditional Access policies exist but none are "
                        "enabled; agent activity would not be policy-gated."
                    ),
                    detail=(
                        f"{len(policies)} policy/policies found, 0 enabled. "
                        "Enable or scope a policy to workload identities."
                    ),
                    evidence={"total": len(policies), "enabled": 0},
                ))
            elif not workload_targeted:
                findings.append(SecurityFinding(
                    category=Category.POLICIES,
                    name="Conditional Access coverage for agents",
                    verdict=Verdict.WARN,
                    statement=(
                        "Conditional Access is active, but no enabled policy "
                        "appears to target workload/agent identities."
                    ),
                    detail=(
                        "Policies exist but are not yet BOUND to agents. Add "
                        "a CA policy with 'Workload identities' in 'Assignments "
                        "> Users or workload identities'."
                    ),
                    evidence={
                        "total_enabled": len(enabled),
                        "workload_targeted": 0,
                    },
                ))
            else:
                findings.append(SecurityFinding(
                    category=Category.POLICIES,
                    name="Conditional Access coverage for agents",
                    verdict=Verdict.PASS,
                    statement=(
                        "Conditional Access policies targeting workload "
                        "identities are enabled; agent sign-ins can be "
                        "policy-enforced."
                    ),
                    detail=(
                        "Verify each onboarded agent's service principal is "
                        "in scope of these policies."
                    ),
                    evidence={
                        "total_enabled": len(enabled),
                        "workload_targeted": len(workload_targeted),
                    },
                ))

    # ---- Security defaults (fallback floor) -----------------------------
    try:
        resp = _graph_get(
            "/policies/identitySecurityDefaultsEnforcementPolicy",
            access_token,
        )
    except requests.RequestException:
        pass
    else:
        if resp.status_code == 200:
            enabled = bool(resp.json().get("isEnabled"))
            if enabled:
                findings.append(SecurityFinding(
                    category=Category.POLICIES,
                    name="Entra security defaults",
                    verdict=Verdict.WARN,
                    statement=(
                        "Security defaults are enabled. They provide a baseline "
                        "but cannot target workload identities with fine-grained "
                        "rules."
                    ),
                    detail=(
                        "Plan to migrate to Conditional Access with workload "
                        "identity scoping for governed agent onboarding."
                    ),
                ))

    return findings


def _policy_targets_workload_identities(policy: dict[str, Any]) -> bool:
    """Heuristic: does a CA policy include workload identities?"""
    conditions = policy.get("conditions") or {}
    users = conditions.get("users") or {}
    # Graph exposes includeGuestsOrExternalUsers and
    # clientApplications.includeServicePrincipals for workload-targeted rules.
    client_apps = conditions.get("clientApplications") or {}
    include_sps = client_apps.get("includeServicePrincipals") or []
    # An "All" or non-empty list means workload identities are in scope.
    if include_sps and include_sps != ["None"]:
        return True
    # Some older policies use includeUsers=All - still ambiguous, treat as False.
    _ = users
    return False


# ---------------------------------------------------------------------------
# 3. AUDIT COVERAGE (Microsoft Purview) + DLP + Defender capability
# ---------------------------------------------------------------------------

def check_audit_coverage(access_token: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []

    # ---- Purview audit log reachability ---------------------------------
    try:
        resp = _graph_get(
            "/auditLogs/directoryAudits",
            access_token,
            params={"$top": "1"},
        )
    except requests.RequestException as e:
        findings.append(SecurityFinding(
            category=Category.AUDIT_DLP,
            name="Purview audit log reachability",
            verdict=Verdict.SKIP,
            statement="Could not evaluate audit log coverage.",
            detail=f"Network/Graph error: {type(e).__name__}: {e}",
        ))
    else:
        if resp.status_code == 200:
            findings.append(SecurityFinding(
                category=Category.AUDIT_DLP,
                name="Purview audit log reachability",
                verdict=Verdict.PASS,
                statement=(
                    "Agent actions will be recorded in Microsoft Purview "
                    "audit logs once agents are identity-anchored."
                ),
                detail=(
                    "Audit records depend on each agent having an Entra "
                    "identity; without it, actions will NOT appear in audit."
                ),
            ))
        elif resp.status_code == 403:
            findings.append(SecurityFinding(
                category=Category.AUDIT_DLP,
                name="Purview audit log reachability",
                verdict=Verdict.SKIP,
                statement="Cannot confirm audit coverage (permission missing).",
                detail="Grant AuditLog.Read.All (application) and admin consent.",
            ))
        else:
            findings.append(SecurityFinding(
                category=Category.AUDIT_DLP,
                name="Purview audit log reachability",
                verdict=Verdict.FAIL,
                statement=(
                    "Audit log endpoint unreachable; in current state, agent "
                    "actions may NOT be auditable."
                ),
                detail=f"Graph returned {resp.status_code} {resp.reason}.",
            ))

    # ---- Licensing-based capability: DLP / Defender / Purview -----------
    sku_service_plans = _collect_service_plan_names(access_token)
    if sku_service_plans is None:
        findings.append(SecurityFinding(
            category=Category.AUDIT_DLP,
            name="Governance licensing",
            verdict=Verdict.SKIP,
            statement="Cannot evaluate DLP / Defender / Purview licensing.",
            detail="Grant Organization.Read.All to enumerate subscribed SKUs.",
        ))
    else:
        findings.append(_licensing_finding(
            name="Microsoft Purview audit capability",
            statement_pass=(
                "Purview audit/compliance licensing detected; audit retention "
                "and search will apply to agent actions."
            ),
            statement_fail=(
                "No Purview audit/compliance SKU detected; agent actions may "
                "not be retained or searchable for security review."
            ),
            hints=PURVIEW_AUDIT_SKU_HINTS,
            service_plans=sku_service_plans,
        ))
        findings.append(_licensing_finding(
            name="Data Loss Prevention (DLP) capability",
            statement_pass=(
                "DLP-capable licensing detected; DLP policies CAN be enforced "
                "on agent-initiated data access once agents are identified."
            ),
            statement_fail=(
                "No DLP-capable SKU detected; agent-initiated data sharing "
                "would BYPASS DLP in current state."
            ),
            hints=DLP_SKU_HINTS,
            service_plans=sku_service_plans,
        ))
        findings.append(_licensing_finding(
            name="Microsoft Defender correlation capability",
            statement_pass=(
                "Defender licensing detected; agent signals can be correlated "
                "into incidents once identity-anchored."
            ),
            statement_fail=(
                "No Defender SKU detected; agent activity will not generate "
                "correlated security alerts."
            ),
            hints=DEFENDER_SKU_HINTS,
            service_plans=sku_service_plans,
        ))

    return findings


def _collect_service_plan_names(access_token: str) -> list[str] | None:
    try:
        resp = _graph_get("/subscribedSkus", access_token)
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    names: list[str] = []
    for sku in resp.json().get("value", []):
        for plan in sku.get("servicePlans") or []:
            name = (plan.get("servicePlanName") or "").lower()
            if name:
                names.append(name)
    return names


def _licensing_finding(
    *,
    name: str,
    statement_pass: str,
    statement_fail: str,
    hints: set[str],
    service_plans: list[str],
) -> SecurityFinding:
    matched = [p for p in service_plans if any(h in p for h in hints)]
    if matched:
        return SecurityFinding(
            category=Category.AUDIT_DLP,
            name=name,
            verdict=Verdict.PASS,
            statement=statement_pass,
            detail="Licensing exists; confirm policies are bound to agents.",
            evidence={"matched_service_plans": matched[:5]},
        )
    return SecurityFinding(
        category=Category.AUDIT_DLP,
        name=name,
        verdict=Verdict.FAIL,
        statement=statement_fail,
        detail="Acquire the appropriate SKU before onboarding agents.",
    )


def _rollup_risk(findings: list[SecurityFinding]) -> Verdict:
    if any(f.verdict is Verdict.FAIL for f in findings):
        return Verdict.FAIL
    if any(f.verdict is Verdict.WARN for f in findings):
        return Verdict.WARN
    return Verdict.PASS


def _risk_statement(findings: list[SecurityFinding]) -> str:
    if any(f.verdict is Verdict.FAIL for f in findings):
        return (
            "In current state, agent actions would BYPASS one or more of: "
            "Purview audit, DLP, Conditional Access. Remediate FAIL items "
            "before onboarding."
        )
    if any(f.verdict is Verdict.WARN for f in findings):
        return (
            "Controls exist but are not yet BOUND to agent identities. Agents "
            "may operate with partial governance until bindings are complete."
        )
    return (
        "Agent actions will be audited and policy-enforced once identity is "
        "established."
    )


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

def run_security_checks(access_token: str) -> list[SecurityFinding]:
    """Run all security/governance pre-flight checks.

    Returns a list of SecurityFinding ordered: Identity, Policies, Audit/DLP,
    followed by an overall Risk Classification rollup.
    Safe to serialize each finding via .to_dict() for JSON/Markdown export.
    """
    findings: list[SecurityFinding] = []
    findings.extend(check_identity_anchoring(access_token))
    findings.extend(check_policy_readiness(access_token))
    findings.extend(check_audit_coverage(access_token))

    # Overall rollup - computed across ALL findings from every category.
    findings.append(SecurityFinding(
        category=Category.AUDIT_DLP,
        name="Risk classification - current bypass posture",
        verdict=_rollup_risk(findings),
        statement=_risk_statement(findings),
        detail=(
            "Heuristic rollup across Identity / Policies / Audit & DLP. Any "
            "FAIL means agent actions would currently bypass that control."
        ),
    ))
    return findings


def findings_to_markdown(findings: list[SecurityFinding]) -> str:
    """Render findings as a Markdown table grouped by category."""
    icon = {Verdict.PASS: "✅", Verdict.WARN: "⚠️",
            Verdict.FAIL: "❌", Verdict.SKIP: "⏭️"}
    lines: list[str] = ["# Agent 365 Security & Governance Readiness", ""]
    for cat in Category:
        scoped = [f for f in findings if f.category is cat]
        if not scoped:
            continue
        lines.append(f"## {cat.value.replace('_', ' ').title()}")
        lines.append("")
        lines.append("| Status | Check | Statement |")
        lines.append("|--------|-------|-----------|")
        for f in scoped:
            statement = f.statement.replace("|", "\\|")
            lines.append(f"| {icon[f.verdict]} | {f.name} | {statement} |")
        lines.append("")
    return "\n".join(lines)
