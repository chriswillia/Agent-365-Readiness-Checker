# Agent 365 Readiness & Pre-Flight Checker

A Python utility that validates your Azure/Entra environment configuration before integrating with the Agent 365 SDK.

![CI](https://github.com/chriswillia/Agent-365-Readiness-Checker/actions/workflows/ci.yml/badge.svg)

## Purpose

This tool catches **80% of onboarding failures** before SDK or API calls fail, giving you fast feedback on configuration issues.

## What It Checks

1. **Environment Variables** - Verifies required Azure credentials are configured
2. **Frontier Preview Enrollment** - Checks if you have access to Frontier preview features
3. **Entra App Registration** - Validates app registration details format and existence
4. **Token Acquisition** - Attempts to acquire an access token from Entra ID
5. **Microsoft Graph Permissions** - Tests Graph API connectivity and required permissions
6. **Security & Governance Readiness** *(opt-in via `--security`)* - Identity anchoring,
   Conditional Access coverage, Purview audit reachability, DLP / Defender
   licensing posture. See [Security & Governance Checks](#security--governance-checks).

## Quick Start

### 1. Prerequisites

- Python 3.8 or higher
- An Azure subscription with Entra ID
- An Entra app registration with:
  - A client secret configured
  - **Microsoft Graph** API permission: `Organization.Read.All`

### 2. Setup

Clone or download this repository, then install dependencies:

```bash
pip install -r requirements.txt
# or, as an installable package with console entry point:
pip install -e .
```

After `pip install -e .`, the checker is available as:

```bash
agent365-preflight --security
```

### 3. Configure Your Environment

Copy the example file and fill in your credentials:

```bash
# Option 1 (dev only): client secret
CLIENT_SECRET=your-client-secret
# Option 2 (recommended for production): certificate auth
# CLIENT_CERT_PATH=./cert.pem
# CLIENT_CERT_THUMBPRINT=AA11BB22...
FRONTIER_PREVIEW_ENABLED=false
```

Certificate auth takes precedence when both `CLIENT_CERT_PATH` and
`CLIENT_CERT_THUMBPRINT` are set.
Edit `.env` with your Azure details:

```
TENANT_ID=your-tenant-id
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret
FRONTIER_PREVIEW_ENABLED=false
```

**Where to find these values:**

- **TENANT_ID**: Azure Portal → Azure Active Directory → Tenant properties → Tenant ID
- **CLIENT_ID**: Azure Portal → App registrations → Your app → Application (client) ID
- **CLIENT_SECRET**: Azure Portal → App registrations → Your app → Certificates & secrets → New client secret

### 4. Run the Checker

```bash
python checker.py
```

## Example Output

```
============================================================
  Agent 365 Readiness & Pre-Flight Checker
============================================================

✅ PASS  Environment variable: TENANT_ID
         ✓ Configured

✅ PASS  Environment variable: CLIENT_ID
         ✓ Configured

✅ PASS  Environment variable: CLIENT_SECRET
         ✓ Configured

============================================================
  Frontier Preview Enrollment
============================================================

❌ FAIL  Frontier preview enrollment
         ⚠ Not enabled. Set FRONTIER_PREVIEW_ENABLED=true if you have access.

============================================================
  Token Acquisition
============================================================

✅ PASS  Token acquisition from Entra ID
         ✓ Successfully acquired access token

============================================================
  Microsoft Graph Permissions
============================================================

✅ PASS  Microsoft Graph connectivity (GET /organization)
         ✓ Successfully called Graph API

============================================================
  Summary
============================================================

Total checks: 7
Passed: 6
Failed: 1
Pass rate: 86%
- **1** - One or more critical checks failed
- **2** - Security findings FAIL when `--fail-on-security` is set
✅ All critical checks passed! Your environment is ready for Agent 365 SDK integration.
```

## Exit Codes

- **0** - All critical checks passed ✅
- **1** - One or more critical checks failed ❌

## Troubleshooting

### "Token acquisition failed"
- Verify CLIENT_ID and CLIENT_SECRET are correct
- Ensure the client secret hasn't expired (regenerate if needed)
- Check that your app registration exists in Entra ID

### "Permission denied" (403 error)
- Grant **Organization.Read.All** permission to your app registration:
  1. Azure Portal → App registrations → Your app
  2. API permissions → Add a permission
  3. Select Microsoft Graph → Application permissions
  4. Search for "Organization" and select **Organization.Read.All**
  5. Click "Grant admin consent"

### "Unauthorized" (401 error)
- Token may have expired (shouldn't happen in this flow)
- Client credentials may be invalid
- Try regenerating the client secret

## What Happens Next?

Once all checks pass, you're ready to:
- Integrate the Agent 365 SDK
- Make authenticated API calls to Microsoft Graph
- Deploy Agent 365 features in your tenant

## Security & Governance Checks

Run with `--security` to evaluate whether agents will be **governed, audited,
and policy-enforced** once onboarded. These are read-only, heuristic,
pre-flight checks grouped into three categories:

- **Identity** — Is Entra Agent ID / workload identity available so agents
  can be identity-anchored? Observability can exist without identity, but
  audit, DLP, Conditional Access and Defender correlation all require it.
- **Policies** — Do Conditional Access policies exist, and do any target
  workload identities? Distinguishes "policies exist but are not yet bound"
  from "policies unavailable".
- **Audit & DLP** — Is Microsoft Purview audit reachable, and does the
  tenant have licensing (Purview / DLP / Defender) that enables governance
  signals to apply to agent actions.

### Additional Graph permissions (recommended for `--security`)

| Permission               | Used by                                         |
| ------------------------ | ----------------------------------------------- |
| `Directory.Read.All`     | Enumerate workload service principals            |
| `Policy.Read.All`        | Read Conditional Access + Security Defaults     |
| `AuditLog.Read.All`      | Confirm Purview audit reachability              |
| `Organization.Read.All`  | Enumerate subscribed SKUs (licensing heuristic) |

Missing permissions produce `SKIP` findings, not failures.

### Usage

```bash
# Human-readable security report alongside standard checks
python checker.py --security

# JSON for CI / security review tooling
python checker.py --security --json

# Export a Markdown report for a security sign-off ticket
python checker.py --security-markdown security-report.md
```

### Example security output

```
[PASS]  (IDENTITY) Entra workload identity surface
       Tenant exposes Entra workload identities that Agent 365 can anchor to...

[WARN]  (POLICIES) Conditional Access coverage for agents
       Conditional Access is active, but no enabled policy appears to target
       workload/agent identities.
       -> Policies exist but are not yet BOUND to agents.

[FAIL]  (AUDIT/DLP) Data Loss Prevention (DLP) capability
       No DLP-capable SKU detected; agent-initiated data sharing would
       BYPASS DLP in current state.

[WARN]  (AUDIT/DLP) Risk classification - current bypass posture
       Controls exist but are not yet BOUND to agent identities.
```
Development

```bash
pip install -e ".[dev]"
ruff check .
pytest -v
```

Tests mock MSAL and Microsoft Graph, so no live tenant is required.

## 
## Support

If issues persist:
1. Double-check all credenti
**Python Version**: 3.9+ permissions in Azure Portal
3. Ensure your tenant isn't blocking third-party app access
4. Check network connectivity to `login.microsoftonline.com` and `graph.microsoft.com`

## License

MIT

---

**Last Updated**: April 2026  
**Python Version**: 3.8+  
**Dependencies**: msal, requests, python-dotenv
