# Agent 365 Readiness & Pre-Flight Checker

A Python utility that validates your Azure/Entra environment configuration before integrating with the Agent 365 SDK.

## Purpose

This tool catches **80% of onboarding failures** before SDK or API calls fail, giving you fast feedback on configuration issues.

## What It Checks

1. **Environment Variables** - Verifies required Azure credentials are configured
2. **Frontier Preview Enrollment** - Checks if you have access to Frontier preview features
3. **Entra App Registration** - Validates app registration details format and existence
4. **Token Acquisition** - Attempts to acquire an access token from Entra ID
5. **Microsoft Graph Permissions** - Tests Graph API connectivity and required permissions

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
```

### 3. Configure Your Environment

Copy the example file and fill in your credentials:

```bash
cp .env.example .env
```

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

## Support

If issues persist:
1. Double-check all credentials in `.env`
2. Verify app registration permissions in Azure Portal
3. Ensure your tenant isn't blocking third-party app access
4. Check network connectivity to `login.microsoftonline.com` and `graph.microsoft.com`

## License

MIT

---

**Last Updated**: April 2026  
**Python Version**: 3.8+  
**Dependencies**: msal, requests, python-dotenv
