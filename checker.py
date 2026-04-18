"""
Agent 365 Readiness & Pre-Flight Checker
Validates that your Azure/Entra environment is configured correctly
before attempting Agent 365 SDK or API integration.
"""

import os
import sys
from typing import Dict, List, Tuple
from dotenv import load_dotenv
from msal import ConfidentialClientApplication
import requests

# Load environment variables from .env file
load_dotenv()

# ANSI color codes for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"


class Agent365PreflightChecker:
    """Performs pre-flight checks for Agent 365 onboarding."""

    def __init__(self):
        self.tenant_id = os.getenv("TENANT_ID")
        self.client_id = os.getenv("CLIENT_ID")
        self.client_secret = os.getenv("CLIENT_SECRET")
        self.frontier_enabled = os.getenv("FRONTIER_PREVIEW_ENABLED", "false").lower() == "true"
        self.checks_passed = 0
        self.checks_failed = 0
        self.results: List[Tuple[str, bool, str]] = []

    def print_header(self, text: str) -> None:
        """Print a formatted header."""
        print(f"\n{BLUE}{BOLD}{'='*60}")
        print(f"  {text}")
        print(f"{'='*60}{RESET}\n")

    def print_result(self, check_name: str, passed: bool, message: str) -> None:
        """Print a check result with appropriate coloring."""
        status = f"{GREEN}✅ PASS{RESET}" if passed else f"{RED}❌ FAIL{RESET}"
        print(f"{status}  {check_name}")
        if message:
            print(f"     {message}\n")
        else:
            print()
        
        self.results.append((check_name, passed, message))
        if passed:
            self.checks_passed += 1
        else:
            self.checks_failed += 1

    def check_environment_variables(self) -> bool:
        """Check that all required environment variables are set."""
        self.print_header("1. Environment Variables")
        
        required_vars = ["TENANT_ID", "CLIENT_ID", "CLIENT_SECRET"]
        all_present = True
        
        for var in required_vars:
            value = os.getenv(var)
            if value:
                self.print_result(
                    f"Environment variable: {var}",
                    True,
                    "✓ Configured"
                )
            else:
                self.print_result(
                    f"Environment variable: {var}",
                    False,
                    f"❌ Not set. Create a .env file or set {var} in your environment."
                )
                all_present = False
        
        return all_present

    def check_frontier_preview(self) -> bool:
        """Check if Frontier preview is enabled (informational)."""
        self.print_header("2. Frontier Preview Enrollment")
        
        if self.frontier_enabled:
            self.print_result(
                "Frontier preview enrollment",
                True,
                "✓ Enabled"
            )
            return True
        else:
            self.print_result(
                "Frontier preview enrollment",
                False,
                "⚠ Not enabled. Set FRONTIER_PREVIEW_ENABLED=true if you have access."
            )
            return False

    def check_entra_app_registration(self) -> bool:
        """Check that Entra app registration details are valid."""
        self.print_header("3. Entra App Registration")
        
        # Basic validation that IDs look reasonable
        if not self.tenant_id or len(self.tenant_id) < 10:
            self.print_result(
                "Tenant ID format",
                False,
                "❌ TENANT_ID appears invalid. Check Azure Portal > Tenant properties."
            )
            return False
        
        self.print_result(
            "Tenant ID format",
            True,
            f"✓ Tenant ID looks valid: {self.tenant_id[:8]}..."
        )
        
        if not self.client_id or len(self.client_id) < 20:
            self.print_result(
                "Application (Client) ID format",
                False,
                "❌ CLIENT_ID appears invalid. Check Azure Portal > App registrations."
            )
            return False
        
        self.print_result(
            "Application (Client) ID format",
            True,
            f"✓ Application ID looks valid: {self.client_id[:8]}..."
        )
        
        if not self.client_secret:
            self.print_result(
                "Client secret",
                False,
                "❌ CLIENT_SECRET not set. Create a secret in Certificates & secrets."
            )
            return False
        
        self.print_result(
            "Client secret",
            True,
            "✓ Client secret is configured"
        )
        
        return True

    def check_token_acquisition(self) -> Tuple[bool, str]:
        """Attempt to acquire a token from Entra ID."""
        self.print_header("4. Token Acquisition")
        
        try:
            authority = f"https://login.microsoftonline.com/{self.tenant_id}"
            scope = ["https://graph.microsoft.com/.default"]
            
            app = ConfidentialClientApplication(
                client_id=self.client_id,
                client_credential=self.client_secret,
                authority=authority
            )
            
            result = app.acquire_token_for_client(scopes=scope)
            
            if "access_token" in result:
                self.print_result(
                    "Token acquisition from Entra ID",
                    True,
                    "✓ Successfully acquired access token"
                )
                return True, result["access_token"]
            else:
                error_msg = result.get("error_description", result.get("error", "Unknown error"))
                self.print_result(
                    "Token acquisition from Entra ID",
                    False,
                    f"❌ Token acquisition failed: {error_msg}"
                )
                return False, ""
        
        except Exception as e:
            self.print_result(
                "Token acquisition from Entra ID",
                False,
                f"❌ Exception during token acquisition: {str(e)}"
            )
            return False, ""

    def check_graph_permissions(self, access_token: str) -> bool:
        """Verify that required Graph permissions are granted."""
        self.print_header("5. Microsoft Graph Permissions")
        
        if not access_token:
            self.print_result(
                "Graph API access",
                False,
                "⏭ Skipped (no token available)"
            )
            return False
        
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            
            # Test basic Graph connectivity
            resp = requests.get(
                "https://graph.microsoft.com/v1.0/organization",
                headers=headers,
                timeout=10
            )
            
            if resp.status_code == 200:
                self.print_result(
                    "Microsoft Graph connectivity (GET /organization)",
                    True,
                    "✓ Successfully called Graph API"
                )
                return True
            elif resp.status_code == 403:
                self.print_result(
                    "Microsoft Graph connectivity (GET /organization)",
                    False,
                    "❌ Permission denied. Required permission 'Organization.Read.All' may not be granted."
                )
                return False
            elif resp.status_code == 401:
                self.print_result(
                    "Microsoft Graph connectivity (GET /organization)",
                    False,
                    "❌ Unauthorized. Token may be invalid or expired."
                )
                return False
            else:
                self.print_result(
                    "Microsoft Graph connectivity (GET /organization)",
                    False,
                    f"❌ Unexpected response: {resp.status_code} {resp.reason}"
                )
                return False
        
        except requests.exceptions.Timeout:
            self.print_result(
                "Microsoft Graph connectivity (GET /organization)",
                False,
                "❌ Request timeout. Check your internet connection."
            )
            return False
        except requests.exceptions.RequestException as e:
            self.print_result(
                "Microsoft Graph connectivity (GET /organization)",
                False,
                f"❌ Network error: {str(e)}"
            )
            return False

    def print_summary(self) -> None:
        """Print a summary of all checks."""
        self.print_header("Summary")
        
        total = self.checks_passed + self.checks_failed
        pass_rate = (self.checks_passed / total * 100) if total > 0 else 0
        
        print(f"Total checks: {total}")
        print(f"Passed: {GREEN}{self.checks_passed}{RESET}")
        print(f"Failed: {RED}{self.checks_failed}{RESET}")
        print(f"Pass rate: {pass_rate:.0f}%\n")
        
        if self.checks_failed == 0:
            print(f"{GREEN}{BOLD}✅ All critical checks passed! Your environment is ready for Agent 365 SDK integration.{RESET}\n")
            return True
        else:
            print(f"{RED}{BOLD}❌ Some checks failed. Please fix the issues above before proceeding.{RESET}\n")
            return False

    def run(self) -> bool:
        """Run all pre-flight checks."""
        print(f"\n{BOLD}{BLUE}Agent 365 Readiness & Pre-Flight Checker{RESET}")
        print(f"{BLUE}Version 1.0.0 - Ready to validate your environment{RESET}\n")
        
        # Run checks in sequence
        env_ok = self.check_environment_variables()
        
        if not env_ok:
            print(f"\n{RED}{BOLD}❌ Environment variables not configured. Cannot proceed.{RESET}\n")
            return False
        
        self.check_frontier_preview()
        self.check_entra_app_registration()
        token_ok, token = self.check_token_acquisition()
        
        if token_ok:
            self.check_graph_permissions(token)
        
        # Print summary and return overall status
        return self.print_summary()


def main():
    """Main entry point."""
    checker = Agent365PreflightChecker()
    success = checker.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
