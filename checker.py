"""
Agent 365 Readiness & Pre-Flight Checker
Validates that your Azure/Entra environment is configured correctly
before attempting Agent 365 SDK or API integration.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from enum import Enum
from typing import List, Optional

from dotenv import load_dotenv
from msal import ConfidentialClientApplication
import requests

from security_checks import (
    SecurityFinding,
    Verdict,
    run_security_checks,
    findings_to_markdown,
)


# --- Constants ---------------------------------------------------------------

AUTHORITY_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}"
GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH_ORG_ENDPOINT = "https://graph.microsoft.com/v1.0/organization"
HTTP_TIMEOUT_SECONDS = 10
GUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# ANSI color codes
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"


# --- Data model --------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"


@dataclass
class CheckResult:
    name: str
    status: Status
    message: str
    severity: Severity = Severity.CRITICAL


# --- Output helpers ----------------------------------------------------------

def _colors_enabled() -> bool:
    """Return True if terminal color output should be used."""
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        # Enable ANSI processing on Windows 10+ consoles.
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            return False
    return True


class Printer:
    def __init__(self, quiet: bool = False, use_color: Optional[bool] = None) -> None:
        self.quiet = quiet
        self.use_color = _colors_enabled() if use_color is None else use_color

    def _c(self, text: str, color: str) -> str:
        return f"{color}{text}{RESET}" if self.use_color else text

    def header(self, text: str) -> None:
        if self.quiet:
            return
        bar = "=" * 60
        print(f"\n{self._c(bar, BLUE + BOLD)}")
        print(self._c(f"  {text}", BLUE + BOLD))
        print(self._c(bar, BLUE + BOLD) + "\n")

    def info(self, text: str) -> None:
        if not self.quiet:
            print(text)

    def result(self, result: CheckResult) -> None:
        if self.quiet:
            return
        if result.status is Status.PASS:
            status = self._c("PASS", GREEN)
        elif result.status is Status.FAIL:
            label = "FAIL" if result.severity is Severity.CRITICAL else "WARN"
            color = RED if result.severity is Severity.CRITICAL else YELLOW
            status = self._c(label, color)
        else:
            status = self._c("SKIP", YELLOW)
        print(f"[{status}]  {result.name}")
        if result.message:
            print(f"       {result.message}")
        print()


# --- Checker -----------------------------------------------------------------

class Agent365PreflightChecker:
    """Performs pre-flight checks for Agent 365 onboarding."""

    def __init__(
        self,
        printer: Printer,
        skip_graph: bool = False,
        run_security: bool = False,
    ) -> None:
        self.printer = printer
        self.skip_graph = skip_graph
        self.run_security = run_security
        self.tenant_id = os.getenv("TENANT_ID", "").strip()
        self.client_id = os.getenv("CLIENT_ID", "").strip()
        self.client_secret = os.getenv("CLIENT_SECRET", "").strip()
        self.frontier_enabled = (
            os.getenv("FRONTIER_PREVIEW_ENABLED", "false").strip().lower() == "true"
        )
        self.results: List[CheckResult] = []
        self.security_findings: List[SecurityFinding] = []

    # ---- utilities -----------------------------------------------------

    def _record(self, result: CheckResult) -> CheckResult:
        self.results.append(result)
        self.printer.result(result)
        return result

    @staticmethod
    def _mask(value: str, keep: int = 8) -> str:
        if not value:
            return "<empty>"
        if len(value) <= keep:
            return "*" * len(value)
        return f"{value[:keep]}...({len(value)} chars)"

    # ---- checks --------------------------------------------------------

    def check_environment_variables(self) -> bool:
        self.printer.header("1. Environment Variables")
        required = ["TENANT_ID", "CLIENT_ID", "CLIENT_SECRET"]
        all_present = True
        for var in required:
            value = os.getenv(var, "").strip()
            if value:
                self._record(CheckResult(
                    name=f"Environment variable: {var}",
                    status=Status.PASS,
                    message="Configured",
                ))
            else:
                self._record(CheckResult(
                    name=f"Environment variable: {var}",
                    status=Status.FAIL,
                    message=f"Not set. Create a .env file or set {var} in your environment.",
                ))
                all_present = False
        return all_present

    def check_frontier_preview(self) -> None:
        self.printer.header("2. Frontier Preview Enrollment (informational)")
        if self.frontier_enabled:
            self._record(CheckResult(
                name="Frontier preview enrollment",
                status=Status.PASS,
                message="Enabled",
                severity=Severity.WARNING,
            ))
        else:
            self._record(CheckResult(
                name="Frontier preview enrollment",
                status=Status.FAIL,
                message="Not enabled. Set FRONTIER_PREVIEW_ENABLED=true if you have access.",
                severity=Severity.WARNING,
            ))

    def check_entra_app_registration(self) -> bool:
        self.printer.header("3. Entra App Registration")
        ok = True

        if GUID_PATTERN.match(self.tenant_id):
            self._record(CheckResult(
                name="Tenant ID format",
                status=Status.PASS,
                message=f"Valid GUID ({self._mask(self.tenant_id)})",
            ))
        else:
            self._record(CheckResult(
                name="Tenant ID format",
                status=Status.FAIL,
                message="TENANT_ID is not a valid GUID. Check Azure Portal > Tenant properties.",
            ))
            ok = False

        if GUID_PATTERN.match(self.client_id):
            self._record(CheckResult(
                name="Application (Client) ID format",
                status=Status.PASS,
                message=f"Valid GUID ({self._mask(self.client_id)})",
            ))
        else:
            self._record(CheckResult(
                name="Application (Client) ID format",
                status=Status.FAIL,
                message="CLIENT_ID is not a valid GUID. Check Azure Portal > App registrations.",
            ))
            ok = False

        if self.client_secret:
            self._record(CheckResult(
                name="Client secret",
                status=Status.PASS,
                message="Client secret is configured",
            ))
        else:
            self._record(CheckResult(
                name="Client secret",
                status=Status.FAIL,
                message="CLIENT_SECRET not set. Create a secret in Certificates & secrets.",
            ))
            ok = False

        return ok

    def check_token_acquisition(self) -> Optional[str]:
        self.printer.header("4. Token Acquisition")
        try:
            app = ConfidentialClientApplication(
                client_id=self.client_id,
                client_credential=self.client_secret,
                authority=AUTHORITY_TEMPLATE.format(tenant_id=self.tenant_id),
            )
            result = app.acquire_token_for_client(scopes=GRAPH_SCOPE)
        except Exception as e:
            self._record(CheckResult(
                name="Token acquisition from Entra ID",
                status=Status.FAIL,
                message=f"Exception during token acquisition: {type(e).__name__}: {e}",
            ))
            return None

        if isinstance(result, dict) and "access_token" in result:
            self._record(CheckResult(
                name="Token acquisition from Entra ID",
                status=Status.PASS,
                message="Successfully acquired access token",
            ))
            return result["access_token"]

        result = result or {}
        error = result.get("error", "unknown_error")
        description_raw = result.get("error_description", "")
        description = description_raw.splitlines()[0] if description_raw else ""
        self._record(CheckResult(
            name="Token acquisition from Entra ID",
            status=Status.FAIL,
            message=f"Token acquisition failed: {error}. {description}".strip(),
        ))
        return None

    def check_graph_permissions(self, access_token: Optional[str]) -> None:
        self.printer.header("5. Microsoft Graph Permissions")

        if self.skip_graph:
            self._record(CheckResult(
                name="Microsoft Graph connectivity",
                status=Status.SKIP,
                message="Skipped by --skip-graph flag",
            ))
            return

        if not access_token:
            self._record(CheckResult(
                name="Microsoft Graph connectivity",
                status=Status.SKIP,
                message="Skipped (no token available)",
            ))
            return

        messages = {
            401: "Unauthorized. Token may be invalid or expired.",
            403: "Permission denied. Grant 'Organization.Read.All' (application permission) and admin consent.",
        }

        try:
            resp = requests.get(
                GRAPH_ORG_ENDPOINT,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=HTTP_TIMEOUT_SECONDS,
            )
        except requests.exceptions.Timeout:
            self._record(CheckResult(
                name="Microsoft Graph connectivity (GET /organization)",
                status=Status.FAIL,
                message="Request timeout. Check your internet connection.",
            ))
            return
        except requests.exceptions.RequestException as e:
            self._record(CheckResult(
                name="Microsoft Graph connectivity (GET /organization)",
                status=Status.FAIL,
                message=f"Network error: {type(e).__name__}: {e}",
            ))
            return

        if resp.status_code == 200:
            self._record(CheckResult(
                name="Microsoft Graph connectivity (GET /organization)",
                status=Status.PASS,
                message="Successfully called Graph API",
            ))
            return

        self._record(CheckResult(
            name="Microsoft Graph connectivity (GET /organization)",
            status=Status.FAIL,
            message=messages.get(
                resp.status_code,
                f"Unexpected response: {resp.status_code} {resp.reason}",
            ),
        ))

    # ---- orchestration -------------------------------------------------

    def run(self) -> bool:
        self.printer.info("")
        self.printer.info("Agent 365 Readiness & Pre-Flight Checker")
        self.printer.info("Version 1.1.0")

        env_ok = self.check_environment_variables()
        self.check_frontier_preview()

        if not env_ok:
            self.printer.info(
                "\nEnvironment variables not configured. Skipping remaining checks.\n"
            )
            return self._summary()

        app_ok = self.check_entra_app_registration()
        token = self.check_token_acquisition() if app_ok else None
        self.check_graph_permissions(token)

        if self.run_security and token and not self.skip_graph:
            self._run_security_checks(token)

        return self._summary()

    # ---- security checks ----------------------------------------------

    def _run_security_checks(self, access_token: str) -> None:
        self.printer.header("6. Security & Governance Readiness")
        self.security_findings = run_security_checks(access_token)
        if not self.printer.quiet:
            for f in self.security_findings:
                self._render_finding(f)

    def _render_finding(self, f: SecurityFinding) -> None:
        icon_and_color = {
            Verdict.PASS: ("PASS", GREEN),
            Verdict.WARN: ("WARN", YELLOW),
            Verdict.FAIL: ("FAIL", RED),
            Verdict.SKIP: ("SKIP", YELLOW),
        }
        label, color = icon_and_color[f.verdict]
        status = self.printer._c(label, color)
        cat = f.category.value.replace("_", "/").upper()
        print(f"[{status}]  ({cat}) {f.name}")
        print(f"       {f.statement}")
        if f.detail:
            print(f"       -> {f.detail}")
        print()

    # ---- summary -------------------------------------------------------

    def _summary(self) -> bool:
        self.printer.header("Summary")

        critical_pass = sum(
            1 for r in self.results
            if r.severity is Severity.CRITICAL and r.status is Status.PASS
        )
        critical_fail = sum(
            1 for r in self.results
            if r.severity is Severity.CRITICAL and r.status is Status.FAIL
        )
        warnings = sum(
            1 for r in self.results
            if r.severity is Severity.WARNING and r.status is Status.FAIL
        )
        skipped = sum(1 for r in self.results if r.status is Status.SKIP)
        total_critical = critical_pass + critical_fail
        pass_rate = (critical_pass / total_critical * 100) if total_critical else 0

        self.printer.info(f"Critical checks: {total_critical}")
        self.printer.info(f"  Passed:   {critical_pass}")
        self.printer.info(f"  Failed:   {critical_fail}")
        self.printer.info(f"Warnings: {warnings}")
        self.printer.info(f"Skipped:  {skipped}")
        self.printer.info(f"Critical pass rate: {pass_rate:.0f}%\n")

        success = critical_fail == 0
        if success:
            self.printer.info(
                "All critical checks passed. Your environment is ready for Agent 365 SDK integration."
            )
        else:
            self.printer.info(
                "Some critical checks failed. Please fix the issues above before proceeding."
            )
        return success


# --- CLI ---------------------------------------------------------------------

def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agent365-preflight",
        description="Validate Azure/Entra environment readiness for Agent 365.",
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to a .env file to load (default: .env).",
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit results as JSON (suppresses human-readable output).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-check output; only print the summary or JSON.",
    )
    parser.add_argument(
        "--skip-graph",
        action="store_true",
        help="Skip the Microsoft Graph connectivity check (offline mode).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output.",
    )
    parser.add_argument(
        "--security",
        action="store_true",
        help=(
            "Run security & governance readiness checks "
            "(Identity / Policies / Audit & DLP). Requires a valid token."
        ),
    )
    parser.add_argument(
        "--security-markdown",
        metavar="PATH",
        help="Write a Markdown security report to PATH (implies --security).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)

    if args.env_file and os.path.exists(args.env_file):
        load_dotenv(args.env_file)
    else:
        load_dotenv()

    use_color: Optional[bool] = False if args.no_color or args.as_json else None
    printer = Printer(quiet=args.quiet or args.as_json, use_color=use_color)
    run_security = bool(args.security or args.security_markdown)
    checker = Agent365PreflightChecker(
        printer=printer,
        skip_graph=args.skip_graph,
        run_security=run_security,
    )
    success = checker.run()

    if args.security_markdown and checker.security_findings:
        try:
            with open(args.security_markdown, "w", encoding="utf-8") as fh:
                fh.write(findings_to_markdown(checker.security_findings))
        except OSError as e:
            print(
                f"Warning: could not write security markdown to "
                f"{args.security_markdown}: {e}",
                file=sys.stderr,
            )

    if args.as_json:
        payload = {
            "success": success,
            "results": [
                {
                    **asdict(r),
                    "status": r.status.value,
                    "severity": r.severity.value,
                }
                for r in checker.results
            ],
            "security_findings": [
                f.to_dict() for f in checker.security_findings
            ],
        }
        print(json.dumps(payload, indent=2))

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())

