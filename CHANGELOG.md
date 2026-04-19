# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/).

## [1.2.0] - 2026-04-18

### Added
- `pyproject.toml` with `agent365-preflight` console entry point.
- MIT `LICENSE` file.
- Test suite under `tests/` (pytest + `responses` for HTTP mocking, MSAL
  stubbed via monkeypatch).
- GitHub Actions CI workflow: `ruff` lint + `pytest` on Python 3.9–3.12.
- JWT `roles` claim decoding: the Graph permissions check now reports the
  exact app permissions Entra granted the service principal and flags
  missing ones (`Organization.Read.All`, `Policy.Read.All`,
  `AuditLog.Read.All`, `Directory.Read.All`).
- Certificate-based authentication: `CLIENT_CERT_PATH` /
  `CLIENT_CERT_THUMBPRINT` env vars used when present, preferred over
  `CLIENT_SECRET`.
- `--fail-on-security` flag: non-zero exit when security findings include
  FAIL.
- `.env.example` updated with certificate-auth placeholders.

### Changed
- `Printer` now exposes `colorize()` publicly (removes private-method usage
  from the finding renderer).
- Security rollup ("Risk classification") moved to a single final finding
  computed over all categories, not per-check.
- Conditional Access workload-identity heuristic documented in the finding
  message so downstream readers know what was (and wasn't) asserted.

## [1.1.0] - 2026-04-18

### Added
- CLI flags: `--json`, `--quiet`, `--skip-graph`, `--no-color`,
  `--env-file`, `--security`, `--security-markdown`.
- `CheckResult` dataclass + `Status` / `Severity` enums separating critical
  failures from informational warnings.
- Strict GUID validation for `TENANT_ID` / `CLIENT_ID`.
- `security_checks.py` module: identity anchoring, Conditional Access
  coverage, Purview audit reachability, DLP / Defender licensing.
- `findings_to_markdown()` for security-review export.
- Windows ANSI enablement + `NO_COLOR` / tty detection.

### Fixed
- `print_summary` return-value bug that could cause a 1 exit code on
  fully-passing runs.
- Frontier preview reclassified from CRITICAL to WARNING.

## [1.0.0] - 2026-04-18

### Added
- Initial release: environment-variable, token-acquisition, and Graph
  `/organization` probe.
