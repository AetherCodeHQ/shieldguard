# Changelog

All notable changes to this project will be documented in this file.

## [v2.0.1] - 2026-08-18
### Added
- **`.shieldguardignore` Support:** Gitignore-style exclude file so users can skip files/directories (e.g. test mocks, generated code) during scans.

### Fixed
- **CommandInjection False Positive (Go):** Rule now requires shell names as quoted strings (`"sh"`, `"bash"`, `"cmd"`), so a variable named `cmd` is no longer flagged.
- **Self-Scan Cleanup:** Added `.shieldguardignore` so ShieldGuard's own rule catalog and test mocks are excluded — dogfooding the tool on itself now reports only real findings.

## [v2.0.0] - 2026-08-18
### Added
- **Multi-Language Support:** Scans Go, JavaScript/TypeScript, Python, Java, PHP, Ruby, and C/C++ (v1 only scanned Go).
- **New Detection Rules:** SSRF, WeakCrypto (MD5/SHA1), InsecureRandom, LDAP Injection, XSS, Unsafe Deserialization, and Python eval/exec — 25 rules total across 7 languages.
- **SARIF 2.1.0 Reporting:** New `--format sarif` output, compatible with GitHub Code Scanning.
- **Severity Filtering:** New `--severity` flag to only report findings at or above a level (low/medium/high/critical).
- **Configurable Fail Threshold:** New `--fail-on` flag to control the CI exit-code threshold (any/low/medium/high/critical/none).

### Changed
- Scanner refactored from hardcoded checks into a rule catalog (`pkg/scanner/rules`), making new rules easy to add.
- HTML report now includes MEDIUM/LOW severity styling and HTML-escapes snippets.

## [v1.0.2] - 2026-08-18
### Added
- **CI-Friendly Exit Codes:** `scan` now exits with code 1 when vulnerabilities are found and not auto-fixed, enabling reliable pipeline integration.
- **Centralized Versioning:** Single `Version` constant in `cmd/version.go`; `--version` flag via Cobra.

### Fixed
- **Scanner False Positives:** Comment lines are skipped; HardcodedSecret now requires a keyword + assignment + string literal.
- **BOM in Config:** Removed UTF-8 BOM from `.shieldguard.yaml` that could break Viper parsing.
- **Go Version Consistency:** Aligned `go.mod` (1.23.0), CI workflow (1.23), and README (Go 1.23+).

## [v1.0.1] - 2026-08-18
### Added
- **HTML & JSON Reporting:** Added `--format json` and `--format html` flags to export scan results.
- **New SAST Rules:** Added detection patterns for SQL Injection and Path Traversal vulnerabilities.
- **Risk Severity Scoring:** Added risk levels (`CRITICAL`, `HIGH`, `MEDIUM`) and severity scores to vulnerabilities.
- **Changelog Tracking:** Added `CHANGELOG.md` to track release notes and version changes.

### Fixed
- Upgraded project version to `v1.0.1` with full English localization across all CLI logs and errors.

## [v1.0.0] - 2026-08-18
### Added
- Initial official release of ShieldGuard CLI.
- Local-first SAST engine using AST pattern matching.
- Ollama LLM integration (`--auto-fix`) for automated code remediation.
- Concurrent worker pool (`sync.WaitGroup` & `context` timeout handling).
- Viper configuration support (`.shieldguard.yaml`).
- GitHub Actions CI workflow for automated testing and builds.