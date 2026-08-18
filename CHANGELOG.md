# Changelog

All notable changes to this project will be documented in this file.

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