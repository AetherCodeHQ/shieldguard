# Changelog

All notable changes to this project will be documented in this file.

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