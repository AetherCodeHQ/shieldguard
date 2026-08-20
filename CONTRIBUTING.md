# Contributing

Thank you for your interest in contributing! This document provides guidelines and information for contributors.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/ShieldGuard.git`
3. Create a feature branch: `git checkout -b feature/amazing-feature`
4. Make your changes
5. Commit your changes: `git commit -m 'feat: add amazing feature'`
6. Push to the branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

## Development Setup

### Prerequisites

- Go 1.21 or higher
- Git

### Installation

```bash
# Clone the repo
git clone https://github.com/Qyroxen/ShieldGuard.cd

# Install dependencies
go mod download

# Build
go build -o shieldguard .

# Run tests
go test ./...
```

## Code Style

- Follow [Effective Go](https://go.dev/doc/effective_go) guidelines
- Use `gofmt` to format your code
- Run `go vet ./...` before committing
- Add tests for new functionality

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, etc.)
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks

Examples:
```
feat: add new detection rule for SQL injection
fix: handle edge case in parser
docs: update README with examples
```

## Pull Request Guidelines

1. **One feature per PR** - Keep changes focused
2. **Write clear PR description** - Explain what and why
3. **Add tests** - Ensure new code is tested
4. **Update documentation** - If adding features, update README
5. **Pass CI** - All checks must pass

## Reporting Issues

- Use GitHub Issues
- Include reproduction steps
- Include Go version and OS
- Provide error messages

## Code of Conduct

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

## Questions?

Feel free to open an issue for questions or discussions!

Thank you for contributing! 🎉
