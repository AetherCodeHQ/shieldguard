# Contributing

Thank you for your interest in contributing! This document provides guidelines and information for contributors.

## 🚀 Quick Start

1. **Fork** the repository
2. **Clone** your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/ShieldGuard.git
   cd ShieldGuard
   ```
3. **Create** a feature branch:
   ```bash
   git checkout -b feature/amazing-feature
   ```
4. **Make** your changes
5. **Commit** with conventional commits:
   ```bash
   git commit -m 'feat: add amazing feature'
   ```
6. **Push** to your fork:
   ```bash
   git push origin feature/amazing-feature
   ```
7. **Open** a Pull Request

## 📋 Development Setup

### Prerequisites

- Go 1.21 or higher
- Git

### Installation

```bash
# Clone the repo
git clone https://github.com/Qyroxen/ShieldGuard.git
cd ShieldGuard

# Install dependencies
go mod download

# Build
go build -o shieldguard .

# Run tests
go test ./...

# Run linter
golangci-lint run
```

## 📝 Commit Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Description |
|--------|-------------|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `docs:` | Documentation changes |
| `style:` | Code style (formatting, etc.) |
| `refactor:` | Code refactoring |
| `test:` | Adding/updating tests |
| `chore:` | Maintenance tasks |
| `perf:` | Performance improvements |
| `ci:` | CI/CD changes |

## 🔍 Code Review Process

1. All PRs require at least one review
2. CI must pass (tests, lint, build)
3. No merge conflicts
4. Follow existing code style

## 🏷️ Labels

- `bug` - Something isn't working
- `enhancement` - New feature or request
- `documentation` - Improvements to docs
- `good first issue` - Good for newcomers
- `help wanted` - Extra attention needed

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 💬 Questions?

Feel free to open an issue for questions or discussions!

Thank you for contributing! 🎉
