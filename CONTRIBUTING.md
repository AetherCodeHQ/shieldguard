# Contributing to Shieldguard

Thank you for your interest in contributing! 🎉

## How to Contribute

### 1. Fork the Repository
```bash
git clone https://github.com/Qyroxen/shieldguard.git
cd shieldguard
```

### 2. Create a Branch
```bash
git checkout -b feature/your-feature-name
```

### 3. Make Your Changes
- Write clean, documented code
- Follow Go conventions (`gofmt`, `golint`)
- Add tests for new functionality

### 4. Run Tests
```bash
go test ./...
golangci-lint run
```

### 5. Commit Your Changes
```bash
git commit -m "feat: add new feature description"
```

### 6. Push and Create PR
```bash
git push origin feature/your-feature-name
```

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation changes
- `style:` — Code style changes (formatting, etc.)
- `refactor:` — Code refactoring
- `test:` — Adding tests
- `chore:` — Maintenance tasks

## Code of Conduct

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

## Questions?

Open an issue or start a discussion!
