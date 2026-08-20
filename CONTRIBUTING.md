# Contributing

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/ShieldGuard.git`
3. Create a feature branch: `git checkout -b feature/amazing-feature`
4. Make your changes
5. Commit: `git commit -m 'feat: add amazing feature'`
6. Push: `git push origin feature/amazing-feature`
7. Open a Pull Request

## Development

```bash
# Install dependencies
go mod download

# Build
go build -o binary .

# Test
go test ./...
```

## Code Style

- Follow Go conventions
- Use `gofmt` to format
- Run `go vet ./...` before committing
- Add tests for new functionality

## Commit Messages

Follow Conventional Commits:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation
- `test:` - Tests
- `chore:` - Maintenance

## Pull Request Guidelines

1. One feature per PR
2. Write clear description
3. Add tests
4. Update documentation
5. Pass CI

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
