# Contributing to PolkitGuard

Thank you for your interest in contributing to PolkitGuard!

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Open a new issue with:
   - Clear title
   - Steps to reproduce
   - Expected vs actual behavior
   - Go version and OS

### Suggesting Features

1. Check existing issues/discussions
2. Open a feature request issue
3. Explain the use case and benefits

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `go test ./...`
5. Format: `gofmt -w .`
6. Commit with clear messages
7. Push and create PR

## Development Setup

```bash
# Clone
git clone https://github.com/Ghostalex07/PolkitGuard.git
cd PolkitGuard

# Install dependencies
go mod download

# Build
go build -o polkitguard ./cmd/scan

# Run tests
go test ./...

# Run with test data
./polkitguard --path ./testdata
```

## Coding Standards

- Use `gofmt` for formatting
- Add tests for new features
- Update CHANGELOG.md for user-facing changes
- Keep PRs focused and small

## Commit Messages

Use clear, descriptive commit messages:
- `fix: describe what was fixed`
- `feat: describe what was added`
- `docs: describe documentation changes`

## License

By contributing, you agree your code will be licensed under MIT License.