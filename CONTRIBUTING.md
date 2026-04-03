# Contributing to portdiff

Thank you for your interest in contributing to portdiff!

## Getting Started

1. Fork the repository and clone it locally:
   ```bash
   git clone https://github.com/<your-username>/portdiff
   cd portdiff
   ```

2. Build and test:
   ```bash
   make build
   make test
   ```

3. Create a feature branch:
   ```bash
   git checkout -b feature/my-feature
   ```

## Development Setup

- Go 1.21 or later is required
- No external dependencies — only the Go standard library
- Run `make lint` before submitting a PR

## Adding a New Parser

To add support for a new scan format:

1. Create `internal/parser/<format>.go` implementing a `ParseXxx(data []byte) (*ScanResult, error)` function
2. Add format detection logic to `internal/parser/detect.go`
3. Register the format in `internal/parser/parser.go`'s `Parse()` function
4. Add tests in `internal/parser/<format>_test.go` with realistic sample data
5. Update `docs/supported-formats.md`

## Code Standards

- All exported functions and types must have doc comments
- Tests must cover: happy path, empty input, malformed input, edge cases
- Use `table-driven tests` for functions with multiple input/output scenarios
- No global mutable state outside of initialization
- Errors should be wrapped with `fmt.Errorf("context: %w", err)` for proper unwrapping

## Pull Request Process

1. Ensure all tests pass: `make test`
2. Ensure `go vet` passes: `make lint`
3. Add or update tests for your changes
4. Update `CHANGELOG.md` with a brief description of your change
5. Submit a PR against the `main` branch with a clear description

## Reporting Issues

- For security vulnerabilities, see [SECURITY.md](SECURITY.md)
- For bugs, open a GitHub issue with:
  - portdiff version (`portdiff version`)
  - OS and architecture
  - Scan file format (nmap XML, grepable, masscan JSON)
  - Steps to reproduce
  - Expected vs. actual behavior

## Code of Conduct

Be professional, constructive, and respectful. Harassment or personal attacks will not be tolerated.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
