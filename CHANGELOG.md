# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2025-08-01

### Added
- Initial release of git-security-scanner
- Core scanning functionality for Git repositories
- Detection of 25+ types of secrets including:
  - Cloud service credentials (AWS, Azure, Google Cloud)
  - AI/ML platform API keys (OpenAI, Anthropic, HuggingFace, Cohere)
  - Version control tokens (GitHub, GitLab)
  - Database connection strings (MongoDB, PostgreSQL, MySQL)
  - Communication platform tokens (Slack, Discord, Telegram)
  - Payment service keys (Stripe, PayPal)
  - Generic patterns (private keys, JWT tokens, passwords)
- Multiple scan modes:
  - Full repository scan
  - Staged files only (pre-commit mode)
  - Working directory scan
  - Commit history scan with configurable depth
- Configuration system:
  - YAML/JSON configuration files
  - Environment variable support
  - Custom pattern definitions
  - Pattern disabling
- Advanced features:
  - Parallel scanning with progress bars
  - Caching system with SQLite backend
  - Multiple export formats (JSON, HTML, CSV, Markdown)
  - Interactive HTML reports with filtering and sorting
  - `.gitscannerignore` file support with glob patterns
- Command-line interface with rich options
- Pre-commit hook support
- Comprehensive test suite (88 tests)
- Full type annotations (MyPy compatible)
- Cross-platform support (Linux, macOS, Windows)

### Security
- Secrets are truncated in output for security
- Binary files are automatically skipped
- Large files can be skipped based on size limits

[0.1.0]: https://github.com/vyacheslavmeyerzon/security-scanner/releases/tag/v0.1.0
[0.1.1]: https://github.com/vyacheslavmeyerzon/security-scanner/releases/tag/v0.1.1
[0.1.2]: https://github.com/vyacheslavmeyerzon/security-scanner/releases/tag/v0.1.2
[0.1.3]: https://github.com/vyacheslavmeyerzon/security-scanner/releases/tag/v0.1.3
