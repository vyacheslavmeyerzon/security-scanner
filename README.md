# Git Security Scanner

[![PyPI version](https://img.shields.io/pypi/v/git-security-scanner.svg)](https://pypi.org/project/git-security-scanner/)
[![Python versions](https://img.shields.io/pypi/pyversions/git-security-scanner.svg)](https://pypi.org/project/git-security-scanner/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/vyacheslavmeyerzon/security-scanner/actions/workflows/tests.yml/badge.svg)](https://github.com/vyacheslavmeyerzon/security-scanner/actions/workflows/tests.yml)

A comprehensive Python tool to detect API keys, passwords, and secrets in Git repositories before they get exposed.

## 🚀 Features

- **🔍 Detects 25+ Secret Types**: AWS keys, API tokens, passwords, private keys, and more
- **🎯 Multiple Scan Modes**: Staged files, working directory, commit history
- **⚡ High Performance**: Parallel scanning with progress bars and caching
- **📊 Rich Reports**: Export to JSON, HTML, CSV, or Markdown
- **🎨 Customizable**: Add custom patterns, ignore files, configure severity levels
- **🔧 CI/CD Ready**: Pre-commit hooks and pipeline integration
- **🌍 Cross-Platform**: Works on Linux, macOS, and Windows

## 📦 Installation

### From PyPI (Recommended)

```bash
pip install git-security-scanner
```

### From Source

```bash
git clone https://github.com/vyacheslavmeyerzon/security-scanner.git
cd security-scanner
pip install -e .
```

## 🔧 Quick Start

### Basic Scan

Scan your current repository:

```bash
git-security-scanner
```

### Scan Specific Repository

```bash
git-security-scanner /path/to/repository
```

### Pre-commit Mode

Check only staged files:

```bash
git-security-scanner --pre-commit
```

### Export Results

```bash
# JSON format
git-security-scanner --export results.json

# HTML report
git-security-scanner --export report.html

# CSV format
git-security-scanner --export findings.csv

# Markdown report
git-security-scanner --export report.md
```

## 🎯 What It Detects

### Cloud Services
- AWS Access Keys and Secret Keys
- Azure Storage Keys
- Google Cloud API Keys and OAuth Tokens

### AI/ML Platforms
- OpenAI API Keys
- Anthropic (Claude) API Keys
- HuggingFace Tokens
- Cohere API Keys

### Version Control
- GitHub Personal Access Tokens
- GitLab Access Tokens
- Bitbucket App Passwords

### Databases
- MongoDB Connection Strings
- PostgreSQL Connection URLs
- MySQL Connection Strings

### Communication & More
- Slack Tokens
- Discord Bot Tokens
- Stripe API Keys
- JWT Tokens
- Private Keys (RSA, EC, DSA)
- Generic Passwords and Secrets

## 📋 Command Line Options

```bash
usage: git-security-scanner [-h] [-v] [-c CONFIG] [--pre-commit] [--no-history]
                           [--history-limit N] [--export FILE] [--quiet]
                           [--min-severity {LOW,MEDIUM,HIGH,CRITICAL}]
                           [--show-patterns] [--no-color] [--no-progress]
                           [path]

Detect API keys, passwords, and secrets in Git repositories

positional arguments:
  path                  Path to Git repository (default: current directory)

optional arguments:
  -h, --help           Show help message
  -v, --version        Show version
  -c, --config         Path to config file
  --pre-commit         Scan only staged files
  --no-history         Skip commit history scan
  --history-limit N    Limit history scan to N commits (default: 100)
  --export FILE        Export findings (.json, .html, .csv, .md)
  --quiet              Minimal output
  --min-severity LEVEL Minimum severity to report
  --show-patterns      Show all detection patterns
  --no-color           Disable colored output
  --no-progress        Disable progress bars
```

## ⚙️ Configuration

### Configuration File

Create `.gitscannerrc.json` or `.gitscannerrc.yaml`:

```json
{
  "patterns": {
    "custom": [
      {
        "name": "Company API Key",
        "pattern": "COMP-[A-Z0-9]{32}",
        "severity": "HIGH",
        "description": "Internal company API key"
      }
    ],
    "disabled": ["Generic Secret", "Environment Variable"]
  },
  "scan": {
    "history_limit": 50,
    "max_file_size_mb": 5,
    "parallel_workers": 4
  },
  "output": {
    "format": "console",
    "min_severity": "MEDIUM",
    "color": true
  },
  "cache": {
    "enabled": true,
    "ttl_hours": 48
  }
}
```

### Environment Variables

```bash
export SCANNER_HISTORY_LIMIT=25
export SCANNER_MIN_SEVERITY=HIGH
export SCANNER_QUIET=true
export SCANNER_NO_COLOR=true
```

### Ignore Files

Create `.gitscannerignore`:

```
# Ignore test files
tests/
*.test.py

# Ignore vendor directories
vendor/
node_modules/

# Ignore specific files
config.example.json
```

## 🪝 Git Hook Setup

### Pre-commit Hook

```bash
# Install as pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
git-security-scanner --pre-commit
EOF

chmod +x .git/hooks/pre-commit
```

### Using pre-commit Framework

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: security-scanner
        name: Git Security Scanner
        entry: git-security-scanner --pre-commit
        language: system
        pass_filenames: false
```

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full history for commit scanning
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install scanner
        run: pip install git-security-scanner
      
      - name: Run security scan
        run: git-security-scanner --export results.json
      
      - name: Upload results
        uses: actions/upload-artifact@v3
        if: failure()
        with:
          name: security-scan-results
          path: results.json
```

### GitLab CI

```yaml
security_scan:
  stage: test
  script:
    - pip install git-security-scanner
    - git-security-scanner --quiet --export report.html
  artifacts:
    reports:
      expose_as: 'Security Report'
      paths: ['report.html']
    when: on_failure
```

## 📈 Understanding Results

### Severity Levels

- 🔴 **CRITICAL**: Immediate action required (database credentials, private keys)
- 🟡 **HIGH**: Serious issues (API keys, access tokens)
- 🟣 **MEDIUM**: Should be reviewed (generic secrets, weak patterns)
- 🔵 **LOW**: Minor concerns (environment variables, configuration)

### Example Output

```
=== Scanning working directory ===
Scanning 150 files in working directory...
100%|████████████| 150/150 [00:02<00:00, 68.42files/s]

[CRITICAL] MongoDB Connection
  Description: MongoDB Connection String with credentials
  File: config/database.py
  Line: 15
  Secret: mongodb://user:****@localhost:27017/db

[HIGH] GitHub Token
  Description: GitHub Personal Access Token
  File: .env.example
  Line: 3
  Secret: ghp_****************************1234

Summary: Found 2 potential secrets:
  CRITICAL: 1
  HIGH: 1
```

## 🛡️ Best Practices

### If Secrets Are Found

1. **Immediately rotate** the exposed credentials
2. **Remove from history** using `git filter-branch` or BFG Repo-Cleaner
3. **Audit access logs** to check if credentials were compromised
4. **Enable 2FA** where possible

### Prevention

- Use environment variables for sensitive data
- Implement secret management tools (HashiCorp Vault, AWS Secrets Manager)
- Add `.env` files to `.gitignore`
- Use `.gitscannerignore` for false positives
- Run scanner in CI/CD pipelines
- Set up pre-commit hooks

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Thanks to all contributors who have helped improve this tool
- Inspired by similar tools like truffleHog and GitLeaks
- Built with love for the security community

---

**Remember**: Never commit secrets to Git. If you do, rotate them immediately! 🔐

## 📚 Documentation

For detailed documentation, visit our [Wiki](https://github.com/vyacheslavmeyerzon/security-scanner/wiki).