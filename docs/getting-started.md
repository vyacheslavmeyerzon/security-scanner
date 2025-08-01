# Getting Started with Git Security Scanner

This guide will help you get up and running with Git Security Scanner in minutes.

## Installation

### Prerequisites

- Python 3.7 or higher
- Git installed on your system
- A Git repository to scan

### Install from PyPI

The easiest way to install Git Security Scanner is from PyPI:

```bash
pip install git-security-scanner
```

### Install from Source

If you want the latest development version:

```bash
git clone https://github.com/vyacheslavmeyerzon/security-scanner.git
cd security-scanner
pip install -e .
```

## Basic Usage

### Your First Scan

Navigate to any Git repository and run:

```bash
git-security-scanner
```

This will scan:
- All files in the working directory
- The last 100 commits in history
- Display findings in the console

### Understanding the Output

The scanner uses color-coded severity levels:

- 🔴 **CRITICAL** (Red): Database passwords, private keys
- 🟡 **HIGH** (Yellow): API keys, access tokens  
- 🟣 **MEDIUM** (Purple): Potential secrets
- 🔵 **LOW** (Blue): Configuration issues

Example output:

```
[CRITICAL] MongoDB Connection
  Description: MongoDB Connection String with credentials
  File: config.py
  Line: 15
  Secret: mongodb://user:****@localhost/db
```

### Common Use Cases

#### 1. Pre-commit Scanning

Check files before committing:

```bash
git add .
git-security-scanner --pre-commit
```

#### 2. Quick Repository Audit

Scan without history for faster results:

```bash
git-security-scanner --no-history
```

#### 3. Export Findings for Review

Generate an HTML report:

```bash
git-security-scanner --export security-report.html
```

Open the HTML file in your browser for an interactive report.

#### 4. CI/CD Integration

Fail the build if secrets are found:

```bash
git-security-scanner --quiet || exit 1
```

## Configuration

### Quick Configuration

Create `.gitscannerrc.json` in your repository:

```json
{
  "output": {
    "min_severity": "MEDIUM"
  },
  "scan": {
    "history_limit": 50
  }
}
```

### Ignoring False Positives

Create `.gitscannerignore`:

```
# Ignore test files
tests/
*.test.py

# Ignore example files  
examples/
*.example
```

## Next Steps

- [Configuration Guide](configuration.md) - Advanced configuration options
- [CI/CD Integration](ci-cd-integration.md) - Set up automated scanning
- [Custom Patterns](custom-patterns.md) - Add your own detection patterns
- [API Reference](api-reference.md) - Use as a Python library

## Getting Help

- Check the [FAQ](faq.md)
- Report issues on [GitHub](https://github.com/vyacheslavmeyerzon/security-scanner/issues)
- Read the [full documentation](https://github.com/vyacheslavmeyerzon/security-scanner/wiki)