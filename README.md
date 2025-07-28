# Git Security Scanner

A simple Python tool to detect API keys, passwords, and secrets in your Git repositories before they get exposed.

## Features

- ✅ Detects 64+ types of secrets (API keys, tokens, passwords)
- ✅ Scans staged files, working directory, and commit history
- ✅ Supports AI/ML platforms (OpenAI, Anthropic, HuggingFace, etc.)
- ✅ Color-coded severity levels
- ✅ Pre-commit hook support
- ✅ JSON export for CI/CD integration

## Quick Start

### Prerequisites
- Python 3.7 or higher
- Git repository to scan

### Installation

1. Download `git-security-scanner.py`
2. Install the required dependency:
```bash
pip install colorama
```

## Usage

### Basic Scan
Scan your current repository:
```bash
python git-security-scanner.py
```

### Scan Another Repository
```bash
python git-security-scanner.py --path /path/to/repo
```

### Pre-commit Mode
Check only staged files (files added with `git add`):
```bash
python git-security-scanner.py --pre-commit
```

### Export Results
Save findings to a JSON file:
```bash
python git-security-scanner.py --export results.json
```

### Quiet Mode
Show only critical information:
```bash
python git-security-scanner.py --quiet
```

### All Options
```bash
# Show help
python git-security-scanner.py --help

# Limit commit history scan (default: 100)
python git-security-scanner.py --history-limit 50

# Combine options
python git-security-scanner.py --quiet --export scan.json --history-limit 20
```

## What It Detects

- **Cloud Services**: AWS, Azure, Google Cloud keys
- **AI Platforms**: OpenAI, Anthropic, HuggingFace, Cohere, etc.
- **Version Control**: GitHub, GitLab, Bitbucket tokens
- **Databases**: MongoDB, PostgreSQL, MySQL connection strings
- **Communication**: Slack, Discord, Telegram tokens
- **Payment**: Stripe, PayPal API keys
- **Generic**: Passwords, private keys, JWT tokens

## Understanding Results

### Severity Levels
- 🔴 **CRITICAL**: Immediate action required (private keys, passwords)
- 🟡 **HIGH**: Serious issues (API keys, tokens)
- 🟣 **MEDIUM**: Should be reviewed (potential secrets)
- 🔵 **LOW**: Minor concerns (configuration files)

### Example Output
```
[CRITICAL] AWS Access Key
Type: PATTERN
File: config.py
Line: 45
Content: AKIA****************

[HIGH] OpenAI API Key
Type: PATTERN
File: .env
Line: 3
Content: sk-************************************************
```

## Git Hook Setup

To automatically check for secrets before every commit:

1. Create `.git/hooks/pre-commit`:
```bash
#!/bin/bash
python /path/to/git-security-scanner.py --pre-commit
```

2. Make it executable:
```bash
chmod +x .git/hooks/pre-commit
```

## Best Practices

1. **Add to .gitignore**: Always exclude sensitive files
   ```
   .env
   *.pem
   *.key
   .cursor/
   ```

2. **If secrets are found**:
   - Immediately rotate/change the exposed credentials
   - Remove from Git history using `git filter-branch` or BFG
   - Check if credentials were used in production

3. **Prevention**:
   - Use environment variables for secrets
   - Use secret management tools (Vault, AWS Secrets Manager)
   - Run scanner in CI/CD pipeline

## CI/CD Integration

### GitHub Actions
```yaml
- name: Security Scan
  run: |
    pip install colorama
    python git-security-scanner.py --quiet --export scan.json
```

### Generic CI/CD
```bash
# Exit with error if secrets found
python git-security-scanner.py --quiet || exit 1
```

## Troubleshooting

**"Not a Git repository" error**
- Make sure you're in a directory with `.git` folder
- Or specify path: `--path /path/to/git/repo`

**Too many false positives**
- The scanner might detect its own patterns
- Example passwords in documentation
- Use `.gitscannerignore` file (coming soon)

**Scanner is slow**
- Use `--history-limit 10` for faster scans
- Use `--pre-commit` for checking only new changes

## License

MIT License - feel free to use and modify!

---

**Remember**: Never commit secrets to Git. If you do, rotate them immediately! 🔐
