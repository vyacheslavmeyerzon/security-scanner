# Release v0.1.0

## 🎉 Initial Release

We're excited to announce the first public release of Git Security Scanner!

Git Security Scanner is a comprehensive tool designed to help developers and security teams detect sensitive information in Git repositories before it gets exposed.

## ✨ Key Features

- 🔍 **25+ Secret Types**: Detects AWS keys, API tokens, passwords, database credentials, and more
- ⚡ **High Performance**: Parallel scanning with progress tracking and caching
- 📊 **Multiple Export Formats**: JSON, HTML, CSV, and Markdown reports
- 🎯 **Flexible Scanning**: Staged files, working directory, or full commit history
- 🔧 **Highly Configurable**: Custom patterns, ignore files, severity filtering
- 🌍 **Cross-Platform**: Works on Linux, macOS, and Windows

## 📦 Installation

```bash
pip install git-security-scanner
```

## 🚀 Quick Start

```bash
# Scan current repository
git-security-scanner

# Pre-commit mode
git-security-scanner --pre-commit

# Export results
git-security-scanner --export report.html
```

## 📚 Documentation

- [Getting Started Guide](https://github.com/vyacheslavmeyerzon/security-scanner/wiki/Getting-Started)
- [Configuration Reference](https://github.com/vyacheslavmeyerzon/security-scanner/wiki/Configuration)
- [CI/CD Integration](https://github.com/vyacheslavmeyerzon/security-scanner/wiki/CI-CD-Integration)

## 🙏 Acknowledgments

Special thanks to all early testers and contributors who helped shape this tool.

## 📝 Full Changelog

See [CHANGELOG.md](https://github.com/vyacheslavmeyerzon/security-scanner/blob/main/CHANGELOG.md) for detailed changes.

---

**Remember**: If you find secrets in your repository, rotate them immediately! 🔐