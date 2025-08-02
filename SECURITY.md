# Security Policy

## Supported Versions

Currently, we support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take the security of Git Security Scanner seriously. If you have discovered a security vulnerability, please follow these steps:

### 1. **Do NOT** create a public GitHub issue
Public disclosure of vulnerabilities can put users at risk.

### 2. Report the vulnerability privately
Please report security vulnerabilities by emailing:
- **Email**: vyacheslav.meyerzon@gmail.com
- **Subject**: [SECURITY] Git Security Scanner Vulnerability

### 3. Include the following information:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Suggested fix (if any)

### 4. Response timeline:
- **Initial response**: Within 48 hours
- **Status update**: Within 10 days
- **Fix timeline**: Depends on severity (critical: immediate, high: 1 week, medium: 2 weeks)

## Security Best Practices for Users

1. **Always use the latest version** of Git Security Scanner
2. **Never commit** the scanner's cache or configuration files containing sensitive patterns
3. **Review findings** before sharing scan results
4. **Use `.gitscannerignore`** to exclude false positives

## Vulnerability Disclosure Policy

- We will acknowledge receipt of your vulnerability report
- We will investigate and validate the issue
- We will develop and test a fix
- We will release the fix and credit the reporter (unless anonymity is requested)

## Security Features of Git Security Scanner

This tool is designed to FIND secrets, not to store them. However:
- Cache files may contain snippets of detected secrets
- Configuration files may contain custom patterns
- Always add `.scanner-cache/` to your `.gitignore`

Thank you for helping keep Git Security Scanner and its users safe!
