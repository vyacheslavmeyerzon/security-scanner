---
title: Stop Leaking Secrets! Introducing Git Security Scanner
published: false
tags: security, git, python, opensource
cover_image: https://dev-to-uploads.s3.amazonaws.com/uploads/articles/security-scanner-cover.png
---

Have you ever accidentally committed an API key to Git? You're not alone! According to GitGuardian's 2024 report, over 10 million secrets were detected in public GitHub commits last year. 😱

Today, I'm excited to introduce **Git Security Scanner** - an open-source tool that helps you catch these mistakes before they become security incidents.

## The Problem 🔓

We've all been there:
- Hardcoded that AWS key "just for testing"
- Committed the `.env` file by mistake
- Forgot to remove the database password from the config

Once it's in Git history, it's there forever (unless you rewrite history, which is painful).

## The Solution 🛡️

Git Security Scanner is a Python tool that scans your repository for:
- 🔑 API keys (AWS, OpenAI, GitHub, etc.)
- 🗄️ Database credentials
- 🔐 Private keys and certificates
- 🎫 Access tokens and passwords

## Quick Demo 🚀

Install it:
```bash
pip install git-security-scanner
```

Scan your repository:
```bash
git-security-scanner
```

You'll see output like:
```
[CRITICAL] AWS Access Key
  File: config.py
  Line: 45
  Secret: AKIA****************

[HIGH] OpenAI API Key  
  File: .env.example
  Line: 3
  Secret: sk-****************************
```

## Key Features ✨

### 1. Pre-commit Hook Support
Catch secrets before they're committed:
```bash
git-security-scanner --pre-commit
```

### 2. Beautiful HTML Reports
```bash
git-security-scanner --export report.html
```
![HTML Report Screenshot](https://example.com/report-screenshot.png)

### 3. CI/CD Ready
Add to your GitHub Actions:
```yaml
- name: Security Scan
  run: |
    pip install git-security-scanner
    git-security-scanner --quiet || exit 1
```

### 4. Customizable
Add your own patterns:
```json
{
  "patterns": {
    "custom": [{
      "name": "Company API Key",
      "pattern": "ACME-[A-Z0-9]{32}",
      "severity": "HIGH"
    }]
  }
}
```

## Real-World Example 💼

Last week, a colleague almost pushed our Stripe production key to GitHub. Our pre-commit hook caught it:

```bash
$ git commit -m "Add payment processing"
Running Git Security Scanner...

❌ Pre-commit check failed!
[CRITICAL] Stripe Secret Key
  File: payment.py
  Line: 12

Please remove secrets before committing.
```

Crisis averted! 🎉

## Performance Matters ⚡

- **Parallel scanning**: Uses all CPU cores
- **Smart caching**: Skips unchanged files
- **Progress bars**: Know what's happening
- **Configurable depth**: Scan only recent commits

On a repository with 10,000 files and 1,000 commits, it completes in under 30 seconds.

## Comparison with Alternatives 📊

| Feature | Git Security Scanner | TruffleHog | GitLeaks |
|---------|---------------------|------------|-----------|
| Python native | ✅ | ✅ | ❌ |
| Pre-commit hook | ✅ | ⚠️ | ✅ |
| HTML reports | ✅ | ❌ | ❌ |
| Custom patterns | ✅ | ✅ | ✅ |
| AI/ML API keys | ✅ | ⚠️ | ⚠️ |
| Progress bars | ✅ | ❌ | ❌ |

## Getting Started 🏁

1. Install:
   ```bash
   pip install git-security-scanner
   ```

2. Add pre-commit hook:
   ```bash
   echo 'git-security-scanner --pre-commit' > .git/hooks/pre-commit
   chmod +x .git/hooks/pre-commit
   ```

3. Create `.gitscannerignore` for false positives:
   ```
   tests/
   examples/
   *.example
   ```

4. Scan and fix:
   ```bash
   git-security-scanner
   ```

## What's Next? 🔮

I'm working on:
- 🤖 Machine learning for better detection
- 🔌 IDE plugins (VS Code, PyCharm)
- 🌐 GitLab and Bitbucket integration
- 📱 Slack/Discord notifications

## Contributing 🤝

This is open source and I'd love your help! Whether it's:
- Adding new secret patterns
- Improving performance
- Writing documentation
- Reporting bugs

Check out the [GitHub repository](https://github.com/vyacheslavmeyerzon/security-scanner).

## Final Thoughts 💭

Security doesn't have to be hard. With the right tools, we can catch mistakes before they become breaches.

Give Git Security Scanner a try and let me know what you think! Drop a ⭐ on GitHub if you find it useful.

**Remember**: If you do find secrets in your repository, rotate them immediately! It only takes one leaked key to compromise your entire system.

---

*Have you ever accidentally committed secrets? How did you handle it? Share your stories in the comments!*

#security #git #python #opensource #devsecops