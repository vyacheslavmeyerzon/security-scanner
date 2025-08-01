# Publishing Guide for Git Security Scanner

This guide documents the process for publishing new releases of git-security-scanner to PyPI.

## Pre-Publication Checklist

- [ ] All tests passing (`pytest`)
- [ ] Code quality checks passing (`black`, `flake8`, `mypy`)
- [ ] Version updated in:
  - [ ] `src/security_scanner/__init__.py`
  - [ ] `setup.py`
  - [ ] `pyproject.toml`
- [ ] CHANGELOG.md updated with release notes
- [ ] README.md reviewed and updated
- [ ] Documentation updated if needed

## Build Process

### 1. Clean Previous Builds

```bash
rm -rf build/ dist/ src/*.egg-info
```

### 2. Install Build Tools

```bash
pip install --upgrade build twine
```

### 3. Build the Package

```bash
python -m build
```

This creates:
- `dist/git-security-scanner-0.1.0.tar.gz` (source distribution)
- `dist/git_security_scanner-0.1.0-py3-none-any.whl` (wheel)

### 4. Verify the Build

```bash
# Check package metadata
twine check dist/*

# Test installation
pip install dist/git_security_scanner-0.1.0-py3-none-any.whl

# Run smoke test
git-security-scanner --version
```

## Testing with Test PyPI

### 1. Upload to Test PyPI

```bash
twine upload --repository testpypi dist/*
```

You'll need your Test PyPI credentials.

### 2. Test Installation

```bash
# Create clean virtual environment
python -m venv test-env
source test-env/bin/activate  # On Windows: test-env\Scripts\activate

# Install from Test PyPI
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ git-security-scanner

# Test it works
git-security-scanner --help
```

### 3. Run Integration Tests

```bash
# Clone a test repository
git clone https://github.com/example/test-repo.git
cd test-repo

# Run scanner
git-security-scanner
git-security-scanner --pre-commit
git-security-scanner --export test.html
```

## Publishing to PyPI

### 1. Final Checks

- [ ] Test PyPI installation works correctly
- [ ] Documentation is up to date
- [ ] Git repository is tagged

### 2. Upload to PyPI

```bash
twine upload dist/*
```

Enter your PyPI credentials when prompted.

### 3. Verify on PyPI

- Check https://pypi.org/project/git-security-scanner/
- Verify all metadata is correct
- Test installation: `pip install git-security-scanner`

## Post-Publication

### 1. Create GitHub Release

```bash
# Tag the release
git tag -a v0.1.0 -m "Release version 0.1.0"
git push origin v0.1.0

# Create release on GitHub
# Go to https://github.com/vyacheslavmeyerzon/security-scanner/releases/new
# Use the release template from .github/RELEASE_TEMPLATE.md
```

### 2. Update Documentation

- [ ] Update the installation instructions if needed
- [ ] Add release notes to documentation
- [ ] Update any version-specific documentation

### 3. Announce the Release

- [ ] Post on Reddit:
  - r/Python
  - r/cybersecurity
  - r/programming
- [ ] Share on Twitter/X with hashtags:
  - #Python #Security #OpenSource #GitSecurity
- [ ] Publish Dev.to article (see `docs/dev.to-article.md`)
- [ ] Post on LinkedIn
- [ ] Share in relevant Slack/Discord communities

### 4. Monitor

- Watch for issues on GitHub
- Monitor PyPI download statistics
- Respond to user feedback

## Version Numbering

We follow [Semantic Versioning](https://semver.org/):
- MAJOR version for incompatible API changes
- MINOR version for new functionality (backwards compatible)
- PATCH version for backwards compatible bug fixes

## Troubleshooting

### "Package already exists" Error

This means the version already exists on PyPI. Increment the version number and rebuild.

### Authentication Issues

Make sure you have:
1. Created accounts on PyPI and Test PyPI
2. Set up 2FA (use API tokens, not passwords)
3. Created `.pypirc` file:

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-your-token-here

[testpypi]
username = __token__
password = pypi-your-test-token-here
```

### Build Issues

- Ensure all dependencies are installed: `pip install -e ".[dev]"`
- Check Python version compatibility
- Verify MANIFEST.in includes all necessary files

## Security Considerations

- Never commit `.pypirc` or tokens to Git
- Use environment variables for CI/CD deployments
- Rotate tokens regularly
- Enable 2FA on PyPI account

## Automation (Future)

Consider setting up GitHub Actions for automated releases:
- Trigger on version tags
- Run full test suite
- Build and upload to PyPI
- Create GitHub release automatically