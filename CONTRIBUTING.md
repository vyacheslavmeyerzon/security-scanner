# Contributing to Git Security Scanner

First off, thank you for considering contributing to Git Security Scanner! It's people like you that make Git Security Scanner such a great tool.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Development Process](#development-process)
- [Style Guidelines](#style-guidelines)
- [Commit Messages](#commit-messages)
- [Pull Requests](#pull-requests)
- [Adding New Patterns](#adding-new-patterns)
- [Testing](#testing)
- [Documentation](#documentation)
- [Community](#community)

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to vyacheslav.meyerzon@gmail.com.

## Getting Started

- Make sure you have a [GitHub account](https://github.com/signup/free)
- Submit an issue for your idea, assuming one does not already exist
  - Clearly describe the issue including steps to reproduce when it is a bug
  - Make sure you fill in the earliest version that you know has the issue
- Fork the repository on GitHub

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps which reproduce the problem**
- **Provide specific examples to demonstrate the steps**
- **Describe the behavior you observed after following the steps**
- **Explain which behavior you expected to see instead and why**
- **Include details about your configuration and environment**

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

- **Use a clear and descriptive title**
- **Provide a step-by-step description of the suggested enhancement**
- **Provide specific examples to demonstrate the steps**
- **Describe the current behavior and explain which behavior you expected to see instead**
- **Explain why this enhancement would be useful**

### Your First Code Contribution

Unsure where to begin contributing? You can start by looking through these `beginner` and `help-wanted` issues:

- [Beginner issues](https://github.com/vyacheslavmeyerzon/security-scanner/labels/beginner) - issues which should only require a few lines of code
- [Help wanted issues](https://github.com/vyacheslavmeyerzon/security-scanner/labels/help%20wanted) - issues which should be a bit more involved than `beginner` issues

## Development Setup

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/your-username/security-scanner.git
   cd security-scanner
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install development dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Create a branch for your feature**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Process

1. **Make your changes**
   - Write your code
   - Add tests for new functionality
   - Update documentation as needed

2. **Run the test suite**
   ```bash
   # Run all tests
   pytest
   
   # Run with coverage
   pytest --cov=security_scanner
   
   # Run specific test file
   pytest tests/test_scanner.py
   ```

3. **Check code quality**
   ```bash
   # Format code with Black
   black src tests
   
   # Sort imports
   isort src tests
   
   # Check with flake8
   flake8 src tests
   
   # Type checking
   mypy src
   ```

4. **Run the full validation suite**
   ```bash
   # All checks that CI will run
   black --check src tests
   isort --check-only src tests
   flake8 src tests
   mypy src
   pytest
   ```

## Style Guidelines

### Python Style Guide

We use [Black](https://black.readthedocs.io/) for code formatting and follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with these specifications:

- Line length: 88 characters (Black default)
- Use type hints for all functions
- Use docstrings for all public modules, functions, classes, and methods
- Imports should be sorted with `isort`

### Code Style Examples

```python
# Good
from typing import List, Optional

from security_scanner.patterns import PatternMatcher


def scan_file(filepath: str, content: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Scan a single file for secrets.
    
    Args:
        filepath: Path to the file
        content: Optional file content
        
    Returns:
        List of findings
    """
    pass


# Bad
def scan_file(filepath,content=None):
    # scan file
    pass
```

### Docstring Style

We use Google style docstrings:

```python
def function_with_docstring(param1: str, param2: int) -> bool:
    """Brief description of function.
    
    More detailed description if needed.
    
    Args:
        param1: Description of param1
        param2: Description of param2
        
    Returns:
        Description of return value
        
    Raises:
        ValueError: Description of when this error occurs
    """
    pass
```

## Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line

### Commit Message Format

```
<type>: <subject>

<body>

<footer>
```

Types:
- **feat**: A new feature
- **fix**: A bug fix
- **docs**: Documentation only changes
- **style**: Changes that do not affect the meaning of the code
- **refactor**: A code change that neither fixes a bug nor adds a feature
- **perf**: A code change that improves performance
- **test**: Adding missing tests or correcting existing tests
- **chore**: Changes to the build process or auxiliary tools

Example:
```
feat: add support for GitLab tokens

Added detection patterns for GitLab personal access tokens
and project access tokens. The patterns follow GitLab's
token format specification.

Closes #123
```

## Pull Requests

1. **Before submitting a PR**
   - Make sure all tests pass
   - Update documentation if needed
   - Add tests for new functionality
   - Ensure code follows style guidelines

2. **PR Description Template**
   ```markdown
   ## Description
   Brief description of what this PR does.
   
   ## Type of Change
   - [ ] Bug fix (non-breaking change which fixes an issue)
   - [ ] New feature (non-breaking change which adds functionality)
   - [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
   - [ ] Documentation update
   
   ## Testing
   - [ ] My code follows the style guidelines of this project
   - [ ] I have performed a self-review of my own code
   - [ ] I have commented my code, particularly in hard-to-understand areas
   - [ ] I have made corresponding changes to the documentation
   - [ ] My changes generate no new warnings
   - [ ] I have added tests that prove my fix is effective or that my feature works
   - [ ] New and existing unit tests pass locally with my changes
   
   ## Related Issues
   Closes #(issue number)
   ```

3. **Review Process**
   - A project maintainer will review your PR
   - They may request changes or ask questions
   - Once approved, your PR will be merged

## Adding New Patterns

### Pattern Structure

When adding new detection patterns, follow this structure:

```python
PatternDefinition(
    name="Service Name Pattern",
    pattern=re.compile(r"your-regex-pattern-here"),
    severity=Severity.HIGH,  # CRITICAL, HIGH, MEDIUM, or LOW
    description="Clear description of what this pattern detects",
    false_positive_check=None  # Optional regex to filter out false positives
)
```

### Pattern Guidelines

1. **Research the pattern format**
   - Check official documentation for the service
   - Look at real examples
   - Consider variations

2. **Choose appropriate severity**
   - CRITICAL: Direct security risk (passwords, private keys)
   - HIGH: API keys and tokens with significant permissions
   - MEDIUM: Less sensitive tokens or potential secrets
   - LOW: Configuration that might contain sensitive data

3. **Test your pattern**
   ```python
   # Add test cases in tests/test_patterns.py
   def test_new_service_pattern():
       matcher = PatternMatcher()
       content = 'api_key = "service_1234567890abcdef"'
       
       findings = matcher.find_secrets(content, "test.py")
       assert len(findings) == 1
       assert findings[0]["type"] == "Service Name Pattern"
   ```

4. **Document the pattern**
   - Add to the pattern list in documentation
   - Include example of what it detects
   - Note any limitations

### Example: Adding a New API Key Pattern

1. **Add pattern to `patterns.py`**
   ```python
   PatternDefinition(
       name="Acme API Key",
       pattern=re.compile(r"acme_[a-f0-9]{40}"),
       severity=Severity.HIGH,
       description="Acme service API key",
   ),
   ```

2. **Add test case**
   ```python
   def test_acme_api_key():
       matcher = PatternMatcher()
       content = 'key = "acme_1234567890abcdef1234567890abcdef12345678"'
       
       findings = matcher.find_secrets(content, "config.py")
       assert len(findings) == 1
       assert findings[0]["type"] == "Acme API Key"
       assert findings[0]["severity"] == "HIGH"
   ```

3. **Update documentation**
   - Add to README.md pattern list
   - Update wiki if applicable

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_scanner.py

# Run specific test
pytest tests/test_scanner.py::TestSecurityScanner::test_scan_file

# Run with coverage
pytest --cov=security_scanner --cov-report=html
```

### Writing Tests

- Every new feature should have tests
- Every bug fix should have a test that reproduces the bug
- Use descriptive test names
- Use fixtures for common test data

Example test:
```python
def test_scan_file_with_multiple_secrets(temp_git_repo):
    """Test scanning a file containing multiple different secrets."""
    scanner = SecurityScanner(repo_path=temp_git_repo)
    
    # Create test file
    test_file = temp_git_repo / "secrets.py"
    test_file.write_text('''
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        github_token = "ghp_1234567890abcdef1234567890abcdef1234"
    ''')
    
    result = scanner.scan_file("secrets.py")
    
    assert result.scanned_files == 1
    assert len(result.findings) >= 2
    assert any(f["type"] == "AWS Access Key" for f in result.findings)
    assert any(f["type"] == "GitHub Token" for f in result.findings)
```

## Documentation

### Types of Documentation

1. **Code Documentation**
   - Use docstrings for all public APIs
   - Include type hints
   - Add inline comments for complex logic

2. **User Documentation**
   - Update README.md for user-facing changes
   - Update Wiki for detailed guides
   - Include examples

3. **API Documentation**
   - Document all public classes and methods
   - Include usage examples
   - Note any limitations or caveats

### Documentation Checklist

- [ ] All new functions have docstrings
- [ ] README.md is updated if needed
- [ ] Wiki pages are updated for new features
- [ ] CHANGELOG.md is updated
- [ ] Examples are provided for new features

## Community

### Getting Help

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and general discussion
- **Email**: vyacheslav.meyerzon@gmail.com for security issues

### Recognition

Contributors who submit accepted PRs will be added to the contributors list. We value all contributions, whether they're code, documentation, bug reports, or feature suggestions!

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Git Security Scanner! 🎉