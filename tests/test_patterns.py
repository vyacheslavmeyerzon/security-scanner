"""
Tests for pattern matching functionality.
"""

import pytest
from security_scanner.patterns import PatternMatcher, Severity, PatternDefinition


class TestPatternMatcher:
    """Test cases for PatternMatcher class."""

    def test_pattern_matcher_initialization(self):
        """Test PatternMatcher initializes with default patterns."""
        matcher = PatternMatcher()
        patterns = matcher.get_patterns()

        assert len(patterns) > 0
        assert all('name' in p for p in patterns)
        assert all('pattern' in p for p in patterns)
        assert all('severity' in p for p in patterns)
        assert all('description' in p for p in patterns)

    def test_find_aws_access_key(self):
        """Test detection of AWS access keys."""
        matcher = PatternMatcher()
        content = """
        aws_access_key_id = AKIAIOSFODNN7EXAMPLE
        aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
        """

        findings = matcher.find_secrets(content, "test.py")

        assert len(findings) >= 1
        aws_finding = next(f for f in findings if f['type'] == 'AWS Access Key')
        assert aws_finding['severity'] == 'CRITICAL'
        assert 'AKIA' in aws_finding['secret']

    def test_find_openai_api_key(self):
        """Test detection of OpenAI API keys."""
        matcher = PatternMatcher()
        content = 'openai_api_key = "sk-proj123456789012345678901234567890123456789012345678"'

        findings = matcher.find_secrets(content, "config.py")

        assert len(findings) >= 1
        openai_finding = next(f for f in findings if f['type'] == 'OpenAI API Key')
        assert openai_finding['severity'] == 'HIGH'
        assert openai_finding['line'] == 1

    def test_find_github_token(self):
        """Test detection of GitHub tokens."""
        matcher = PatternMatcher()
        content = """
        # GitHub configuration
        GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"
        GITHUB_OAUTH = "gho_1234567890abcdef1234567890abcdef1234"
        """

        findings = matcher.find_secrets(content, ".env")

        github_findings = [f for f in findings if 'GitHub' in f['type']]
        assert len(github_findings) == 2
        assert all(f['severity'] == 'HIGH' for f in github_findings)

    def test_find_mongodb_connection(self):
        """Test detection of MongoDB connection strings."""
        matcher = PatternMatcher()
        content = 'MONGO_URI = "mongodb://user:password123@localhost:27017/mydb"'

        findings = matcher.find_secrets(content, "config.py")

        mongo_finding = next(f for f in findings if f['type'] == 'MongoDB Connection')
        assert mongo_finding['severity'] == 'CRITICAL'
        assert 'mongodb://' in mongo_finding['content']

    def test_find_private_key(self):
        """Test detection of private keys."""
        matcher = PatternMatcher()
        content = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA1234567890...
        -----END RSA PRIVATE KEY-----
        """

        findings = matcher.find_secrets(content, "private.key")

        key_finding = next(f for f in findings if f['type'] == 'Private Key')
        assert key_finding['severity'] == 'CRITICAL'
        assert key_finding['line'] == 2

    def test_line_number_tracking(self):
        """Test that line numbers are correctly tracked."""
        matcher = PatternMatcher()
        content = """Line 1
Line 2
api_key = "sk-1234567890123456789012345678901234567890123456789012"
Line 4
password = "super_secret_password_123"
        """

        findings = matcher.find_secrets(content, "test.txt")

        # Sort by line number
        findings_by_line = sorted(findings, key=lambda f: f['line'])

        assert findings_by_line[0]['line'] == 3
        assert findings_by_line[-1]['line'] == 5

    def test_secret_truncation(self):
        """Test that long secrets are truncated for security."""
        matcher = PatternMatcher()
        long_secret = "sk-" + "a" * 60
        content = f'api_key = "{long_secret}"'

        findings = matcher.find_secrets(content, "config.py")

        assert len(findings) > 0
        finding = findings[0]
        assert len(finding['secret']) < len(long_secret)
        assert '...' in finding['secret']

    def test_should_scan_file(self):
        """Test file exclusion logic."""
        matcher = PatternMatcher()

        # Should scan
        assert matcher.should_scan_file("main.py")
        assert matcher.should_scan_file("src/config.json")
        assert matcher.should_scan_file(".env")

        # Should not scan
        assert not matcher.should_scan_file(".git/config")
        assert not matcher.should_scan_file("node_modules/package.json")
        assert not matcher.should_scan_file("image.jpg")
        assert not matcher.should_scan_file("archive.zip")
        assert not matcher.should_scan_file("script.min.js")

    def test_environment_variable_false_positives(self):
        """Test that common environment variables are not flagged."""
        matcher = PatternMatcher()
        content = """
        export PATH=/usr/local/bin:$PATH
        export HOME=/home/user
        export USER=testuser
        export MY_SECRET_KEY=actual_secret_value_here
        """

        findings = matcher.find_secrets(content, ".bashrc")

        # Should not flag PATH, HOME, USER
        env_findings = [f for f in findings if f['type'] == 'Environment Variable']
        assert len(env_findings) == 1
        assert 'MY_SECRET_KEY' in env_findings[0]['content']

    def test_add_custom_pattern(self):
        """Test adding custom patterns."""
        matcher = PatternMatcher()
        initial_count = len(matcher.get_patterns())

        matcher.add_custom_pattern(
            name="Custom API Key",
            pattern=r'custom_key_[a-f0-9]{32}',
            severity=Severity.HIGH,
            description="Custom API key pattern"
        )

        assert len(matcher.get_patterns()) == initial_count + 1

        # Test detection
        content = 'key = "custom_key_1234567890abcdef1234567890abcdef"'
        findings = matcher.find_secrets(content, "test.py")

        custom_finding = next(f for f in findings if f['type'] == 'Custom API Key')
        assert custom_finding['severity'] == 'HIGH'

    def test_remove_pattern(self):
        """Test removing patterns."""
        matcher = PatternMatcher()

        # Add a custom pattern
        matcher.add_custom_pattern(
            name="Test Pattern",
            pattern=r'test_[0-9]+',
            severity=Severity.LOW,
            description="Test pattern"
        )

        initial_count = len(matcher.get_patterns())

        # Remove it
        removed = matcher.remove_pattern("Test Pattern")
        assert removed is True
        assert len(matcher.get_patterns()) == initial_count - 1

        # Try to remove non-existent
        removed = matcher.remove_pattern("Non Existent")
        assert removed is False

    def test_multiple_findings_same_line(self):
        """Test multiple secrets on the same line."""
        matcher = PatternMatcher()
        content = 'keys = {"aws": "AKIAIOSFODNN7EXAMPLE", "github": "ghp_1234567890abcdef1234567890abcdef1234"}'

        findings = matcher.find_secrets(content, "config.json")

        assert len(findings) >= 2
        line_numbers = [f['line'] for f in findings]
        assert all(line == 1 for line in line_numbers)


class TestSeverityEnum:
    """Test cases for Severity enum."""

    def test_severity_values(self):
        """Test Severity enum has correct values."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"

    def test_severity_ordering(self):
        """Test that severities can be compared."""
        severities = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

        # Create a custom ordering
        severity_order = {
            Severity.LOW: 0,
            Severity.MEDIUM: 1,
            Severity.HIGH: 2,
            Severity.CRITICAL: 3
        }

        sorted_severities = sorted(severities, key=lambda s: severity_order[s])
        assert sorted_severities == severities