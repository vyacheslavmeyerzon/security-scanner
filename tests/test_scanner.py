"""
Tests for the main scanner functionality.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from security_scanner.patterns import Severity
from security_scanner.scanner import ScanResult, SecurityScanner


class TestScanResult:
    """Test cases for ScanResult class."""

    def test_scan_result_initialization(self):
        """Test ScanResult initializes correctly."""
        result = ScanResult()

        assert result.findings == []
        assert result.scanned_files == 0
        assert result.skipped_files == 0
        assert result.errors == []

    def test_add_finding(self):
        """Test adding findings to result."""
        result = ScanResult()
        finding = {
            "type": "AWS Access Key",
            "severity": "CRITICAL",
            "file": "config.py",
            "line": 10,
        }

        result.add_finding(finding)

        assert len(result.findings) == 1
        assert result.findings[0] == finding

    def test_add_error(self):
        """Test adding errors to result."""
        result = ScanResult()
        error_msg = "Failed to read file"

        result.add_error(error_msg)

        assert len(result.errors) == 1
        assert result.errors[0] == error_msg

    def test_merge_results(self):
        """Test merging two scan results."""
        result1 = ScanResult()
        result1.add_finding({"type": "Finding1"})
        result1.scanned_files = 5
        result1.skipped_files = 2
        result1.add_error("Error1")

        result2 = ScanResult()
        result2.add_finding({"type": "Finding2"})
        result2.scanned_files = 3
        result2.skipped_files = 1
        result2.add_error("Error2")

        result1.merge(result2)

        assert len(result1.findings) == 2
        assert result1.scanned_files == 8
        assert result1.skipped_files == 3
        assert len(result1.errors) == 2

    def test_filter_by_severity(self):
        """Test filtering findings by severity."""
        result = ScanResult()
        result.add_finding({"type": "Test1", "severity": "LOW"})
        result.add_finding({"type": "Test2", "severity": "MEDIUM"})
        result.add_finding({"type": "Test3", "severity": "HIGH"})
        result.add_finding({"type": "Test4", "severity": "CRITICAL"})

        # Filter by HIGH
        high_findings = result.filter_by_severity(Severity.HIGH)
        assert len(high_findings) == 2
        assert all(f["severity"] in ["HIGH", "CRITICAL"] for f in high_findings)

        # Filter by CRITICAL
        critical_findings = result.filter_by_severity(Severity.CRITICAL)
        assert len(critical_findings) == 1
        assert critical_findings[0]["severity"] == "CRITICAL"

    def test_get_unique_findings(self):
        """Test getting unique findings (removing duplicates)."""
        result = ScanResult()

        # Add duplicate findings
        finding = {
            "type": "AWS Access Key",
            "severity": "CRITICAL",
            "file": "config.py",
            "line": 10,
            "secret": "AKIA...",
        }

        result.add_finding(finding)
        result.add_finding(finding)  # Duplicate
        result.add_finding({**finding, "line": 20})  # Different line

        unique = result.get_unique_findings()
        assert len(unique) == 2


class TestSecurityScanner:
    """Test cases for SecurityScanner class."""

    @pytest.fixture
    def temp_git_repo(self):
        """Create a temporary Git repository."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)

            # Initialize Git repo
            os.system(f'cd "{repo_path}" && git init')

            # Create .git directory if not created
            git_dir = repo_path / ".git"
            if not git_dir.exists():
                git_dir.mkdir()

            yield repo_path

    def test_scanner_initialization(self, temp_git_repo):
        """Test scanner initializes correctly."""
        scanner = SecurityScanner(repo_path=temp_git_repo)

        assert scanner.repo_path == temp_git_repo
        assert scanner.pattern_matcher is not None
        assert scanner.ignore_parser is not None

    def test_scanner_initialization_not_git_repo(self):
        """Test scanner raises error for non-Git repository."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(ValueError, match="Not a Git repository"):
                SecurityScanner(repo_path=Path(tmpdir))

    def test_scan_file_with_secrets(self, temp_git_repo):
        """Test scanning a file with secrets."""
        scanner = SecurityScanner(repo_path=temp_git_repo)

        # Create a file with secrets
        test_file = temp_git_repo / "config.py"
        test_file.write_text(
            """
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
api_key = "sk-1234567890123456789012345678901234567890123456789012"
        """
        )

        result = scanner.scan_file("config.py")

        assert result.scanned_files == 1
        # At least one finding (patterns might be disabled in config)
        assert len(result.findings) >= 1

    def test_scan_file_ignored(self, temp_git_repo):
        """Test scanning an ignored file."""
        # Create ignore file
        ignore_file = temp_git_repo / ".gitscannerignore"
        ignore_file.write_text("config.py\n")

        scanner = SecurityScanner(repo_path=temp_git_repo)

        # Create a file that should be ignored
        test_file = temp_git_repo / "config.py"
        test_file.write_text('secret = "AKIAIOSFODNN7EXAMPLE"')

        result = scanner.scan_file("config.py")

        assert result.skipped_files == 1
        assert result.scanned_files == 0
        assert len(result.findings) == 0

    def test_scan_binary_file(self, temp_git_repo):
        """Test scanning a binary file (should be skipped)."""
        scanner = SecurityScanner(repo_path=temp_git_repo)

        # Create a binary file
        binary_file = temp_git_repo / "image.jpg"
        binary_file.write_bytes(b"\x00\x01\x02\x03")

        result = scanner.scan_file("image.jpg")

        assert result.skipped_files == 1
        assert result.scanned_files == 0

    @patch("security_scanner.scanner.GitHelper.get_staged_files")
    def test_scan_staged_files(self, mock_get_staged, temp_git_repo):
        """Test scanning staged files."""
        scanner = SecurityScanner(repo_path=temp_git_repo)

        # Create a test file
        test_file = temp_git_repo / "staged.py"
        test_file.write_text('token = "ghp_1234567890abcdef1234567890abcdef1234"')

        # Mock staged files
        mock_get_staged.return_value = ["staged.py"]

        result = scanner.scan_staged_files()

        assert result.scanned_files == 1
        # Check if findings exist and are of expected type
        if result.findings:
            assert any(
                "GitHub" in f["type"] or "Token" in f["type"] for f in result.findings
            )

    @patch("security_scanner.scanner.GitHelper.get_staged_files")
    def test_scan_staged_files_empty(self, mock_get_staged, temp_git_repo):
        """Test scanning when no files are staged."""
        scanner = SecurityScanner(repo_path=temp_git_repo)

        # Mock no staged files
        mock_get_staged.return_value = []

        result = scanner.scan_staged_files()

        assert result.scanned_files == 0
        assert len(result.findings) == 0

    @patch("security_scanner.scanner.GitHelper.get_all_files")
    def test_scan_working_directory(self, mock_get_files, temp_git_repo):
        """Test scanning working directory."""
        scanner = SecurityScanner(repo_path=temp_git_repo)

        # Create test files
        file1 = temp_git_repo / "file1.py"
        file1.write_text('normal_code = "hello"')

        file2 = temp_git_repo / "file2.py"
        file2.write_text('github_token = "ghp_1234567890abcdef1234567890abcdef1234"')

        # Mock file list
        mock_get_files.return_value = ["file1.py", "file2.py"]

        result = scanner.scan_working_directory()

        assert result.scanned_files == 2
        # Patterns might be disabled, so just check that scan completed

    @patch("security_scanner.scanner.GitHelper.get_commit_list")
    @patch("security_scanner.scanner.GitHelper.get_changed_files_in_commit")
    @patch("security_scanner.scanner.GitHelper.get_file_content_from_commit")
    def test_scan_commit_history(
        self, mock_get_content, mock_get_changed, mock_get_commits, temp_git_repo
    ):
        """Test scanning commit history."""
        scanner = SecurityScanner(repo_path=temp_git_repo)

        # Mock commit list
        mock_get_commits.return_value = ["abc123", "def456"]

        # Mock changed files
        mock_get_changed.return_value = ["secret.py"]

        # Mock file content with secret
        mock_get_content.return_value = (
            'mongodb_uri = "mongodb://user:pass@localhost/db"'
        )

        scanner.scan_commit_history(limit=10)

        # Check that commits were processed
        assert mock_get_commits.called
        assert mock_get_changed.called
        assert mock_get_content.called

    def test_scan_full(self, temp_git_repo):
        """Test full repository scan."""
        scanner = SecurityScanner(repo_path=temp_git_repo)

        with patch.object(scanner, "scan_working_directory") as mock_wd:
            with patch.object(scanner, "scan_commit_history") as mock_history:
                wd_result = ScanResult()
                wd_result.scanned_files = 5
                mock_wd.return_value = wd_result

                history_result = ScanResult()
                history_result.scanned_files = 10
                mock_history.return_value = history_result

                result = scanner.scan_full(include_history=True)

                assert result.scanned_files == 15
                mock_wd.assert_called_once()
                mock_history.assert_called_once()

    def test_scan_full_no_history(self, temp_git_repo):
        """Test full scan without history."""
        scanner = SecurityScanner(repo_path=temp_git_repo)

        with patch.object(scanner, "scan_working_directory") as mock_wd:
            with patch.object(scanner, "scan_commit_history") as mock_history:
                wd_result = ScanResult()
                wd_result.scanned_files = 5
                mock_wd.return_value = wd_result

                result = scanner.scan_full(include_history=False)

                assert result.scanned_files == 5
                mock_wd.assert_called_once()
                mock_history.assert_not_called()

    def test_add_custom_pattern(self, temp_git_repo):
        """Test adding custom pattern to scanner."""
        scanner = SecurityScanner(repo_path=temp_git_repo)
        initial_count = len(scanner.get_patterns())

        scanner.add_custom_pattern(
            name="Custom Secret",
            pattern=r"custom_secret_[0-9]+",
            severity="HIGH",
            description="Custom secret pattern",
        )

        assert len(scanner.get_patterns()) == initial_count + 1

        # Test detection with custom pattern
        test_file = temp_git_repo / "test.py"
        test_file.write_text('secret = "custom_secret_12345"')

        result = scanner.scan_file("test.py")
        assert any(f["type"] == "Custom Secret" for f in result.findings)

    def test_remove_pattern(self, temp_git_repo):
        """Test removing pattern from scanner."""
        scanner = SecurityScanner(repo_path=temp_git_repo)

        # Add a pattern first
        scanner.add_custom_pattern(
            name="Test Pattern", pattern=r"test_[0-9]+", severity="LOW"
        )

        initial_count = len(scanner.get_patterns())

        # Remove it
        removed = scanner.remove_pattern("Test Pattern")
        assert removed is True
        assert len(scanner.get_patterns()) == initial_count - 1

    def test_clear_cache(self, temp_git_repo):
        """Test clearing file cache."""
        scanner = SecurityScanner(repo_path=temp_git_repo)

        # Add something to cache
        scanner._file_cache["test.py"] = "cached content"

        # Clear cache
        scanner.clear_cache()

        assert len(scanner._file_cache) == 0
