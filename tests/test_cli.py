"""
Tests for CLI functionality.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from security_scanner.cli import create_parser, main, show_patterns
from security_scanner.scanner import ScanResult


class TestCLI:
    """Test cases for CLI functionality."""

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

    def test_create_parser(self):
        """Test argument parser creation."""
        parser = create_parser()

        # Test parsing various arguments
        # Skip --version as it causes SystemExit

        args = parser.parse_args(["--pre-commit"])
        assert args.pre_commit is True

        args = parser.parse_args(["--history-limit", "50"])
        assert args.history_limit == 50

        args = parser.parse_args(["--min-severity", "HIGH"])
        assert args.min_severity == "HIGH"

    def test_parser_defaults(self):
        """Test parser default values."""
        parser = create_parser()
        args = parser.parse_args([])

        assert args.path == Path.cwd()
        assert args.pre_commit is False
        assert args.no_history is False
        assert args.history_limit == 100
        assert args.quiet is False
        assert args.min_severity is None  # No default in parser, handled by config
        assert args.ignore_file == ".gitscannerignore"

    @patch("security_scanner.cli.SecurityScanner")
    def test_show_patterns(self, mock_scanner_class):
        """Test showing patterns."""
        # Mock scanner instance
        mock_scanner = MagicMock()
        mock_scanner.get_patterns.return_value = [
            {"name": "Pattern1", "severity": "HIGH", "description": "Test pattern 1"},
            {
                "name": "Pattern2",
                "severity": "CRITICAL",
                "description": "Test pattern 2",
            },
            {"name": "Pattern3", "severity": "LOW", "description": "Test pattern 3"},
        ]

        # Capture output
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            show_patterns(mock_scanner)

        output = f.getvalue()
        assert "Pattern1" in output
        assert "Pattern2" in output
        assert "Pattern3" in output
        assert "HIGH" in output
        assert "CRITICAL" in output
        assert "LOW" in output

    @patch("security_scanner.cli.SecurityScanner")
    def test_main_show_patterns(self, mock_scanner_class, temp_git_repo):
        """Test main function with --show-patterns."""
        mock_scanner = MagicMock()
        mock_scanner.get_patterns.return_value = []
        mock_scanner_class.return_value = mock_scanner

        result = main(["--show-patterns", str(temp_git_repo)])

        assert result == 0
        mock_scanner.get_patterns.assert_called_once()

    @patch("security_scanner.cli.SecurityScanner")
    def test_main_pre_commit_mode(self, mock_scanner_class, temp_git_repo):
        """Test main function in pre-commit mode."""
        mock_scanner = MagicMock()
        mock_result = ScanResult()
        mock_result.scanned_files = 5
        mock_scanner.scan_staged_files.return_value = mock_result
        mock_scanner_class.return_value = mock_scanner

        result = main(["--pre-commit", str(temp_git_repo)])

        assert result == 0
        mock_scanner.scan_staged_files.assert_called_once()

    @patch("security_scanner.cli.SecurityScanner")
    def test_main_full_scan(self, mock_scanner_class, temp_git_repo):
        """Test main function with full scan."""
        mock_scanner = MagicMock()
        mock_result = ScanResult()
        mock_result.scanned_files = 10
        mock_scanner.scan_full.return_value = mock_result
        mock_scanner_class.return_value = mock_scanner

        result = main([str(temp_git_repo)])

        assert result == 0
        mock_scanner.scan_full.assert_called_once_with(include_history=True)

    @patch("security_scanner.cli.SecurityScanner")
    def test_main_no_history(self, mock_scanner_class, temp_git_repo):
        """Test main function with --no-history."""
        mock_scanner = MagicMock()
        mock_result = ScanResult()
        mock_scanner.scan_full.return_value = mock_result
        mock_scanner_class.return_value = mock_scanner

        result = main(["--no-history", str(temp_git_repo)])

        assert result == 0
        mock_scanner.scan_full.assert_called_once_with(include_history=False)

    @patch("security_scanner.cli.SecurityScanner")
    def test_main_with_findings(self, mock_scanner_class, temp_git_repo):
        """Test main function when secrets are found."""
        mock_scanner = MagicMock()
        mock_result = MagicMock(spec=ScanResult)
        mock_result.scanned_files = 5
        mock_result.skipped_files = 0
        mock_result.findings = [
            {
                "type": "AWS Access Key",
                "severity": "CRITICAL",
                "file": "config.py",
                "line": 10,
                "secret": "AKIA...",
                "description": "AWS Access Key found",
                "content": 'aws_key = "AKIA..."',
            }
        ]
        mock_result.errors = []
        mock_result.get_unique_findings.return_value = mock_result.findings
        mock_result.filter_by_severity.return_value = mock_result.findings

        mock_scanner.scan_full.return_value = mock_result
        mock_scanner_class.return_value = mock_scanner

        result = main([str(temp_git_repo)])

        assert result == 1  # Should return 1 when findings exist

    @patch("security_scanner.cli.SecurityScanner")
    @patch("security_scanner.cli.ReportGenerator")
    def test_main_with_export(
        self, mock_report_gen_class, mock_scanner_class, temp_git_repo
    ):
        """Test main function with export option."""
        mock_scanner = MagicMock()
        mock_result = MagicMock(spec=ScanResult)
        mock_result.scanned_files = 5
        mock_result.skipped_files = 0
        mock_result.findings = []
        mock_result.errors = []
        mock_result.get_unique_findings.return_value = []
        mock_result.filter_by_severity.return_value = []
        mock_scanner.scan_full.return_value = mock_result
        mock_scanner_class.return_value = mock_scanner

        # Mock ReportGenerator
        mock_report_gen = MagicMock()
        mock_report_gen_class.return_value = mock_report_gen

        export_file = temp_git_repo / "findings.json"

        result = main(["--export", str(export_file), str(temp_git_repo)])

        assert result == 0
        # Check that ReportGenerator was created and export method was called
        mock_report_gen_class.assert_called_once()
        mock_report_gen.export_to_json_with_stats.assert_called_once_with(export_file)

    @patch("security_scanner.cli.SecurityScanner")
    def test_main_quiet_mode(self, mock_scanner_class, temp_git_repo):
        """Test main function in quiet mode."""
        mock_scanner = MagicMock()
        mock_result = MagicMock(spec=ScanResult)
        mock_result.scanned_files = 5
        mock_result.skipped_files = 0
        mock_result.findings = []
        mock_result.errors = []
        mock_result.get_unique_findings.return_value = []
        mock_result.filter_by_severity.return_value = []
        mock_scanner.scan_full.return_value = mock_result
        mock_scanner_class.return_value = mock_scanner

        # Capture output
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            main(["--quiet", str(temp_git_repo)])

        output = f.getvalue()
        # In quiet mode, should have minimal output
        assert len(output.strip()) == 0 or "All clear" not in output

    @patch("security_scanner.cli.SecurityScanner")
    def test_main_min_severity_filter(self, mock_scanner_class, temp_git_repo):
        """Test main function with minimum severity filter."""
        mock_scanner = MagicMock()
        mock_result = MagicMock(spec=ScanResult)
        mock_result.scanned_files = 10
        mock_result.skipped_files = 2

        # Add findings of different severities
        findings = [
            {
                "type": "Test1",
                "severity": "LOW",
                "description": "Low severity finding",
                "file": "test1.py",
                "line": 1,
                "secret": "secret1",
                "content": "content1",
            },
            {
                "type": "Test2",
                "severity": "MEDIUM",
                "description": "Medium severity finding",
                "file": "test2.py",
                "line": 2,
                "secret": "secret2",
                "content": "content2",
            },
            {
                "type": "Test3",
                "severity": "HIGH",
                "description": "High severity finding",
                "file": "test3.py",
                "line": 3,
                "secret": "secret3",
                "content": "content3",
            },
            {
                "type": "Test4",
                "severity": "CRITICAL",
                "description": "Critical severity finding",
                "file": "test4.py",
                "line": 4,
                "secret": "secret4",
                "content": "content4",
            },
        ]
        mock_result.findings = findings
        mock_result.errors = []

        mock_result.get_unique_findings.return_value = findings
        mock_result.filter_by_severity.return_value = [
            f for f in findings if f["severity"] in ["HIGH", "CRITICAL"]
        ]

        mock_scanner.scan_full.return_value = mock_result
        mock_scanner_class.return_value = mock_scanner

        result = main(["--min-severity", "HIGH", str(temp_git_repo)])

        assert result == 1  # Has findings
        mock_result.filter_by_severity.assert_called_once()

    def test_main_not_git_repo(self):
        """Test main function with non-Git repository."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = main([tmpdir])
            assert result == 2  # Should return error code

    @patch("security_scanner.cli.SecurityScanner")
    def test_main_keyboard_interrupt(self, mock_scanner_class, temp_git_repo):
        """Test handling KeyboardInterrupt."""
        mock_scanner_class.side_effect = KeyboardInterrupt()

        result = main([str(temp_git_repo)])
        assert result == 2

    @patch("security_scanner.cli.SecurityScanner")
    def test_main_unexpected_error(self, mock_scanner_class, temp_git_repo):
        """Test handling unexpected errors."""
        mock_scanner_class.side_effect = Exception("Unexpected error")

        result = main([str(temp_git_repo)])
        assert result == 2

    def test_main_no_color(self, temp_git_repo):
        """Test --no-color option."""
        with patch("security_scanner.cli.SecurityScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_result = MagicMock(spec=ScanResult)
            mock_result.scanned_files = 3
            mock_result.skipped_files = 0
            mock_result.findings = []
            mock_result.errors = []
            mock_result.get_unique_findings.return_value = []
            mock_result.filter_by_severity.return_value = []
            mock_scanner.scan_full.return_value = mock_result
            mock_scanner_class.return_value = mock_scanner

            # Clear env var first
            if "NO_COLOR" in os.environ:
                del os.environ["NO_COLOR"]

            result = main(["--no-color", str(temp_git_repo)])

            assert result == 0
            assert os.environ.get("NO_COLOR") == "1"

    @patch("security_scanner.cli.SecurityScanner")
    def test_main_pre_commit_with_findings(self, mock_scanner_class, temp_git_repo):
        """Test pre-commit mode with findings (should fail)."""
        mock_scanner = MagicMock()
        mock_result = MagicMock(spec=ScanResult)
        mock_result.scanned_files = 1
        mock_result.skipped_files = 0
        mock_result.findings = [
            {
                "type": "Secret",
                "severity": "HIGH",
                "file": "test.py",
                "line": 1,
                "secret": "secret",
                "description": "Found secret",
                "content": 'secret = "value"',
            }
        ]
        mock_result.errors = []
        mock_result.get_unique_findings.return_value = mock_result.findings
        mock_result.filter_by_severity.return_value = mock_result.findings

        mock_scanner.scan_staged_files.return_value = mock_result
        mock_scanner_class.return_value = mock_scanner

        # Capture output
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            result = main(["--pre-commit", str(temp_git_repo)])

        output = f.getvalue()
        assert result == 1
        assert "Pre-commit check failed" in output
