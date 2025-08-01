"""
Tests for export functionality.
"""

import csv
import json
from datetime import datetime

import pytest

from security_scanner.export import ReportGenerator


class TestReportGenerator:
    """Test cases for ReportGenerator class."""

    @pytest.fixture
    def sample_findings(self):
        """Create sample findings for testing."""
        return [
            {
                "type": "AWS Access Key",
                "severity": "CRITICAL",
                "file": "config.py",
                "line": 10,
                "column": 15,
                "secret": "AKIAIOSFODNN7EXAMPLE",
                "description": "AWS Access Key found",
                "content": 'aws_key = "AKIAIOSFODNN7EXAMPLE"',
            },
            {
                "type": "GitHub Token",
                "severity": "HIGH",
                "file": "settings.py",
                "line": 25,
                "column": 10,
                "secret": "ghp_1234567890abcdef1234567890abcdef1234",
                "description": "GitHub Personal Access Token",
                "content": 'token = "ghp_1234567890abcdef1234567890abcdef1234"',
            },
            {
                "type": "Generic Secret",
                "severity": "MEDIUM",
                "file": "test.py",
                "line": 5,
                "column": 8,
                "secret": "super_secret_password_123",
                "description": "Generic secret pattern",
                "content": 'password = "super_secret_password_123"',
            },
            {
                "type": "Environment Variable",
                "severity": "LOW",
                "file": ".env",
                "line": 3,
                "column": 1,
                "secret": "SECRET_KEY=mysecret",
                "description": "Environment variable assignment",
                "content": "SECRET_KEY=mysecret",
            },
            {
                "type": "AWS Access Key",
                "severity": "CRITICAL",
                "file": "backup/old_config.py",
                "line": 45,
                "column": 20,
                "secret": "AKIAIOSFODNN8EXAMPLE",
                "description": "AWS Access Key found",
                "content": 'old_key = "AKIAIOSFODNN8EXAMPLE"',
                "commit": "abc123",
            },
        ]

    @pytest.fixture
    def scan_stats(self):
        """Create sample scan statistics."""
        return {
            "scanned_files": 150,
            "skipped_files": 25,
            "errors": 2,
            "scan_timestamp": datetime.now().isoformat(),
        }

    def test_report_generator_initialization(self, sample_findings, scan_stats):
        """Test ReportGenerator initialization."""
        report_gen = ReportGenerator(sample_findings, scan_stats)

        assert report_gen.findings == sample_findings
        assert report_gen.scan_stats == scan_stats
        assert isinstance(report_gen.timestamp, datetime)

    def test_generate_statistics(self, sample_findings, scan_stats):
        """Test statistics generation."""
        report_gen = ReportGenerator(sample_findings, scan_stats)
        stats = report_gen.generate_statistics()

        # Check basic counts
        assert stats["total_findings"] == 5
        assert stats["by_severity"]["CRITICAL"] == 2
        assert stats["by_severity"]["HIGH"] == 1
        assert stats["by_severity"]["MEDIUM"] == 1
        assert stats["by_severity"]["LOW"] == 1

        # Check type distribution
        assert stats["by_type"]["AWS Access Key"] == 2
        assert stats["by_type"]["GitHub Token"] == 1

        # Check most common types
        assert len(stats["most_common_types"]) > 0
        assert stats["most_common_types"][0]["type"] == "AWS Access Key"
        assert stats["most_common_types"][0]["count"] == 2

        # Check files with most findings
        assert len(stats["files_with_most_findings"]) > 0

        # Check scan stats are included
        assert stats["scanned_files"] == 150
        assert stats["skipped_files"] == 25

    def test_export_to_csv(self, sample_findings, tmp_path):
        """Test CSV export functionality."""
        report_gen = ReportGenerator(sample_findings)
        csv_path = tmp_path / "report.csv"

        report_gen.export_to_csv(csv_path)

        assert csv_path.exists()

        # Read and verify CSV content
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 5

        # Check first row
        first_row = rows[0]
        assert first_row["severity"] == "CRITICAL"
        assert first_row["type"] == "AWS Access Key"
        assert first_row["file"] == "config.py"
        assert first_row["line"] == "10"

        # Check that secret is present (not truncated for short secrets)
        assert first_row["secret"] == "AKIAIOSFODNN7EXAMPLE"

    def test_export_to_html(self, sample_findings, scan_stats, tmp_path):
        """Test HTML export functionality."""
        report_gen = ReportGenerator(sample_findings, scan_stats)
        html_path = tmp_path / "report.html"

        report_gen.export_to_html(html_path)

        assert html_path.exists()

        # Read and verify HTML content
        html_content = html_path.read_text(encoding="utf-8")

        # Check basic structure
        assert "<!DOCTYPE html>" in html_content
        assert "<title>Security Scanner Report" in html_content

        # Check statistics are present
        assert "Total Findings" in html_content
        assert "5" in html_content  # Total findings count

        # Check severity counts
        assert "Critical" in html_content
        assert "High" in html_content

        # Check findings table
        assert "AWS Access Key" in html_content
        assert "config.py" in html_content

        # Check JavaScript functions
        assert "function filterTable()" in html_content
        assert "function sortTable(" in html_content

        # Check CSS styles
        assert ".severity-critical" in html_content
        assert ".findings-table" in html_content

    def test_export_to_json_with_stats(self, sample_findings, scan_stats, tmp_path):
        """Test JSON export with statistics."""
        report_gen = ReportGenerator(sample_findings, scan_stats)
        json_path = tmp_path / "report.json"

        report_gen.export_to_json_with_stats(json_path)

        assert json_path.exists()

        # Read and verify JSON content
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert "metadata" in data
        assert "statistics" in data
        assert "findings" in data

        assert data["metadata"]["version"] == "1.0"
        assert data["statistics"]["total_findings"] == 5
        assert len(data["findings"]) == 5

    def test_export_to_markdown(self, sample_findings, scan_stats, tmp_path):
        """Test Markdown export functionality."""
        report_gen = ReportGenerator(sample_findings, scan_stats)
        md_path = tmp_path / "report.md"

        report_gen.export_to_markdown(md_path)

        assert md_path.exists()

        # Read and verify Markdown content
        md_content = md_path.read_text(encoding="utf-8")

        # Check structure
        assert "# Security Scanner Report" in md_content
        assert "## Summary" in md_content
        assert "## Top Secret Types" in md_content
        assert "## Detailed Findings" in md_content

        # Check statistics
        assert "**Total Findings**: 5" in md_content
        assert "**Critical**: 2" in md_content

        # Check findings are grouped by severity
        assert "### CRITICAL Severity" in md_content
        assert "### HIGH Severity" in md_content

        # Check specific findings
        assert "AWS Access Key" in md_content
        assert "config.py:10" in md_content

    def test_empty_findings(self, tmp_path):
        """Test export with no findings."""
        report_gen = ReportGenerator([])

        # Test all export formats
        csv_path = tmp_path / "empty.csv"
        report_gen.export_to_csv(csv_path)
        assert csv_path.exists()

        html_path = tmp_path / "empty.html"
        report_gen.export_to_html(html_path)
        assert html_path.exists()
        html_content = html_path.read_text()
        assert "Total Findings" in html_content
        assert ">0<" in html_content  # Zero findings

        json_path = tmp_path / "empty.json"
        report_gen.export_to_json_with_stats(json_path)
        with open(json_path) as f:
            data = json.load(f)
        assert data["statistics"]["total_findings"] == 0

    def test_long_secret_truncation(self, tmp_path):
        """Test that long secrets are truncated in CSV."""
        long_secret = "a" * 100
        findings = [
            {
                "type": "Test",
                "severity": "HIGH",
                "file": "test.py",
                "line": 1,
                "secret": long_secret,
                "description": "Test finding",
            }
        ]

        report_gen = ReportGenerator(findings)
        csv_path = tmp_path / "truncated.csv"
        report_gen.export_to_csv(csv_path)

        with open(csv_path, "r") as f:
            reader = csv.DictReader(f)
            row = next(reader)

        # Check secret is truncated
        assert len(row["secret"]) < len(long_secret)
        assert "..." in row["secret"]

    def test_html_escaping(self, tmp_path):
        """Test HTML escaping in HTML export."""
        findings = [
            {
                "type": "<script>alert('XSS')</script>",
                "severity": "HIGH",
                "file": "test<>.py",
                "line": 1,
                "secret": "secret",
                "description": "Test & finding",
            }
        ]

        report_gen = ReportGenerator(findings)
        html_path = tmp_path / "escaped.html"
        report_gen.export_to_html(html_path)

        html_content = html_path.read_text()

        # Check that HTML is properly escaped in the table content
        assert "&lt;script&gt;" in html_content
        assert "test&lt;&gt;.py" in html_content

        # Check that the script tags in the template are legitimate
        # (not from user input)
        # Split by the actual JavaScript section
        parts = html_content.split("<script>")

        # The first part (before any script tags) should have escaped content
        assert "&lt;script&gt;" in parts[0]

        # Check that description is also escaped
        assert "Test &amp; finding" in html_content

    def test_statistics_with_no_scan_stats(self, sample_findings):
        """Test statistics generation without scan stats."""
        report_gen = ReportGenerator(sample_findings)
        stats = report_gen.generate_statistics()

        assert stats["total_findings"] == 5
        assert "by_severity" in stats
        assert "by_type" in stats
        # Scan stats should not be present
        assert "scanned_files" not in stats

    def test_file_paths_in_statistics(self, tmp_path):
        """Test file path handling in statistics."""
        findings = [
            {
                "type": "Secret",
                "severity": "HIGH",
                "file": "very/long/path/to/file/that/exceeds/normal/length/test.py",
                "line": 1,
                "secret": "secret",
            },
            {
                "type": "Secret",
                "severity": "HIGH",
                "file": "very/long/path/to/file/that/exceeds/normal/length/test.py",
                "line": 10,
                "secret": "secret2",
            },
        ]

        report_gen = ReportGenerator(findings)
        html_path = tmp_path / "longpath.html"
        report_gen.export_to_html(html_path)

        html_content = html_path.read_text()
        # Check that long paths are truncated in charts
        assert "..." in html_content
