"""
Core scanner module for detecting secrets in Git repositories.
"""

import os
from pathlib import Path
from typing import List, Dict, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

from .patterns import PatternMatcher, Severity
from .utils import GitHelper, FileHelper, ColorPrinter, IgnoreFileParser


class ScanResult:
    """Container for scan results."""

    def __init__(self):
        """Initialize empty scan result."""
        self.findings: List[Dict[str, any]] = []
        self.scanned_files: int = 0
        self.skipped_files: int = 0
        self.errors: List[str] = []

    def add_finding(self, finding: Dict[str, any]) -> None:
        """Add a finding to results."""
        self.findings.append(finding)

    def add_error(self, error: str) -> None:
        """Add an error message."""
        self.errors.append(error)

    def merge(self, other: 'ScanResult') -> None:
        """Merge another scan result into this one."""
        self.findings.extend(other.findings)
        self.scanned_files += other.scanned_files
        self.skipped_files += other.skipped_files
        self.errors.extend(other.errors)

    def filter_by_severity(self, min_severity: Severity) -> List[Dict[str, any]]:
        """Filter findings by minimum severity level."""
        severity_order = {
            Severity.LOW: 0,
            Severity.MEDIUM: 1,
            Severity.HIGH: 2,
            Severity.CRITICAL: 3
        }

        min_level = severity_order[min_severity]

        return [
            f for f in self.findings
            if severity_order[Severity[f['severity']]] >= min_level
        ]

    def get_unique_findings(self) -> List[Dict[str, any]]:
        """Get unique findings (remove duplicates)."""
        seen = set()
        unique_findings = []

        for finding in self.findings:
            # Create a unique key for each finding
            key = (
                finding['type'],
                finding['file'],
                finding['line'],
                finding['secret']
            )

            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        return unique_findings


class SecurityScanner:
    """Main scanner class for detecting secrets in repositories."""

    def __init__(self, repo_path: Optional[Path] = None,
                 pattern_matcher: Optional[PatternMatcher] = None,
                 ignore_file: Optional[str] = ".gitscannerignore"):
        """
        Initialize the security scanner.

        Args:
            repo_path: Path to the Git repository (defaults to current directory)
            pattern_matcher: Custom pattern matcher (defaults to built-in patterns)
            ignore_file: Name of ignore file to use
        """
        self.repo_path = Path(repo_path) if repo_path else Path.cwd()
        self.pattern_matcher = pattern_matcher or PatternMatcher()

        # Load ignore patterns
        ignore_file_path = self.repo_path / ignore_file if ignore_file else None
        self.ignore_parser = IgnoreFileParser(ignore_file_path)

        # Cache for file contents to avoid re-reading
        self._file_cache: Dict[str, Optional[str]] = {}

        # Validate repository
        if not GitHelper.is_git_repository(self.repo_path):
            raise ValueError(f"Not a Git repository: {self.repo_path}")

    def scan_file(self, filepath: str, content: Optional[str] = None) -> ScanResult:
        """
        Scan a single file for secrets.

        Args:
            filepath: Path to the file relative to repo root
            content: Optional file content (will be read if not provided)

        Returns:
            ScanResult containing findings for this file
        """
        result = ScanResult()

        # Check if file should be ignored
        if self.ignore_parser.should_ignore(filepath):
            result.skipped_files = 1
            return result

        # Check if file should be scanned based on patterns
        if not self.pattern_matcher.should_scan_file(filepath):
            result.skipped_files = 1
            return result

        # Get file content
        if content is None:
            full_path = self.repo_path / filepath
            content = FileHelper.read_file_safely(full_path)

            if content is None:
                result.skipped_files = 1
                return result

        # Scan for secrets
        findings = self.pattern_matcher.find_secrets(content, filepath)
        for finding in findings:
            result.add_finding(finding)

        result.scanned_files = 1
        return result

    def scan_staged_files(self) -> ScanResult:
        """Scan only staged files (for pre-commit hook)."""
        result = ScanResult()

        # Get staged files
        staged_files = GitHelper.get_staged_files(self.repo_path)

        if not staged_files:
            ColorPrinter.print_info("No staged files to scan")
            return result

        ColorPrinter.print_info(f"Scanning {len(staged_files)} staged files...")

        # Scan each staged file
        for filepath in staged_files:
            file_result = self.scan_file(filepath)
            result.merge(file_result)

        return result

    def scan_working_directory(self) -> ScanResult:
        """Scan all files in the working directory."""
        result = ScanResult()

        # Get all tracked files
        all_files = GitHelper.get_all_files(self.repo_path)

        if not all_files:
            ColorPrinter.print_info("No files to scan")
            return result

        ColorPrinter.print_info(f"Scanning {len(all_files)} files in working directory...")

        # Use thread pool for parallel scanning
        with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
            future_to_file = {
                executor.submit(self.scan_file, filepath): filepath
                for filepath in all_files
            }

            for future in as_completed(future_to_file):
                filepath = future_to_file[future]
                try:
                    file_result = future.result()
                    result.merge(file_result)
                except Exception as e:
                    result.add_error(f"Error scanning {filepath}: {str(e)}")

        return result

    def scan_commit_history(self, limit: int = 100) -> ScanResult:
        """
        Scan commit history for secrets.

        Args:
            limit: Maximum number of commits to scan

        Returns:
            ScanResult containing findings from commit history
        """
        result = ScanResult()

        # Get list of commits
        commits = GitHelper.get_commit_list(self.repo_path, limit)

        if not commits:
            ColorPrinter.print_info("No commits to scan")
            return result

        ColorPrinter.print_info(f"Scanning {len(commits)} commits...")

        # Track files we've already scanned to avoid duplicates
        scanned_file_versions: Set[str] = set()

        for i, commit in enumerate(commits):
            # Get changed files in this commit
            changed_files = GitHelper.get_changed_files_in_commit(self.repo_path, commit)

            for filepath in changed_files:
                # Create unique key for this file version
                file_version_key = f"{commit}:{filepath}"

                if file_version_key in scanned_file_versions:
                    continue

                scanned_file_versions.add(file_version_key)

                # Get file content from commit
                content = GitHelper.get_file_content_from_commit(
                    self.repo_path, commit, filepath
                )

                if content:
                    file_result = self.scan_file(filepath, content)

                    # Add commit info to findings
                    for finding in file_result.findings:
                        finding['commit'] = commit[:8]

                    result.merge(file_result)

            # Show progress
            if (i + 1) % 10 == 0:
                ColorPrinter.print_info(f"Processed {i + 1}/{len(commits)} commits...")

        return result

    def scan_full(self, include_history: bool = True, history_limit: int = 100) -> ScanResult:
        """
        Perform a full scan of the repository.

        Args:
            include_history: Whether to scan commit history
            history_limit: Maximum number of commits to scan

        Returns:
            Complete scan results
        """
        result = ScanResult()

        # Scan working directory
        ColorPrinter.print_info("=== Scanning working directory ===")
        wd_result = self.scan_working_directory()
        result.merge(wd_result)

        # Scan commit history if requested
        if include_history:
            ColorPrinter.print_info("\n=== Scanning commit history ===")
            history_result = self.scan_commit_history(history_limit)
            result.merge(history_result)

        return result

    @lru_cache(maxsize=128)
    def _get_cached_file_content(self, filepath: str) -> Optional[str]:
        """Get file content with caching."""
        full_path = self.repo_path / filepath
        return FileHelper.read_file_safely(full_path)

    def clear_cache(self) -> None:
        """Clear the file content cache."""
        self._get_cached_file_content.cache_clear()
        self._file_cache.clear()

    def add_custom_pattern(self, name: str, pattern: str,
                           severity: str = "MEDIUM", description: str = "") -> None:
        """
        Add a custom pattern to the scanner.

        Args:
            name: Name of the pattern
            pattern: Regular expression pattern
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            description: Description of what this pattern detects
        """
        severity_enum = Severity[severity.upper()]
        self.pattern_matcher.add_custom_pattern(
            name=name,
            pattern=pattern,
            severity=severity_enum,
            description=description or f"Custom pattern: {name}"
        )

    def remove_pattern(self, name: str) -> bool:
        """
        Remove a pattern by name.

        Args:
            name: Name of the pattern to remove

        Returns:
            True if pattern was removed, False if not found
        """
        return self.pattern_matcher.remove_pattern(name)

    def get_patterns(self) -> List[Dict[str, str]]:
        """Get list of all active patterns."""
        return self.pattern_matcher.get_patterns()