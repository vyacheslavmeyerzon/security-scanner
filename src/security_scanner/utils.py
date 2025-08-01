"""
Utility functions for the security scanner.
"""

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from colorama import Fore, Style, init

# Initialize colorama for cross-platform color support
init(autoreset=True)


class ColorPrinter:
    """Handle colored output to terminal."""

    SEVERITY_COLORS = {
        "CRITICAL": Fore.RED,
        "HIGH": Fore.YELLOW,
        "MEDIUM": Fore.MAGENTA,
        "LOW": Fore.BLUE,
    }

    @classmethod
    def print_finding(cls, finding: Dict[str, Any], quiet: bool = False) -> None:
        """Print a single finding with appropriate color."""
        severity = finding["severity"]
        color = cls.SEVERITY_COLORS.get(severity, Fore.WHITE)

        if quiet:
            # Minimal output for quiet mode
            print(
                f"{color}[{severity}] {finding['type']} in "
                f"{finding['file']}:{finding['line']}"
            )
        else:
            # Detailed output
            print(f"\n{color}[{severity}] {finding['type']}{Style.RESET_ALL}")
            print(f"  Description: {finding['description']}")
            print(f"  File: {finding['file']}")
            print(f"  Line: {finding['line']}")
            print(f"  Secret: {finding['secret']}")
            if finding.get("content"):
                print(f"  Content: {finding['content'][:80]}...")

    @classmethod
    def print_summary(cls, findings: List[Dict[str, Any]]) -> None:
        """Print summary of findings."""
        if not findings:
            print(f"\n{Fore.GREEN}✓ No secrets found!{Style.RESET_ALL}")
            return

        # Count by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in findings:
            severity_counts[finding["severity"]] += 1

        print(
            f"\n{Fore.RED}⚠ Found {len(findings)} potential "
            f"secrets:{Style.RESET_ALL}"
        )
        for severity, count in severity_counts.items():
            if count > 0:
                color = cls.SEVERITY_COLORS[severity]
                print(f"  {color}{severity}: {count}{Style.RESET_ALL}")

    @classmethod
    def print_error(cls, message: str) -> None:
        """Print error message."""
        print(f"{Fore.RED}Error: {message}{Style.RESET_ALL}")

    @classmethod
    def print_info(cls, message: str) -> None:
        """Print info message."""
        print(f"{Fore.CYAN}{message}{Style.RESET_ALL}")


class GitHelper:
    """Helper class for Git operations."""

    @staticmethod
    def is_git_repository(path: Path) -> bool:
        """Check if the given path is a Git repository."""
        git_dir = path / ".git"
        return git_dir.exists() and git_dir.is_dir()

    @staticmethod
    def run_git_command(
        command: List[str], cwd: Optional[Path] = None
    ) -> Optional[str]:
        """Run a Git command and return output."""
        try:
            result = subprocess.run(
                ["git"] + command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=cwd,
                check=True,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            # Silently ignore file not found errors in history
            if "does not exist" in e.stderr:
                return None
            ColorPrinter.print_error(f"Git command failed: {' '.join(command)}")
            ColorPrinter.print_error(f"Error: {e.stderr}")
            return None
        except FileNotFoundError:
            ColorPrinter.print_error("Git is not installed or not in PATH")
            return None

    @staticmethod
    def get_staged_files(repo_path: Path) -> List[str]:
        """Get list of staged files in the repository."""
        output = GitHelper.run_git_command(
            ["diff", "--cached", "--name-only"], cwd=repo_path
        )
        if output:
            return [f for f in output.split("\n") if f]
        return []

    @staticmethod
    def get_all_files(repo_path: Path) -> List[str]:
        """Get all tracked files in the repository."""
        output = GitHelper.run_git_command(["ls-files"], cwd=repo_path)
        if output:
            return [f for f in output.split("\n") if f]
        return []

    @staticmethod
    def get_file_content_from_commit(
        repo_path: Path, commit: str, filepath: str
    ) -> Optional[str]:
        """Get file content from a specific commit."""
        # Ensure filepath doesn't have duplicate extensions
        if filepath.endswith(".py.py"):
            filepath = filepath[:-3]

        output = GitHelper.run_git_command(
            ["show", f"{commit}:{filepath}"], cwd=repo_path
        )
        return output

    @staticmethod
    def get_commit_list(repo_path: Path, limit: int = 100) -> List[str]:
        """Get list of commit hashes."""
        output = GitHelper.run_git_command(
            ["rev-list", "--max-count", str(limit), "HEAD"], cwd=repo_path
        )
        if output:
            return [c for c in output.split("\n") if c]
        return []

    @staticmethod
    def get_changed_files_in_commit(repo_path: Path, commit: str) -> List[str]:
        """Get list of files changed in a specific commit."""
        output = GitHelper.run_git_command(
            ["diff-tree", "--no-commit-id", "--name-only", "-r", commit], cwd=repo_path
        )
        if output:
            return [f for f in output.split("\n") if f]
        return []


class FileHelper:
    """Helper class for file operations."""

    @staticmethod
    def read_file_safely(
        filepath: Union[str, Path], max_size_mb: int = 10
    ) -> Optional[str]:
        """Read file content safely with size limit."""
        filepath = Path(filepath)

        if not filepath.exists():
            return None

        # Check file size
        file_size_mb = filepath.stat().st_size / (1024 * 1024)
        if file_size_mb > max_size_mb:
            ColorPrinter.print_info(
                f"Skipping large file: {filepath} ({file_size_mb:.1f}MB)"
            )
            return None

        try:
            # Try to read as text with different encodings
            encodings = ["utf-8", "latin-1", "cp1252"]
            for encoding in encodings:
                try:
                    return filepath.read_text(encoding=encoding)
                except UnicodeDecodeError:
                    continue

            # If all encodings fail, skip the file
            ColorPrinter.print_info(f"Skipping binary file: {filepath}")
            return None

        except Exception as e:
            ColorPrinter.print_error(f"Error reading file {filepath}: {str(e)}")
            return None

    @staticmethod
    def is_binary_file(filepath: Union[str, Path]) -> bool:
        """Check if file is likely binary."""
        filepath = Path(filepath)

        # Check common binary extensions
        binary_extensions = {
            ".exe",
            ".dll",
            ".so",
            ".dylib",
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".pdf",
            ".zip",
            ".tar",
            ".gz",
            ".rar",
            ".7z",
            ".mp3",
            ".mp4",
            ".avi",
            ".mov",
            ".bin",
            ".dat",
            ".db",
        }

        if filepath.suffix.lower() in binary_extensions:
            return True

        # Check file content for binary data
        try:
            with open(filepath, "rb") as f:
                chunk = f.read(8192)  # Read first 8KB
                # File is binary if it contains null bytes
                return b"\x00" in chunk
        except Exception:
            return True

    @staticmethod
    def export_findings_to_json(
        findings: List[Dict[str, Any]], output_path: Union[str, Path]
    ) -> bool:
        """Export findings to JSON file."""
        try:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(
                    {"total_findings": len(findings), "findings": findings}, f, indent=2
                )

            ColorPrinter.print_info(f"Findings exported to: {output_path}")
            return True

        except Exception as e:
            ColorPrinter.print_error(f"Failed to export findings: {str(e)}")
            return False

    @staticmethod
    def determine_export_format(
        output_path: Union[str, Path], format_hint: Optional[str] = None
    ) -> str:
        """
        Determine export format from file extension or format hint.

        Args:
            output_path: Path to output file
            format_hint: Optional format hint (json, html, csv, markdown)

        Returns:
            Export format string
        """
        output_path = Path(output_path)

        if format_hint:
            return format_hint.lower()

        suffix = output_path.suffix.lower()
        format_map = {
            ".json": "json",
            ".html": "html",
            ".htm": "html",
            ".csv": "csv",
            ".md": "markdown",
            ".markdown": "markdown",
        }

        return format_map.get(suffix, "json")


class IgnoreFileParser:
    """Parser for .gitscannerignore files."""

    def __init__(self, ignore_file_path: Optional[Path] = None):
        """Initialize with optional ignore file path."""
        self.patterns: List[str] = []
        self.regex_patterns: List[re.Pattern] = []
        if ignore_file_path and ignore_file_path.exists():
            self._load_ignore_file(ignore_file_path)

    def _load_ignore_file(self, filepath: Path) -> None:
        """Load patterns from ignore file."""
        try:
            content = filepath.read_text(encoding="utf-8")
            for line in content.splitlines():
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith("#"):
                    self.patterns.append(line)
                    # Convert glob pattern to regex
                    regex_pattern = self._glob_to_regex(line)
                    self.regex_patterns.append(re.compile(regex_pattern))
        except Exception as e:
            ColorPrinter.print_error(f"Failed to load ignore file: {str(e)}")

    def _glob_to_regex(self, pattern: str) -> str:
        """Convert glob pattern to regex."""
        # Escape special regex characters except glob wildcards
        pattern = pattern.replace("\\", "\\\\")
        pattern = pattern.replace(".", "\\.")
        pattern = pattern.replace("+", "\\+")
        pattern = pattern.replace("^", "\\^")
        pattern = pattern.replace("$", "\\$")
        pattern = pattern.replace("(", "\\(")
        pattern = pattern.replace(")", "\\)")
        pattern = pattern.replace("[", "\\[")
        pattern = pattern.replace("]", "\\]")
        pattern = pattern.replace("{", "\\{")
        pattern = pattern.replace("}", "\\}")

        # Convert glob wildcards to regex
        pattern = pattern.replace("**/", "(?:.*/)?")  # Match any number of directories
        pattern = pattern.replace("*", "[^/]*")  # Match any characters except /
        pattern = pattern.replace("?", "[^/]")  # Match single character except /

        # Handle directory patterns (ending with /)
        if pattern.endswith("/"):
            pattern = pattern + ".*"

        # Anchor pattern
        if pattern.startswith("/"):
            pattern = "^" + pattern[1:]
        else:
            pattern = "(?:^|/)" + pattern

        return pattern + "$"

    def should_ignore(self, filepath: str) -> bool:
        """Check if file should be ignored based on patterns."""
        # Normalize path separators
        filepath = filepath.replace("\\", "/")

        for regex_pattern in self.regex_patterns:
            if regex_pattern.search(filepath):
                return True

        return False


def get_version() -> str:
    """Get the package version."""
    from . import __version__

    return __version__
