"""
Command-line interface for the security scanner.
"""

import argparse
from pathlib import Path
from typing import Optional, List, Dict

from . import __version__
from .scanner import SecurityScanner
from .patterns import Severity
from .utils import ColorPrinter, FileHelper


def create_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(
        prog="git-security-scanner",
        description="Detect API keys, passwords, and secrets in your Git repositories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan current repository
  git-security-scanner

  # Scan specific repository
  git-security-scanner --path /path/to/repo

  # Check only staged files (for pre-commit hook)
  git-security-scanner --pre-commit

  # Export findings to JSON
  git-security-scanner --export findings.json

  # Scan with limited history
  git-security-scanner --history-limit 50

  # Quiet mode (only show critical issues)
  git-security-scanner --quiet --min-severity CRITICAL
        """,
    )

    # Positional arguments
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=Path.cwd(),
        help="Path to Git repository (default: current directory)",
    )

    # Optional arguments
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}"
    )

    parser.add_argument(
        "--pre-commit",
        action="store_true",
        help="Scan only staged files (for pre-commit hook)",
    )

    parser.add_argument(
        "--no-history", action="store_true", help="Skip commit history scan"
    )

    parser.add_argument(
        "--history-limit",
        type=int,
        default=100,
        metavar="N",
        help="Limit commit history scan to N commits (default: 100)",
    )

    parser.add_argument(
        "--export", type=Path, metavar="FILE", help="Export findings to JSON file"
    )

    parser.add_argument(
        "--quiet", action="store_true", help="Quiet mode - minimal output"
    )

    parser.add_argument(
        "--min-severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW",
        help="Minimum severity level to report (default: LOW)",
    )

    parser.add_argument(
        "--ignore-file",
        type=str,
        default=".gitscannerignore",
        help="Path to ignore file (default: .gitscannerignore)",
    )

    parser.add_argument(
        "--show-patterns",
        action="store_true",
        help="Show all detection patterns and exit",
    )

    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )

    return parser


def show_patterns(scanner: SecurityScanner) -> None:
    """Display all active patterns."""
    patterns = scanner.get_patterns()

    print(f"\nActive detection patterns ({len(patterns)} total):\n")

    # Group by severity
    by_severity: Dict[str, List[Dict[str, str]]] = {}
    for pattern in patterns:
        severity = pattern["severity"]
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(pattern)

    # Display by severity
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if severity in by_severity:
            ColorPrinter.print_info(f"\n{severity} Severity:")
            for pattern in by_severity[severity]:
                print(f"  - {pattern['name']}: {pattern['description']}")


def main(args: Optional[List[str]] = None) -> int:
    """
    Main entry point for the CLI.

    Args:
        args: Command line arguments (for testing)

    Returns:
        Exit code (0 for success, 1 for findings, 2 for errors)
    """
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    # Disable color if requested
    if parsed_args.no_color:
        import os

        os.environ["NO_COLOR"] = "1"

    try:
        # Initialize scanner
        scanner = SecurityScanner(
            repo_path=parsed_args.path, ignore_file=parsed_args.ignore_file
        )

        # Show patterns if requested
        if parsed_args.show_patterns:
            show_patterns(scanner)
            return 0

        # Perform scan based on mode
        if parsed_args.pre_commit:
            # Pre-commit mode - scan only staged files
            ColorPrinter.print_info("Running in pre-commit mode...")
            result = scanner.scan_staged_files()
        else:
            # Full scan mode
            include_history = not parsed_args.no_history
            result = scanner.scan_full(
                include_history=include_history, history_limit=parsed_args.history_limit
            )

        # Filter by severity
        min_severity = Severity[parsed_args.min_severity]
        filtered_findings = result.filter_by_severity(min_severity)

        # Display findings
        if not parsed_args.quiet:
            ColorPrinter.print_info(f"\nScanned {result.scanned_files} files")
            if result.skipped_files > 0:
                ColorPrinter.print_info(f"Skipped {result.skipped_files} files")

        # Show errors if any
        if result.errors and not parsed_args.quiet:
            ColorPrinter.print_error("\nErrors encountered:")
            for error in result.errors[:5]:  # Show first 5 errors
                ColorPrinter.print_error(f"  - {error}")
            if len(result.errors) > 5:
                ColorPrinter.print_error(
                    f"  ... and {len(result.errors) - 5} more"
                )

        # Display findings
        for finding in filtered_findings:
            ColorPrinter.print_finding(finding, quiet=parsed_args.quiet)

        # Show summary
        if not parsed_args.quiet:
            ColorPrinter.print_summary(filtered_findings)

        # Export if requested
        if parsed_args.export:
            FileHelper.export_findings_to_json(filtered_findings, parsed_args.export)

        # Determine exit code
        if filtered_findings:
            # Found secrets - exit with 1
            if parsed_args.pre_commit:
                ColorPrinter.print_error(
                    "\n❌ Pre-commit check failed! "
                    "Please remove secrets before committing."
                )
            return 1
        else:
            if not parsed_args.quiet:
                ColorPrinter.print_info("\n✅ All clear! No secrets detected.")
            return 0

    except ValueError as e:
        ColorPrinter.print_error(str(e))
        return 2
    except KeyboardInterrupt:
        ColorPrinter.print_error("\nScan interrupted by user")
        return 2
    except Exception as e:
        ColorPrinter.print_error(f"Unexpected error: {str(e)}")
        if not parsed_args.quiet:
            import traceback

            traceback.print_exc()
        return 2


def run_cli() -> None:
    """Run the CLI and exit with appropriate code."""
    import sys

    sys.exit(main())


if __name__ == "__main__":
    run_cli()