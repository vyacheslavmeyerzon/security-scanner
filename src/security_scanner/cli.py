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
from .config import ScannerConfig, create_example_config


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

  # Generate example configuration
  git-security-scanner --generate-config
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
        "-c",
        "--config",
        type=Path,
        help="Path to configuration file",
    )

    parser.add_argument(
        "--generate-config",
        action="store_true",
        help="Generate example configuration file",
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
        "--output-format",
        choices=["console", "json", "html", "csv"],
        help="Output format (overrides config)",
    )

    parser.add_argument(
        "--quiet", action="store_true", help="Quiet mode - minimal output"
    )

    parser.add_argument(
        "--min-severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Minimum severity level to report",
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

    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress bars",
    )

    parser.add_argument(
        "--validate-config",
        action="store_true",
        help="Validate configuration and exit",
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

    # Handle config generation
    if parsed_args.generate_config:
        config_path = Path.cwd() / ".gitscannerrc.json"
        create_example_config(config_path)
        return 0

    # Load configuration
    config = ScannerConfig(parsed_args.config)

    # Apply command-line overrides to config
    if parsed_args.quiet:
        config.set("output.quiet", True)
    if parsed_args.min_severity:
        config.set("output.min_severity", parsed_args.min_severity)
    if parsed_args.history_limit is not None:
        config.set("scan.history_limit", parsed_args.history_limit)
    if parsed_args.output_format:
        config.set("output.format", parsed_args.output_format)
    if parsed_args.no_progress:
        config.set("scan.show_progress", False)

    # Disable color if requested
    if parsed_args.no_color or not config.get("output.color", True):
        import os

        os.environ["NO_COLOR"] = "1"

    # Validate config if requested
    if parsed_args.validate_config:
        errors = config.validate()
        if errors:
            ColorPrinter.print_error("Configuration errors found:")
            for error in errors:
                ColorPrinter.print_error(f"  - {error}")
            return 2
        else:
            ColorPrinter.print_info("Configuration is valid!")
            if config.config_path:
                ColorPrinter.print_info(f"Loaded from: {config.config_path}")
            return 0

    try:
        # Initialize scanner with config
        scanner = SecurityScanner(
            repo_path=parsed_args.path,
            ignore_file=parsed_args.ignore_file,
            config=config,
        )

        # Show patterns if requested
        if parsed_args.show_patterns:
            show_patterns(scanner)
            return 0

        # Perform scan based on mode
        if parsed_args.pre_commit:
            # Pre-commit mode - scan only staged files
            if not config.get("output.quiet"):
                ColorPrinter.print_info("Running in pre-commit mode...")
            result = scanner.scan_staged_files()
        else:
            # Full scan mode
            include_history = not parsed_args.no_history
            result = scanner.scan_full(include_history=include_history)

        # Filter by severity
        min_severity_str = config.get("output.min_severity", "LOW")
        min_severity = Severity[min_severity_str]
        filtered_findings = result.filter_by_severity(min_severity)

        # Handle different output formats
        output_format = config.get_output_format()

        if output_format == "json":
            # JSON output
            import json
            output_data = {
                "version": __version__,
                "scanned_files": result.scanned_files,
                "skipped_files": result.skipped_files,
                "total_findings": len(filtered_findings),
                "findings": filtered_findings,
                "errors": result.errors[:10],  # Limit errors in output
            }
            print(json.dumps(output_data, indent=2))

        elif output_format == "console":
            # Console output (default)
            if not config.get("output.quiet"):
                ColorPrinter.print_info(f"\nScanned {result.scanned_files} files")
                if result.skipped_files > 0:
                    ColorPrinter.print_info(f"Skipped {result.skipped_files} files")

            # Show errors if any
            if result.errors and not config.get("output.quiet"):
                ColorPrinter.print_error("\nErrors encountered:")
                for error in result.errors[:5]:  # Show first 5 errors
                    ColorPrinter.print_error(f"  - {error}")
                if len(result.errors) > 5:
                    ColorPrinter.print_error(
                        f"  ... and {len(result.errors) - 5} more"
                    )

            # Display findings
            for finding in filtered_findings:
                ColorPrinter.print_finding(
                    finding, quiet=config.get("output.quiet", False)
                )

            # Show summary
            if not config.get("output.quiet"):
                ColorPrinter.print_summary(filtered_findings)

        elif output_format in ["html", "csv"]:
            # These formats need to be exported to file
            ColorPrinter.print_error(
                f"Output format '{output_format}' requires --export option"
            )
            return 2

        # Export if requested
        if parsed_args.export:
            if output_format == "json" or parsed_args.export.suffix == ".json":
                FileHelper.export_findings_to_json(filtered_findings, parsed_args.export)
            elif output_format == "html" or parsed_args.export.suffix == ".html":
                # TODO: Implement HTML export
                ColorPrinter.print_error("HTML export not yet implemented")
            elif output_format == "csv" or parsed_args.export.suffix == ".csv":
                # TODO: Implement CSV export
                ColorPrinter.print_error("CSV export not yet implemented")
            else:
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
            if not config.get("output.quiet") and output_format == "console":
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
        if not config.get("output.quiet", False):
            import traceback

            traceback.print_exc()
        return 2


def run_cli() -> None:
    """Run the CLI and exit with appropriate code."""
    import sys

    sys.exit(main())


if __name__ == "__main__":
    run_cli()
