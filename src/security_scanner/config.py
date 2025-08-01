"""
Configuration management for the security scanner.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


class ScannerConfig:
    """Manages scanner configuration from files and environment."""

    DEFAULT_CONFIG_NAMES = [
        ".gitscannerrc",
        ".gitscannerrc.json",
        ".gitscannerrc.yaml",
        ".gitscannerrc.yml",
        "scanner.config.json",
        "scanner.config.yaml",
        "scanner.config.yml",
    ]

    DEFAULT_CONFIG = {
        "patterns": {
            "custom": [],
            "disabled": [],
        },
        "scan": {
            "history_limit": 100,
            "max_file_size_mb": 10,
            "parallel_workers": None,  # Auto-detect
            "show_progress": True,
        },
        "output": {
            "format": "console",  # console, json, html, csv
            "color": True,
            "quiet": False,
            "min_severity": "LOW",
        },
        "ignore": {
            "paths": [],
            "patterns": [],
        },
        "cache": {
            "enabled": True,
            "ttl_hours": 24,
            "show_hits": False,
        },
    }

    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize configuration.

        Args:
            config_path: Explicit path to config file
        """
        self.config: Dict[str, Any] = self.DEFAULT_CONFIG.copy()
        self.config_path: Optional[Path] = None

        if config_path:
            self.load_from_file(config_path)
        else:
            self.auto_load()

        self.load_from_env()

    def auto_load(self) -> bool:
        """
        Automatically find and load configuration file.

        Returns:
            True if config file was found and loaded
        """
        # Check current directory and parents
        current = Path.cwd()
        for _ in range(5):  # Check up to 5 levels up
            for config_name in self.DEFAULT_CONFIG_NAMES:
                config_path = current / config_name
                if config_path.exists():
                    return self.load_from_file(config_path)

            parent = current.parent
            if parent == current:  # Reached root
                break
            current = parent

        return False

    def load_from_file(self, config_path: Path) -> bool:
        """
        Load configuration from file.

        Args:
            config_path: Path to configuration file

        Returns:
            True if successfully loaded
        """
        if not config_path.exists():
            return False

        try:
            content = config_path.read_text(encoding="utf-8")

            if config_path.suffix in [".yaml", ".yml"]:
                data = yaml.safe_load(content) or {}
            else:
                # Assume JSON
                data = json.loads(content)

            self.config_path = config_path
            self._merge_config(data)
            return True

        except (json.JSONDecodeError, yaml.YAMLError, OSError) as e:
            print(f"Warning: Failed to load config from {config_path}: {e}")
            return False

    def load_from_env(self) -> None:
        """Load configuration from environment variables."""
        # Map environment variables to config paths
        env_mapping = {
            "SCANNER_HISTORY_LIMIT": ("scan", "history_limit", int),
            "SCANNER_MAX_FILE_SIZE": ("scan", "max_file_size_mb", int),
            "SCANNER_PARALLEL_WORKERS": ("scan", "parallel_workers", int),
            "SCANNER_SHOW_PROGRESS": ("scan", "show_progress", self._parse_bool),
            "SCANNER_OUTPUT_FORMAT": ("output", "format", str),
            "SCANNER_NO_COLOR": (
                "output",
                "color",
                lambda x: not self._parse_bool(x),
            ),  # noqa: E501
            "SCANNER_QUIET": ("output", "quiet", self._parse_bool),
            "SCANNER_MIN_SEVERITY": ("output", "min_severity", str),
            "SCANNER_CACHE_ENABLED": ("cache", "enabled", self._parse_bool),
            "SCANNER_CACHE_TTL": ("cache", "ttl_hours", int),
        }

        for env_var, (section, key, parser) in env_mapping.items():
            value = os.environ.get(env_var)
            if value is not None:
                try:
                    parsed_value = parser(value)
                    self.config[section][key] = parsed_value
                except (ValueError, KeyError):
                    pass

    def _merge_config(self, data: Dict[str, Any]) -> None:
        """Recursively merge configuration data."""
        for key, value in data.items():
            if key in self.config and isinstance(self.config[key], dict):
                if isinstance(value, dict):
                    self.config[key].update(value)
                else:
                    self.config[key] = value
            else:
                self.config[key] = value

    def _parse_bool(self, value: str) -> bool:
        """Parse boolean from string."""
        return value.lower() in ("true", "yes", "1", "on")

    def get(self, path: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-separated path.

        Args:
            path: Dot-separated path (e.g., "scan.history_limit")
            default: Default value if not found

        Returns:
            Configuration value or default
        """
        keys = path.split(".")
        value = self.config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    def set(self, path: str, value: Any) -> None:
        """
        Set configuration value by dot-separated path.

        Args:
            path: Dot-separated path
            value: Value to set
        """
        keys = path.split(".")
        config = self.config

        # Navigate to the parent
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]

        # Set the value
        config[keys[-1]] = value

    def get_custom_patterns(self) -> List[Dict[str, Any]]:
        """Get custom patterns from configuration."""
        return self.get("patterns.custom", [])

    def get_disabled_patterns(self) -> List[str]:
        """Get list of disabled pattern names."""
        return self.get("patterns.disabled", [])

    def get_ignored_paths(self) -> List[str]:
        """Get additional paths to ignore."""
        return self.get("ignore.paths", [])

    def get_output_format(self) -> str:
        """Get output format."""
        return self.get("output.format", "console")

    def should_show_progress(self) -> bool:
        """Check if progress bars should be shown."""
        return self.get("scan.show_progress", True)

    def get_parallel_workers(self) -> Optional[int]:
        """Get number of parallel workers."""
        return self.get("scan.parallel_workers")

    def save(self, config_path: Optional[Path] = None) -> bool:
        """
        Save configuration to file.

        Args:
            config_path: Path to save to (uses loaded path if not provided)

        Returns:
            True if successfully saved
        """
        save_path = config_path or self.config_path
        if not save_path:
            save_path = Path.cwd() / ".gitscannerrc.json"

        try:
            if save_path.suffix in [".yaml", ".yml"]:
                content = yaml.dump(
                    self.config, default_flow_style=False, sort_keys=True
                )
            else:
                content = json.dumps(self.config, indent=2, sort_keys=True)

            save_path.write_text(content, encoding="utf-8")
            return True

        except (OSError, IOError) as e:
            print(f"Error saving config to {save_path}: {e}")
            return False

    def validate(self) -> List[str]:
        """
        Validate configuration.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Validate severity
        min_severity = self.get("output.min_severity", "LOW")
        if min_severity not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            errors.append(f"Invalid min_severity: {min_severity}")

        # Validate output format
        output_format = self.get_output_format()
        if output_format not in ["console", "json", "html", "csv"]:
            errors.append(f"Invalid output format: {output_format}")

        # Validate custom patterns
        for i, pattern in enumerate(self.get_custom_patterns()):
            if not isinstance(pattern, dict):
                errors.append(f"Custom pattern {i} is not a dictionary")
                continue

            required_fields = ["name", "pattern", "severity"]
            for field in required_fields:
                if field not in pattern:
                    errors.append(f"Custom pattern {i} missing required field: {field}")

            if "severity" in pattern:
                if pattern["severity"] not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                    errors.append(
                        f"Custom pattern {i} has invalid severity: "  # noqa: E501
                        f"{pattern['severity']}"
                    )

        return errors


def create_example_config(output_path: Path) -> None:
    """Create an example configuration file."""
    example_config = {
        "patterns": {
            "custom": [
                {
                    "name": "Company API Key",
                    "pattern": "COMP-[A-Z0-9]{32}",
                    "severity": "HIGH",
                    "description": "Company internal API key",
                }
            ],
            "disabled": ["Generic Secret", "Environment Variable"],
        },
        "scan": {
            "history_limit": 50,
            "max_file_size_mb": 5,
            "parallel_workers": 4,
            "show_progress": True,
        },
        "output": {
            "format": "console",
            "color": True,
            "quiet": False,
            "min_severity": "MEDIUM",
        },
        "ignore": {
            "paths": ["vendor/", "third_party/"],
            "patterns": ["*.test.js", "*.spec.ts"],
        },
        "cache": {
            "enabled": True,
            "ttl_hours": 48,
            "show_hits": False,
        },
    }

    if output_path.suffix in [".yaml", ".yml"]:
        content = yaml.dump(example_config, default_flow_style=False, sort_keys=True)
    else:
        content = json.dumps(example_config, indent=2, sort_keys=True)

    output_path.write_text(content, encoding="utf-8")
    print(f"Created example config at: {output_path}")
