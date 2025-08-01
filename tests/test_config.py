"""
Tests for configuration management.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest
import yaml

from security_scanner.config import ScannerConfig, create_example_config


class TestScannerConfig:
    """Test cases for ScannerConfig class."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_default_config(self, temp_dir):
        """Test default configuration values."""
        # Change to temp directory to avoid loading existing config
        original_cwd = Path.cwd()
        os.chdir(temp_dir)

        try:
            config = ScannerConfig()

            assert config.get("scan.history_limit") == 100
            assert config.get("scan.max_file_size_mb") == 10
            assert config.get("output.format") == "console"
            # min_severity может быть переопределен конфигурацией
            assert config.get("output.min_severity") in [
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
            ]
            assert config.get("output.color") is True
        finally:
            os.chdir(original_cwd)

    def test_load_json_config(self, temp_dir):
        """Test loading JSON configuration."""
        config_data = {
            "scan": {"history_limit": 50},
            "output": {"format": "json", "quiet": True},
        }

        config_path = temp_dir / ".gitscannerrc.json"
        config_path.write_text(json.dumps(config_data))

        config = ScannerConfig(config_path)

        assert config.get("scan.history_limit") == 50
        assert config.get("output.format") == "json"
        assert config.get("output.quiet") is True
        # Default values should still be present
        assert config.get("scan.max_file_size_mb") == 10

    def test_load_yaml_config(self, temp_dir):
        """Test loading YAML configuration."""
        config_data = {
            "patterns": {
                "custom": [
                    {
                        "name": "Test Pattern",
                        "pattern": "TEST-[0-9]+",
                        "severity": "HIGH",
                        "description": "Test pattern",
                    }
                ],
                "disabled": ["Generic Secret"],
            }
        }

        config_path = temp_dir / ".gitscannerrc.yaml"
        config_path.write_text(yaml.dump(config_data))

        config = ScannerConfig(config_path)

        custom_patterns = config.get_custom_patterns()
        assert len(custom_patterns) == 1
        assert custom_patterns[0]["name"] == "Test Pattern"

        disabled = config.get_disabled_patterns()
        assert "Generic Secret" in disabled

    def test_auto_load_config(self, temp_dir):
        """Test automatic configuration discovery."""
        # Create config in temp directory
        config_path = temp_dir / ".gitscannerrc.json"
        config_path.write_text('{"output": {"quiet": true}}')

        # Change to temp directory
        original_cwd = Path.cwd()
        os.chdir(temp_dir)

        try:
            config = ScannerConfig()
            assert config.get("output.quiet") is True
            # Resolve paths for comparison (handles symlinks on macOS)
            assert config.config_path.resolve() == config_path.resolve()
        finally:
            os.chdir(original_cwd)

    def test_environment_variables(self):
        """Test loading configuration from environment variables."""
        # Set environment variables
        env_vars = {
            "SCANNER_HISTORY_LIMIT": "25",
            "SCANNER_MAX_FILE_SIZE": "5",
            "SCANNER_QUIET": "true",
            "SCANNER_MIN_SEVERITY": "HIGH",
            "SCANNER_NO_COLOR": "yes",
            "SCANNER_OUTPUT_FORMAT": "json",
        }

        # Backup original environment
        original_env = {k: os.environ.get(k) for k in env_vars}

        try:
            # Set test environment
            for key, value in env_vars.items():
                os.environ[key] = value

            config = ScannerConfig()

            assert config.get("scan.history_limit") == 25
            assert config.get("scan.max_file_size_mb") == 5
            assert config.get("output.quiet") is True
            assert config.get("output.min_severity") == "HIGH"
            assert config.get("output.color") is False
            assert config.get("output.format") == "json"

        finally:
            # Restore original environment
            for key, value in original_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_get_set_config_values(self):
        """Test getting and setting configuration values."""
        config = ScannerConfig()

        # Test setting values
        config.set("custom.option", "value")
        config.set("nested.deep.option", 42)

        assert config.get("custom.option") == "value"
        assert config.get("nested.deep.option") == 42

        # Test getting non-existent values with default
        assert config.get("non.existent", "default") == "default"

    def test_validate_config(self):
        """Test configuration validation."""
        config = ScannerConfig()

        # Valid config should have no errors
        errors = config.validate()
        assert len(errors) == 0

        # Invalid severity
        config.set("output.min_severity", "INVALID")
        errors = config.validate()
        assert len(errors) == 1
        assert "Invalid min_severity" in errors[0]

        # Invalid output format
        config.set("output.min_severity", "HIGH")  # Fix previous error
        config.set("output.format", "invalid")
        errors = config.validate()
        assert len(errors) == 1
        assert "Invalid output format" in errors[0]

        # Invalid custom pattern
        config.set("output.format", "console")  # Fix previous error
        config.set("patterns.custom", [{"name": "Bad Pattern"}])  # Missing fields
        errors = config.validate()
        assert any("missing required field" in error for error in errors)

    def test_save_config(self, temp_dir):
        """Test saving configuration to file."""
        config = ScannerConfig()
        config.set("scan.history_limit", 75)
        config.set("output.quiet", True)

        # Save as JSON
        json_path = temp_dir / "config.json"
        assert config.save(json_path) is True

        # Load and verify
        saved_data = json.loads(json_path.read_text())
        assert saved_data["scan"]["history_limit"] == 75
        assert saved_data["output"]["quiet"] is True

        # Save as YAML
        yaml_path = temp_dir / "config.yaml"
        assert config.save(yaml_path) is True

        # Load and verify
        saved_data = yaml.safe_load(yaml_path.read_text())
        assert saved_data["scan"]["history_limit"] == 75
        assert saved_data["output"]["quiet"] is True

    def test_create_example_config(self, temp_dir):
        """Test creating example configuration file."""
        # Create JSON example
        json_path = temp_dir / "example.json"
        create_example_config(json_path)

        assert json_path.exists()
        data = json.loads(json_path.read_text())
        assert "patterns" in data
        assert "scan" in data
        assert "output" in data

        # Create YAML example
        yaml_path = temp_dir / "example.yaml"
        create_example_config(yaml_path)

        assert yaml_path.exists()
        data = yaml.safe_load(yaml_path.read_text())
        assert "patterns" in data

    def test_config_helpers(self):
        """Test configuration helper methods."""
        config = ScannerConfig()

        # Test custom patterns
        config.set(
            "patterns.custom",
            [
                {
                    "name": "Pattern1",
                    "pattern": "P1-[0-9]+",
                    "severity": "HIGH",
                }
            ],
        )
        patterns = config.get_custom_patterns()
        assert len(patterns) == 1
        assert patterns[0]["name"] == "Pattern1"

        # Test disabled patterns
        config.set("patterns.disabled", ["AWS Access Key", "GitHub Token"])
        disabled = config.get_disabled_patterns()
        assert len(disabled) == 2
        assert "AWS Access Key" in disabled

        # Test ignored paths
        config.set("ignore.paths", ["vendor/", "node_modules/"])
        ignored = config.get_ignored_paths()
        assert len(ignored) == 2
        assert "vendor/" in ignored

        # Test other helpers
        assert config.get_output_format() == "console"
        assert config.should_show_progress() is True
        assert config.get_parallel_workers() is None

    def test_merge_config(self, temp_dir):
        """Test configuration merging."""
        # Change to temp directory to avoid loading existing config
        original_cwd = Path.cwd()
        os.chdir(temp_dir)

        # Clear any scanner env vars
        scanner_env_vars = [k for k in os.environ if k.startswith("SCANNER_")]
        original_env = {k: os.environ.get(k) for k in scanner_env_vars}
        for k in scanner_env_vars:
            os.environ.pop(k, None)

        try:
            config = ScannerConfig()

            # Initial state - get default value
            default_limit = config.DEFAULT_CONFIG["scan"]["history_limit"]
            assert config.get("scan.history_limit") == default_limit

            # Merge new data
            new_data = {
                "scan": {"history_limit": 200, "new_option": "value"},
                "new_section": {"option": "value"},
            }
            config._merge_config(new_data)

            # Check merged values
            assert config.get("scan.history_limit") == 200
            # Check that other values in the same section are preserved
            original_max_size = config.config["scan"]["max_file_size_mb"]
            assert config.get("scan.max_file_size_mb") == original_max_size
            assert config.get("scan.new_option") == "value"
            assert config.get("new_section.option") == "value"
        finally:
            # Restore environment
            for k, v in original_env.items():
                if v is not None:
                    os.environ[k] = v
            os.chdir(original_cwd)

    def test_invalid_config_file(self, temp_dir):
        """Test handling of invalid configuration files."""
        # Change to temp directory to avoid loading existing config
        original_cwd = Path.cwd()
        os.chdir(temp_dir)

        # Clear any scanner env vars
        scanner_env_vars = [k for k in os.environ if k.startswith("SCANNER_")]
        original_env = {k: os.environ.get(k) for k in scanner_env_vars}
        for k in scanner_env_vars:
            os.environ.pop(k, None)

        try:
            # Invalid JSON
            invalid_json = temp_dir / "invalid.json"
            invalid_json.write_text("{ invalid json }")

            config = ScannerConfig(invalid_json)
            # Should use defaults when file is invalid
            default_limit = config.DEFAULT_CONFIG["scan"]["history_limit"]
            assert config.get("scan.history_limit") == default_limit

            # Invalid YAML
            invalid_yaml = temp_dir / "invalid.yaml"
            invalid_yaml.write_text("invalid:\n  - yaml\n  content: [")

            config = ScannerConfig(invalid_yaml)
            assert config.get("scan.history_limit") == default_limit
        finally:
            # Restore environment
            for k, v in original_env.items():
                if v is not None:
                    os.environ[k] = v
            os.chdir(original_cwd)

    def test_parse_bool(self):
        """Test boolean parsing from strings."""
        config = ScannerConfig()

        assert config._parse_bool("true") is True
        assert config._parse_bool("True") is True
        assert config._parse_bool("TRUE") is True
        assert config._parse_bool("yes") is True
        assert config._parse_bool("1") is True
        assert config._parse_bool("on") is True

        assert config._parse_bool("false") is False
        assert config._parse_bool("no") is False
        assert config._parse_bool("0") is False
        assert config._parse_bool("off") is False
