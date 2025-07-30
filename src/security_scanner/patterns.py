"""
Pattern definitions for detecting various types of secrets.
"""

import re
from enum import Enum
from typing import Dict, List, NamedTuple, Pattern, Optional, Any


class Severity(Enum):
    """Severity levels for detected secrets."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class PatternDefinition(NamedTuple):
    """Definition of a secret pattern."""

    name: str
    pattern: Pattern[str]
    severity: Severity
    description: str
    false_positive_check: Optional[Pattern[str]] = None


class PatternMatcher:
    """Manages and matches secret patterns."""

    def __init__(self) -> None:
        """Initialize pattern matcher with default patterns."""
        self._patterns: List[PatternDefinition] = self._load_default_patterns()
        self._exclusion_patterns: List[Pattern[str]] = self._load_exclusion_patterns()

    def _load_default_patterns(self) -> List[PatternDefinition]:
        """Load default secret patterns."""
        patterns = [
            # Cloud Services - AWS
            PatternDefinition(
                name="AWS Access Key",
                pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
                severity=Severity.CRITICAL,
                description="AWS Access Key ID",
            ),
            PatternDefinition(
                name="AWS Secret Key",
                pattern=re.compile(r'(?i)aws(.{0,20})?["\']?[0-9a-zA-Z/+=]{40}["\']?'),
                severity=Severity.CRITICAL,
                description="AWS Secret Access Key",
            ),
            # Cloud Services - Azure
            PatternDefinition(
                name="Azure Storage Key",
                pattern=re.compile(
                    r"(?i)(?:storage|azure)(.{0,20})?[a-zA-Z0-9/+=]{86}=="
                ),
                severity=Severity.CRITICAL,
                description="Azure Storage Account Key",
            ),
            # Cloud Services - Google Cloud
            PatternDefinition(
                name="Google API Key",
                pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
                severity=Severity.HIGH,
                description="Google API Key",
            ),
            PatternDefinition(
                name="Google OAuth",
                pattern=re.compile(
                    r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"
                ),
                severity=Severity.HIGH,
                description="Google OAuth Client ID",
            ),
            # AI/ML Platforms
            PatternDefinition(
                name="OpenAI API Key",
                pattern=re.compile(r"sk-[a-zA-Z0-9]{48}"),
                severity=Severity.HIGH,
                description="OpenAI API Key",
            ),
            PatternDefinition(
                name="Anthropic API Key",
                pattern=re.compile(r"sk-ant-[a-zA-Z0-9]{93}"),
                severity=Severity.HIGH,
                description="Anthropic Claude API Key",
            ),
            PatternDefinition(
                name="HuggingFace Token",
                pattern=re.compile(r"hf_[a-zA-Z0-9]{34}"),
                severity=Severity.HIGH,
                description="HuggingFace API Token",
            ),
            PatternDefinition(
                name="Cohere API Key",
                pattern=re.compile(r"(?i)cohere(.{0,20})?[a-zA-Z0-9]{40}"),
                severity=Severity.HIGH,
                description="Cohere API Key",
            ),
            # Version Control
            PatternDefinition(
                name="GitHub Token",
                pattern=re.compile(r"ghp_[a-zA-Z0-9]{36}"),
                severity=Severity.HIGH,
                description="GitHub Personal Access Token",
            ),
            PatternDefinition(
                name="GitHub OAuth",
                pattern=re.compile(r"gho_[a-zA-Z0-9]{36}"),
                severity=Severity.HIGH,
                description="GitHub OAuth Access Token",
            ),
            PatternDefinition(
                name="GitLab Token",
                pattern=re.compile(r"glpat-[a-zA-Z0-9\-_]{20}"),
                severity=Severity.HIGH,
                description="GitLab Personal Access Token",
            ),
            # Databases
            PatternDefinition(
                name="MongoDB Connection",
                pattern=re.compile(r"mongodb(\+srv)?://[^:]+:[^@]+@[^/]+"),
                severity=Severity.CRITICAL,
                description="MongoDB Connection String with credentials",
            ),
            PatternDefinition(
                name="PostgreSQL Connection",
                pattern=re.compile(r"postgres(ql)?://[^:]+:[^@]+@[^/]+"),
                severity=Severity.CRITICAL,
                description="PostgreSQL Connection String with credentials",
            ),
            PatternDefinition(
                name="MySQL Connection",
                pattern=re.compile(r"mysql://[^:]+:[^@]+@[^/]+"),
                severity=Severity.CRITICAL,
                description="MySQL Connection String with credentials",
            ),
            # Communication Platforms
            PatternDefinition(
                name="Slack Token",
                pattern=re.compile(r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}"),
                severity=Severity.HIGH,
                description="Slack API Token",
            ),
            PatternDefinition(
                name="Discord Token",
                pattern=re.compile(
                    r"(?i)discord(.{0,20})?"
                    r"[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9\-_]{27}"
                ),
                severity=Severity.HIGH,
                description="Discord Bot Token",
            ),
            PatternDefinition(
                name="Telegram Token",
                pattern=re.compile(r"[0-9]{9}:[a-zA-Z0-9_\-]{35}"),
                severity=Severity.HIGH,
                description="Telegram Bot Token",
            ),
            # Payment Services
            PatternDefinition(
                name="Stripe Secret Key",
                pattern=re.compile(r"sk_(test|live)_[a-zA-Z0-9]{24}"),
                severity=Severity.CRITICAL,
                description="Stripe Secret Key",
            ),
            PatternDefinition(
                name="Stripe Restricted Key",
                pattern=re.compile(r"rk_(test|live)_[a-zA-Z0-9]{24}"),
                severity=Severity.HIGH,
                description="Stripe Restricted API Key",
            ),
            PatternDefinition(
                name="PayPal Token",
                pattern=re.compile(
                    r"access_token\$production\$[a-z0-9]{16}\$[a-z0-9]{32}"
                ),
                severity=Severity.CRITICAL,
                description="PayPal Access Token",
            ),
            # Generic Secrets
            PatternDefinition(
                name="Private Key",
                pattern=re.compile(
                    r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
                ),
                severity=Severity.CRITICAL,
                description="Private Cryptographic Key",
            ),
            PatternDefinition(
                name="JWT Token",
                pattern=re.compile(
                    r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"
                ),
                severity=Severity.HIGH,
                description="JSON Web Token",
            ),
            PatternDefinition(
                name="Generic API Key",
                pattern=re.compile(
                    r"(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*"
                    r'["\']([a-zA-Z0-9]{32,64})["\']'
                ),
                severity=Severity.MEDIUM,
                description="Generic API Key pattern",
            ),
            PatternDefinition(
                name="Generic Secret",
                pattern=re.compile(
                    r'(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*["\']'
                    r'([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};:,.<>?]{8,})["\']'
                ),
                severity=Severity.MEDIUM,
                description="Generic secret or password pattern",
            ),
            PatternDefinition(
                name="Environment Variable",
                pattern=re.compile(
                    r"(?:export\s+)?(?P<key>[A-Z_]{2,}[A-Z0-9_]*)=" r"(?P<value>[^\s]+)"
                ),
                severity=Severity.LOW,
                description="Environment variable assignment",
                false_positive_check=re.compile(
                    r"^(PATH|HOME|USER|SHELL|TERM|LANG|LC_|PWD|OLDPWD)$"
                ),
            ),
        ]
        return patterns

    def _load_exclusion_patterns(self) -> List[Pattern[str]]:
        """Load patterns for paths/files to exclude from scanning."""
        return [
            re.compile(r"\.git/"),
            re.compile(r"\.gitignore"),
            re.compile(r"node_modules/"),
            re.compile(r"\.min\.js$"),
            re.compile(r"\.min\.css$"),
            re.compile(
                r"\.(jpg|jpeg|png|gif|ico|svg|pdf|zip|tar|gz|rar)$", re.IGNORECASE
            ),
            re.compile(r"package-lock\.json$"),
            re.compile(r"yarn\.lock$"),
            re.compile(r"poetry\.lock$"),
            re.compile(r"Pipfile\.lock$"),
        ]

    def should_scan_file(self, filepath: str) -> bool:
        """Check if file should be scanned based on exclusion patterns."""
        for pattern in self._exclusion_patterns:
            if pattern.search(filepath):
                return False
        return True

    def find_secrets(self, content: str, filepath: str = "") -> List[Dict[str, Any]]:
        """Find secrets in the given content."""
        findings: List[Dict[str, Any]] = []

        # Skip pattern files to avoid false positives
        if "patterns.py" in filepath:
            return findings

        # Split content into lines for line number tracking
        lines = content.split("\n")

        for pattern_def in self._patterns:
            for line_num, line in enumerate(lines, 1):
                matches = pattern_def.pattern.finditer(line)

                for match in matches:
                    # Check for false positives
                    if pattern_def.false_positive_check:
                        if pattern_def.name == "Environment Variable":
                            key_match = (
                                match.group("key")
                                if "key" in match.groupdict()
                                else match.group(0)
                            )
                            if pattern_def.false_positive_check.match(key_match):
                                continue

                    # Extract the matched secret (truncate for security)
                    secret = match.group(0)
                    if len(secret) > 20:
                        secret = secret[:8] + "..." + secret[-8:]

                    findings.append(
                        {
                            "type": pattern_def.name,
                            "severity": pattern_def.severity.value,
                            "description": pattern_def.description,
                            "file": filepath,
                            "line": line_num,
                            "column": match.start() + 1,
                            "secret": secret,
                            "content": line.strip(),
                        }
                    )

        return findings

    def add_custom_pattern(
        self,
        name: str,
        pattern: str,
        severity: Severity,
        description: str,
        false_positive_pattern: Optional[str] = None,
    ) -> None:
        """Add a custom pattern to the matcher."""
        fp_check = (
            re.compile(false_positive_pattern) if false_positive_pattern else None
        )

        pattern_def = PatternDefinition(
            name=name,
            pattern=re.compile(pattern),
            severity=severity,
            description=description,
            false_positive_check=fp_check,
        )
        self._patterns.append(pattern_def)

    def remove_pattern(self, name: str) -> bool:
        """Remove a pattern by name."""
        original_length = len(self._patterns)
        self._patterns = [p for p in self._patterns if p.name != name]
        return len(self._patterns) < original_length

    def get_patterns(self) -> List[Dict[str, str]]:
        """Get all patterns as a list of dictionaries."""
        return [
            {
                "name": p.name,
                "pattern": p.pattern.pattern,
                "severity": p.severity.value,
                "description": p.description,
            }
            for p in self._patterns
        ]
