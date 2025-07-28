#!/usr/bin/env python3
"""
Git Security Scanner - Comprehensive repository security analysis tool
Detects secrets, API keys, tokens, and sensitive information in Git repositories
"""

import re
import os
import sys
import json
import math
import subprocess
from pathlib import Path
from typing import List, Dict, Tuple, Set, Optional
from dataclasses import dataclass
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

@dataclass
class Finding:
    """Security finding representation"""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    type: str      # SECRET, ENTROPY, FILE_TYPE, PATTERN
    file_path: str
    line_number: Optional[int]
    content: str
    pattern: str
    commit_hash: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None

class GitSecurityScanner:
    """Comprehensive Git repository security scanner"""
    
    # Extensive patterns for secret detection
    SECRET_PATTERNS = {
        # Cloud Provider Keys
        'aws_access_key': {
            'pattern': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            'severity': 'CRITICAL',
            'description': 'AWS Access Key ID'
        },
        'aws_secret_key': {
            'pattern': r'(?i)aws[_\-\.]?(?:secret|access)[_\-\.]?(?:key|token)?[\s\"\':=]*([a-zA-Z0-9\/\+=]{40})',
            'severity': 'CRITICAL',
            'description': 'AWS Secret Access Key'
        },
        'aws_session_token': {
            'pattern': r'(?i)(?:aws[_\-\.]?)?session[_\-\.]?token[\s\"\':=]*([a-zA-Z0-9\/\+=]{16,})',
            'severity': 'HIGH',
            'description': 'AWS Session Token'
        },
        'azure_key': {
            'pattern': r'(?i)(?:azure|az)[_\-\.]?(?:subscription|tenant|client|app)[_\-\.]?(?:key|secret|password|id)[\s\"\':=]*([a-zA-Z0-9\-\.]{32,})',
            'severity': 'CRITICAL',
            'description': 'Azure Key/Secret'
        },
        'gcp_api_key': {
            'pattern': r'AIza[0-9A-Za-z\-_]{35}',
            'severity': 'HIGH',
            'description': 'Google Cloud Platform API Key'
        },
        'gcp_service_account': {
            'pattern': r'\"type\"\s*:\s*\"service_account\"',
            'severity': 'CRITICAL',
            'description': 'GCP Service Account JSON'
        },
        
        # AI/ML Platform Keys
        'openai_api_key': {
            'pattern': r'sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}',
            'severity': 'CRITICAL',
            'description': 'OpenAI API Key'
        },
        'anthropic_api_key': {
            'pattern': r'sk-ant-[a-zA-Z0-9]{95,}',
            'severity': 'CRITICAL',
            'description': 'Anthropic/Claude API Key'
        },
        'huggingface_token': {
            'pattern': r'hf_[a-zA-Z0-9]{30,}',
            'severity': 'HIGH',
            'description': 'HuggingFace Access Token'
        },
        'cohere_api_key': {
            'pattern': r'(?i)cohere[_\-\.]?(?:api[_\-\.]?)?key[\s\"\':=]*([a-zA-Z0-9]{40})',
            'severity': 'HIGH',
            'description': 'Cohere API Key'
        },
        'replicate_api_token': {
            'pattern': r'r8_[a-zA-Z0-9]{40}',
            'severity': 'HIGH',
            'description': 'Replicate API Token'
        },
        'stability_api_key': {
            'pattern': r'sk-[a-zA-Z0-9]{48,}',
            'severity': 'HIGH',
            'description': 'Stability AI API Key'
        },
        'midjourney_token': {
            'pattern': r'(?i)midjourney[_\-\.]?(?:api[_\-\.]?)?(?:key|token)[\s\"\':=]*([a-zA-Z0-9\-\_]{32,})',
            'severity': 'HIGH',
            'description': 'Midjourney API Token'
        },
        'deepai_api_key': {
            'pattern': r'(?i)deepai[_\-\.]?(?:api[_\-\.]?)?key[\s\"\':=]*([a-zA-Z0-9]{32,})',
            'severity': 'HIGH',
            'description': 'DeepAI API Key'
        },
        'ai21_api_key': {
            'pattern': r'(?i)ai21[_\-\.]?(?:api[_\-\.]?)?key[\s\"\':=]*([a-zA-Z0-9]{32,})',
            'severity': 'HIGH',
            'description': 'AI21 Labs API Key'
        },
        'palm_api_key': {
            'pattern': r'(?i)palm[_\-\.]?(?:api[_\-\.]?)?key[\s\"\':=]*([a-zA-Z0-9]{39})',
            'severity': 'HIGH',
            'description': 'Google PaLM API Key'
        },
        'eleven_labs_api_key': {
            'pattern': r'(?i)(?:eleven[_\-\.]?labs|xi)[_\-\.]?(?:api[_\-\.]?)?key[\s\"\':=]*([a-zA-Z0-9]{32})',
            'severity': 'HIGH',
            'description': 'ElevenLabs API Key'
        },
        'runway_api_key': {
            'pattern': r'rw_[a-zA-Z0-9]{40,}',
            'severity': 'HIGH',
            'description': 'Runway ML API Key'
        },
        'together_api_key': {
            'pattern': r'(?i)together[_\-\.]?(?:api[_\-\.]?)?key[\s\"\':=]*([a-f0-9]{64})',
            'severity': 'HIGH',
            'description': 'Together AI API Key'
        },
        'perplexity_api_key': {
            'pattern': r'pplx-[a-f0-9]{48}',
            'severity': 'HIGH',
            'description': 'Perplexity AI API Key'
        },
        'groq_api_key': {
            'pattern': r'gsk_[a-zA-Z0-9]{52}',
            'severity': 'HIGH',
            'description': 'Groq API Key'
        },
        
        # Version Control & CI/CD
        'github_token': {
            'pattern': r'gh[pousr]_[0-9a-zA-Z]{36,}',
            'severity': 'CRITICAL',
            'description': 'GitHub Token'
        },
        'github_app_token': {
            'pattern': r'ghs_[0-9a-zA-Z]{36,}',
            'severity': 'CRITICAL',
            'description': 'GitHub App Token'
        },
        'github_refresh_token': {
            'pattern': r'ghr_[0-9a-zA-Z]{36,}',
            'severity': 'CRITICAL',
            'description': 'GitHub Refresh Token'
        },
        'gitlab_token': {
            'pattern': r'glpat-[0-9a-zA-Z\-\_]{20,}',
            'severity': 'CRITICAL',
            'description': 'GitLab Personal Access Token'
        },
        'gitlab_pipeline_token': {
            'pattern': r'glcbt-[0-9a-zA-Z\-\_]{20,}',
            'severity': 'HIGH',
            'description': 'GitLab Pipeline Token'
        },
        'bitbucket_token': {
            'pattern': r'(?i)bitbucket[_\-\.]?(?:oauth[_\-\.]?)?(?:key|token|secret)[\s\"\':=]*([a-zA-Z0-9\-\_]{32,})',
            'severity': 'HIGH',
            'description': 'Bitbucket Token'
        },
        'circleci_token': {
            'pattern': r'circle-token-[a-f0-9]{40}',
            'severity': 'HIGH',
            'description': 'CircleCI Token'
        },
        
        # Communication Platforms
        'slack_token': {
            'pattern': r'xox[baprs]-[0-9a-zA-Z\-]+',
            'severity': 'HIGH',
            'description': 'Slack Token'
        },
        'slack_webhook': {
            'pattern': r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+',
            'severity': 'MEDIUM',
            'description': 'Slack Webhook URL'
        },
        'discord_token': {
            'pattern': r'(?:discord|bot)[_\-\.]?token[\s\"\':=]*([a-zA-Z0-9\-\_\.]{50,})',
            'severity': 'HIGH',
            'description': 'Discord Bot Token'
        },
        'discord_webhook': {
            'pattern': r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9\-\_]+',
            'severity': 'MEDIUM',
            'description': 'Discord Webhook URL'
        },
        'telegram_bot_token': {
            'pattern': r'[0-9]+:AA[a-zA-Z0-9\-\_]{32,}',
            'severity': 'HIGH',
            'description': 'Telegram Bot Token'
        },
        'twilio_api_key': {
            'pattern': r'SK[a-f0-9]{32}',
            'severity': 'HIGH',
            'description': 'Twilio API Key'
        },
        
        # Payment & Finance
        'stripe_api_key': {
            'pattern': r'(?:sk|pk|rk)_(?:test|live)_[0-9a-zA-Z]{24,}',
            'severity': 'CRITICAL',
            'description': 'Stripe API Key'
        },
        'paypal_token': {
            'pattern': r'access_token\$[a-z\d]{2,32}\$[a-f\d]{40,}',
            'severity': 'CRITICAL',
            'description': 'PayPal Access Token'
        },
        'square_token': {
            'pattern': r'(?:sandbox-)?sq0[a-z]{3}-[0-9A-Za-z\-\_]{22,}',
            'severity': 'CRITICAL',
            'description': 'Square Access Token'
        },
        'coinbase_api_key': {
            'pattern': r'(?i)coinbase[_\-\.]?(?:api[_\-\.]?)?key[\s\"\':=]*([a-zA-Z0-9]{16})',
            'severity': 'CRITICAL',
            'description': 'Coinbase API Key'
        },
        
        # Database & Infrastructure
        'mongodb_uri': {
            'pattern': r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^\/]+',
            'severity': 'CRITICAL',
            'description': 'MongoDB Connection String'
        },
        'postgresql_uri': {
            'pattern': r'postgres(?:ql)?://[^:]+:[^@]+@[^\/]+',
            'severity': 'CRITICAL',
            'description': 'PostgreSQL Connection String'
        },
        'mysql_uri': {
            'pattern': r'mysql://[^:]+:[^@]+@[^\/]+',
            'severity': 'CRITICAL',
            'description': 'MySQL Connection String'
        },
        'redis_uri': {
            'pattern': r'redis://(?::[^@]+@)?[^\/]+',
            'severity': 'HIGH',
            'description': 'Redis Connection String'
        },
        'elasticsearch_uri': {
            'pattern': r'(?:http|https)://[^:]+:[^@]+@[^\/]+:\d+',
            'severity': 'HIGH',
            'description': 'Elasticsearch Connection String'
        },
        
        # Authentication & Security
        'jwt_token': {
            'pattern': r'eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*',
            'severity': 'HIGH',
            'description': 'JSON Web Token'
        },
        'oauth_token': {
            'pattern': r'(?i)(?:oauth|bearer)[_\-\.]?token[\s\"\':=]*([a-zA-Z0-9\-\.\_\~\+\/]{20,})',
            'severity': 'HIGH',
            'description': 'OAuth Token'
        },
        'api_key_generic': {
            'pattern': r'(?i)(?:api|app)[_\-\.]?(?:key|token|secret)[\s\"\':=]*[\"\']?([a-zA-Z0-9\-\_]{20,})[\"\']?',
            'severity': 'HIGH',
            'description': 'Generic API Key'
        },
        'private_key': {
            'pattern': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?:\s|[A-Z\s]+)?-----',
            'severity': 'CRITICAL',
            'description': 'Private Cryptographic Key'
        },
        'ssh_private_key': {
            'pattern': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'severity': 'CRITICAL',
            'description': 'SSH Private Key'
        },
        
        # Cloud Storage
        's3_bucket_url': {
            'pattern': r'(?:s3://|https?://s3[.-])[a-zA-Z0-9\-\.]+\.amazonaws\.com',
            'severity': 'MEDIUM',
            'description': 'AWS S3 Bucket URL'
        },
        'firebase_url': {
            'pattern': r'https://[a-z0-9\-]+\.firebaseio\.com',
            'severity': 'MEDIUM',
            'description': 'Firebase Database URL'
        },
        'firebase_api_key': {
            'pattern': r'(?i)firebase[_\-\.]?(?:api[_\-\.]?)?key[\s\"\':=]*([a-zA-Z0-9\-\_]{39})',
            'severity': 'HIGH',
            'description': 'Firebase API Key'
        },
        
        # Development & Testing
        'npm_token': {
            'pattern': r'npm_[a-zA-Z0-9]{36}',
            'severity': 'HIGH',
            'description': 'npm Access Token'
        },
        'pypi_token': {
            'pattern': r'pypi-[a-zA-Z0-9\-\_]{40,}',
            'severity': 'HIGH',
            'description': 'PyPI API Token'
        },
        'docker_auth': {
            'pattern': r'(?i)docker[_\-\.]?(?:hub[_\-\.]?)?(?:auth|token|password)[\s\"\':=]*([a-zA-Z0-9\-\_\.]{20,})',
            'severity': 'HIGH',
            'description': 'Docker Registry Auth Token'
        },
        'kubernetes_token': {
            'pattern': r'(?i)k8s[_\-\.]?token[\s\"\':=]*([a-zA-Z0-9\-\.\_]{40,})',
            'severity': 'CRITICAL',
            'description': 'Kubernetes Service Account Token'
        },
        
        # Monitoring & Analytics
        'datadog_api_key': {
            'pattern': r'(?i)datadog[_\-\.]?(?:api[_\-\.]?)?key[\s\"\':=]*([a-f0-9]{32})',
            'severity': 'HIGH',
            'description': 'Datadog API Key'
        },
        'newrelic_key': {
            'pattern': r'(?i)new[_\-\.]?relic[_\-\.]?(?:api[_\-\.]?)?key[\s\"\':=]*([a-zA-Z0-9]{40})',
            'severity': 'HIGH',
            'description': 'New Relic API Key'
        },
        'sentry_dsn': {
            'pattern': r'https://[a-f0-9]+@[a-z0-9\-\.]+\.ingest\.sentry\.io/\d+',
            'severity': 'MEDIUM',
            'description': 'Sentry DSN'
        },
        
        # Email Services
        'sendgrid_api_key': {
            'pattern': r'SG\.[a-zA-Z0-9\-\_]{22}\.[a-zA-Z0-9\-\_]{43}',
            'severity': 'HIGH',
            'description': 'SendGrid API Key'
        },
        'mailgun_api_key': {
            'pattern': r'key-[a-f0-9]{32}',
            'severity': 'HIGH',
            'description': 'Mailgun API Key'
        },
        'mailchimp_api_key': {
            'pattern': r'[a-f0-9]{32}-us\d{1,2}',
            'severity': 'HIGH',
            'description': 'Mailchimp API Key'
        },
        
        # Generic Patterns
        'password_in_url': {
            'pattern': r'(?i)(https?|ftp|smtp)://[^:]+:([^@]+)@',
            'severity': 'CRITICAL',
            'description': 'Password in URL'
        },
        'hardcoded_password': {
            'pattern': r'(?i)(?:password|passwd|pwd|pass|secret)[\s\"\':=]*[\"\']([^\"\'\s]{8,})[\"\']',
            'severity': 'HIGH',
            'description': 'Hardcoded Password'
        },
        'base64_credentials': {
            'pattern': r'(?i)(?:basic|bearer|auth)[\s\"\':=]*([a-zA-Z0-9+/]{40,}={0,2})',
            'severity': 'HIGH',
            'description': 'Base64 Encoded Credentials'
        }
    }
    
    # High-risk file extensions
    DANGEROUS_EXTENSIONS = {
        # Private keys and certificates
        '.pem': 'CRITICAL',
        '.key': 'CRITICAL',
        '.p12': 'CRITICAL',
        '.pfx': 'CRITICAL',
        '.pkcs12': 'CRITICAL',
        '.keystore': 'CRITICAL',
        '.jks': 'CRITICAL',
        '.ppk': 'CRITICAL',
        '.id_rsa': 'CRITICAL',
        '.id_dsa': 'CRITICAL',
        '.id_ecdsa': 'CRITICAL',
        '.id_ed25519': 'CRITICAL',
        '.asc': 'HIGH',
        '.gpg': 'HIGH',
        '.pgp': 'HIGH',
        
        # Configuration files
        '.env': 'HIGH',
        '.env.local': 'HIGH',
        '.env.production': 'HIGH',
        '.env.development': 'HIGH',
        '.env.staging': 'HIGH',
        '.env.test': 'HIGH',
        '.config': 'MEDIUM',
        '.cfg': 'MEDIUM',
        '.conf': 'MEDIUM',
        '.ini': 'MEDIUM',
        '.properties': 'MEDIUM',
        '.yml': 'LOW',
        '.yaml': 'LOW',
        '.toml': 'LOW',
        
        # Credential files
        '.htpasswd': 'CRITICAL',
        '.netrc': 'HIGH',
        '.git-credentials': 'CRITICAL',
        '.dockercfg': 'HIGH',
        '.npmrc': 'HIGH',
        '.pypirc': 'HIGH',
        '.aws/credentials': 'CRITICAL',
        '.ssh/config': 'HIGH',
        
        # Database files
        '.sql': 'MEDIUM',
        '.sqlite': 'MEDIUM',
        '.sqlite3': 'MEDIUM',
        '.db': 'MEDIUM',
        
        # Backup files
        '.bak': 'MEDIUM',
        '.backup': 'MEDIUM',
        '.old': 'MEDIUM',
        '.orig': 'MEDIUM',
        '.tmp': 'LOW',
        '.temp': 'LOW',
        '.swp': 'LOW',
        
        # Log files that might contain secrets
        '.log': 'LOW',
        '.history': 'MEDIUM',
        '.bash_history': 'HIGH',
        '.zsh_history': 'HIGH',
        '.mysql_history': 'HIGH',
        '.psql_history': 'HIGH',
        '.irb_history': 'MEDIUM'
    }
    
    # Directories to ignore during scanning
    IGNORE_DIRS = {
        '.git', 'node_modules', '__pycache__', '.venv', 'venv', 
        'env', '.env', 'dist', 'build', '.idea', '.vscode',
        'vendor', 'packages', '.pytest_cache', '.mypy_cache',
        'coverage', '.coverage', 'htmlcov', '.tox', '.eggs',
        'target', 'out', 'bin', 'obj', '.gradle', '.maven',
        '.cursor'  # Cursor IDE configuration folder
    }
    
    # File patterns that should be in .gitignore
    RECOMMENDED_GITIGNORE_PATTERNS = [
        # Environment and config
        '.env*', '*.env', 'config/secrets.*', 'secrets/*',
        
        # Keys and certificates
        '*.pem', '*.key', '*.p12', '*.pfx', '*.jks', '*.keystore',
        'id_rsa*', 'id_dsa*', 'id_ecdsa*', 'id_ed25519*',
        '*.ppk', '*.pub', '*.asc', '*.gpg', '*.pgp',
        
        # Credentials
        'credentials', 'credentials.*', '*.credentials',
        '.htpasswd', '.netrc', '.git-credentials',
        
        # Cloud provider files
        '.aws/credentials', '.aws/config', 'google-credentials.json',
        'azure-credentials.json', 'service-account*.json',
        
        # Package manager files
        '.npmrc', '.pypirc', '.dockercfg', 'docker/config.json',
        
        # IDE configuration folders
        '.cursor/', '.idea/', '.vscode/',
        
        # Database
        '*.sql', '*.sqlite', '*.sqlite3', '*.db',
        
        # Logs and history
        '*.log', '.history', '.bash_history', '.zsh_history',
        
        # Backup files
        '*.bak', '*.backup', '*.old', '*.orig', '*.tmp', '*.temp'
    ]
    
    def __init__(self, repo_path: str = ".", verbose: bool = True):
        """
        Initialize the security scanner
        
        Args:
            repo_path: Path to the Git repository
            verbose: Enable verbose output
        """
        self.repo_path = Path(repo_path).resolve()
        self.verbose = verbose
        self.findings: List[Finding] = []
        self.scanned_files = 0
        self.scanned_commits = 0
        
        if not self._is_git_repo():
            raise ValueError(f"{self.repo_path} is not a Git repository")
    
    def _is_git_repo(self) -> bool:
        """Check if directory is a Git repository"""
        return (self.repo_path / '.git').exists()
    
    def _run_git_command(self, command: List[str]) -> Tuple[bool, str]:
        """Execute a Git command and return the result"""
        try:
            result = subprocess.run(
                ['git'] + command,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            return True, result.stdout.strip()
        except subprocess.CalledProcessError as e:
            return False, e.stderr.strip()
    
    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of a string
        High entropy indicates randomness (potential keys/secrets)
        """
        if not text:
            return 0
        
        entropy = 0
        for i in range(256):
            char = chr(i)
            freq = text.count(char)
            if freq > 0:
                freq = float(freq) / len(text)
                entropy += freq * math.log(freq) / math.log(2)
        
        return -entropy
    
    def _is_likely_false_positive(self, content: str, pattern_name: str) -> bool:
        """
        Check if a finding is likely a false positive
        
        Args:
            content: The matched content
            pattern_name: The pattern that matched
            
        Returns:
            True if likely false positive, False otherwise
        """
        # Common false positive indicators
        false_positive_indicators = [
            'example', 'test', 'demo', 'sample', 'dummy', 'fake',
            'placeholder', 'your_', 'my_', 'xxx', '...', '___',
            'todo', 'fixme', 'change_me', 'replace_with'
        ]
        
        content_lower = content.lower()
        
        # Check for obvious placeholders
        for indicator in false_positive_indicators:
            if indicator in content_lower:
                return True
        
        # Check for repeated characters (like AAAAAAA)
        if len(set(content)) < len(content) / 4:
            return True
        
        # Pattern-specific checks
        if pattern_name == 'jwt_token' and content.count('.') != 2:
            return True
        
        return False
    
    def _print_banner(self):
        """Print scanner banner"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}Git Security Scanner v2.0")
        print(f"{Fore.CYAN}Repository: {self.repo_path}")
        print(f"{Fore.CYAN}Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}{'='*70}\n")
    
    def _print_finding(self, finding: Finding):
        """Print a security finding with color coding"""
        color = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.YELLOW,
            'MEDIUM': Fore.MAGENTA,
            'LOW': Fore.BLUE
        }.get(finding.severity, Fore.WHITE)
        
        print(f"\n{color}[{finding.severity}] {finding.pattern}")
        print(f"{Fore.WHITE}Type: {finding.type}")
        print(f"{Fore.WHITE}File: {finding.file_path}")
        if finding.line_number:
            print(f"{Fore.WHITE}Line: {finding.line_number}")
        if finding.commit_hash:
            print(f"{Fore.WHITE}Commit: {finding.commit_hash}")
        if finding.author:
            print(f"{Fore.WHITE}Author: {finding.author}")
        if finding.date:
            print(f"{Fore.WHITE}Date: {finding.date}")
        
        # Safely display masked content
        if finding.content:
            masked = self._mask_secret(finding.content)
            print(f"{Fore.WHITE}Content: {masked}")
    
    def _mask_secret(self, secret: str, show_chars: int = 4) -> str:
        """
        Mask sensitive content for safe display
        
        Args:
            secret: The secret to mask
            show_chars: Number of characters to show at start/end
            
        Returns:
            Masked version of the secret
        """
        if len(secret) <= show_chars * 2:
            return '*' * len(secret)
        
        return secret[:show_chars] + '*' * (len(secret) - show_chars * 2) + secret[-show_chars:]
    
    def _check_file_content(self, file_path: Path, content: str, commit_info: Dict = None):
        """
        Check file content for secrets and sensitive information
        
        Args:
            file_path: Path to the file
            content: File content to check
            commit_info: Optional commit information
        """
        # Skip scanning the scanner itself
        if file_path.name == 'git_security_scanner.py' or file_path.name == 'git-security-scanner.py':
            return
            
        lines = content.split('\n')
        
        # Check against all secret patterns
        for pattern_name, pattern_info in self.SECRET_PATTERNS.items():
            pattern = pattern_info['pattern']
            
            for line_num, line in enumerate(lines, 1):
                # Skip empty lines and comments
                if not line.strip() or line.strip().startswith(('#', '//', '/*', '*')):
                    continue
                
                matches = re.finditer(pattern, line, re.IGNORECASE)
                
                for match in matches:
                    # Extract the actual secret (might be in a capture group)
                    if match.groups():
                        secret_content = match.group(1)
                    else:
                        secret_content = match.group(0)
                    
                    # Check for false positives
                    if self._is_likely_false_positive(secret_content, pattern_name):
                        continue
                    
                    finding = Finding(
                        severity=pattern_info['severity'],
                        type='PATTERN',
                        file_path=str(file_path.relative_to(self.repo_path)),
                        line_number=line_num,
                        content=secret_content,
                        pattern=pattern_info['description'],
                        commit_hash=commit_info.get('hash') if commit_info else None,
                        author=commit_info.get('author') if commit_info else None,
                        date=commit_info.get('date') if commit_info else None
                    )
                    self.findings.append(finding)
                    if self.verbose:
                        self._print_finding(finding)
        
        # Entropy-based detection for high-entropy strings
        for line_num, line in enumerate(lines, 1):
            # Look for potential secrets (long alphanumeric strings)
            potential_secrets = re.findall(r'[a-zA-Z0-9+/]{32,}={0,2}', line)
            
            for secret in potential_secrets:
                entropy = self._calculate_entropy(secret)
                
                # High entropy threshold (indicates randomness)
                if entropy > 4.5:
                    # Additional checks to reduce false positives
                    if len(secret) < 40 or self._is_likely_false_positive(secret, 'entropy'):
                        continue
                    
                    finding = Finding(
                        severity='MEDIUM',
                        type='ENTROPY',
                        file_path=str(file_path.relative_to(self.repo_path)),
                        line_number=line_num,
                        content=secret,
                        pattern=f'High Entropy String (entropy: {entropy:.2f})',
                        commit_hash=commit_info.get('hash') if commit_info else None,
                        author=commit_info.get('author') if commit_info else None,
                        date=commit_info.get('date') if commit_info else None
                    )
                    self.findings.append(finding)
                    if self.verbose:
                        self._print_finding(finding)
    
    def _check_file_extension(self, file_path: Path):
        """Check if file has a dangerous extension"""
        # Check full filename for specific cases
        filename = file_path.name.lower()
        full_path_str = str(file_path).lower()
        
        # Check for specific dangerous files
        dangerous_files = {
            '.git-credentials': 'CRITICAL',
            '.aws/credentials': 'CRITICAL',
            '.ssh/id_rsa': 'CRITICAL',
            '.ssh/id_dsa': 'CRITICAL',
            '.ssh/id_ecdsa': 'CRITICAL',
            '.ssh/id_ed25519': 'CRITICAL',
            '.cursor/config.json': 'CRITICAL',  # Cursor IDE config with potential API keys
            '.cursor/settings.json': 'HIGH',    # Cursor IDE settings
            'wp-config.php': 'HIGH',
            'config.php': 'MEDIUM',
            'settings.py': 'MEDIUM',
            'application.properties': 'MEDIUM'
        }
        
        for dangerous_file, severity in dangerous_files.items():
            if dangerous_file in full_path_str:
                finding = Finding(
                    severity=severity,
                    type='FILE_TYPE',
                    file_path=str(file_path.relative_to(self.repo_path)),
                    line_number=None,
                    content='',
                    pattern=f'Sensitive file: {dangerous_file}'
                )
                self.findings.append(finding)
                if self.verbose:
                    self._print_finding(finding)
                return
        
        # Check file extension
        ext = file_path.suffix.lower()
        if ext in self.DANGEROUS_EXTENSIONS:
            finding = Finding(
                severity=self.DANGEROUS_EXTENSIONS[ext],
                type='FILE_TYPE',
                file_path=str(file_path.relative_to(self.repo_path)),
                line_number=None,
                content='',
                pattern=f'Sensitive file type: {ext}'
            )
            self.findings.append(finding)
            if self.verbose:
                self._print_finding(finding)
    
    def scan_staged_files(self):
        """Scan files in Git staging area (added via git add)"""
        print(f"{Fore.GREEN}[*] Scanning staged files...")
        
        # Get list of staged files
        success, output = self._run_git_command(['diff', '--cached', '--name-only'])
        
        if not success:
            print(f"{Fore.RED}[!] Error getting staged files: {output}")
            return
        
        staged_files = output.split('\n') if output else []
        
        for file_path in staged_files:
            if not file_path:
                continue
            
            full_path = self.repo_path / file_path
            
            # Skip deleted files
            if not full_path.exists():
                continue
            
            self.scanned_files += 1
            
            if self.verbose:
                print(f"{Fore.BLUE}[+] Checking: {file_path}")
            
            # Check file extension
            self._check_file_extension(full_path)
            
            # Check file content
            try:
                # Get content from staging area
                success, content = self._run_git_command(['show', f':{file_path}'])
                if success:
                    self._check_file_content(Path(file_path), content)
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.YELLOW}[!] Could not read {file_path}: {e}")
    
    def scan_working_directory(self):
        """Scan all files in the working directory"""
        print(f"{Fore.GREEN}[*] Scanning working directory...")
        
        for root, dirs, files in os.walk(self.repo_path):
            # Filter out ignored directories
            dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS]
            
            for file in files:
                file_path = Path(root) / file
                self.scanned_files += 1
                
                if self.verbose and self.scanned_files % 100 == 0:
                    print(f"{Fore.BLUE}[+] Files processed: {self.scanned_files}")
                
                # Check file extension
                self._check_file_extension(file_path)
                
                # Check file content
                try:
                    # Skip large files (>5MB)
                    if file_path.stat().st_size > 5 * 1024 * 1024:
                        continue
                    
                    # Skip binary files
                    with open(file_path, 'rb') as f:
                        chunk = f.read(1024)
                        if b'\0' in chunk:  # Binary file detection
                            continue
                    
                    # Read and check text content
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        self._check_file_content(file_path, content)
                except Exception:
                    # Skip files that can't be read
                    pass
    
    def scan_commit_history(self, branch: str = 'HEAD', limit: int = 100):
        """
        Scan Git commit history for secrets
        
        Args:
            branch: Git branch to scan
            limit: Maximum number of commits to scan
        """
        print(f"{Fore.GREEN}[*] Scanning commit history (last {limit} commits)...")
        
        # Get commit list
        success, output = self._run_git_command([
            'log', branch, f'-{limit}', '--pretty=format:%H|%an|%ae|%ad', '--date=short'
        ])
        
        if not success:
            print(f"{Fore.RED}[!] Error getting commit history: {output}")
            return
        
        commits = output.split('\n') if output else []
        
        for commit_line in commits:
            if not commit_line:
                continue
            
            parts = commit_line.split('|')
            if len(parts) != 4:
                continue
            
            commit_hash, author_name, author_email, date = parts
            self.scanned_commits += 1
            
            if self.verbose and self.scanned_commits % 10 == 0:
                print(f"{Fore.BLUE}[+] Commits processed: {self.scanned_commits}")
            
            # Get changed files in commit
            success, diff_output = self._run_git_command([
                'diff-tree', '--no-commit-id', '--name-only', '-r', commit_hash
            ])
            
            if not success:
                continue
            
            changed_files = diff_output.split('\n') if diff_output else []
            
            for file_path in changed_files:
                if not file_path:
                    continue
                
                # Get file content at this commit
                success, content = self._run_git_command(['show', f'{commit_hash}:{file_path}'])
                
                if success:
                    commit_info = {
                        'hash': commit_hash[:8],  # Short hash
                        'author': f"{author_name} <{author_email}>",
                        'date': date
                    }
                    self._check_file_content(Path(file_path), content, commit_info)
    
    def check_gitignore(self):
        """Check .gitignore for recommended patterns"""
        print(f"{Fore.GREEN}[*] Checking .gitignore...")
        
        gitignore_path = self.repo_path / '.gitignore'
        
        if not gitignore_path.exists():
            print(f"{Fore.YELLOW}[!] No .gitignore file found")
            print(f"{Fore.YELLOW}[!] Creating .gitignore is highly recommended")
            return
        
        with open(gitignore_path, 'r') as f:
            gitignore_content = f.read().lower()
        
        missing_patterns = []
        for pattern in self.RECOMMENDED_GITIGNORE_PATTERNS:
            # Simple check - could be improved with proper gitignore parsing
            pattern_check = pattern.replace('*', '').replace('.', '')
            if pattern_check not in gitignore_content:
                missing_patterns.append(pattern)
        
        if missing_patterns:
            print(f"{Fore.YELLOW}[!] Recommended patterns missing from .gitignore:")
            for pattern in missing_patterns[:10]:  # Show first 10
                print(f"    {pattern}")
            if len(missing_patterns) > 10:
                print(f"    ... and {len(missing_patterns) - 10} more")
    
    def generate_summary(self):
        """Generate and display scan summary"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}SCAN SUMMARY")
        print(f"{Fore.CYAN}{'='*70}")
        
        print(f"\n{Fore.WHITE}Scan Statistics:")
        print(f"  - Files scanned: {self.scanned_files}")
        print(f"  - Commits scanned: {self.scanned_commits}")
        print(f"  - Total findings: {len(self.findings)}")
        
        # Group by severity
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in self.findings:
            severity_count[finding.severity] += 1
        
        print(f"\n{Fore.WHITE}Findings by Severity:")
        print(f"  {Fore.RED}- CRITICAL: {severity_count['CRITICAL']}")
        print(f"  {Fore.YELLOW}- HIGH: {severity_count['HIGH']}")
        print(f"  {Fore.MAGENTA}- MEDIUM: {severity_count['MEDIUM']}")
        print(f"  {Fore.BLUE}- LOW: {severity_count['LOW']}")
        
        # Group by type
        type_count = {}
        for finding in self.findings:
            type_count[finding.type] = type_count.get(finding.type, 0) + 1
        
        print(f"\n{Fore.WHITE}Findings by Type:")
        for finding_type, count in type_count.items():
            print(f"  - {finding_type}: {count}")
        
        # Unique affected files
        affected_files = set(f.file_path for f in self.findings)
        print(f"\n{Fore.WHITE}Affected files: {len(affected_files)}")
        
        # Top pattern matches
        pattern_count = {}
        for finding in self.findings:
            pattern_count[finding.pattern] = pattern_count.get(finding.pattern, 0) + 1
        
        print(f"\n{Fore.WHITE}Top Security Issues:")
        for pattern, count in sorted(pattern_count.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  - {pattern}: {count}")
        
        # Security recommendations
        if severity_count['CRITICAL'] > 0:
            print(f"\n{Fore.RED}[!!!] CRITICAL SECURITY ISSUES FOUND!")
            print(f"{Fore.RED}[!!!] Immediate action required:")
            print(f"{Fore.RED}      1. Rotate all compromised credentials immediately")
            print(f"{Fore.RED}      2. Check if these credentials were used in production")
            print(f"{Fore.RED}      3. Audit access logs for suspicious activity")
            print(f"{Fore.RED}      4. Remove secrets from Git history completely")
        
        return severity_count['CRITICAL'] == 0
    
    def export_findings(self, output_file: str = "security_report.json"):
        """
        Export findings to JSON file
        
        Args:
            output_file: Output file path
        """
        findings_data = []
        for finding in self.findings:
            findings_data.append({
                'severity': finding.severity,
                'type': finding.type,
                'file_path': finding.file_path,
                'line_number': finding.line_number,
                'pattern': finding.pattern,
                'commit_hash': finding.commit_hash,
                'author': finding.author,
                'date': finding.date
            })
        
        report = {
            'scan_date': datetime.now().isoformat(),
            'repository': str(self.repo_path),
            'total_findings': len(self.findings),
            'files_scanned': self.scanned_files,
            'commits_scanned': self.scanned_commits,
            'findings': findings_data
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{Fore.GREEN}[✓] Report exported to: {output_file}")
    
    def run_full_scan(self):
        """Execute comprehensive repository scan"""
        self._print_banner()
        
        # Check .gitignore
        self.check_gitignore()
        print()
        
        # Scan staged files
        self.scan_staged_files()
        print()
        
        # Scan working directory
        self.scan_working_directory()
        print()
        
        # Scan commit history
        self.scan_commit_history()
        print()
        
        # Generate summary
        is_safe = self.generate_summary()
        
        return is_safe
    
    def run_pre_commit_scan(self):
        """Quick scan for pre-commit hook integration"""
        print(f"{Fore.CYAN}[*] Running pre-commit security check...")
        
        self.scan_staged_files()
        
        critical_count = sum(1 for f in self.findings if f.severity == 'CRITICAL')
        high_count = sum(1 for f in self.findings if f.severity == 'HIGH')
        
        if critical_count > 0 or high_count > 0:
            print(f"\n{Fore.RED}[!] Security issues detected!")
            print(f"{Fore.RED}    CRITICAL: {critical_count}, HIGH: {high_count}")
            print(f"{Fore.RED}[!] Commit blocked. Please fix security issues first.")
            return False
        
        print(f"{Fore.GREEN}[✓] Security check passed")
        return True


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Git Security Scanner - Detect secrets and sensitive data in repositories',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full repository scan
  python git_security_scanner.py
  
  # Pre-commit hook mode
  python git_security_scanner.py --pre-commit
  
  # Scan specific repository
  python git_security_scanner.py --path /path/to/repo
  
  # Export findings to JSON
  python git_security_scanner.py --export report.json
  
  # Quiet mode with limited history
  python git_security_scanner.py --quiet --history-limit 50
        """
    )
    
    parser.add_argument('--path', '-p', default='.', 
                        help='Path to Git repository (default: current directory)')
    parser.add_argument('--pre-commit', action='store_true', 
                        help='Run in pre-commit hook mode (staged files only)')
    parser.add_argument('--history-limit', '-l', type=int, default=100, 
                        help='Number of commits to scan in history (default: 100)')
    parser.add_argument('--quiet', '-q', action='store_true', 
                        help='Minimal output mode')
    parser.add_argument('--export', '-e', 
                        help='Export findings to JSON file')
    
    args = parser.parse_args()
    
    try:
        # Initialize scanner
        scanner = GitSecurityScanner(args.path, verbose=not args.quiet)
        
        if args.pre_commit:
            # Pre-commit mode
            success = scanner.run_pre_commit_scan()
            sys.exit(0 if success else 1)
        else:
            # Full scan mode
            success = scanner.run_full_scan()
            
            # Export if requested
            if args.export:
                scanner.export_findings(args.export)
            
            sys.exit(0 if success else 1)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
