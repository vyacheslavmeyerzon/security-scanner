"""
Git Security Scanner - A tool to detect secrets in Git repositories.

This package provides functionality to scan Git repositories for exposed secrets,
API keys, passwords, and other sensitive information.
"""

__version__ = "0.1.0"
__author__ = "Vyacheslav Meyerzon"
__email__ = "vyacheslav.meyerzon@gmail.com"

from .scanner import SecurityScanner
from .patterns import PatternMatcher, Severity

__all__ = ["SecurityScanner", "PatternMatcher", "Severity"]