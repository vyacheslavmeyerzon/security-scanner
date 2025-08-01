"""
Git Security Scanner - A tool to detect secrets in Git repositories.

This package provides functionality to scan Git repositories for exposed secrets,
API keys, passwords, and other sensitive information.
"""

__version__ = "0.1.3"
__author__ = "Vyacheslav Meyerzon"
__email__ = "vyacheslav.meyerzon@gmail.com"

from .patterns import PatternMatcher, Severity
from .scanner import SecurityScanner

__all__ = ["SecurityScanner", "PatternMatcher", "Severity"]
