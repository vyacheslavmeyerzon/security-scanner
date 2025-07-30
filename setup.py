"""
Setup script for git-security-scanner.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = ""
if readme_file.exists():
    long_description = readme_file.read_text(encoding="utf-8")

setup(
    name="git-security-scanner",
    version="0.1.0",
    author="Vyacheslav Meyerzon",
    author_email="vyacheslav.meyerzon@gmail.com",
    description="A simple Python tool to detect API keys, passwords, and secrets in your Git repositories",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/vyacheslavmeyerzon/security-scanner",
    project_urls={
        "Bug Tracker": "https://github.com/vyacheslavmeyerzon/security-scanner/issues",
        "Source Code": "https://github.com/vyacheslavmeyerzon/security-scanner",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.7",
    install_requires=[
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "git-security-scanner=security_scanner.cli:run_cli",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)