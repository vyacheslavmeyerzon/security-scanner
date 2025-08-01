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
    version="0.1.2",
    author="Vyacheslav Meyerzon",
    author_email="vyacheslav.meyerzon@gmail.com",
    description="A comprehensive tool to detect secrets and sensitive information in Git repositories",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/vyacheslavmeyerzon/security-scanner",
    project_urls={
        "Bug Tracker": "https://github.com/vyacheslavmeyerzon/security-scanner/issues",
        "Source Code": "https://github.com/vyacheslavmeyerzon/security-scanner",
        "Documentation": "https://github.com/vyacheslavmeyerzon/security-scanner/wiki",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Security",
        "Topic :: Software Development :: Version Control :: Git",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.8",
    install_requires=[
        "colorama>=0.4.6",
        "PyYAML>=6.0",
        "tqdm>=4.65.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-mock>=3.10.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "isort>=5.12.0",
            "types-colorama>=0.4.15",
            "types-PyYAML>=6.0",
            "types-PyYAML>=6.0",
            "build>=0.10.0",
            "twine>=4.0.2",
        ],
    },
    entry_points={
        "console_scripts": [
            "git-security-scanner=security_scanner.cli:run_cli",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords=[
        "security", "git", "secrets", "scanner", "api-keys", "passwords",
        "security-tools", "devsecops", "secret-detection", "code-security"
    ],
)