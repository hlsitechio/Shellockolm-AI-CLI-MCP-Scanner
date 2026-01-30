"""
Shellockolm - CLI & MCP Security Scanner for AI Agents
Complete security toolkit for React, Next.js, Node.js & npm ecosystem

Integrates with:
- Claude (Desktop & Code CLI)
- GitHub Copilot CLI
- Google Gemini CLI
- Cursor IDE
- Continue.dev
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

# Read requirements
requirements = (this_directory / "requirements.txt").read_text(encoding='utf-8').splitlines()

setup(
    name="shellockolm-security-scanner",
    version="3.0.0",
    author="HLS iTech",
    author_email="hlarosesurprenant@gmail.com",
    description="CLI & MCP Security Scanner for AI Agents - Detects 32 CVEs, malware & supply chain attacks in React/Next.js/npm projects",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hlsitechio/shellockolm",
    project_urls={
        "Bug Tracker": "https://github.com/hlsitechio/shellockolm/issues",
        "Documentation": "https://github.com/hlsitechio/shellockolm/blob/main/README.md",
        "Source Code": "https://github.com/hlsitechio/shellockolm",
        "Changelog": "https://github.com/hlsitechio/shellockolm/blob/main/docs/CHANGELOG.md",
        "MCP Setup Guide": "https://github.com/hlsitechio/shellockolm/blob/main/docs/MCP_SETUP.md",
        "Claude Code CLI": "https://github.com/hlsitechio/shellockolm/blob/main/docs/CLAUDE_CODE_CLI.md",
    },
    packages=find_packages(),
    py_modules=[
        'scanner',
        'remediation',
        'server',
        'auto_fix',
        'mass_patcher',
        'scan_simple',
        'malware_scanner'
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Environment :: Console",
        "Natural Language :: English",
    ],
    keywords=[
        # Primary
        "security-scanner", "ai-agent-tools", "mcp-server", "cli-security",
        # AI Platforms
        "claude-mcp", "copilot-cli", "gemini-cli", "ai-assistant",
        # Technologies
        "react-security", "nextjs-security", "nodejs-security", "npm-security",
        # Threats
        "vulnerability-scanner", "cve-detection", "malware-scanner", 
        "supply-chain-security", "rce-detection",
        # Use Cases
        "devsecops", "cybersecurity", "security-automation",
        # Brand
        "shellockolm", "sherlock-holmes-security"
    ],
    python_requires=">=3.10",
    install_requires=requirements,
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=4.0.0',
            'black>=23.0.0',
            'flake8>=6.0.0',
            'mypy>=1.0.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'shellockolm=cli:main',
            'shellockolm-scan=cli:main',
            'shellockolm-fix=auto_fix:main',
            'shellockolm-patch=mass_patcher:main',
            'shellockolm-malware=malware_scanner:main',
        ],
    },
    include_package_data=True,
    package_data={
        '': ['*.md', '*.txt', 'LICENSE'],
    },
    zip_safe=False,
)
