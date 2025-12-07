"""
CVE-2025-55182 Security Tools - Setup Configuration
Complete toolset for detecting and patching CVE-2025-55182 (React2Shell)
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

# Read requirements
requirements = (this_directory / "requirements.txt").read_text(encoding='utf-8').splitlines()

setup(
    name="cve-2025-55182-tools",
    version="1.1.0",
    author="HLS iTech",
    author_email="hlarosesurprenant@gmail.com",
    description="Complete security toolkit for CVE-2025-55182 (React Server Components RCE vulnerability)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hlsitechio/cve-2025-55182-tools",
    project_urls={
        "Bug Tracker": "https://github.com/hlsitechio/cve-2025-55182-tools/issues",
        "Documentation": "https://github.com/hlsitechio/cve-2025-55182-tools/blob/main/README.md",
        "Source Code": "https://github.com/hlsitechio/cve-2025-55182-tools",
        "Changelog": "https://github.com/hlsitechio/cve-2025-55182-tools/blob/main/CHANGELOG.md",
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
        "security", "vulnerability", "cve", "react", "nextjs", "rce",
        "vulnerability-scanner", "security-tools", "patch-management",
        "react-server-components", "cybersecurity", "devsecops",
        "npm", "malware-scanner", "supply-chain-security"
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
            'cve-2025-55182-scan=scan_simple:main',
            'cve-2025-55182-fix=auto_fix:main',
            'cve-2025-55182-patch=mass_patcher:main',
            'cve-2025-55182-malware=malware_scanner:main',
        ],
    },
    include_package_data=True,
    package_data={
        '': ['*.md', '*.txt', 'LICENSE'],
    },
    zip_safe=False,
)
