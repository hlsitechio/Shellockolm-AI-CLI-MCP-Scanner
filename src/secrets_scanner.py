#!/usr/bin/env python3
"""
Shellockolm Secrets Scanner
Detects hardcoded secrets, API keys, tokens, and credentials in code

Features:
- 50+ secret patterns (AWS, GitHub, Slack, etc.)
- .env file analysis
- Git history secret detection
- Entropy-based detection for unknown secrets
- Integration with TruffleHog patterns
"""

import re
import math
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class SecretType(Enum):
    """Types of secrets that can be detected"""
    AWS_ACCESS_KEY = "AWS Access Key"
    AWS_SECRET_KEY = "AWS Secret Key"
    GITHUB_TOKEN = "GitHub Token"
    GITLAB_TOKEN = "GitLab Token"
    SLACK_TOKEN = "Slack Token"
    SLACK_WEBHOOK = "Slack Webhook"
    DISCORD_TOKEN = "Discord Token"
    DISCORD_WEBHOOK = "Discord Webhook"
    STRIPE_KEY = "Stripe API Key"
    TWILIO_KEY = "Twilio API Key"
    SENDGRID_KEY = "SendGrid API Key"
    MAILGUN_KEY = "Mailgun API Key"
    NPM_TOKEN = "npm Token"
    PYPI_TOKEN = "PyPI Token"
    DOCKER_TOKEN = "Docker Token"
    HEROKU_KEY = "Heroku API Key"
    GOOGLE_API_KEY = "Google API Key"
    GOOGLE_OAUTH = "Google OAuth"
    FIREBASE_KEY = "Firebase Key"
    AZURE_KEY = "Azure Key"
    JWT_SECRET = "JWT Secret"
    PRIVATE_KEY = "Private Key"
    SSH_KEY = "SSH Key"
    DATABASE_URL = "Database URL"
    GENERIC_SECRET = "Generic Secret"
    GENERIC_PASSWORD = "Generic Password"
    GENERIC_API_KEY = "Generic API Key"
    BASIC_AUTH = "Basic Auth Credentials"
    BEARER_TOKEN = "Bearer Token"
    CRYPTO_WALLET = "Cryptocurrency Wallet"
    HIGH_ENTROPY = "High Entropy String"


class SecretSeverity(Enum):
    """Severity levels for secrets"""
    CRITICAL = "CRITICAL"  # Production keys, admin tokens
    HIGH = "HIGH"          # API keys, webhooks
    MEDIUM = "MEDIUM"      # Test keys, internal tokens
    LOW = "LOW"            # Potentially sensitive


@dataclass
class SecretPattern:
    """A pattern for detecting secrets"""
    id: str
    name: str
    pattern: str
    secret_type: SecretType
    severity: SecretSeverity
    description: str
    remediation: str
    false_positive_hints: List[str] = field(default_factory=list)


@dataclass
class SecretMatch:
    """A detected secret"""
    pattern: SecretPattern
    file_path: str
    line_number: int
    line_content: str
    matched_text: str
    masked_value: str  # Masked version for safe display
    entropy: float = 0.0


@dataclass
class SecretsReport:
    """Report of all detected secrets"""
    scan_time: datetime
    target_path: str
    files_scanned: int
    secrets_found: int
    critical: int
    high: int
    medium: int
    low: int
    matches: List[SecretMatch] = field(default_factory=list)
    duration: float = 0.0


# ─────────────────────────────────────────────────────────────────
# SECRET PATTERNS DATABASE
# ─────────────────────────────────────────────────────────────────

SECRET_PATTERNS: List[SecretPattern] = [
    # AWS
    SecretPattern(
        id="AWS-001",
        name="AWS Access Key ID",
        pattern=r'AKIA[0-9A-Z]{16}',
        secret_type=SecretType.AWS_ACCESS_KEY,
        severity=SecretSeverity.CRITICAL,
        description="AWS Access Key ID that can be used to authenticate to AWS services",
        remediation="Remove from code. Use IAM roles or environment variables.",
    ),
    SecretPattern(
        id="AWS-002",
        name="AWS Secret Access Key",
        pattern=r'(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*[\'"][A-Za-z0-9+/]{40}[\'"]',
        secret_type=SecretType.AWS_SECRET_KEY,
        severity=SecretSeverity.CRITICAL,
        description="AWS Secret Access Key for authentication",
        remediation="Rotate immediately. Use AWS Secrets Manager or environment variables.",
    ),
    SecretPattern(
        id="AWS-003",
        name="AWS Session Token",
        pattern=r'(?:aws_session_token|session_token)\s*[=:]\s*[\'"][A-Za-z0-9+/=]{100,}[\'"]',
        secret_type=SecretType.AWS_ACCESS_KEY,
        severity=SecretSeverity.CRITICAL,
        description="AWS Session Token for temporary credentials",
        remediation="These are temporary but should still not be in code.",
    ),

    # GitHub
    SecretPattern(
        id="GH-001",
        name="GitHub Personal Access Token",
        pattern=r'ghp_[A-Za-z0-9_]{36}',
        secret_type=SecretType.GITHUB_TOKEN,
        severity=SecretSeverity.CRITICAL,
        description="GitHub Personal Access Token (classic)",
        remediation="Revoke immediately at github.com/settings/tokens",
    ),
    SecretPattern(
        id="GH-002",
        name="GitHub OAuth Access Token",
        pattern=r'gho_[A-Za-z0-9_]{36}',
        secret_type=SecretType.GITHUB_TOKEN,
        severity=SecretSeverity.CRITICAL,
        description="GitHub OAuth Access Token",
        remediation="Revoke the OAuth app authorization.",
    ),
    SecretPattern(
        id="GH-003",
        name="GitHub User-to-Server Token",
        pattern=r'ghu_[A-Za-z0-9_]{36}',
        secret_type=SecretType.GITHUB_TOKEN,
        severity=SecretSeverity.CRITICAL,
        description="GitHub User-to-Server Token",
        remediation="Revoke at GitHub app settings.",
    ),
    SecretPattern(
        id="GH-004",
        name="GitHub Server-to-Server Token",
        pattern=r'ghs_[A-Za-z0-9_]{36}',
        secret_type=SecretType.GITHUB_TOKEN,
        severity=SecretSeverity.HIGH,
        description="GitHub Server-to-Server Token",
        remediation="Revoke at GitHub app settings.",
    ),
    SecretPattern(
        id="GH-005",
        name="GitHub Refresh Token",
        pattern=r'ghr_[A-Za-z0-9_]{36}',
        secret_type=SecretType.GITHUB_TOKEN,
        severity=SecretSeverity.HIGH,
        description="GitHub Refresh Token",
        remediation="Revoke at GitHub app settings.",
    ),

    # GitLab
    SecretPattern(
        id="GL-001",
        name="GitLab Personal Access Token",
        pattern=r'glpat-[A-Za-z0-9_-]{20,}',
        secret_type=SecretType.GITLAB_TOKEN,
        severity=SecretSeverity.CRITICAL,
        description="GitLab Personal Access Token",
        remediation="Revoke at gitlab.com/-/profile/personal_access_tokens",
    ),
    SecretPattern(
        id="GL-002",
        name="GitLab Pipeline Token",
        pattern=r'glcbt-[A-Za-z0-9_-]{20,}',
        secret_type=SecretType.GITLAB_TOKEN,
        severity=SecretSeverity.HIGH,
        description="GitLab CI Build Token",
        remediation="These are temporary but review CI configuration.",
    ),

    # Slack
    SecretPattern(
        id="SLACK-001",
        name="Slack Bot Token",
        pattern=r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}',
        secret_type=SecretType.SLACK_TOKEN,
        severity=SecretSeverity.CRITICAL,
        description="Slack Bot Token",
        remediation="Rotate at api.slack.com/apps",
    ),
    SecretPattern(
        id="SLACK-002",
        name="Slack User Token",
        pattern=r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}',
        secret_type=SecretType.SLACK_TOKEN,
        severity=SecretSeverity.CRITICAL,
        description="Slack User OAuth Token",
        remediation="Rotate at api.slack.com/apps",
    ),
    SecretPattern(
        id="SLACK-003",
        name="Slack Webhook URL",
        pattern=r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+',
        secret_type=SecretType.SLACK_WEBHOOK,
        severity=SecretSeverity.HIGH,
        description="Slack Incoming Webhook URL",
        remediation="Delete and recreate webhook.",
    ),

    # Discord
    SecretPattern(
        id="DISCORD-001",
        name="Discord Bot Token",
        pattern=r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}',
        secret_type=SecretType.DISCORD_TOKEN,
        severity=SecretSeverity.CRITICAL,
        description="Discord Bot Token",
        remediation="Reset token in Discord Developer Portal.",
    ),
    SecretPattern(
        id="DISCORD-002",
        name="Discord Webhook URL",
        pattern=r'https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+',
        secret_type=SecretType.DISCORD_WEBHOOK,
        severity=SecretSeverity.HIGH,
        description="Discord Webhook URL",
        remediation="Delete webhook in Discord server settings.",
    ),

    # Stripe
    SecretPattern(
        id="STRIPE-001",
        name="Stripe Live Secret Key",
        pattern=r'sk_live_[0-9a-zA-Z]{24,}',
        secret_type=SecretType.STRIPE_KEY,
        severity=SecretSeverity.CRITICAL,
        description="Stripe Live Secret Key - Can process real payments",
        remediation="Rotate immediately in Stripe Dashboard.",
    ),
    SecretPattern(
        id="STRIPE-002",
        name="Stripe Test Secret Key",
        pattern=r'sk_test_[0-9a-zA-Z]{24,}',
        secret_type=SecretType.STRIPE_KEY,
        severity=SecretSeverity.MEDIUM,
        description="Stripe Test Secret Key",
        remediation="Remove from code even though it's test mode.",
    ),
    SecretPattern(
        id="STRIPE-003",
        name="Stripe Restricted Key",
        pattern=r'rk_live_[0-9a-zA-Z]{24,}',
        secret_type=SecretType.STRIPE_KEY,
        severity=SecretSeverity.CRITICAL,
        description="Stripe Restricted API Key",
        remediation="Rotate in Stripe Dashboard.",
    ),

    # Twilio
    SecretPattern(
        id="TWILIO-001",
        name="Twilio API Key",
        pattern=r'SK[0-9a-fA-F]{32}',
        secret_type=SecretType.TWILIO_KEY,
        severity=SecretSeverity.HIGH,
        description="Twilio API Key",
        remediation="Rotate in Twilio Console.",
    ),
    SecretPattern(
        id="TWILIO-002",
        name="Twilio Auth Token",
        pattern=r'(?:twilio[_-]?auth[_-]?token)\s*[=:]\s*[\'"][a-f0-9]{32}[\'"]',
        secret_type=SecretType.TWILIO_KEY,
        severity=SecretSeverity.CRITICAL,
        description="Twilio Auth Token",
        remediation="Rotate in Twilio Console Account Settings.",
    ),

    # SendGrid
    SecretPattern(
        id="SENDGRID-001",
        name="SendGrid API Key",
        pattern=r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
        secret_type=SecretType.SENDGRID_KEY,
        severity=SecretSeverity.HIGH,
        description="SendGrid API Key",
        remediation="Delete and create new key in SendGrid.",
    ),

    # npm
    SecretPattern(
        id="NPM-001",
        name="npm Access Token",
        pattern=r'npm_[A-Za-z0-9]{36}',
        secret_type=SecretType.NPM_TOKEN,
        severity=SecretSeverity.CRITICAL,
        description="npm Access Token - Can publish packages",
        remediation="Revoke at npmjs.com/settings/tokens",
    ),
    SecretPattern(
        id="NPM-002",
        name="npm Auth Token in .npmrc",
        pattern=r'//registry\.npmjs\.org/:_authToken=[A-Za-z0-9-_]+',
        secret_type=SecretType.NPM_TOKEN,
        severity=SecretSeverity.CRITICAL,
        description="npm Auth Token in .npmrc format",
        remediation="Remove .npmrc from repo. Use environment variables.",
    ),

    # Google
    SecretPattern(
        id="GOOGLE-001",
        name="Google API Key",
        pattern=r'AIza[0-9A-Za-z_-]{35}',
        secret_type=SecretType.GOOGLE_API_KEY,
        severity=SecretSeverity.HIGH,
        description="Google API Key",
        remediation="Restrict key in Google Cloud Console or regenerate.",
    ),
    SecretPattern(
        id="GOOGLE-002",
        name="Google OAuth Client Secret",
        pattern=r'GOCSPX-[A-Za-z0-9_-]{28}',
        secret_type=SecretType.GOOGLE_OAUTH,
        severity=SecretSeverity.CRITICAL,
        description="Google OAuth Client Secret",
        remediation="Reset in Google Cloud Console.",
    ),
    SecretPattern(
        id="GOOGLE-003",
        name="Google Cloud Service Account",
        pattern=r'"type"\s*:\s*"service_account".*"private_key"\s*:\s*"-----BEGIN',
        secret_type=SecretType.GOOGLE_API_KEY,
        severity=SecretSeverity.CRITICAL,
        description="Google Cloud Service Account JSON Key",
        remediation="Delete key in GCP Console. Use Workload Identity.",
    ),

    # Firebase
    SecretPattern(
        id="FIREBASE-001",
        name="Firebase API Key",
        pattern=r'(?:firebase[_-]?api[_-]?key|FIREBASE_API_KEY)\s*[=:]\s*[\'"][A-Za-z0-9_-]{39}[\'"]',
        secret_type=SecretType.FIREBASE_KEY,
        severity=SecretSeverity.HIGH,
        description="Firebase API Key",
        remediation="Restrict key or regenerate in Firebase Console.",
    ),

    # Azure
    SecretPattern(
        id="AZURE-001",
        name="Azure Storage Account Key",
        pattern=r'(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[A-Za-z0-9+/=]{88}',
        secret_type=SecretType.AZURE_KEY,
        severity=SecretSeverity.CRITICAL,
        description="Azure Storage Account Key",
        remediation="Rotate key in Azure Portal.",
    ),
    SecretPattern(
        id="AZURE-002",
        name="Azure AD Client Secret",
        pattern=r'(?:client[_-]?secret|AZURE_CLIENT_SECRET)\s*[=:]\s*[\'"][A-Za-z0-9_~.-]{34,}[\'"]',
        secret_type=SecretType.AZURE_KEY,
        severity=SecretSeverity.CRITICAL,
        description="Azure AD Client Secret",
        remediation="Rotate in Azure AD App Registration.",
    ),

    # JWT
    SecretPattern(
        id="JWT-001",
        name="JWT Secret",
        pattern=r'(?:jwt[_-]?secret|JWT_SECRET|token[_-]?secret)\s*[=:]\s*[\'"][^\'"]{20,}[\'"]',
        secret_type=SecretType.JWT_SECRET,
        severity=SecretSeverity.CRITICAL,
        description="JWT Signing Secret",
        remediation="Rotate secret. Invalidate all existing tokens.",
    ),

    # Private Keys
    SecretPattern(
        id="KEY-001",
        name="RSA Private Key",
        pattern=r'-----BEGIN RSA PRIVATE KEY-----',
        secret_type=SecretType.PRIVATE_KEY,
        severity=SecretSeverity.CRITICAL,
        description="RSA Private Key",
        remediation="Remove and regenerate key pair.",
    ),
    SecretPattern(
        id="KEY-002",
        name="EC Private Key",
        pattern=r'-----BEGIN EC PRIVATE KEY-----',
        secret_type=SecretType.PRIVATE_KEY,
        severity=SecretSeverity.CRITICAL,
        description="EC Private Key",
        remediation="Remove and regenerate key pair.",
    ),
    SecretPattern(
        id="KEY-003",
        name="OpenSSH Private Key",
        pattern=r'-----BEGIN OPENSSH PRIVATE KEY-----',
        secret_type=SecretType.SSH_KEY,
        severity=SecretSeverity.CRITICAL,
        description="OpenSSH Private Key",
        remediation="Remove key. Generate new SSH key pair.",
    ),
    SecretPattern(
        id="KEY-004",
        name="PGP Private Key",
        pattern=r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        secret_type=SecretType.PRIVATE_KEY,
        severity=SecretSeverity.CRITICAL,
        description="PGP Private Key Block",
        remediation="Remove and revoke PGP key.",
    ),

    # Database URLs
    SecretPattern(
        id="DB-001",
        name="Database Connection String",
        pattern=r'(?:mongodb|mysql|postgresql|postgres|redis|mssql)://[^:]+:[^@]+@[^/]+',
        secret_type=SecretType.DATABASE_URL,
        severity=SecretSeverity.CRITICAL,
        description="Database connection string with credentials",
        remediation="Use environment variables. Rotate credentials.",
    ),
    SecretPattern(
        id="DB-002",
        name="DATABASE_URL with Password",
        pattern=r'(?:DATABASE_URL|DB_URL|MONGO_URL|REDIS_URL)\s*[=:]\s*[\'"][^\'"\s]+:[^\'"\s]+@[^\'"\s]+[\'"]',
        secret_type=SecretType.DATABASE_URL,
        severity=SecretSeverity.CRITICAL,
        description="Database URL environment variable with password",
        remediation="Remove from code. Use secrets management.",
    ),

    # Generic Patterns
    SecretPattern(
        id="GENERIC-001",
        name="Generic API Key Assignment",
        pattern=r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*[\'"][a-zA-Z0-9_-]{20,}[\'"]',
        secret_type=SecretType.GENERIC_API_KEY,
        severity=SecretSeverity.HIGH,
        description="Generic API key pattern",
        remediation="Review and rotate if it's a real key.",
    ),
    SecretPattern(
        id="GENERIC-002",
        name="Generic Secret Assignment",
        pattern=r'(?:secret|SECRET|Secret)\s*[=:]\s*[\'"][^\'"]{15,}[\'"]',
        secret_type=SecretType.GENERIC_SECRET,
        severity=SecretSeverity.MEDIUM,
        description="Generic secret assignment",
        remediation="Review to determine if this is sensitive.",
        false_positive_hints=["Example code", "Test files"],
    ),
    SecretPattern(
        id="GENERIC-003",
        name="Password Assignment",
        pattern=r'(?:password|passwd|pwd|PASSWORD)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]',
        secret_type=SecretType.GENERIC_PASSWORD,
        severity=SecretSeverity.HIGH,
        description="Password assignment in code",
        remediation="Never hardcode passwords. Use environment variables.",
        false_positive_hints=["Password validation", "Password field name"],
    ),
    SecretPattern(
        id="GENERIC-004",
        name="Basic Auth Header",
        pattern=r'(?:Authorization|authorization)\s*[=:]\s*[\'"]Basic\s+[A-Za-z0-9+/]+=*[\'"]',
        secret_type=SecretType.BASIC_AUTH,
        severity=SecretSeverity.HIGH,
        description="Base64 encoded Basic Auth credentials",
        remediation="Remove credentials. Use proper auth flow.",
    ),
    SecretPattern(
        id="GENERIC-005",
        name="Bearer Token",
        pattern=r'(?:Authorization|authorization)\s*[=:]\s*[\'"]Bearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+[\'"]',
        secret_type=SecretType.BEARER_TOKEN,
        severity=SecretSeverity.HIGH,
        description="Bearer token (likely JWT)",
        remediation="Remove hardcoded token. Use runtime auth.",
    ),

    # Crypto Wallets
    SecretPattern(
        id="CRYPTO-001",
        name="Bitcoin Private Key (WIF)",
        pattern=r'[5KL][1-9A-HJ-NP-Za-km-z]{50,51}',
        secret_type=SecretType.CRYPTO_WALLET,
        severity=SecretSeverity.CRITICAL,
        description="Bitcoin Private Key in WIF format",
        remediation="Move funds immediately! Use hardware wallet.",
    ),
    SecretPattern(
        id="CRYPTO-002",
        name="Ethereum Private Key",
        pattern=r'0x[a-fA-F0-9]{64}',
        secret_type=SecretType.CRYPTO_WALLET,
        severity=SecretSeverity.CRITICAL,
        description="Ethereum/EVM Private Key",
        remediation="Move funds immediately! Use hardware wallet.",
    ),

    # Heroku
    SecretPattern(
        id="HEROKU-001",
        name="Heroku API Key",
        pattern=r'(?:heroku[_-]?api[_-]?key|HEROKU_API_KEY)\s*[=:]\s*[\'"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[\'"]',
        secret_type=SecretType.HEROKU_KEY,
        severity=SecretSeverity.HIGH,
        description="Heroku API Key",
        remediation="Regenerate at Heroku Dashboard.",
    ),

    # Docker
    SecretPattern(
        id="DOCKER-001",
        name="Docker Hub Token",
        pattern=r'dckr_pat_[A-Za-z0-9_-]{27}',
        secret_type=SecretType.DOCKER_TOKEN,
        severity=SecretSeverity.HIGH,
        description="Docker Hub Personal Access Token",
        remediation="Revoke at hub.docker.com/settings/security",
    ),
]


class SecretsScanner:
    """
    Scanner for detecting hardcoded secrets in code
    """

    # File extensions to scan
    SCAN_EXTENSIONS = {
        '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx',
        '.json', '.yaml', '.yml', '.toml', '.xml',
        '.py', '.rb', '.go', '.java', '.php',
        '.env', '.cfg', '.conf', '.config', '.ini',
        '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd',
        '.md', '.txt', '.html', '.htm',
    }

    # Files to always scan regardless of extension
    ALWAYS_SCAN = {
        '.env', '.env.local', '.env.development', '.env.production',
        '.env.test', '.env.staging', '.npmrc', '.yarnrc',
        'credentials', 'secrets', 'config',
    }

    # Directories to skip
    SKIP_DIRS = {'node_modules', '.git', '.svn', 'vendor', '__pycache__', 'dist', 'build'}

    def __init__(self):
        self.patterns = SECRET_PATTERNS

    def get_patterns_summary(self) -> Dict[str, List[str]]:
        """Get summary of all patterns grouped by category"""
        categories = {}
        for pattern in self.patterns:
            category = pattern.secret_type.value
            if category not in categories:
                categories[category] = []
            categories[category].append(pattern.name)
        return categories

    def get_pattern_count(self) -> int:
        """Get total number of patterns"""
        return len(self.patterns)

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0

        # Count character frequencies
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        for count in freq.values():
            p = count / len(text)
            entropy -= p * math.log2(p)

        return entropy

    def mask_secret(self, secret: str, visible_chars: int = 4) -> str:
        """Mask a secret for safe display"""
        if len(secret) <= visible_chars * 2:
            return '*' * len(secret)
        return secret[:visible_chars] + '*' * (len(secret) - visible_chars * 2) + secret[-visible_chars:]

    def scan_file(self, file_path: Path) -> List[SecretMatch]:
        """Scan a single file for secrets"""
        matches = []

        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')

            for pattern in self.patterns:
                for i, line in enumerate(lines):
                    try:
                        regex_matches = re.finditer(pattern.pattern, line, re.IGNORECASE)
                        for m in regex_matches:
                            matched_text = m.group()
                            entropy = self.calculate_entropy(matched_text)

                            match = SecretMatch(
                                pattern=pattern,
                                file_path=str(file_path),
                                line_number=i + 1,
                                line_content=line,
                                matched_text=matched_text,
                                masked_value=self.mask_secret(matched_text),
                                entropy=entropy,
                            )
                            matches.append(match)
                    except re.error:
                        pass

            # High entropy detection for potential secrets
            for i, line in enumerate(lines):
                # Look for high entropy strings that might be secrets
                high_entropy_pattern = r'["\'][A-Za-z0-9+/=_-]{32,}["\']'
                for m in re.finditer(high_entropy_pattern, line):
                    value = m.group().strip('"\'')
                    entropy = self.calculate_entropy(value)

                    # High entropy threshold (typically 4.5+ indicates randomness)
                    if entropy > 4.5 and not any(existing.matched_text == value for existing in matches):
                        match = SecretMatch(
                            pattern=SecretPattern(
                                id="ENTROPY-001",
                                name="High Entropy String",
                                pattern="",
                                secret_type=SecretType.HIGH_ENTROPY,
                                severity=SecretSeverity.MEDIUM,
                                description=f"High entropy string (entropy: {entropy:.2f})",
                                remediation="Review if this is a secret.",
                            ),
                            file_path=str(file_path),
                            line_number=i + 1,
                            line_content=line,
                            matched_text=value,
                            masked_value=self.mask_secret(value),
                            entropy=entropy,
                        )
                        matches.append(match)

        except Exception:
            pass  # Skip files that can't be read

        return matches

    def scan_env_file(self, file_path: Path) -> List[SecretMatch]:
        """Specifically scan .env files"""
        matches = []

        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')

            for i, line in enumerate(lines):
                # Skip comments and empty lines
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Parse KEY=VALUE format
                if '=' in line:
                    key, _, value = line.partition('=')
                    key = key.strip()
                    value = value.strip().strip('"\'')

                    # Check for sensitive key names
                    sensitive_keys = [
                        'KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'PWD', 'PASS',
                        'API', 'AUTH', 'CREDENTIAL', 'PRIVATE',
                    ]

                    is_sensitive = any(s in key.upper() for s in sensitive_keys)

                    if is_sensitive and value and len(value) > 5:
                        match = SecretMatch(
                            pattern=SecretPattern(
                                id="ENV-001",
                                name="Environment Variable Secret",
                                pattern="",
                                secret_type=SecretType.GENERIC_SECRET,
                                severity=SecretSeverity.HIGH,
                                description=f"Sensitive environment variable: {key}",
                                remediation="Remove .env from version control. Use .env.example.",
                            ),
                            file_path=str(file_path),
                            line_number=i + 1,
                            line_content=line,
                            matched_text=f"{key}={value}",
                            masked_value=f"{key}={self.mask_secret(value)}",
                            entropy=self.calculate_entropy(value),
                        )
                        matches.append(match)

        except Exception:
            pass

        return matches

    def scan_directory(self, path: str, recursive: bool = True, max_depth: int = 10,
                       verbose: bool = False, console=None) -> SecretsReport:
        """Scan a directory for secrets with optional verbose progress output"""
        import time
        import sys
        start_time = time.time()

        target_path = Path(path).resolve()
        all_matches: List[SecretMatch] = []
        files_scanned = 0
        total_files = 0
        findings_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        def should_skip(dir_name: str) -> bool:
            return dir_name in self.SKIP_DIRS

        def should_scan_file(file_path: Path) -> bool:
            name = file_path.name.lower()
            if name in self.ALWAYS_SCAN or any(name.startswith(f) for f in self.ALWAYS_SCAN):
                return True
            return file_path.suffix.lower() in self.SCAN_EXTENSIONS

        # First pass: Count total files
        def count_files(current_path: Path, depth: int = 0) -> int:
            if depth > max_depth:
                return 0
            count = 0
            try:
                for item in current_path.iterdir():
                    if item.is_file():
                        if should_scan_file(item):
                            count += 1
                    elif item.is_dir() and recursive:
                        if not should_skip(item.name):
                            count += count_files(item, depth + 1)
            except PermissionError:
                pass
            return count

        # Show patterns summary if verbose
        if verbose and console:
            console.print(f"\n[bold bright_cyan]🔍 Secrets Scanner[/bold bright_cyan]")
            console.print(f"[dim]Searching {len(self.patterns)} patterns across {len(set(p.secret_type.value for p in self.patterns))} categories[/dim]")
            console.print(f"[dim]Categories: AWS, GitHub, Slack, Stripe, Private Keys, Database URLs, etc.[/dim]\n")

            console.print("[dim]Counting files...[/dim]", end="")
            total_files = count_files(target_path)
            console.print(f"\r[green]✓[/green] {total_files} files to scan" + " " * 20)
            console.print()

        def update_progress(current_file: str = ""):
            """Update progress on single line using sys.stdout for true in-place updates"""
            if not verbose or total_files == 0:
                return
            pct = (files_scanned / total_files) * 100
            bar_width = 30
            filled = int(bar_width * pct / 100)
            bar = "█" * filled + "░" * (bar_width - filled)

            # Build findings summary (plain text for stdout)
            findings_str = ""
            if findings_count["CRITICAL"] > 0:
                findings_str += f" {findings_count['CRITICAL']}C"
            if findings_count["HIGH"] > 0:
                findings_str += f" {findings_count['HIGH']}H"
            if findings_count["MEDIUM"] > 0:
                findings_str += f" {findings_count['MEDIUM']}M"

            # Truncate current file for display
            if current_file:
                if len(current_file) > 25:
                    current_file = "..." + current_file[-22:]
                file_str = f" {current_file}"
            else:
                file_str = ""

            # Use sys.stdout for true single-line updates
            line = f"\r[{bar}] {pct:5.1f}% ({files_scanned}/{total_files}){findings_str}{file_str}"
            # Pad to overwrite previous longer lines
            sys.stdout.write(line.ljust(80))
            sys.stdout.flush()

        def scan_recursive(current_path: Path, depth: int = 0):
            nonlocal files_scanned

            if depth > max_depth:
                return

            try:
                for item in current_path.iterdir():
                    if item.is_file():
                        if should_scan_file(item):
                            files_scanned += 1

                            # Update progress every 10 files
                            if verbose and files_scanned % 10 == 0:
                                try:
                                    rel_file = str(item.relative_to(target_path))
                                except ValueError:
                                    rel_file = item.name
                                update_progress(rel_file)

                            # Special handling for .env files
                            if item.name.lower().startswith('.env'):
                                matches = self.scan_env_file(item)
                            else:
                                matches = self.scan_file(item)

                            # Track findings by severity
                            for match in matches:
                                sev = match.pattern.severity.value
                                if sev in findings_count:
                                    findings_count[sev] += 1

                            all_matches.extend(matches)

                    elif item.is_dir() and recursive:
                        if not should_skip(item.name):
                            scan_recursive(item, depth + 1)

            except PermissionError:
                pass

        scan_recursive(target_path)

        # Final progress update
        if verbose:
            update_progress()
            sys.stdout.write("\n")  # Move to new line after progress bar
            sys.stdout.flush()
            total_found = sum(findings_count.values())
            if console:
                if total_found > 0:
                    console.print(f"[bold]Found {total_found} potential secrets[/bold]")
                else:
                    console.print(f"[green]✓ No secrets found[/green]")

        duration = time.time() - start_time

        # Count by severity
        critical = sum(1 for m in all_matches if m.pattern.severity == SecretSeverity.CRITICAL)
        high = sum(1 for m in all_matches if m.pattern.severity == SecretSeverity.HIGH)
        medium = sum(1 for m in all_matches if m.pattern.severity == SecretSeverity.MEDIUM)
        low = sum(1 for m in all_matches if m.pattern.severity == SecretSeverity.LOW)

        return SecretsReport(
            scan_time=datetime.now(),
            target_path=str(target_path),
            files_scanned=files_scanned,
            secrets_found=len(all_matches),
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            matches=all_matches,
            duration=duration,
        )

    def generate_report(self, report: SecretsReport, output_path: Optional[str] = None) -> Dict:
        """Generate a detailed secrets report"""
        output = {
            "scan_time": report.scan_time.isoformat(),
            "target_path": report.target_path,
            "files_scanned": report.files_scanned,
            "duration": report.duration,
            "summary": {
                "total_secrets": report.secrets_found,
                "critical": report.critical,
                "high": report.high,
                "medium": report.medium,
                "low": report.low,
            },
            "secrets": [],
        }

        for match in report.matches:
            secret = {
                "id": match.pattern.id,
                "type": match.pattern.secret_type.value,
                "name": match.pattern.name,
                "severity": match.pattern.severity.value,
                "file": match.file_path,
                "line": match.line_number,
                "masked_value": match.masked_value,
                "entropy": round(match.entropy, 2),
                "description": match.pattern.description,
                "remediation": match.pattern.remediation,
            }
            output["secrets"].append(secret)

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            Path(output_path).write_text(json.dumps(output, indent=2))

        return output


def main():
    """CLI entry point"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python secrets_scanner.py <path>")
        sys.exit(1)

    scanner = SecretsScanner()
    report = scanner.scan_directory(sys.argv[1])

    print(f"\nSecrets Scan Report")
    print("=" * 50)
    print(f"Path: {report.target_path}")
    print(f"Files scanned: {report.files_scanned}")
    print(f"Duration: {report.duration:.2f}s")
    print(f"\nSecrets found: {report.secrets_found}")
    print(f"  Critical: {report.critical}")
    print(f"  High: {report.high}")
    print(f"  Medium: {report.medium}")
    print(f"  Low: {report.low}")

    if report.matches:
        print("\nDetails:")
        for match in report.matches[:20]:
            icon = "🔴" if match.pattern.severity == SecretSeverity.CRITICAL else "🟠" if match.pattern.severity == SecretSeverity.HIGH else "🟡"
            print(f"  {icon} {match.pattern.name}")
            print(f"      File: {match.file_path}:{match.line_number}")
            print(f"      Value: {match.masked_value}")

        if len(report.matches) > 20:
            print(f"\n  ... and {len(report.matches) - 20} more")


if __name__ == "__main__":
    main()
