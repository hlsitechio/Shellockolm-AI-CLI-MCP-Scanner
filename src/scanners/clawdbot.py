"""
Clawdbot/Moltbot AI Gateway Scanner
Detects credential exposure, unauthorized installations, and network leaks:
- Plaintext OAuth token files (~/.clawdbot/, ~/.moltbot/)
- Claude Code credential piggybacking (~/.claude/.credentials.json)
- mDNS service broadcasting (port 5353 leaking paths/usernames)
- Exposed gateway ports (18789)
- Insecure file permissions on credential stores

Based on Shodan research: 957 exposed instances found in first week.
Argus security audit: 512 findings, 8 CRITICAL.
"""

import json
import os
import re
import socket
import stat
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from .base import BaseScanner, ScanResult, ScanFinding, FindingSeverity


class ClawdbotScanner(BaseScanner):
    """Scanner for Clawdbot/Moltbot AI gateway credential exposure"""

    NAME = "clawdbot"
    DESCRIPTION = "Detects Clawdbot/Moltbot AI gateway installations and credential leaks"
    CVE_IDS = [
        "CLAWDBOT-AUTH-BYPASS",
        "CLAWDBOT-PLAINTEXT-CREDS",
        "CLAWDBOT-PROMPT-RCE",
        "CLAWDBOT-QSTRING-AUTH",
    ]
    SUPPORTED_PACKAGES = ["clawdbot", "moltbot"]

    # =========================================================================
    # CREDENTIAL FILE PATHS (relative to home directory)
    # =========================================================================
    CREDENTIAL_PATHS: List[Dict[str, Any]] = [
        {
            "path": ".claude/.credentials.json",
            "description": "Claude Code OAuth tokens (piggybacked by Clawdbot)",
            "severity": FindingSeverity.CRITICAL,
            "cve": "CLAWDBOT-PLAINTEXT-CREDS",
            "tokens": True,
        },
        {
            "path": ".clawdbot/clawdbot.json",
            "description": "Clawdbot gateway config with stored tokens",
            "severity": FindingSeverity.CRITICAL,
            "cve": "CLAWDBOT-PLAINTEXT-CREDS",
            "tokens": True,
        },
        {
            "path": ".moltbot/moltbot.json",
            "description": "Moltbot (rebrand) gateway config with stored tokens",
            "severity": FindingSeverity.CRITICAL,
            "cve": "CLAWDBOT-PLAINTEXT-CREDS",
            "tokens": True,
        },
        {
            "path": ".clawdbot/",
            "description": "Clawdbot config directory",
            "severity": FindingSeverity.HIGH,
            "cve": "CLAWDBOT-PLAINTEXT-CREDS",
            "tokens": False,
        },
        {
            "path": ".moltbot/",
            "description": "Moltbot config directory",
            "severity": FindingSeverity.HIGH,
            "cve": "CLAWDBOT-PLAINTEXT-CREDS",
            "tokens": False,
        },
        {
            "path": ".claude.json",
            "description": "Claude MCP config (may reference Clawdbot)",
            "severity": FindingSeverity.MEDIUM,
            "cve": "CLAWDBOT-PLAINTEXT-CREDS",
            "tokens": False,
        },
    ]

    # =========================================================================
    # INSTALLATION DETECTION PATHS
    # =========================================================================
    INSTALL_PATHS: List[Dict[str, str]] = [
        {"path": ".npm-global/lib/node_modules/clawdbot/", "type": "npm-global"},
        {"path": ".npm-global/lib/node_modules/moltbot/", "type": "npm-global"},
    ]

    SYSTEM_BINARIES = [
        "/usr/bin/clawdbot",
        "/usr/local/bin/clawdbot",
        "/usr/bin/moltbot",
        "/usr/local/bin/moltbot",
    ]

    # =========================================================================
    # TOKEN / SECRET PATTERNS
    # =========================================================================
    TOKEN_PATTERNS = [
        (r'"accessToken"\s*:\s*"([^"]{20,})"', "OAuth Access Token"),
        (r'"refreshToken"\s*:\s*"([^"]{20,})"', "OAuth Refresh Token"),
        (r'"token"\s*:\s*"([^"]{20,})"', "API Token"),
        (r'"apiKey"\s*:\s*"(sk-[^"]{20,})"', "Anthropic API Key"),
        (r'"apiKey"\s*:\s*"([^"]{20,})"', "API Key"),
        (r'"discordToken"\s*:\s*"([^"]{20,})"', "Discord Bot Token"),
        (r'"botToken"\s*:\s*"([^"]{20,})"', "Bot Token"),
        (r'"sessionKey"\s*:\s*"([^"]{20,})"', "Session Key"),
        (r'"idToken"\s*:\s*"(eyJ[^"]{50,})"', "JWT ID Token"),
        (r'"password"\s*:\s*"([^"]+)"', "Plaintext Password"),
    ]

    # Clawdbot gateway default port
    GATEWAY_PORT = 18789
    MDNS_PORT = 5353

    # =========================================================================
    # MAIN SCAN ENTRY POINT
    # =========================================================================

    def scan_directory(
        self,
        path: str,
        recursive: bool = True,
        max_depth: int = 10,
    ) -> ScanResult:
        """Scan for Clawdbot/Moltbot installations and credential exposure"""
        result = self.create_result(path)

        credential_files_found = 0
        installations_found = 0
        network_exposures_found = 0
        packages_scanned = 0
        insecure_permissions = 0

        # Phase 1: Credential file detection
        cred_findings = self._scan_credential_files()
        for f in cred_findings:
            if "permission" in f.detection_method:
                insecure_permissions += 1
            else:
                credential_files_found += 1
        result.findings.extend(cred_findings)

        # Phase 2: Installation detection
        install_findings = self._scan_for_clawdbot_install(Path(path))
        installations_found = len(install_findings)
        result.findings.extend(install_findings)

        # Phase 3: Network exposure detection
        net_findings = self._scan_network_exposure()
        network_exposures_found = len(net_findings)
        result.findings.extend(net_findings)

        # Phase 4: Package dependency scanning
        for package_json in self.find_package_json_files(path, recursive, max_depth):
            packages_scanned += 1
            pkg_findings = self._scan_package(package_json)
            result.findings.extend(pkg_findings)

        result.stats["credential_files_found"] = credential_files_found
        result.stats["installations_found"] = installations_found
        result.stats["network_exposures"] = network_exposures_found
        result.stats["packages_scanned"] = packages_scanned
        result.stats["insecure_permissions"] = insecure_permissions

        return self.finalize_result(result)

    # =========================================================================
    # PHASE 1: CREDENTIAL FILE DETECTION
    # =========================================================================

    def _scan_credential_files(self) -> List[ScanFinding]:
        """Check home directory for Clawdbot credential files and token exposure"""
        findings = []
        home = Path.home()

        for cred in self.CREDENTIAL_PATHS:
            cred_path = home / cred["path"]

            # Directory check
            if cred["path"].endswith("/"):
                if cred_path.exists() and cred_path.is_dir():
                    findings.append(ScanFinding(
                        cve_id=cred["cve"],
                        title=f"Clawdbot Config Directory: {cred['path']}",
                        severity=cred["severity"],
                        cvss_score=7.5,
                        package="clawdbot",
                        version="detected",
                        patched_version=None,
                        file_path=str(cred_path),
                        description=cred["description"],
                        exploit_difficulty="Trivial",
                        remediation=(
                            f"Remove {cred_path} if Clawdbot is not intentionally used. "
                            "Audit stored tokens and rotate any exposed credentials."
                        ),
                        detection_method="credential_directory",
                    ))

                    # Check permissions on the directory
                    perm_finding = self._check_file_permissions(cred_path)
                    if perm_finding:
                        findings.append(perm_finding)
                continue

            # File check
            if not cred_path.exists():
                continue

            # Check file permissions
            perm_finding = self._check_file_permissions(cred_path)
            if perm_finding:
                findings.append(perm_finding)

            # Scan for tokens if flagged
            if cred.get("tokens"):
                token_findings = self._scan_file_for_tokens(cred_path, cred)
                findings.extend(token_findings)
            else:
                # Still report the file exists
                findings.append(ScanFinding(
                    cve_id=cred["cve"],
                    title=f"Clawdbot Config File: {cred['path']}",
                    severity=cred["severity"],
                    cvss_score=5.3 if cred["severity"] == FindingSeverity.MEDIUM else 7.5,
                    package="clawdbot",
                    version="detected",
                    patched_version=None,
                    file_path=str(cred_path),
                    description=cred["description"],
                    exploit_difficulty="Trivial",
                    remediation=(
                        f"Review {cred_path} for Clawdbot references. "
                        "Remove Clawdbot MCP entries if not intentionally used."
                    ),
                    detection_method="credential_file",
                ))

                # If it's .claude.json, check for clawdbot references
                if cred["path"] == ".claude.json":
                    self._check_claude_json_refs(cred_path, findings)

        return findings

    def _scan_file_for_tokens(
        self,
        file_path: Path,
        cred_info: Dict[str, Any],
    ) -> List[ScanFinding]:
        """Scan a credential file for exposed tokens"""
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (IOError, PermissionError):
            return findings

        tokens_found = []
        for pattern, token_type in self.TOKEN_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                tokens_found.append((token_type, len(matches)))

        if tokens_found:
            token_summary = ", ".join(
                f"{count}x {ttype}" for ttype, count in tokens_found
            )
            findings.append(ScanFinding(
                cve_id=cred_info["cve"],
                title=f"Plaintext Tokens in {file_path.name}",
                severity=FindingSeverity.CRITICAL,
                cvss_score=9.0,
                package="clawdbot",
                version="detected",
                patched_version=None,
                file_path=str(file_path),
                description=(
                    f"Plaintext credentials found: {token_summary}. "
                    "Clawdbot stores OAuth tokens in plaintext JSON. "
                    "Any local process or malware can steal these tokens. "
                    "Tokens piggyback on your Claude Pro/Max subscription."
                ),
                exploit_difficulty="Trivial",
                remediation=(
                    "1. Revoke all exposed tokens immediately\n"
                    "2. Re-authenticate with Claude Code (claude login)\n"
                    "3. Remove Clawdbot: npm uninstall -g clawdbot\n"
                    f"4. Delete {file_path}\n"
                    "5. Rotate any Discord/API tokens found"
                ),
                detection_method="token_scan",
                raw_data={"tokens_found": tokens_found},
            ))

        return findings

    def _check_file_permissions(self, file_path: Path) -> Optional[ScanFinding]:
        """Check if a credential file has insecure permissions"""
        try:
            st = file_path.stat()
            mode = st.st_mode
        except (OSError, PermissionError):
            return None

        # Check if world-readable or group-readable
        world_readable = bool(mode & stat.S_IROTH)
        group_readable = bool(mode & stat.S_IRGRP)
        world_writable = bool(mode & stat.S_IWOTH)

        issues = []
        if world_readable:
            issues.append("world-readable (o+r)")
        if group_readable:
            issues.append("group-readable (g+r)")
        if world_writable:
            issues.append("world-writable (o+w)")

        if not issues:
            return None

        perm_str = oct(mode)[-3:]
        return ScanFinding(
            cve_id="CLAWDBOT-PLAINTEXT-CREDS",
            title=f"Insecure Permissions on {file_path.name} ({perm_str})",
            severity=FindingSeverity.HIGH,
            cvss_score=7.5,
            package="clawdbot",
            version="detected",
            patched_version=None,
            file_path=str(file_path),
            description=(
                f"Credential file has insecure permissions: {', '.join(issues)}. "
                f"Current mode: {perm_str}. Any local user can read these credentials."
            ),
            exploit_difficulty="Trivial",
            remediation=f"chmod 600 {file_path}",
            detection_method="permission_check",
            raw_data={"mode": perm_str, "issues": issues},
        )

    def _check_claude_json_refs(
        self,
        claude_json: Path,
        findings: List[ScanFinding],
    ) -> None:
        """Check .claude.json for Clawdbot MCP server references"""
        try:
            data = json.loads(claude_json.read_text(encoding="utf-8", errors="ignore"))
        except (json.JSONDecodeError, IOError):
            return

        mcp_servers = data.get("mcpServers", {})
        for name, config in mcp_servers.items():
            cmd = str(config.get("command", ""))
            args = " ".join(str(a) for a in config.get("args", []))
            combined = f"{cmd} {args}".lower()

            if "clawdbot" in combined or "moltbot" in combined:
                findings.append(ScanFinding(
                    cve_id="CLAWDBOT-AUTH-BYPASS",
                    title=f"Clawdbot MCP Server Reference: {name}",
                    severity=FindingSeverity.HIGH,
                    cvss_score=7.5,
                    package="clawdbot",
                    version="detected",
                    patched_version=None,
                    file_path=str(claude_json),
                    description=(
                        f"MCP server '{name}' references Clawdbot/Moltbot. "
                        "This grants Clawdbot access to Claude Code's tool execution "
                        "capabilities, expanding the attack surface for prompt injection to RCE."
                    ),
                    exploit_difficulty="Easy",
                    remediation=(
                        f"Remove the '{name}' entry from mcpServers in {claude_json} "
                        "unless Clawdbot integration is intentional and understood."
                    ),
                    detection_method="config_reference",
                ))

        # Also check project-level configs
        projects = data.get("projects", {})
        for proj_path, proj_config in projects.items():
            if "clawdbot" in proj_path.lower() or "moltbot" in proj_path.lower():
                findings.append(ScanFinding(
                    cve_id="CLAWDBOT-PLAINTEXT-CREDS",
                    title=f"Clawdbot Project Reference: {proj_path}",
                    severity=FindingSeverity.MEDIUM,
                    cvss_score=5.3,
                    package="clawdbot",
                    version="detected",
                    patched_version=None,
                    file_path=str(claude_json),
                    description=(
                        f"Claude config references Clawdbot project at {proj_path}. "
                        "This may indicate Clawdbot source code or configs on disk."
                    ),
                    exploit_difficulty="Moderate",
                    remediation="Review and remove the project reference if no longer needed.",
                    detection_method="config_reference",
                ))

    # =========================================================================
    # PHASE 2: INSTALLATION DETECTION
    # =========================================================================

    def _scan_for_clawdbot_install(self, root_path: Path) -> List[ScanFinding]:
        """Detect Clawdbot/Moltbot installations on the system"""
        findings = []
        home = Path.home()

        # Check npm global installs
        for install in self.INSTALL_PATHS:
            install_path = home / install["path"]
            if install_path.exists():
                pkg_name = "clawdbot" if "clawdbot" in install["path"] else "moltbot"
                version = self._get_installed_version(install_path)
                findings.append(ScanFinding(
                    cve_id="CLAWDBOT-AUTH-BYPASS",
                    title=f"{pkg_name.capitalize()} Installed ({install['type']})",
                    severity=FindingSeverity.HIGH,
                    cvss_score=9.8,
                    package=pkg_name,
                    version=version or "unknown",
                    patched_version=None,
                    file_path=str(install_path),
                    description=(
                        f"{pkg_name.capitalize()} is installed via {install['type']}. "
                        "This AI gateway piggbybacks Claude Code OAuth tokens, "
                        "stores credentials in plaintext, and trusts localhost by default. "
                        "Argus audit found 512 security findings including 8 CRITICAL."
                    ),
                    exploit_difficulty="Trivial",
                    remediation=(
                        f"npm uninstall -g {pkg_name}\n"
                        "Then: rm -rf ~/.clawdbot ~/.moltbot\n"
                        "Then: claude login (to rotate OAuth tokens)"
                    ),
                    detection_method="install_detection",
                ))

        # Check system binaries
        for binary in self.SYSTEM_BINARIES:
            if Path(binary).exists():
                pkg_name = "clawdbot" if "clawdbot" in binary else "moltbot"
                findings.append(ScanFinding(
                    cve_id="CLAWDBOT-AUTH-BYPASS",
                    title=f"{pkg_name.capitalize()} System Binary Found",
                    severity=FindingSeverity.HIGH,
                    cvss_score=9.8,
                    package=pkg_name,
                    version="system",
                    patched_version=None,
                    file_path=binary,
                    description=(
                        f"System-wide {pkg_name} binary at {binary}. "
                        "System-level install means ALL users' credentials may be at risk."
                    ),
                    exploit_difficulty="Trivial",
                    remediation=f"rm {binary} && npm uninstall -g {pkg_name}",
                    detection_method="binary_detection",
                ))

        # Check for cloned repos in scan path
        for candidate in [root_path, home]:
            for dirname in ["clawdbot", "clawbot", "moltbot"]:
                repo_path = candidate / dirname
                if repo_path.exists() and (repo_path / "package.json").exists():
                    version = self._get_repo_version(repo_path)
                    findings.append(ScanFinding(
                        cve_id="CLAWDBOT-PLAINTEXT-CREDS",
                        title=f"Clawdbot Source Repository: {repo_path}",
                        severity=FindingSeverity.MEDIUM,
                        cvss_score=5.3,
                        package="clawdbot",
                        version=version or "source",
                        patched_version=None,
                        file_path=str(repo_path),
                        description=(
                            f"Clawdbot/Moltbot source code found at {repo_path}. "
                            "If node_modules exists, vulnerable dependencies may be present."
                        ),
                        exploit_difficulty="Moderate",
                        remediation=(
                            f"Remove if unused: rm -rf {repo_path}\n"
                            "If needed for research, ensure node_modules is deleted."
                        ),
                        detection_method="repo_detection",
                    ))

        # Check for running processes
        proc_findings = self._check_running_processes()
        findings.extend(proc_findings)

        return findings

    def _get_installed_version(self, install_path: Path) -> Optional[str]:
        """Get version from an installed package"""
        pkg_json = install_path / "package.json"
        if pkg_json.exists():
            data = self.parse_package_json(pkg_json)
            if data:
                return data.get("version")
        return None

    def _get_repo_version(self, repo_path: Path) -> Optional[str]:
        """Get version from a cloned repository"""
        return self._get_installed_version(repo_path)

    def _check_running_processes(self) -> List[ScanFinding]:
        """Check if Clawdbot gateway is running"""
        findings = []
        try:
            result = subprocess.run(
                ["pgrep", "-af", "clawdbot|moltbot"],
                capture_output=True, text=True, timeout=5,
            )
            if result.stdout.strip():
                processes = result.stdout.strip().split("\n")
                findings.append(ScanFinding(
                    cve_id="CLAWDBOT-AUTH-BYPASS",
                    title=f"Clawdbot Process Running ({len(processes)} instance(s))",
                    severity=FindingSeverity.CRITICAL,
                    cvss_score=9.8,
                    package="clawdbot",
                    version="running",
                    patched_version=None,
                    file_path="process",
                    description=(
                        f"Active Clawdbot/Moltbot process detected: {len(processes)} instance(s). "
                        "The gateway is actively piggybacking your Claude credentials "
                        "and may be broadcasting via mDNS."
                    ),
                    exploit_difficulty="Trivial",
                    remediation=(
                        "Kill the process: pkill -f clawdbot\n"
                        "Disable autostart: systemctl disable clawdbot (if systemd)\n"
                        "Then uninstall and rotate credentials."
                    ),
                    detection_method="process_detection",
                    raw_data={"processes": processes[:5]},
                ))
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return findings

    # =========================================================================
    # PHASE 3: NETWORK EXPOSURE DETECTION
    # =========================================================================

    def _scan_network_exposure(self) -> List[ScanFinding]:
        """Check for Clawdbot network exposure"""
        findings = []

        # Check if gateway port is listening
        if self._is_port_listening(self.GATEWAY_PORT):
            findings.append(ScanFinding(
                cve_id="CLAWDBOT-AUTH-BYPASS",
                title=f"Clawdbot Gateway Listening on Port {self.GATEWAY_PORT}",
                severity=FindingSeverity.CRITICAL,
                cvss_score=9.8,
                package="clawdbot",
                version="active",
                patched_version=None,
                file_path="network",
                description=(
                    f"Clawdbot gateway is listening on port {self.GATEWAY_PORT}. "
                    "If this port is exposed beyond localhost (via reverse proxy, "
                    "port forwarding, or firewall misconfiguration), any remote attacker "
                    "gets full unauthenticated access to your Claude tokens and tools. "
                    "Shodan found 957 exposed instances in the first week."
                ),
                exploit_difficulty="Trivial",
                remediation=(
                    f"1. Firewall: ufw deny {self.GATEWAY_PORT}\n"
                    "2. Bind to localhost only in Clawdbot config\n"
                    "3. Never expose via reverse proxy without auth\n"
                    "4. Check: ss -tlnp | grep 18789"
                ),
                detection_method="port_scan",
            ))

        # Check if mDNS port is active (broadcasting service discovery)
        if self._is_port_listening(self.MDNS_PORT, udp=True):
            findings.append(ScanFinding(
                cve_id="CLAWDBOT-PLAINTEXT-CREDS",
                title="mDNS Broadcasting Clawdbot Service Discovery",
                severity=FindingSeverity.HIGH,
                cvss_score=7.5,
                package="clawdbot",
                version="active",
                patched_version=None,
                file_path="network",
                description=(
                    "mDNS (port 5353) is active and may be broadcasting Clawdbot "
                    "gateway discovery data to the network. Shodan captures show these "
                    "broadcasts leak: username, CLI path, SSH port, gateway port, "
                    "internal IPs, and Tailscale hostnames. This maps directly to "
                    "where ~/.claude/.credentials.json lives."
                ),
                exploit_difficulty="Easy",
                remediation=(
                    "1. Disable Clawdbot mDNS: set gateway.mdns=false in config\n"
                    "2. Block outbound: iptables -A OUTPUT -p udp --dport 5353 -j DROP\n"
                    "3. Or disable avahi: systemctl stop avahi-daemon"
                ),
                detection_method="mdns_detection",
            ))

        # Check for reverse proxy configs pointing to clawdbot
        proxy_findings = self._check_reverse_proxy_configs()
        findings.extend(proxy_findings)

        return findings

    def _is_port_listening(self, port: int, udp: bool = False) -> bool:
        """Check if a port is listening on localhost"""
        try:
            sock_type = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
            with socket.socket(socket.AF_INET, sock_type) as sock:
                sock.settimeout(1)
                if udp:
                    # For UDP, try to connect — won't error if port exists
                    sock.connect(("127.0.0.1", port))
                    return True
                else:
                    result = sock.connect_ex(("127.0.0.1", port))
                    return result == 0
        except (socket.timeout, socket.error, OSError):
            return False

    def _check_reverse_proxy_configs(self) -> List[ScanFinding]:
        """Check nginx/caddy configs for Clawdbot proxy rules"""
        findings = []
        config_paths = [
            "/etc/nginx/sites-enabled/",
            "/etc/nginx/conf.d/",
            "/etc/caddy/",
        ]

        for config_dir in config_paths:
            config_path = Path(config_dir)
            if not config_path.exists():
                continue

            try:
                for conf_file in config_path.iterdir():
                    if not conf_file.is_file():
                        continue
                    try:
                        content = conf_file.read_text(encoding="utf-8", errors="ignore")
                        if re.search(
                            r"(proxy_pass|reverse_proxy).*"
                            r"(18789|clawdbot|moltbot)",
                            content, re.IGNORECASE,
                        ):
                            findings.append(ScanFinding(
                                cve_id="CLAWDBOT-AUTH-BYPASS",
                                title=f"Reverse Proxy Exposing Clawdbot: {conf_file.name}",
                                severity=FindingSeverity.CRITICAL,
                                cvss_score=9.8,
                                package="clawdbot",
                                version="proxied",
                                patched_version=None,
                                file_path=str(conf_file),
                                description=(
                                    f"Reverse proxy config {conf_file} forwards traffic "
                                    "to Clawdbot gateway. This bypasses localhost trust "
                                    "and exposes the gateway to remote attackers."
                                ),
                                exploit_difficulty="Trivial",
                                remediation=(
                                    f"Remove Clawdbot proxy rules from {conf_file}\n"
                                    "If proxy is needed, add authentication middleware."
                                ),
                                detection_method="proxy_config",
                            ))
                    except (IOError, PermissionError):
                        continue
            except PermissionError:
                continue

        return findings

    # =========================================================================
    # PHASE 4: PACKAGE DEPENDENCY CHECK
    # =========================================================================

    def _scan_package(self, package_json: Path) -> List[ScanFinding]:
        """Check package.json for Clawdbot/Moltbot dependencies"""
        findings = []

        data = self.parse_package_json(package_json)
        if not data:
            return findings

        deps = self.get_dependencies(data)

        for pkg_name in self.SUPPORTED_PACKAGES:
            if pkg_name in deps:
                version = self.extract_version(deps[pkg_name])

                # Check against vulnerability database
                vulns = self.check_package_vulnerability(pkg_name, version)
                for vuln in vulns:
                    findings.append(self.create_finding(
                        vuln, pkg_name, version,
                        str(package_json), "manifest",
                    ))

                # If no DB match, still flag presence
                if not vulns:
                    findings.append(ScanFinding(
                        cve_id="CLAWDBOT-AUTH-BYPASS",
                        title=f"{pkg_name} in Dependencies",
                        severity=FindingSeverity.HIGH,
                        cvss_score=9.8,
                        package=pkg_name,
                        version=version,
                        patched_version=None,
                        file_path=str(package_json),
                        description=(
                            f"{pkg_name} found as a project dependency. "
                            "This AI gateway piggbybacks Claude Code OAuth tokens "
                            "and has critical auth bypass and credential exposure issues."
                        ),
                        exploit_difficulty="Trivial",
                        remediation=f"npm uninstall {pkg_name}",
                        detection_method="dependency_scan",
                    ))

        return findings
