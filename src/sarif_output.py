#!/usr/bin/env python3
"""
Shellockolm SARIF Output Generator
Generates SARIF (Static Analysis Results Interchange Format) reports
for integration with GitHub Code Scanning, VS Code, and CI/CD pipelines

SARIF Spec: https://sarifweb.azurewebsites.net/
"""

import json
import os
import re
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

# SARIF version we generate
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


@dataclass
class SarifRule:
    """A SARIF rule (vulnerability definition)"""
    id: str
    name: str
    short_description: str
    full_description: str
    help_uri: str
    security_severity: str  # "critical", "high", "medium", "low", "note"
    tags: List[str] = field(default_factory=list)
    
    def to_sarif(self) -> Dict[str, Any]:
        """Convert to SARIF rule format"""
        # Map severity to SARIF level
        severity_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }
        level = severity_map.get(self.security_severity.lower(), "warning")
        
        # Security severity score (0-10)
        severity_scores = {
            "critical": "9.8",
            "high": "8.0",
            "medium": "5.0",
            "low": "2.0",
            "info": "0.0",
        }
        score = severity_scores.get(self.security_severity.lower(), "5.0")
        
        return {
            "id": self.id,
            "name": self.name,
            "shortDescription": {
                "text": self.short_description
            },
            "fullDescription": {
                "text": self.full_description
            },
            "helpUri": self.help_uri,
            "defaultConfiguration": {
                "level": level
            },
            "properties": {
                "security-severity": score,
                "tags": self.tags
            }
        }


@dataclass
class SarifResult:
    """A SARIF result (finding instance)"""
    rule_id: str
    message: str
    file_path: str
    start_line: int
    start_column: int = 1
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    level: str = "warning"  # "error", "warning", "note"
    fingerprint: Optional[str] = None
    # Optional SARIF result-level properties (e.g. detection confidence). Emitted
    # only when set, so existing results serialize byte-identically.
    properties: Optional[Dict[str, Any]] = None

    def to_sarif(self, base_path: str = "") -> Dict[str, Any]:
        """Convert to SARIF result format"""
        # Calculate fingerprint for deduplication
        if not self.fingerprint:
            fp_data = f"{self.rule_id}:{self.file_path}:{self.start_line}:{self.message}"
            self.fingerprint = hashlib.sha256(fp_data.encode()).hexdigest()[:16]
        
        # Build location
        physical_location = {
            "artifactLocation": {
                "uri": self.file_path,
                "uriBaseId": "%SRCROOT%"
            },
            "region": {
                "startLine": self.start_line,
                "startColumn": self.start_column,
            }
        }
        
        if self.end_line:
            physical_location["region"]["endLine"] = self.end_line
        if self.end_column:
            physical_location["region"]["endColumn"] = self.end_column
        
        result: Dict[str, Any] = {
            "ruleId": self.rule_id,
            "level": self.level,
            "message": {
                "text": self.message
            },
            "locations": [{
                "physicalLocation": physical_location
            }],
            "fingerprints": {
                "primary": self.fingerprint
            }
        }
        if self.properties:
            result["properties"] = self.properties
        return result


class SarifGenerator:
    """
    Generates SARIF reports from Shellockolm scan results
    """
    
    TOOL_NAME = "shellockolm"
    TOOL_VERSION = "2.0.0"
    TOOL_INFO_URI = "https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner"
    
    def __init__(self):
        self.rules: Dict[str, SarifRule] = {}
        self.results: List[SarifResult] = []
        self._init_builtin_rules()
    
    def _init_builtin_rules(self):
        """Initialize built-in security rules"""
        # CVE rules
        cve_rules = [
            SarifRule(
                id="CVE-2025-29927",
                name="Next.js Middleware Bypass",
                short_description="Next.js middleware authorization bypass",
                full_description="Critical authorization bypass in Next.js middleware via x-middleware-subrequest header",
                help_uri="https://nvd.nist.gov/vuln/detail/CVE-2025-29927",
                security_severity="critical",
                tags=["security", "vulnerability", "cve", "nextjs"]
            ),
            SarifRule(
                id="CVE-2025-55182",
                name="React Server RCE",
                short_description="React Server Components RCE via registerServerReference",
                full_description="Remote code execution in React Server Components through arbitrary function registration",
                help_uri="https://nvd.nist.gov/vuln/detail/CVE-2025-55182",
                security_severity="critical",
                tags=["security", "vulnerability", "cve", "react", "rce"]
            ),
            SarifRule(
                id="CVE-2026-21858",
                name="n8n Unauthenticated RCE",
                short_description="n8n Ni8mare unauthenticated RCE",
                full_description="Unauthenticated RCE in n8n workflow automation via Form Webhooks Content-Type confusion",
                help_uri="https://nvd.nist.gov/vuln/detail/CVE-2026-21858",
                security_severity="critical",
                tags=["security", "vulnerability", "cve", "n8n", "rce"]
            ),
        ]
        
        # Malware rules
        malware_rules = [
            SarifRule(
                id="MALWARE-RCE-001",
                name="Remote Code Execution Pattern",
                short_description="Code execution pattern detected",
                full_description="Detected code pattern that could lead to remote code execution (eval, exec, etc.)",
                help_uri="https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner#malware-patterns",
                security_severity="critical",
                tags=["security", "malware", "rce"]
            ),
            SarifRule(
                id="MALWARE-EXFIL-001",
                name="Data Exfiltration Pattern",
                short_description="Data exfiltration pattern detected",
                full_description="Detected code pattern that could exfiltrate sensitive data",
                help_uri="https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner#malware-patterns",
                security_severity="high",
                tags=["security", "malware", "exfiltration"]
            ),
            SarifRule(
                id="MALWARE-BACKDOOR-001",
                name="Backdoor Pattern",
                short_description="Backdoor pattern detected",
                full_description="Detected code pattern that could be a backdoor",
                help_uri="https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner#malware-patterns",
                security_severity="critical",
                tags=["security", "malware", "backdoor"]
            ),
        ]
        
        # Secret rules
        secret_rules = [
            SarifRule(
                id="SECRET-AWS-001",
                name="AWS Credentials Exposed",
                short_description="AWS credentials found in code",
                full_description="Hardcoded AWS access keys or secrets detected in source code",
                help_uri="https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html",
                security_severity="critical",
                tags=["security", "secrets", "aws", "credential"]
            ),
            SarifRule(
                id="SECRET-API-001",
                name="API Key Exposed",
                short_description="API key found in code",
                full_description="Hardcoded API key or token detected in source code",
                help_uri="https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                security_severity="high",
                tags=["security", "secrets", "api-key"]
            ),
            SarifRule(
                id="SECRET-GENERIC-001",
                name="Generic Secret Exposed",
                short_description="Potential secret found in code",
                full_description="High entropy string detected that may be a secret or credential",
                help_uri="https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner#secrets-scanner",
                security_severity="medium",
                tags=["security", "secrets"]
            ),
        ]
        
        # Dependency rules
        dependency_rules = [
            SarifRule(
                id="DEP-TYPOSQUAT-001",
                name="Typosquatting Package",
                short_description="Potential typosquatting package detected",
                full_description="Package name appears to be a typosquat of a legitimate package",
                help_uri="https://snyk.io/blog/typosquatting-attacks/",
                security_severity="critical",
                tags=["security", "supply-chain", "typosquatting"]
            ),
            SarifRule(
                id="DEP-VULN-001",
                name="Vulnerable Dependency",
                short_description="Vulnerable dependency version",
                full_description="Dependency has known security vulnerabilities",
                help_uri="https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner#vulnerability-scanner",
                security_severity="high",
                tags=["security", "dependency", "vulnerability"]
            ),
        ]
        
        # Add all rules
        for rule in cve_rules + malware_rules + secret_rules + dependency_rules:
            self.rules[rule.id] = rule
    
    def add_rule(self, rule: SarifRule):
        """Add a custom rule"""
        self.rules[rule.id] = rule
    
    def add_result(self, result: SarifResult):
        """Add a result (finding)"""
        self.results.append(result)

    # ─────────────────────────────────────────────────────────────────
    # Unified ScanFinding → SARIF (covers CVE, secret, malware AND the
    # AGENT-* agent-supply-chain rules). This is the path used by the
    # `scan --sarif` CLI flag so agent-scan findings are ingestible by
    # GitHub Code Scanning alongside dependency CVEs.
    # ─────────────────────────────────────────────────────────────────

    # severity → SARIF level
    _LEVEL_MAP = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
        "note": "note",
    }

    # AGENT-<FAMILY>-NNN → an extra descriptive SARIF tag for the attack class.
    _AGENT_SUBTAGS = {
        "PI": "prompt-injection",
        "PRO": "prompt-injection",
        "MCP": "mcp",
        "N8N": "n8n",
        "HOOK": "hooks",
        "SECRET": "secrets",
        "EXFIL": "exfiltration",
        "DESTRUCT": "destructive",
    }

    @staticmethod
    def _truncate(text: str, limit: int = 400) -> str:
        """Collapse whitespace and bound a description for SARIF message/help text."""
        collapsed = " ".join((text or "").split())
        if len(collapsed) <= limit:
            return collapsed
        return collapsed[: limit - 1] + "…"

    @staticmethod
    def _split_location(file_path: str, raw_data: Optional[Dict[str, Any]] = None):
        """Resolve a finding's ``file_path`` into a clean (path, line) pair.

        Agent findings label location as ``<path>:<line>`` for text rules or
        ``<path> » server:<name>`` / ``» node:<name>`` for structured rules. SARIF
        needs a bare artifact path plus a separate ``startLine``, so we strip the
        structured suffix, then take the line from ``raw_data['line']`` when present
        and otherwise from a trailing ``:<digits>``. A Windows drive colon
        (``G:\\…``) is preserved because the regex is anchored to end-of-string.
        """
        path = (file_path or "").split(" » ", 1)[0]
        line: Optional[int] = None
        if isinstance(raw_data, dict) and "line" in raw_data:
            try:
                line = int(raw_data["line"])
            except (TypeError, ValueError):
                line = None
        # Always strip a trailing ":<digits>" (the agent text-rule "<path>:<line>"
        # label) from the path so the SARIF artifact URI is a bare file path; use it
        # as the line when raw_data didn't already supply one.
        m = re.search(r":(\d+)$", path)
        if m:
            if line is None:
                line = int(m.group(1))
            path = path[: m.start()]
        return path, (line if line and line > 0 else 1)

    @staticmethod
    def _uri(path: str, base_path: str = "") -> str:
        """Best-effort relative, forward-slash URI for the SARIF artifact location.

        GitHub Code Scanning maps results to files by repo-relative path, so we
        relativize against ``base_path`` when the artifact lives under it (guarded:
        ``relpath`` raises across Windows drives) and normalize separators to ``/``.
        """
        p = path
        if base_path:
            try:
                rel = os.path.relpath(path, base_path)
                if not rel.startswith(".."):
                    p = rel
            except (ValueError, OSError):
                pass
        return p.replace("\\", "/")

    @classmethod
    def _agent_subtags(cls, rule_id: str) -> List[str]:
        parts = rule_id.split("-")
        if len(parts) >= 2:
            tag = cls._AGENT_SUBTAGS.get(parts[1].upper())
            if tag:
                return [tag]
        return []

    def _rule_for_finding(self, rule_id: str, finding: Any, severity: str) -> SarifRule:
        """Build the SARIF rule definition for a finding's rule id, choosing a
        correct helpUri + tags by id family (AGENT-* / CVE-* / other)."""
        title = (getattr(finding, "title", "") or rule_id).strip()
        description = self._truncate(getattr(finding, "description", "") or title)
        if rule_id.startswith("AGENT-"):
            help_uri = f"{self.TOOL_INFO_URI}#ai-agent-supply-chain-scanning"
            tags = ["security", "agent", "supply-chain"] + self._agent_subtags(rule_id)
        elif rule_id.startswith("CVE-"):
            help_uri = f"https://nvd.nist.gov/vuln/detail/{rule_id}"
            tags = ["security", "vulnerability", "cve"]
        else:
            help_uri = f"{self.TOOL_INFO_URI}#detections"
            tags = ["security"]
        return SarifRule(
            id=rule_id,
            name=title[:120] or rule_id,
            short_description=title[:200] or rule_id,
            full_description=description,
            help_uri=help_uri,
            security_severity=severity,
            tags=tags,
        )

    def add_scan_finding(self, finding: Any, base_path: str = ""):
        """Add a single ``ScanFinding`` (duck-typed) as a SARIF rule + result.

        Works uniformly for every scanner: dependency CVEs, secrets, malware, and
        the agent-supply-chain ``AGENT-*`` rules. Descriptions are already redacted
        by the agent scanner, so no live secret is re-emitted here.
        """
        rule_id = getattr(finding, "cve_id", None) or "UNKNOWN"
        raw_sev = getattr(finding, "severity", "medium")
        severity = (raw_sev.value if hasattr(raw_sev, "value") else str(raw_sev)).lower()
        path, line = self._split_location(
            getattr(finding, "file_path", "") or "",
            getattr(finding, "raw_data", None),
        )
        uri = self._uri(path, base_path)

        if rule_id not in self.rules:
            self.add_rule(self._rule_for_finding(rule_id, finding, severity))

        title = (getattr(finding, "title", "") or rule_id).strip()
        message = self._truncate(
            f"{title}: {getattr(finding, 'description', '') or ''}".rstrip(": ").strip()
        )
        confidence = getattr(finding, "confidence", None)
        self.add_result(SarifResult(
            rule_id=rule_id,
            message=message or title or rule_id,
            file_path=uri,
            start_line=line,
            level=self._LEVEL_MAP.get(severity, "warning"),
            properties={"confidence": confidence} if confidence else None,
        ))

    def from_scan_findings(self, findings: List[Any], base_path: str = ""):
        """Add a flat list of ``ScanFinding`` objects (the unified scan path)."""
        for finding in findings:
            self.add_scan_finding(finding, base_path=base_path)
    
    def add_cve_finding(self, cve_id: str, file_path: str, line_number: int,
                       message: str, severity: str = "high"):
        """Add a CVE finding"""
        # Ensure we have a rule for this CVE
        if cve_id not in self.rules:
            self.add_rule(SarifRule(
                id=cve_id,
                name=f"{cve_id} Vulnerability",
                short_description=message[:100],
                full_description=message,
                help_uri=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                security_severity=severity,
                tags=["security", "vulnerability", "cve"]
            ))
        
        level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
        level = level_map.get(severity.lower(), "warning")
        
        self.add_result(SarifResult(
            rule_id=cve_id,
            message=message,
            file_path=file_path,
            start_line=line_number,
            level=level
        ))
    
    def add_malware_finding(self, pattern_id: str, pattern_name: str, file_path: str,
                           line_number: int, message: str, severity: str = "high",
                           malware_type: Optional[str] = None):
        """Add a malware pattern finding

        ``malware_type`` is the analyzer's classification of the match (e.g.
        credential-stealer, backdoor). When supplied it becomes an extra rule
        tag, mirroring how ``add_secret_finding`` tags the secret type, so the
        family survives into SARIF instead of being dropped. Omitted by default
        so existing callers serialize byte-identically.
        """
        rule_id = f"MALWARE-{pattern_id}"

        if rule_id not in self.rules:
            tags = ["security", "malware"]
            if malware_type:
                tags.append(str(malware_type).lower())
            self.add_rule(SarifRule(
                id=rule_id,
                name=pattern_name,
                short_description=pattern_name,
                full_description=message,
                help_uri="https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner#malware-patterns",
                security_severity=severity,
                tags=tags
            ))
        
        level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
        level = level_map.get(severity.lower(), "warning")
        
        self.add_result(SarifResult(
            rule_id=rule_id,
            message=message,
            file_path=file_path,
            start_line=line_number,
            level=level
        ))
    
    def add_secret_finding(self, secret_type: str, file_path: str, line_number: int,
                          message: str, severity: str = "high"):
        """Add a secret finding"""
        rule_id = f"SECRET-{secret_type.upper()}"
        
        if rule_id not in self.rules:
            self.add_rule(SarifRule(
                id=rule_id,
                name=f"{secret_type} Exposed",
                short_description=f"Exposed {secret_type}",
                full_description=message,
                help_uri="https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner#secrets-scanner",
                security_severity=severity,
                tags=["security", "secrets", secret_type.lower()]
            ))
        
        level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
        level = level_map.get(severity.lower(), "warning")
        
        self.add_result(SarifResult(
            rule_id=rule_id,
            message=message,
            file_path=file_path,
            start_line=line_number,
            level=level
        ))
    
    def generate(self, output_path: Optional[str] = None) -> Dict[str, Any]:
        """Generate complete SARIF report"""
        # Build tool section
        tool = {
            "driver": {
                "name": self.TOOL_NAME,
                "version": self.TOOL_VERSION,
                "informationUri": self.TOOL_INFO_URI,
                "rules": [rule.to_sarif() for rule in self.rules.values()]
            }
        }
        
        # Build run section
        run = {
            "tool": tool,
            "results": [result.to_sarif() for result in self.results],
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.utcnow().isoformat() + "Z"
            }]
        }
        
        # Build complete SARIF document
        sarif = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [run]
        }
        
        # Write to file if path provided
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(sarif, f, indent=2)
        
        return sarif
    
    def from_scan_results(self, results: List[Any], base_path: str = ""):
        """Import results from Shellockolm scan"""
        for result in results:
            # Handle ScanFinding objects
            if hasattr(result, 'cve_id'):
                self.add_cve_finding(
                    cve_id=result.cve_id,
                    file_path=result.file_path,
                    line_number=getattr(result, 'line_number', 1),
                    message=f"{result.title}: {result.description[:200]}",
                    severity=result.severity.value if hasattr(result.severity, 'value') else str(result.severity)
                )
    
    def from_malware_report(self, report: Any):
        """Import results from MalwareAnalyzer report"""
        for match in report.matches:
            severity = match.threat_level.value if hasattr(match.threat_level, 'value') else str(match.threat_level)
            malware_type = match.malware_type.value if hasattr(match.malware_type, 'value') else str(match.malware_type)
            
            self.add_malware_finding(
                pattern_id=match.pattern_id,
                pattern_name=match.pattern_name,
                file_path=match.file_path,
                line_number=match.line_number,
                message=f"{match.pattern_name}: {match.explanation}",
                severity=severity,
                malware_type=malware_type,
            )
    
    def from_secrets_report(self, report: Any):
        """Import results from SecretsScanner report"""
        for match in report.matches:
            severity = match.pattern.severity.value if hasattr(match.pattern.severity, 'value') else str(match.pattern.severity)
            secret_type = match.pattern.secret_type.value if hasattr(match.pattern.secret_type, 'value') else str(match.pattern.secret_type)
            
            self.add_secret_finding(
                secret_type=secret_type,
                file_path=match.file_path,
                line_number=match.line_number,
                message=f"{match.pattern.name}: {match.pattern.description}",
                severity=severity
            )
    
    def from_lockfile_report(self, report: Any):
        """Import results from LockfileAnalyzer report"""
        for issue in report.issues:
            rule_id = f"DEP-{issue.issue_type.value.upper()}"
            severity = issue.severity.value if hasattr(issue.severity, 'value') else str(issue.severity)
            
            if rule_id not in self.rules:
                self.add_rule(SarifRule(
                    id=rule_id,
                    name=issue.title[:50],
                    short_description=issue.title,
                    full_description=issue.description,
                    help_uri="https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner#lockfile-analyzer",
                    security_severity=severity,
                    tags=["security", "dependency", issue.issue_type.value]
                ))
            
            level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
            level = level_map.get(severity.lower(), "warning")
            
            self.add_result(SarifResult(
                rule_id=rule_id,
                message=f"{issue.title}: {issue.description}",
                file_path=report.file_path,
                start_line=issue.line_number or 1,
                level=level
            ))


# ─────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────

def main():
    """CLI entry point for testing"""
    import sys
    
    generator = SarifGenerator()
    
    # Add some test findings
    generator.add_cve_finding(
        cve_id="CVE-2025-29927",
        file_path="middleware.ts",
        line_number=15,
        message="Next.js middleware bypass vulnerability detected",
        severity="critical"
    )
    
    generator.add_secret_finding(
        secret_type="AWS_KEY",
        file_path="config.js",
        line_number=42,
        message="AWS access key exposed in source code",
        severity="critical"
    )
    
    output = generator.generate("sarif-report.json")
    print(f"Generated SARIF report with {len(generator.results)} findings")
    print(f"Rules defined: {len(generator.rules)}")
    print(json.dumps(output, indent=2)[:500] + "...")


if __name__ == "__main__":
    main()
