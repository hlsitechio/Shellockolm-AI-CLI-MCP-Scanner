# React CVE Scanner MCP Server
## Python-based Model Context Protocol Server for CVE-2025-55182 Detection

---

## Overview

A Python-based MCP (Model Context Protocol) server designed to help developers scan their projects for the critical CVE-2025-55182 vulnerability affecting React Server Components. This tool enables AI assistants to automatically detect and help remediate this critical security flaw.

### Key Features

1. **Automated Vulnerability Scanning**
   - Recursively scan directories for package.json files
   - Detect vulnerable React versions (19.0.0, 19.1.0, 19.1.1, 19.2.0)
   - Identify react-server-dom packages
   - Check Next.js projects using React Server Components

2. **Intelligent Analysis**
   - Parse package.json and package-lock.json
   - Identify direct and transitive dependencies
   - Detect framework-specific vulnerabilities (Next.js, Remix, etc.)
   - Generate detailed vulnerability reports

3. **Remediation Assistance**
   - Suggest appropriate patched versions
   - Generate update commands
   - Optionally auto-patch package.json files
   - Verify fixes after application

4. **MCP Integration**
   - Seamless integration with AI assistants (Claude, etc.)
   - Real-time scanning capabilities
   - Interactive remediation workflows

---

## Architecture

### MCP Server Structure

```
react-cve-mcp/
├── server.py              # Main MCP server implementation
├── scanner.py             # Vulnerability scanning logic
├── analyzer.py            # Package analysis and version detection
├── remediation.py         # Patching and fix generation
├── utils.py               # Utility functions
├── requirements.txt       # Python dependencies
├── README.md              # Documentation
└── tests/                 # Test suite
    ├── test_scanner.py
    ├── test_analyzer.py
    └── test_remediation.py
```

### Core Components

#### 1. MCP Server (server.py)
- Implements MCP protocol
- Exposes tools/resources to AI assistants
- Handles client communication

#### 2. Scanner Module (scanner.py)
- Directory traversal
- package.json discovery
- Exclusion filters (node_modules, etc.)

#### 3. Analyzer Module (analyzer.py)
- JSON parsing
- Version comparison
- Dependency graph analysis
- CVE matching logic

#### 4. Remediation Module (remediation.py)
- Patch generation
- Version updates
- Fix verification
- Rollback capabilities

---

## MCP Tools & Resources

### Tools (Actions AI can invoke)

#### 1. `scan_directory`
Scan a directory for vulnerable React projects.

**Parameters:**
- `path` (string, required): Directory path to scan
- `recursive` (boolean, default: true): Recursively scan subdirectories
- `exclude_patterns` (array, optional): Patterns to exclude
- `check_lock_files` (boolean, default: true): Check package-lock.json

**Returns:**
```json
{
  "summary": {
    "total_projects": 15,
    "vulnerable_projects": 3,
    "safe_projects": 12
  },
  "vulnerable_projects": [
    {
      "path": "/path/to/project",
      "react_version": "19.0.0",
      "recommended_version": "19.0.1",
      "risk_level": "CRITICAL",
      "next_js_version": "15.0.3",
      "uses_server_components": true
    }
  ]
}
```

#### 2. `analyze_project`
Analyze a specific project for vulnerability details.

**Parameters:**
- `path` (string, required): Path to project directory
- `deep_analysis` (boolean, default: false): Check node_modules

**Returns:**
```json
{
  "vulnerable": true,
  "react_version": "19.1.0",
  "vulnerable_packages": [
    "react-server-dom-webpack@19.1.0"
  ],
  "framework": "Next.js 15.5.3",
  "server_components_enabled": true,
  "remediation": {
    "update_command": "npm install react@19.1.2 react-dom@19.1.2",
    "estimated_breaking_changes": false
  }
}
```

#### 3. `patch_project`
Apply security patches to a vulnerable project.

**Parameters:**
- `path` (string, required): Path to project
- `target_version` (string, optional): Specific version to update to
- `dry_run` (boolean, default: true): Preview changes without applying
- `backup` (boolean, default: true): Create backup before patching

**Returns:**
```json
{
  "success": true,
  "changes_made": [
    "Updated react from 19.0.0 to 19.0.1",
    "Updated react-dom from 19.0.0 to 19.0.1"
  ],
  "backup_location": "/path/to/backup/package.json.bak",
  "next_steps": [
    "Run: npm install",
    "Run: npm run build",
    "Test your application"
  ]
}
```

#### 4. `generate_report`
Generate a comprehensive vulnerability report.

**Parameters:**
- `scan_results` (object, required): Results from scan_directory
- `format` (string, default: "markdown"): Output format (markdown, json, html)
- `output_path` (string, optional): Save report to file

**Returns:**
```json
{
  "report": "# Vulnerability Report\n...",
  "file_path": "/path/to/report.md",
  "summary": {
    "critical_issues": 3,
    "warnings": 0,
    "safe_projects": 12
  }
}
```

#### 5. `verify_fix`
Verify that a patch was successfully applied.

**Parameters:**
- `path` (string, required): Path to patched project

**Returns:**
```json
{
  "verified": true,
  "react_version": "19.1.2",
  "still_vulnerable": false,
  "message": "Project successfully patched and verified"
}
```

### Resources (Data AI can read)

#### 1. `cve://2025-55182`
Get details about CVE-2025-55182.

**Returns:**
- CVE description
- Affected versions
- Patched versions
- References
- CVSS score

---

## Technology Stack

### Core Dependencies

```python
# requirements.txt
mcp>=1.0.0                 # Model Context Protocol SDK
packaging>=21.0            # Version comparison
semver>=3.0.0              # Semantic versioning
jsonschema>=4.0.0          # JSON validation
pydantic>=2.0.0            # Data validation
aiofiles>=23.0.0           # Async file operations
rich>=13.0.0               # Beautiful CLI output
typer>=0.9.0               # CLI interface (optional)
pytest>=7.0.0              # Testing framework
```

### Python Version
- Python 3.10 or higher (for modern async/await support)

---

## Implementation Phases

### Phase 1: Core Scanner (MVP)
- [x] Basic directory scanning
- [x] package.json parsing
- [x] React version detection
- [x] Simple vulnerability matching

### Phase 2: MCP Integration
- [ ] MCP server setup
- [ ] Tool registration
- [ ] Resource provisioning
- [ ] Error handling

### Phase 3: Advanced Features
- [ ] package-lock.json analysis
- [ ] Transitive dependency checking
- [ ] Framework detection (Next.js, Remix, etc.)
- [ ] Auto-patching capabilities

### Phase 4: Remediation
- [ ] Safe patching logic
- [ ] Backup and rollback
- [ ] Fix verification
- [ ] Post-patch testing suggestions

### Phase 5: Reporting
- [ ] Markdown reports
- [ ] JSON output
- [ ] HTML dashboards
- [ ] CI/CD integration

---

## Security Considerations

1. **File System Access**
   - Read-only by default
   - Write operations require explicit confirmation
   - Sandboxed execution environment

2. **Backup Strategy**
   - Always create backups before modifications
   - Timestamped backup files
   - Easy rollback mechanism

3. **Validation**
   - Validate all file paths
   - Sanitize user inputs
   - Verify package.json integrity

4. **Permissions**
   - Respect file system permissions
   - No elevation of privileges
   - User confirmation for sensitive operations

---

## Usage Examples

### Example 1: Scan a directory

```python
# AI invokes scan_directory tool
result = await scan_directory(
    path="/path/to/projects",
    recursive=True,
    exclude_patterns=["node_modules", ".git", "dist"]
)

# Result shows 3 vulnerable projects
print(f"Found {result['summary']['vulnerable_projects']} vulnerable projects")
```

### Example 2: Patch a project

```python
# First, do a dry run
patch_result = await patch_project(
    path="/path/to/vulnerable-project",
    dry_run=True
)

# Review changes, then apply
if user_confirms():
    patch_result = await patch_project(
        path="/path/to/vulnerable-project",
        dry_run=False,
        backup=True
    )
```

### Example 3: Generate report

```python
# Scan and generate report
scan_results = await scan_directory(path="/projects")
report = await generate_report(
    scan_results=scan_results,
    format="markdown",
    output_path="/reports/cve-2025-55182.md"
)
```

---

## Extension Opportunities

1. **Multi-CVE Support**
   - Extend to detect other CVEs
   - Configurable CVE database
   - Auto-update CVE definitions

2. **CI/CD Integration**
   - GitHub Actions workflow
   - GitLab CI pipeline
   - Jenkins plugin

3. **Web Dashboard**
   - Real-time scanning
   - Project health monitoring
   - Team collaboration features

4. **IDE Plugins**
   - VS Code extension
   - JetBrains plugin
   - Neovim integration

---

## Contributing

This MCP server is designed to help the community stay safe from critical vulnerabilities. Contributions welcome!

### Priority Areas
1. Additional CVE detection
2. Framework-specific scanners
3. Improved patching logic
4. Test coverage

---

## License

MIT License - Use freely to protect your projects and help others!

---

**Created**: 2025-12-06
**Last Updated**: 2025-12-06
**Version**: 1.0.0-design
