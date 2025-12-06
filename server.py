"""
CVE-2025-55182 MCP Server
Model Context Protocol server for detecting and patching CVE-2025-55182
"""

import asyncio
from pathlib import Path
from typing import Any
from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from mcp.server.stdio import stdio_server
import mcp.types as types

from scanner import CVEScanner
from remediation import Remediator


# Create MCP server instance
server = Server("react-cve-scanner")

# Initialize scanner and remediator
scanner = CVEScanner()
remediator = Remediator()


@server.list_resources()
async def handle_list_resources() -> list[types.Resource]:
    """List available resources"""
    return [
        types.Resource(
            uri="cve://2025-55182",
            name="CVE-2025-55182 Details",
            description="Information about the React Server Components RCE vulnerability",
            mimeType="text/plain"
        )
    ]


@server.read_resource()
async def handle_read_resource(uri: str) -> str:
    """Read a resource"""
    if uri == "cve://2025-55182":
        return """CVE-2025-55182: React Server Components Remote Code Execution

**CVSS Score**: 10.0 (CRITICAL)
**Type**: Unauthenticated Remote Code Execution (RCE)

**Description**:
An unauthenticated attacker can craft malicious HTTP requests to Server Function
endpoints that, when deserialized by React, achieve remote code execution on the server.

**Affected Packages**:
- react-server-dom-webpack: 19.0.0, 19.1.0, 19.1.1, 19.2.0
- react-server-dom-parcel: 19.0.0, 19.1.0, 19.1.1, 19.2.0
- react-server-dom-turbopack: 19.0.0, 19.1.0, 19.1.1, 19.2.0

**Patched Versions**:
- 19.0.1 (for 19.0.x series)
- 19.1.2 (for 19.1.x series)
- 19.2.1 (for 19.2.x series)

**Root Cause**:
The vulnerable code unsafely deserializes payloads from HTTP requests to
Server Function endpoints.

**Affected Frameworks**:
Next.js, React Router, Waku, Parcel, Vite RSC plugin, Redwood SDK

**References**:
- https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components
- https://www.cve.org/CVERecord?id=CVE-2025-55182
- https://github.com/facebook/react/pull/35277

**Discovered By**: Lachlan Davidson (November 29, 2025)
**Public Disclosure**: December 3, 2025
"""
    raise ValueError(f"Unknown resource: {uri}")


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available tools"""
    return [
        types.Tool(
            name="scan_directory",
            description="Scan a directory for vulnerable React projects affected by CVE-2025-55182",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory path to scan"
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Recursively scan subdirectories",
                        "default": True
                    }
                },
                "required": ["path"]
            }
        ),
        types.Tool(
            name="analyze_project",
            description="Analyze a specific project for CVE-2025-55182 vulnerability details",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to project directory or package.json"
                    }
                },
                "required": ["path"]
            }
        ),
        types.Tool(
            name="patch_project",
            description="Apply security patches to a vulnerable project",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to project directory or package.json"
                    },
                    "target_version": {
                        "type": "string",
                        "description": "Target React version to update to (optional, auto-detected if not provided)"
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "Preview changes without applying",
                        "default": True
                    },
                    "backup": {
                        "type": "boolean",
                        "description": "Create backup before patching",
                        "default": True
                    }
                },
                "required": ["path"]
            }
        ),
        types.Tool(
            name="verify_fix",
            description="Verify that a patch was successfully applied",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to project directory or package.json"
                    }
                },
                "required": ["path"]
            }
        ),
        types.Tool(
            name="generate_report",
            description="Generate a comprehensive vulnerability report",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_path": {
                        "type": "string",
                        "description": "Directory path that was scanned"
                    },
                    "output_path": {
                        "type": "string",
                        "description": "Path to save the report (optional)"
                    }
                },
                "required": ["scan_path"]
            }
        )
    ]


@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Handle tool execution"""

    if name == "scan_directory":
        path = arguments.get("path")
        recursive = arguments.get("recursive", True)

        results = scanner.scan_directory(path, recursive)

        # Format results as readable text
        output = f"""# Scan Results for {path}

## Summary
- Total projects scanned: {results['summary']['total_projects']}
- Vulnerable projects: {results['summary']['vulnerable_projects']}
- Safe projects: {results['summary']['safe_projects']}

"""
        if results['vulnerable_projects']:
            output += "## Vulnerable Projects (CRITICAL - Immediate Action Required)\n\n"
            for vp in results['vulnerable_projects']:
                output += f"### {vp['path']}\n"
                output += f"- **Current React Version**: {vp['react_version']}\n"
                output += f"- **Recommended Version**: {vp['recommended_version']}\n"
                output += f"- **Risk Level**: {vp['risk_level']}\n"
                if vp['next_js_version']:
                    output += f"- **Next.js Version**: {vp['next_js_version']}\n"
                if vp['vulnerable_packages']:
                    output += f"- **Vulnerable Packages**: {', '.join(vp['vulnerable_packages'])}\n"
                output += f"\n**Fix Command**: `npm install react@{vp['recommended_version']} react-dom@{vp['recommended_version']}`\n\n"

        return [types.TextContent(type="text", text=output)]

    elif name == "analyze_project":
        path = Path(arguments.get("path"))
        if path.is_dir():
            path = path / "package.json"

        result = scanner.analyze_project(path)

        if not result:
            output = f"✅ Project at {path.parent} is NOT vulnerable to CVE-2025-55182"
        else:
            output = f"""🚨 CRITICAL VULNERABILITY DETECTED

**Project**: {result.path}
**React Version**: {result.react_version}
**Recommended Version**: {result.recommended_version}
**Risk Level**: {result.risk_level}
**Next.js Version**: {result.next_js_version or 'N/A'}
**Uses Server Components**: {result.uses_server_components}

**Vulnerable Packages**:
{chr(10).join(f'  - {pkg}' for pkg in result.vulnerable_packages) if result.vulnerable_packages else '  None'}

**Remediation**:
```bash
cd {result.path}
npm install react@{result.recommended_version} react-dom@{result.recommended_version}
npm run build
# Test thoroughly before deploying
```
"""
        return [types.TextContent(type="text", text=output)]

    elif name == "patch_project":
        path = Path(arguments.get("path"))
        if path.is_dir():
            path = path / "package.json"

        # Analyze first to get recommended version
        project = scanner.analyze_project(path)
        if not project:
            return [types.TextContent(
                type="text",
                text=f"Project at {path.parent} is not vulnerable to CVE-2025-55182. No patching needed."
            )]

        target_version = arguments.get("target_version", project.recommended_version)
        dry_run = arguments.get("dry_run", True)
        backup = arguments.get("backup", True)

        result = remediator.patch_package_json(
            path, target_version, dry_run, backup
        )

        output = "# Patch Results\n\n"
        if result["success"]:
            output += "✅ " + ("Dry run completed successfully" if dry_run else "Patch applied successfully") + "\n\n"
            output += "## Changes Made:\n"
            for change in result["changes_made"]:
                output += f"- {change}\n"
            output += "\n"
            if result["backup_location"]:
                output += f"**Backup created**: {result['backup_location']}\n\n"
            output += "## Next Steps:\n"
            for step in result["next_steps"]:
                output += f"- {step}\n"
        else:
            output += "❌ Patch failed\n\n"
            output += "## Errors:\n"
            for error in result["errors"]:
                output += f"- {error}\n"

        return [types.TextContent(type="text", text=output)]

    elif name == "verify_fix":
        path = Path(arguments.get("path"))
        if path.is_dir():
            path = path / "package.json"

        result = remediator.verify_fix(path, "19.1.2")

        if result["verified"]:
            output = f"""✅ Verification Successful

**React Version**: {result['react_version']}
**React DOM Version**: {result['react_dom_version']}
**Still Vulnerable**: {result['still_vulnerable']}

{result['message']}
"""
        else:
            output = f"""❌ Verification Failed

**React Version**: {result['react_version'] or 'Unknown'}
**Still Vulnerable**: {result['still_vulnerable']}

{result['message']}
"""
        return [types.TextContent(type="text", text=output)]

    elif name == "generate_report":
        scan_path = arguments.get("scan_path")
        output_path = arguments.get("output_path")

        results = scanner.scan_directory(scan_path, recursive=True)

        report = f"""# CVE-2025-55182 Vulnerability Report

**Scan Date**: {asyncio.get_event_loop().time()}
**Scanned Path**: {scan_path}

## Executive Summary

- **Total Projects**: {results['summary']['total_projects']}
- **Vulnerable Projects**: {results['summary']['vulnerable_projects']}
- **Safe Projects**: {results['summary']['safe_projects']}

## Critical Findings

"""
        for vp in results['vulnerable_projects']:
            report += f"""### {vp['path']}

- **Current React**: {vp['react_version']}
- **Required Update**: {vp['recommended_version']}
- **Risk Level**: {vp['risk_level']}
- **Next.js**: {vp['next_js_version'] or 'N/A'}

**Fix**:
```bash
cd {vp['path']}
npm install react@{vp['recommended_version']} react-dom@{vp['recommended_version']}
```

---

"""
        if output_path:
            Path(output_path).write_text(report)
            return [types.TextContent(
                type="text",
                text=f"Report generated and saved to: {output_path}\n\n{report}"
            )]

        return [types.TextContent(type="text", text=report)]

    raise ValueError(f"Unknown tool: {name}")


async def main():
    """Main entry point for the MCP server"""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="react-cve-scanner",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
