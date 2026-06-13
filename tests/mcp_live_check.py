"""Live end-to-end MCP check: launch the server over stdio like an AI client would,
initialize, list tools, and call two of them. Not part of the pytest suite (it spawns
a subprocess); run manually:  python tests/mcp_live_check.py
"""
import asyncio
import os
import sys
import tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "src")


async def main() -> int:
    # A throwaway vulnerable fixture for the scan tool.
    fixture = os.path.join(tempfile.gettempdir(), "shellockolm_mcp_fixture")
    os.makedirs(fixture, exist_ok=True)
    with open(os.path.join(fixture, "package.json"), "w", encoding="utf-8") as f:
        f.write('{"name":"t","dependencies":{"next":"14.1.5"}}')

    env = dict(os.environ, PYTHONPATH=SRC, PYTHONIOENCODING="utf-8")
    params = StdioServerParameters(
        command=sys.executable,
        args=[os.path.join(SRC, "mcp_server.py")],
        env=env,
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            print(f"[+] initialized: {init.serverInfo.name} v{init.serverInfo.version}")

            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            print(f"[+] {len(names)} tools exposed: {', '.join(names)}")

            # 1) a pure-data tool
            cves = await session.call_tool("list_cves", {})
            head = cves.content[0].text.splitlines()[0] if cves.content else ""
            print(f"[+] list_cves OK -> {head[:70]}")

            # 2) a real scan of the vulnerable fixture
            scan = await session.call_tool("scan_directory", {"path": fixture})
            text = scan.content[0].text if scan.content else ""
            hit = "CVE-2025-29927" in text
            print(f"[+] scan_directory OK; detected CVE-2025-29927: {hit}")

            # 3) SSRF guard should refuse a loopback URL
            ssrf = await session.call_tool("scan_live", {"url": "http://127.0.0.1:8080"})
            blocked = "block" in (ssrf.content[0].text.lower() if ssrf.content else "")
            print(f"[+] scan_live SSRF guard blocks loopback: {blocked}")

            ok = bool(names) and hit and blocked
            print("\nRESULT:", "PASS" if ok else "FAIL")
            return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
