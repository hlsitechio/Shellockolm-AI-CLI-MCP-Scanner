#!/usr/bin/env python3
"""
Shellockolm MCP Auto-Configurator
Automatically sets up MCP server for installed AI tools
"""

import json
import os
import platform
import shutil
import sys
from pathlib import Path


class MCPConfigurator:
    """Auto-configure Shellockolm MCP for AI tools"""
    
    def __init__(self):
        self.shellockolm_root = Path(__file__).parent.parent.absolute()
        self.mcp_config = self.shellockolm_root / ".mcp-config.json"
        self.detected_tools = []
        
    def detect_ai_tools(self):
        """Detect installed AI tools that support MCP"""
        tools = []
        
        # Claude Desktop
        if platform.system() == "Windows":
            claude_config = Path(os.environ.get("APPDATA", "")) / "Claude" / "claude_desktop_config.json"
        elif platform.system() == "Darwin":  # macOS
            claude_config = Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        else:  # Linux
            claude_config = Path.home() / ".config" / "Claude" / "claude_desktop_config.json"
            
        if claude_config.exists() or self._check_command("claude"):
            tools.append(("Claude Desktop", claude_config))
        
        # GitHub Copilot CLI
        if self._check_command("gh"):
            tools.append(("GitHub Copilot CLI", None))
        
        # Cursor IDE
        if platform.system() == "Windows":
            cursor_config = Path(os.environ.get("APPDATA", "")) / "Cursor" / "User" / "settings.json"
        elif platform.system() == "Darwin":
            cursor_config = Path.home() / "Library" / "Application Support" / "Cursor" / "User" / "settings.json"
        else:
            cursor_config = Path.home() / ".config" / "Cursor" / "User" / "settings.json"
            
        if cursor_config.exists():
            tools.append(("Cursor IDE", cursor_config))
        
        # Continue.dev
        continue_config = Path.home() / ".continue" / "config.json"
        if continue_config.exists():
            tools.append(("Continue.dev", continue_config))
        
        self.detected_tools = tools
        return tools
    
    def _check_command(self, cmd):
        """Check if a command exists"""
        return shutil.which(cmd) is not None
    
    def configure_claude_desktop(self, config_path):
        """Configure Claude Desktop"""
        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Load existing config or create new
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}
            
            # Ensure mcpServers key exists
            if "mcpServers" not in config:
                config["mcpServers"] = {}
            
            # Add shellockolm server.
            # Use sys.executable (the interpreter currently running this
            # configurator) rather than a bare "python", which may resolve to a
            # Windows Store shim or a Python without the `mcp` package installed.
            config["mcpServers"]["shellockolm"] = {
                "command": sys.executable,
                "args": [str(self.shellockolm_root / "src" / "mcp_server.py")],
                "env": {
                    "PYTHONPATH": str(self.shellockolm_root / "src")
                }
            }
            
            # Write config
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            
            return True
        except Exception as e:
            print(f"❌ Error configuring Claude Desktop: {e}")
            return False
    
    def configure_copilot_cli(self):
        """Configure GitHub Copilot CLI"""
        try:
            import subprocess
            
            config_json = json.dumps({
                "command": sys.executable,
                "args": [str(self.shellockolm_root / "src" / "mcp_server.py")],
                "cwd": str(self.shellockolm_root),
                "env": {
                    "PYTHONPATH": str(self.shellockolm_root / "src")
                }
            })
            
            # Note: This is a placeholder - actual Copilot CLI MCP config method TBD
            print("ℹ️  GitHub Copilot CLI MCP configuration is manual")
            print("   Add to your Copilot settings:")
            print(f"   {config_json}")
            return True
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
    
    def configure_cursor(self, config_path):
        """Configure Cursor IDE"""
        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}
            
            if "mcpServers" not in config:
                config["mcpServers"] = []
            
            # Check if already configured
            if not any(s.get("name") == "shellockolm" for s in config["mcpServers"]):
                config["mcpServers"].append({
                    "name": "shellockolm",
                    "command": sys.executable,
                    "args": [str(self.shellockolm_root / "src" / "mcp_server.py")],
                    "cwd": str(self.shellockolm_root)
                })

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            return True
        except Exception as e:
            print(f"❌ Error configuring Cursor: {e}")
            return False
    
    def configure_continue(self, config_path):
        """Configure Continue.dev"""
        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}
            
            if "mcpServers" not in config:
                config["mcpServers"] = []
            
            if not any(s.get("name") == "shellockolm" for s in config["mcpServers"]):
                config["mcpServers"].append({
                    "name": "shellockolm",
                    "command": sys.executable,
                    "args": [str(self.shellockolm_root / "src" / "mcp_server.py")],
                    "cwd": str(self.shellockolm_root)
                })

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            return True
        except Exception as e:
            print(f"❌ Error configuring Continue.dev: {e}")
            return False
    
    def run_interactive(self):
        """Interactive configuration"""
        print("🤖 Shellockolm MCP Auto-Configurator")
        print("=" * 50)
        print()
        
        print("📡 Detecting installed AI tools...")
        tools = self.detect_ai_tools()
        
        if not tools:
            print("❌ No supported AI tools detected")
            print()
            print("Supported tools:")
            print("  - Claude Desktop")
            print("  - GitHub Copilot CLI")
            print("  - Cursor IDE")
            print("  - Continue.dev")
            print()
            print("See docs/MCP_SETUP.md for manual setup")
            return
        
        print(f"✅ Found {len(tools)} tool(s):")
        for i, (name, path) in enumerate(tools, 1):
            print(f"  {i}. {name}")
        print()
        
        print("Configure MCP for:")
        print("  [A] All detected tools")
        for i, (name, _) in enumerate(tools, 1):
            print(f"  [{i}] {name} only")
        print("  [N] None (exit)")
        print()
        
        choice = input("Your choice: ").strip().upper()
        
        if choice == "N":
            print("Cancelled")
            return
        
        if choice == "A":
            selected = tools
        elif choice.isdigit() and 1 <= int(choice) <= len(tools):
            selected = [tools[int(choice) - 1]]
        else:
            print("Invalid choice")
            return
        
        print()
        print("🔧 Configuring MCP...")
        
        for name, path in selected:
            print(f"\n→ {name}...")
            
            if name == "Claude Desktop":
                if self.configure_claude_desktop(path):
                    print(f"  ✅ Configured successfully")
                    print(f"  📍 Config: {path}")
                    print("  ⚠️  Restart Claude Desktop to apply changes")
                    
            elif name == "GitHub Copilot CLI":
                self.configure_copilot_cli()
                
            elif name == "Cursor IDE":
                if self.configure_cursor(path):
                    print(f"  ✅ Configured successfully")
                    print(f"  📍 Config: {path}")
                    print("  ⚠️  Restart Cursor to apply changes")
                    
            elif name == "Continue.dev":
                if self.configure_continue(path):
                    print(f"  ✅ Configured successfully")
                    print(f"  📍 Config: {path}")
                    print("  ⚠️  Restart your IDE to apply changes")
        
        print()
        print("✅ Configuration complete!")
        print()
        print("📚 Next steps:")
        print("  1. Restart your AI tool(s)")
        print("  2. Try: 'scan this project for vulnerabilities'")
        print("  3. See docs/MCP_SETUP.md for examples")
        print()
        print("🧪 Test MCP server:")
        print(f"  python {self.shellockolm_root / 'src' / 'mcp_server.py'}")


def main():
    """Main entry point"""
    configurator = MCPConfigurator()
    
    if len(sys.argv) > 1 and sys.argv[1] == "--auto":
        # Auto-configure all detected tools
        tools = configurator.detect_ai_tools()
        if tools:
            print(f"Auto-configuring {len(tools)} tool(s)...")
            for name, path in tools:
                if name == "Claude Desktop":
                    configurator.configure_claude_desktop(path)
                elif name == "Cursor IDE":
                    configurator.configure_cursor(path)
                elif name == "Continue.dev":
                    configurator.configure_continue(path)
            print("✅ Done")
        else:
            print("No tools detected")
    else:
        configurator.run_interactive()


if __name__ == "__main__":
    main()
