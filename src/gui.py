#!/usr/bin/env python3
"""
Shellockolm GUI - Tkinter Dark Theme
Your Security Detective with a graphical interface

🔍 Elementary security for complex codebases
"""

import sys
import tkinter as tk

import compat  # noqa: F401 — Windows UTF-8 fix
from tkinter import ttk, filedialog, scrolledtext
from pathlib import Path
import json
import time
from threading import Thread
from scanner import CVEScanner
from malware_scanner import MalwareScanner
from vulnerability_database import VulnerabilityDatabase


class OutputRedirector(io.StringIO):
    """Redirect stdout/stderr to GUI tabs in real-time"""
    def __init__(self, gui, tab_name):
        super().__init__()
        self.gui = gui
        self.tab_name = tab_name

    def write(self, text):
        if text and text.strip():
            self.gui.root.after(0, self.gui.append_to_tab, self.tab_name, text, "info")

    def flush(self):
        pass


# 🎨 DARK THEME COLORS
class Colors:
    """Dark theme color palette for Shellockolm"""
    BG_DARK = "#1e1e1e"           # Main background
    BG_PANEL = "#252526"          # Panel background
    BG_INPUT = "#3c3c3c"          # Input fields
    BG_BUTTON = "#0e639c"         # Buttons
    BG_BUTTON_HOVER = "#1177bb"   # Button hover

    FG_PRIMARY = "#d4d4d4"        # Primary text
    FG_SECONDARY = "#808080"      # Secondary text

    DETECTIVE = "#ffd700"         # Bright yellow (Sherlock theme)
    SUCCESS = "#4ec9b0"           # Bright green
    DANGER = "#f48771"            # Bright red
    WARNING = "#dcdcaa"           # Bright yellow
    INFO = "#4fc1ff"              # Bright cyan
    HIGHLIGHT = "#c586c0"         # Bright magenta
    PATH = "#569cd6"              # Bright blue

    BORDER = "#3c3c3c"            # Border color


class ShellockolmGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 Shellockolm - Security Detective")
        self.root.geometry("1200x800")
        self.root.configure(bg=Colors.BG_DARK)

        # Scanner instances
        self.cve_scanner = CVEScanner()
        self.malware_scanner = MalwareScanner()
        self.vuln_db = VulnerabilityDatabase()
        self.scanning = False

        # Scan options
        self.scan_cve = tk.BooleanVar(value=True)
        self.scan_malware = tk.BooleanVar(value=True)
        self.scan_recursive = tk.BooleanVar(value=True)
        self.max_depth = tk.IntVar(value=5)  # Default depth limit for speed

        # Progress tracking
        self.start_time = None
        self.timer_id = None
        self.projects_scanned = 0
        self.current_file = ""

        # Configure styles
        self.setup_styles()

        # Create GUI elements
        self.create_header()
        self.create_scan_options()
        self.create_tabbed_results()
        self.create_status_bar()

    def setup_styles(self):
        """Configure ttk styles for dark theme"""
        style = ttk.Style()
        style.theme_use('clam')

        # Configure button style
        style.configure("Detective.TButton",
                       background=Colors.BG_BUTTON,
                       foreground=Colors.FG_PRIMARY,
                       borderwidth=0,
                       focuscolor='none',
                       font=('Segoe UI', 10, 'bold'),
                       padding=10)
        style.map("Detective.TButton",
                 background=[('active', Colors.BG_BUTTON_HOVER)])

        # Configure label style
        style.configure("Header.TLabel",
                       background=Colors.BG_DARK,
                       foreground=Colors.DETECTIVE,
                       font=('Segoe UI', 20, 'bold'))

        style.configure("Subtitle.TLabel",
                       background=Colors.BG_DARK,
                       foreground=Colors.INFO,
                       font=('Segoe UI', 10, 'italic'))

        style.configure("Normal.TLabel",
                       background=Colors.BG_PANEL,
                       foreground=Colors.FG_PRIMARY,
                       font=('Segoe UI', 10))

    def create_header(self):
        """Create the header with Shellockolm branding"""
        header_frame = tk.Frame(self.root, bg=Colors.BG_DARK, pady=20)
        header_frame.pack(fill=tk.X)

        # Title
        title = ttk.Label(header_frame,
                         text="🔍 SHELLOCKOLM - SECURITY DETECTIVE",
                         style="Header.TLabel")
        title.pack()

        # Subtitle
        subtitle = ttk.Label(header_frame,
                            text="CVE-2025-55182 & CVE-2025-66478 Scanner • CVSS 10.0 CRITICAL",
                            style="Subtitle.TLabel")
        subtitle.pack()

        # Tagline
        tagline = tk.Label(header_frame,
                          text="Elementary security for complex codebases",
                          bg=Colors.BG_DARK,
                          fg=Colors.FG_SECONDARY,
                          font=('Segoe UI', 9, 'italic'))
        tagline.pack(pady=(5, 0))

    def create_scan_options(self):
        """Create the scan options and control panel"""
        main_frame = tk.Frame(self.root, bg=Colors.BG_PANEL, pady=20, padx=20)
        main_frame.pack(fill=tk.X, padx=20, pady=(0, 10))

        # Directory selection
        dir_frame = tk.Frame(main_frame, bg=Colors.BG_PANEL)
        dir_frame.pack(fill=tk.X, pady=(0, 15))

        dir_label = ttk.Label(dir_frame, text="Scan Directory:", style="Normal.TLabel")
        dir_label.pack(side=tk.LEFT, padx=(0, 10))

        self.dir_entry = tk.Entry(dir_frame,
                                  bg=Colors.BG_INPUT,
                                  fg=Colors.FG_PRIMARY,
                                  font=('Segoe UI', 10),
                                  insertbackground=Colors.FG_PRIMARY,
                                  relief=tk.FLAT,
                                  borderwidth=2)
        self.dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.dir_entry.insert(0, str(Path.home()))

        browse_btn = ttk.Button(dir_frame,
                               text="Browse...",
                               style="Detective.TButton",
                               command=self.browse_directory)
        browse_btn.pack(side=tk.LEFT)

        # Scan type options
        options_frame = tk.Frame(main_frame, bg=Colors.BG_PANEL)
        options_frame.pack(fill=tk.X, pady=(0, 15))

        scan_types_label = tk.Label(options_frame,
                                    text="Scan Types:",
                                    bg=Colors.BG_PANEL,
                                    fg=Colors.FG_PRIMARY,
                                    font=('Segoe UI', 10, 'bold'))
        scan_types_label.pack(side=tk.LEFT, padx=(0, 15))

        cve_check = tk.Checkbutton(options_frame,
                                   text="🔍 CVE Scanner (React/Next.js)",
                                   variable=self.scan_cve,
                                   bg=Colors.BG_PANEL,
                                   fg=Colors.FG_PRIMARY,
                                   selectcolor=Colors.BG_INPUT,
                                   activebackground=Colors.BG_PANEL,
                                   activeforeground=Colors.FG_PRIMARY,
                                   font=('Segoe UI', 9))
        cve_check.pack(side=tk.LEFT, padx=(0, 15))

        malware_check = tk.Checkbutton(options_frame,
                                       text="☠️ Malware Scanner (NPM)",
                                       variable=self.scan_malware,
                                       bg=Colors.BG_PANEL,
                                       fg=Colors.FG_PRIMARY,
                                       selectcolor=Colors.BG_INPUT,
                                       activebackground=Colors.BG_PANEL,
                                       activeforeground=Colors.FG_PRIMARY,
                                       font=('Segoe UI', 9))
        malware_check.pack(side=tk.LEFT, padx=(0, 15))

        recursive_check = tk.Checkbutton(options_frame,
                                        text="🔁 Recursive",
                                        variable=self.scan_recursive,
                                        bg=Colors.BG_PANEL,
                                        fg=Colors.FG_PRIMARY,
                                        selectcolor=Colors.BG_INPUT,
                                        activebackground=Colors.BG_PANEL,
                                        activeforeground=Colors.FG_PRIMARY,
                                        font=('Segoe UI', 9))
        recursive_check.pack(side=tk.LEFT, padx=(0, 15))

        # Depth limit
        depth_label = tk.Label(options_frame,
                              text="⚡ Max Depth:",
                              bg=Colors.BG_PANEL,
                              fg=Colors.FG_PRIMARY,
                              font=('Segoe UI', 9))
        depth_label.pack(side=tk.LEFT, padx=(0, 5))

        depth_spinbox = tk.Spinbox(options_frame,
                                   from_=1,
                                   to=20,
                                   textvariable=self.max_depth,
                                   width=5,
                                   bg=Colors.BG_INPUT,
                                   fg=Colors.FG_PRIMARY,
                                   font=('Segoe UI', 9),
                                   relief=tk.FLAT,
                                   buttonbackground=Colors.BG_BUTTON)
        depth_spinbox.pack(side=tk.LEFT)

        # Action buttons
        btn_frame = tk.Frame(main_frame, bg=Colors.BG_PANEL)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        self.scan_btn = ttk.Button(btn_frame,
                                   text="🔍 Start Complete Investigation",
                                   style="Detective.TButton",
                                   command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 10))

        clear_btn = ttk.Button(btn_frame,
                              text="Clear Results",
                              style="Detective.TButton",
                              command=self.clear_results)
        clear_btn.pack(side=tk.LEFT)

    def create_tabbed_results(self):
        """Create tabbed results panel for different scan types"""
        results_frame = tk.Frame(self.root, bg=Colors.BG_PANEL, padx=20, pady=15)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 10))

        # Create notebook (tabbed interface)
        style = ttk.Style()
        style.configure("Dark.TNotebook",
                       background=Colors.BG_PANEL,
                       borderwidth=0)
        style.configure("Dark.TNotebook.Tab",
                       background=Colors.BG_INPUT,
                       foreground=Colors.FG_PRIMARY,
                       padding=[20, 10])
        style.map("Dark.TNotebook.Tab",
                 background=[("selected", Colors.BG_BUTTON)],
                 foreground=[("selected", Colors.FG_PRIMARY)])

        self.notebook = ttk.Notebook(results_frame, style="Dark.TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab 1: Summary
        self.summary_tab = self.create_text_tab("📊 Summary")
        self.notebook.add(self.summary_tab, text="📊 Summary")

        # Tab 2: CVE Results
        self.cve_tab = self.create_text_tab("🔍 CVE Scanner")
        self.notebook.add(self.cve_tab, text="🔍 CVE Scanner")

        # Tab 3: Malware Results
        self.malware_tab = self.create_text_tab("☠️ Malware Scanner")
        self.notebook.add(self.malware_tab, text="☠️ Malware Scanner")

        # Tab 4: Full Report
        self.report_tab = self.create_text_tab("📋 Full Report")
        self.notebook.add(self.report_tab, text="📋 Full Report")

    def create_text_tab(self, tab_name):
        """Create a text widget for a tab"""
        tab_frame = tk.Frame(self.notebook, bg=Colors.BG_PANEL)

        text_widget = scrolledtext.ScrolledText(tab_frame,
                                                bg=Colors.BG_INPUT,
                                                fg=Colors.FG_PRIMARY,
                                                font=('Consolas', 10),
                                                insertbackground=Colors.FG_PRIMARY,
                                                relief=tk.FLAT,
                                                borderwidth=2,
                                                wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Configure text tags for colors
        text_widget.tag_config("detective", foreground=Colors.DETECTIVE, font=('Consolas', 10, 'bold'))
        text_widget.tag_config("success", foreground=Colors.SUCCESS)
        text_widget.tag_config("danger", foreground=Colors.DANGER, font=('Consolas', 10, 'bold'))
        text_widget.tag_config("warning", foreground=Colors.WARNING)
        text_widget.tag_config("info", foreground=Colors.INFO)
        text_widget.tag_config("path", foreground=Colors.PATH)
        text_widget.tag_config("highlight", foreground=Colors.HIGHLIGHT)

        # Store reference to text widget
        setattr(self, f"{tab_name.lower().replace(' ', '_').replace('📊', 'summary').replace('🔍', 'cve').replace('☠️', 'malware').replace('📋', 'report')}_text", text_widget)

        return tab_frame

    def create_status_bar(self):
        """Create the status bar at the bottom"""
        status_frame = tk.Frame(self.root, bg=Colors.BG_PANEL, pady=10, padx=20)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        # Left side: Status text
        self.status_label = tk.Label(status_frame,
                                     text="Ready to investigate",
                                     bg=Colors.BG_PANEL,
                                     fg=Colors.FG_SECONDARY,
                                     font=('Segoe UI', 9),
                                     anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Right side: Timer and progress
        right_frame = tk.Frame(status_frame, bg=Colors.BG_PANEL)
        right_frame.pack(side=tk.RIGHT)

        self.timer_label = tk.Label(right_frame,
                                    text="⏱️ 00:00",
                                    bg=Colors.BG_PANEL,
                                    fg=Colors.INFO,
                                    font=('Segoe UI', 9, 'bold'))
        self.timer_label.pack(side=tk.LEFT, padx=(0, 10))

        # Progress indicator
        self.progress = ttk.Progressbar(right_frame,
                                       mode='indeterminate',
                                       length=150)
        # Don't pack it yet - only show during scan

    def browse_directory(self):
        """Open directory browser dialog"""
        directory = filedialog.askdirectory(initialdir=self.dir_entry.get(),
                                           title="Select directory to scan")
        if directory:
            self.dir_entry.delete(0, tk.END)
            self.dir_entry.insert(0, directory)

    def start_scan(self):
        """Start the vulnerability scan in a separate thread"""
        if self.scanning:
            return

        scan_path = self.dir_entry.get()
        if not Path(scan_path).exists():
            self.append_to_tab('summary', "❌ Error: Directory does not exist\n", "danger")
            return

        self.scanning = True
        self.scan_btn.configure(state='disabled')
        self.clear_results()

        # Reset tracking
        self.projects_scanned = 0
        self.current_file = ""
        self.start_time = time.time()

        # Show progress
        self.progress.pack(side=tk.LEFT)
        self.progress.start(10)
        self.status_label.configure(text=f"🔎 Investigating {scan_path}...")

        # Start timer
        self.update_timer()

        # Start scan in background thread
        scan_thread = Thread(target=self.run_scan, args=(scan_path,))
        scan_thread.daemon = True
        scan_thread.start()

    def update_timer(self):
        """Update the elapsed time display"""
        if self.scanning and self.start_time:
            elapsed = int(time.time() - self.start_time)
            minutes = elapsed // 60
            seconds = elapsed % 60
            self.timer_label.configure(text=f"⏱️ {minutes:02d}:{seconds:02d}")
            self.timer_id = self.root.after(1000, self.update_timer)

    def update_progress(self, message):
        """Update progress status"""
        self.root.after(0, self.status_label.configure, {'text': message})

    def run_scan(self, scan_path):
        """Execute the scan (runs in background thread)"""
        try:
            results = {}
            recursive = self.scan_recursive.get()

            # Show what we're scanning
            scan_types = []
            if self.scan_cve.get():
                scan_types.append("CVE")
            if self.scan_malware.get():
                scan_types.append("Malware")

            if not scan_types:
                error_msg = "⚠️ No scan types selected! Please enable at least one scanner.\n"
                self.root.after(0, self.append_to_tab, 'summary', error_msg, "warning")
                self.root.after(0, self.scan_complete)
                return

            scan_types_str = " + ".join(scan_types)
            self.root.after(0, self.status_label.configure, {'text': f'🔍 Starting {scan_types_str} scan...'})

            # Run CVE scan if enabled
            if self.scan_cve.get():
                try:
                    self.update_progress('🔍 Finding package.json files...')
                    self.root.after(0, self.append_to_tab, 'cve_scanner', "🔍 Initializing CVE scanner...\n", "detective")
                    self.root.after(0, self.append_to_tab, 'cve_scanner', "=" * 70 + "\n", "detective")

                    # Find package.json files first to show count
                    max_depth_val = self.max_depth.get()
                    self.root.after(0, self.append_to_tab, 'cve_scanner', f"⚡ Search depth limit: {max_depth_val} levels\n", "warning")

                    package_files = self.cve_scanner.find_package_json_files(scan_path, recursive=recursive, max_depth=max_depth_val)

                    self.update_progress(f'🔍 Found {len(package_files)} projects to scan...')
                    self.root.after(0, self.append_to_tab, 'cve_scanner', f"📂 Found {len(package_files)} projects in {len(package_files)} locations\n\n", "info")

                    # Redirect stdout to capture scanner output
                    old_stdout = sys.stdout
                    sys.stdout = OutputRedirector(self, 'cve_scanner')

                    try:
                        results['cve'] = self.cve_scanner.scan_directory(scan_path, recursive=recursive)
                    finally:
                        sys.stdout = old_stdout

                    self.update_progress('✅ CVE scan completed')
                    self.root.after(0, self.append_to_tab, 'cve_scanner', "\n" + "=" * 70 + "\n", "success")
                    self.root.after(0, self.append_to_tab, 'cve_scanner', "✅ CVE scan completed!\n", "success")
                except Exception as e:
                    sys.stdout = old_stdout
                    error_msg = f"\n❌ CVE Scanner Error: {str(e)}\n\n"
                    self.root.after(0, self.append_to_tab, 'cve_scanner', error_msg, "danger")
                    self.root.after(0, self.append_to_tab, 'summary', f"⚠️ CVE scan failed: {str(e)}\n", "warning")

            # Run Malware scan if enabled
            if self.scan_malware.get():
                try:
                    self.update_progress('☠️ Scanning for malware indicators...')
                    self.root.after(0, self.append_to_tab, 'malware_scanner', "☠️ Initializing malware scanner...\n", "detective")
                    self.root.after(0, self.append_to_tab, 'malware_scanner', "=" * 70 + "\n\n", "detective")

                    # Redirect stdout to capture scanner output
                    old_stdout = sys.stdout
                    sys.stdout = OutputRedirector(self, 'malware_scanner')

                    try:
                        results['malware'] = self.malware_scanner.scan_directory(scan_path)
                    finally:
                        sys.stdout = old_stdout

                    self.update_progress('✅ Malware scan completed')
                    self.root.after(0, self.append_to_tab, 'malware_scanner', "\n" + "=" * 70 + "\n", "success")
                    self.root.after(0, self.append_to_tab, 'malware_scanner', "✅ Malware scan completed!\n", "success")
                except Exception as e:
                    sys.stdout = old_stdout
                    error_msg = f"\n❌ Malware Scanner Error: {str(e)}\n\n"
                    self.root.after(0, self.append_to_tab, 'malware_scanner', error_msg, "danger")
                    self.root.after(0, self.append_to_tab, 'summary', f"⚠️ Malware scan failed: {str(e)}\n", "warning")

            # Display results in main thread
            if results:
                self.root.after(0, self.status_label.configure, {'text': '📊 Generating report...'})
                self.root.after(0, self.display_all_results, results)
            else:
                self.root.after(0, self.append_to_tab, 'summary', "⚠️ No scan results available.\n", "warning")

        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            error_msg = f"❌ Fatal Error: {str(e)}\n\n{error_details}\n"
            self.root.after(0, self.append_to_tab, 'summary', error_msg, "danger")
            self.root.after(0, self.status_label.configure, {'text': f'❌ Error: {str(e)}'})
        finally:
            self.root.after(0, self.scan_complete)

    def scan_complete(self):
        """Clean up after scan completes"""
        self.scanning = False
        self.scan_btn.configure(state='normal')
        self.progress.stop()
        self.progress.pack_forget()

        # Stop timer and show final time
        if self.timer_id:
            self.root.after_cancel(self.timer_id)
            self.timer_id = None

        if self.start_time:
            elapsed = int(time.time() - self.start_time)
            minutes = elapsed // 60
            seconds = elapsed % 60
            self.timer_label.configure(text=f"⏱️ {minutes:02d}:{seconds:02d} (completed)")
            self.status_label.configure(text=f"✅ Investigation complete in {minutes}m {seconds}s")
        else:
            self.status_label.configure(text="Investigation complete")

    def display_all_results(self, results):
        """Display all scan results in appropriate tabs"""
        # Display Summary
        self.display_summary(results)

        # Display CVE results
        if 'cve' in results:
            self.display_cve_results(results['cve'])

        # Display Malware results
        if 'malware' in results:
            self.display_malware_results(results['malware'])

        # Display full report
        self.display_full_report(results)

    def display_summary(self, results):
        """Display summary in summary tab"""
        self.clear_tab('summary')

        self.append_to_tab('summary', "═" * 70 + "\n", "detective")
        self.append_to_tab('summary', "═══ INVESTIGATION SUMMARY ═══\n", "detective")
        self.append_to_tab('summary', "═" * 70 + "\n\n", "detective")

        # CVE Summary
        if 'cve' in results:
            cve_summary = results['cve']['summary']
            self.append_to_tab('summary', "🔍 CVE SCANNER RESULTS:\n", "info")
            self.append_to_tab('summary', f"  📂 Projects scanned: {cve_summary['total_projects']}\n", "info")
            self.append_to_tab('summary', f"  ⚠️  Vulnerable: {cve_summary['vulnerable_projects']}\n",
                             "danger" if cve_summary['vulnerable_projects'] > 0 else "success")
            self.append_to_tab('summary', f"  ✅ Safe: {cve_summary['safe_projects']}\n\n", "success")

        # Malware Summary
        if 'malware' in results:
            malware_summary = results['malware']
            infected = malware_summary.get('infected_projects', 0)
            self.append_to_tab('summary', "☠️ MALWARE SCANNER RESULTS:\n", "info")
            self.append_to_tab('summary', f"  📂 Projects scanned: {malware_summary.get('scanned_projects', 0)}\n", "info")
            self.append_to_tab('summary', f"  ⚠️  Infected: {infected}\n",
                             "danger" if infected > 0 else "success")
            self.append_to_tab('summary', f"  ✅ Clean: {malware_summary.get('scanned_projects', 0) - infected}\n\n", "success")

        # Overall status
        total_issues = 0
        if 'cve' in results:
            total_issues += results['cve']['summary']['vulnerable_projects']
        if 'malware' in results:
            total_issues += results['malware'].get('infected_projects', 0)

        if total_issues == 0:
            self.append_to_tab('summary', "=" * 70 + "\n", "success")
            self.append_to_tab('summary', "🎉 ALL PROJECTS ARE SECURE!\n", "success")
            self.append_to_tab('summary', "=" * 70 + "\n\n", "success")
            self.append_to_tab('summary', "✅ Investigation complete: No vulnerabilities or malware detected.\n", "success")
            self.append_to_tab('summary', "🛡️  Your projects are protected!\n\n", "success")
            self.append_to_tab('summary', "Elementary, my dear developer!\n", "info")
        else:
            self.append_to_tab('summary', "=" * 70 + "\n", "danger")
            self.append_to_tab('summary', f"🚨 {total_issues} ISSUES DETECTED!\n", "danger")
            self.append_to_tab('summary', "=" * 70 + "\n\n", "danger")
            self.append_to_tab('summary', "⚠️  IMMEDIATE ACTION REQUIRED\n", "danger")
            self.append_to_tab('summary', "Check individual tabs for details and remediation steps.\n", "warning")

    def display_cve_results(self, results):
        """Display CVE scan results"""
        self.clear_tab('cve_scanner')

        summary = results['summary']
        self.append_to_tab('cve_scanner', "═" * 70 + "\n", "detective")
        self.append_to_tab('cve_scanner', "═══ CVE-2025-55182 & CVE-2025-66478 SCANNER ═══\n", "detective")
        self.append_to_tab('cve_scanner', "═" * 70 + "\n", "detective")
        self.append_to_tab('cve_scanner', f"  📂 Total projects scanned: {summary['total_projects']}\n", "info")
        self.append_to_tab('cve_scanner', f"  ⚠️  Vulnerable projects:    {summary['vulnerable_projects']}\n",
                         "danger" if summary['vulnerable_projects'] > 0 else "success")
        self.append_to_tab('cve_scanner', f"  ✅ Safe projects:          {summary['safe_projects']}\n\n", "success")

        # Display vulnerable projects (keeping original detailed format)
        if results['vulnerable_projects']:
            self.append_to_tab('cve_scanner', "=" * 70 + "\n", "danger")
            self.append_to_tab('cve_scanner', "🚨 CRITICAL VULNERABILITIES DETECTED!\n", "danger")
            self.append_to_tab('cve_scanner', "=" * 70 + "\n\n", "danger")

            for i, vp in enumerate(results['vulnerable_projects'], 1):
                self.append_to_tab('cve_scanner', f"┌─ Case #{i}: ", "info")
                self.append_to_tab('cve_scanner', f"{vp['path']}\n", "path")
                self.append_to_tab('cve_scanner', f"│  ⚠️  React Version:       ", "info")
                self.append_to_tab('cve_scanner', f"{vp['react_version']}\n", "danger")
                self.append_to_tab('cve_scanner', f"│  ✅ Recommended Version: ", "info")
                self.append_to_tab('cve_scanner', f"{vp['recommended_version']}\n", "success")

                if vp.get('next_js_version'):
                    self.append_to_tab('cve_scanner', f"│  🌐 Next.js Version:     ", "info")
                    tag = "danger" if vp.get('next_js_vulnerable') else "success"
                    self.append_to_tab('cve_scanner', f"{vp['next_js_version']}", tag)
                    if vp.get('next_js_vulnerable'):
                        self.append_to_tab('cve_scanner', " ⚠️", "danger")
                    self.append_to_tab('cve_scanner', "\n", "info")

                if vp.get('next_js_vulnerable') and vp.get('next_js_recommended'):
                    self.append_to_tab('cve_scanner', f"│  ✅ Next.js Recommended: ", "info")
                    self.append_to_tab('cve_scanner', f"{vp['next_js_recommended']}\n", "success")

                if vp.get('uses_server_components'):
                    self.append_to_tab('cve_scanner', f"│  🔧 Server Components:   ", "info")
                    self.append_to_tab('cve_scanner', "✅ Detected\n", "highlight")

                self.append_to_tab('cve_scanner', "└─\n\n", "info")

            # Remediation
            self.append_to_tab('cve_scanner', "=" * 70 + "\n", "detective")
            self.append_to_tab('cve_scanner', "🔧 REMEDIATION STEPS\n", "detective")
            self.append_to_tab('cve_scanner', "=" * 70 + "\n\n", "detective")

            for i, vp in enumerate(results['vulnerable_projects'], 1):
                self.append_to_tab('cve_scanner', f"┌─ Case #{i}: {vp['path']}\n", "info")
                self.append_to_tab('cve_scanner', f"│  cd {vp['path']}\n", "path")
                self.append_to_tab('cve_scanner', f"│  npm install react@{vp['recommended_version']} react-dom@{vp['recommended_version']}\n", "success")

                if vp.get('next_js_vulnerable') and vp.get('next_js_recommended'):
                    self.append_to_tab('cve_scanner', f"│  npm install next@{vp['next_js_recommended']}\n", "success")

                self.append_to_tab('cve_scanner', f"│  npm run build\n", "success")
                self.append_to_tab('cve_scanner', "└─ ✓ Case resolved\n\n", "info")
        else:
            self.append_to_tab('cve_scanner', "=" * 70 + "\n", "success")
            self.append_to_tab('cve_scanner', "🎉 NO CVE VULNERABILITIES FOUND!\n", "success")
            self.append_to_tab('cve_scanner', "=" * 70 + "\n", "success")

    def display_malware_results(self, results):
        """Display malware scan results"""
        self.clear_tab('malware_scanner')

        self.append_to_tab('malware_scanner', "═" * 70 + "\n", "detective")
        self.append_to_tab('malware_scanner', "═══ NPM MALWARE SCANNER ═══\n", "detective")
        self.append_to_tab('malware_scanner', "═" * 70 + "\n", "detective")
        self.append_to_tab('malware_scanner', f"  📂 Projects scanned: {results.get('scanned_projects', 0)}\n", "info")
        self.append_to_tab('malware_scanner', f"  ☠️  Infected projects: {results.get('infected_projects', 0)}\n",
                         "danger" if results.get('infected_projects', 0) > 0 else "success")

        findings = results.get('findings', [])
        if findings:
            self.append_to_tab('malware_scanner', "\n" + "=" * 70 + "\n", "danger")
            self.append_to_tab('malware_scanner', "☠️ MALWARE DETECTED!\n", "danger")
            self.append_to_tab('malware_scanner', "=" * 70 + "\n\n", "danger")

            for i, finding in enumerate(findings, 1):
                self.append_to_tab('malware_scanner', f"┌─ Infection #{i}\n", "danger")
                self.append_to_tab('malware_scanner', f"│  📁 Project: ", "info")
                self.append_to_tab('malware_scanner', f"{finding.get('project', 'Unknown')}\n", "path")

                for indicator in finding.get('indicators', []):
                    self.append_to_tab('malware_scanner', f"│  ⚠️  {indicator.get('type', 'unknown')}: ", "warning")
                    self.append_to_tab('malware_scanner', f"{indicator.get('indicator', 'N/A')}\n", "danger")

                self.append_to_tab('malware_scanner', "└─\n\n", "info")

            self.append_to_tab('malware_scanner', "=" * 70 + "\n", "danger")
            self.append_to_tab('malware_scanner', "⚠️  REMOVE INFECTED PACKAGES IMMEDIATELY!\n", "danger")
            self.append_to_tab('malware_scanner', "=" * 70 + "\n", "danger")
        else:
            self.append_to_tab('malware_scanner', "\n" + "=" * 70 + "\n", "success")
            self.append_to_tab('malware_scanner', "🎉 NO MALWARE DETECTED!\n", "success")
            self.append_to_tab('malware_scanner', "=" * 70 + "\n", "success")

    def display_full_report(self, results):
        """Display complete JSON report"""
        self.clear_tab('full_report')

        self.append_to_tab('full_report', "═" * 70 + "\n", "detective")
        self.append_to_tab('full_report', "═══ FULL INVESTIGATION REPORT ═══\n", "detective")
        self.append_to_tab('full_report', "═" * 70 + "\n\n", "detective")

        # Convert results to pretty JSON
        report_json = json.dumps(results, indent=2)
        self.append_to_tab('full_report', report_json, "info")

    def append_to_tab(self, tab_name, text, tag=None):
        """Append text to a specific tab's text widget"""
        widget_name = f"{tab_name}_text"
        if hasattr(self, widget_name):
            text_widget = getattr(self, widget_name)
            text_widget.insert(tk.END, text, tag)
            text_widget.see(tk.END)

    def clear_tab(self, tab_name):
        """Clear a specific tab's text widget"""
        widget_name = f"{tab_name}_text"
        if hasattr(self, widget_name):
            text_widget = getattr(self, widget_name)
            text_widget.delete(1.0, tk.END)

    def clear_results(self):
        """Clear all result tabs"""
        for tab in ['summary', 'cve_scanner', 'malware_scanner', 'full_report']:
            self.clear_tab(tab)
        self.status_label.configure(text="Ready to investigate")


def main():
    """Launch the Shellockolm GUI"""
    root = tk.Tk()
    app = ShellockolmGUI(root)

    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')

    root.mainloop()


if __name__ == "__main__":
    main()
