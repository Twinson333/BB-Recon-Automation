#!/usr/bin/env python3
"""GUI interface for bb-recon using tkinter."""

from __future__ import annotations

import sys
import subprocess
import threading
from pathlib import Path
from tkinter import *
from tkinter import ttk, scrolledtext, messagebox, filedialog


class BBReconGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BB-Recon GUI")
        self.root.geometry("900x900")
        self.root.resizable(True, True)
        
        self.process = None
        self.is_running = False
        
        # Apply modern style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Create main notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.config_frame = ttk.Frame(self.notebook)
        self.output_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.config_frame, text="Configuration")
        self.notebook.add(self.output_frame, text="Output")
        
        self._create_config_tab()
        self._create_output_tab()
    
    def _create_config_tab(self):
        """Create the configuration tab."""
        # Create a canvas with scrollbar for the config options
        canvas = Canvas(self.config_frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.config_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Domain input
        ttk.Label(scrollable_frame, text="Target Domain*", font=("Arial", 10, "bold")).grid(
            row=0, column=0, sticky="w", padx=10, pady=10
        )
        self.domain_var = StringVar()
        domain_entry = ttk.Entry(scrollable_frame, textvariable=self.domain_var, width=40)
        domain_entry.grid(row=0, column=1, sticky="w", padx=10, pady=10)
        
        # Threads
        ttk.Label(scrollable_frame, text="Threads:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.threads_var = IntVar(value=8)
        ttk.Spinbox(scrollable_frame, from_=1, to=64, textvariable=self.threads_var, width=10).grid(
            row=1, column=1, sticky="w", padx=10, pady=5
        )
        
        # Timeout
        ttk.Label(scrollable_frame, text="Timeout (seconds):").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.timeout_var = IntVar(value=600)
        ttk.Spinbox(scrollable_frame, from_=60, to=3600, textvariable=self.timeout_var, width=10).grid(
            row=2, column=1, sticky="w", padx=10, pady=5
        )
        
        # Katana depth
        ttk.Label(scrollable_frame, text="Katana Depth:").grid(row=3, column=0, sticky="w", padx=10, pady=5)
        self.katana_depth_var = IntVar(value=3)
        ttk.Spinbox(scrollable_frame, from_=1, to=10, textvariable=self.katana_depth_var, width=10).grid(
            row=3, column=1, sticky="w", padx=10, pady=5
        )
        
        # Naabu rate
        ttk.Label(scrollable_frame, text="Naabu Rate:").grid(row=4, column=0, sticky="w", padx=10, pady=5)
        self.naabu_rate_var = IntVar(value=1000)
        ttk.Spinbox(scrollable_frame, from_=100, to=10000, textvariable=self.naabu_rate_var, width=10).grid(
            row=4, column=1, sticky="w", padx=10, pady=5
        )
        
        # Max screenshots
        ttk.Label(scrollable_frame, text="Max Screenshots:").grid(row=5, column=0, sticky="w", padx=10, pady=5)
        self.max_screenshots_var = IntVar(value=500)
        ttk.Spinbox(scrollable_frame, from_=0, to=5000, textvariable=self.max_screenshots_var, width=10).grid(
            row=5, column=1, sticky="w", padx=10, pady=5
        )
        
        # Hakrawler limit
        ttk.Label(scrollable_frame, text="Hakrawler URL Limit:").grid(row=6, column=0, sticky="w", padx=10, pady=5)
        self.hakrawler_limit_var = IntVar(value=500)
        ttk.Spinbox(scrollable_frame, from_=100, to=5000, textvariable=self.hakrawler_limit_var, width=10).grid(
            row=6, column=1, sticky="w", padx=10, pady=5
        )
        
        # Nuclei templates path
        ttk.Label(scrollable_frame, text="Nuclei Templates:").grid(row=7, column=0, sticky="w", padx=10, pady=5)
        self.nuclei_templates_var = StringVar()
        ttk.Entry(scrollable_frame, textvariable=self.nuclei_templates_var, width=40).grid(
            row=7, column=1, sticky="w", padx=10, pady=5
        )
        ttk.Button(scrollable_frame, text="Browse", command=self._browse_templates).grid(
            row=7, column=2, sticky="w", padx=5, pady=5
        )
        
        # Checkboxes (row 8+)
        ttk.Separator(scrollable_frame, orient="horizontal").grid(row=8, column=0, columnspan=3, sticky="ew", padx=10, pady=10)
        
        row = 9
        self.passive_only_var = BooleanVar(value=False)
        ttk.Checkbutton(scrollable_frame, text="Passive Only (no active scanning)", variable=self.passive_only_var).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=10, pady=5
        )
        
        row += 1
        self.skip_port_scan_var = BooleanVar(value=False)
        ttk.Checkbutton(scrollable_frame, text="Skip Port Scan", variable=self.skip_port_scan_var).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=10, pady=5
        )
        
        row += 1
        self.run_nuclei_var = BooleanVar(value=False)
        ttk.Checkbutton(scrollable_frame, text="Run Nuclei", variable=self.run_nuclei_var).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=10, pady=5
        )
        
        row += 1
        self.screenshots_var = BooleanVar(value=False)
        ttk.Checkbutton(scrollable_frame, text="Enable Screenshots", variable=self.screenshots_var).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=10, pady=5
        )
        
        row += 1
        self.resume_var = BooleanVar(value=False)
        ttk.Checkbutton(scrollable_frame, text="Resume Run", variable=self.resume_var).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=10, pady=5
        )
        
        row += 1
        self.clean_tmp_var = BooleanVar(value=False)
        ttk.Checkbutton(scrollable_frame, text="Clean Temp Files", variable=self.clean_tmp_var).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=10, pady=5
        )
        
        # Buttons
        ttk.Separator(scrollable_frame, orient="horizontal").grid(row=row+1, column=0, columnspan=3, sticky="ew", padx=10, pady=10)
        
        button_frame = ttk.Frame(scrollable_frame)
        button_frame.grid(row=row+2, column=0, columnspan=3, sticky="ew", padx=10, pady=10)
        
        self.run_button = ttk.Button(button_frame, text="▶ Run Scan", command=self._run_scan)
        self.run_button.pack(side="left", padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="⏹ Stop", command=self._stop_scan, state="disabled")
        self.stop_button.pack(side="left", padx=5)
        
        ttk.Button(button_frame, text="Clear Output", command=self._clear_output).pack(side="left", padx=5)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def _create_output_tab(self):
        """Create the output tab."""
        # Output text area
        self.output_text = scrolledtext.ScrolledText(
            self.output_frame, wrap=WORD, height=30, font=("Consolas", 9)
        )
        self.output_text.pack(fill=BOTH, expand=True, padx=10, pady=10)
        self.output_text.config(state="disabled")
    
    def _browse_templates(self):
        """Browse for nuclei templates directory."""
        path = filedialog.askdirectory(title="Select Nuclei Templates Directory")
        if path:
            self.nuclei_templates_var.set(path)
    
    def _log_output(self, message: str):
        """Append message to output text area."""
        self.output_text.config(state="normal")
        self.output_text.insert("end", message + "\n")
        self.output_text.see("end")
        self.output_text.config(state="disabled")
        self.root.update()
    
    def _clear_output(self):
        """Clear the output text area."""
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.config(state="disabled")
    
    def _run_scan(self):
        """Run the scan in a separate thread."""
        domain = self.domain_var.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a target domain")
            return
        
        # Switch to output tab
        self.notebook.select(self.output_frame)
        self._clear_output()
        
        # Disable run button, enable stop button
        self.run_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.is_running = True
        
        # Start scan in background thread
        thread = threading.Thread(target=self._scan_thread, args=(domain,), daemon=True)
        thread.start()
    
    def _scan_thread(self, domain: str):
        """Execute the scan in a background thread."""
        try:
            target_script = Path(__file__).with_name("bb-recon.py")
            if not target_script.exists():
                self._log_output(f"ERROR: Could not find {target_script.name}")
                return
            
            # Build command
            cmd = [sys.executable, str(target_script), domain]
            cmd.extend(["-t", str(self.threads_var.get())])
            cmd.extend(["--timeout", str(self.timeout_var.get())])
            cmd.extend(["--katana-depth", str(self.katana_depth_var.get())])
            cmd.extend(["--naabu-rate", str(self.naabu_rate_var.get())])
            cmd.extend(["--max-screenshots", str(self.max_screenshots_var.get())])
            cmd.extend(["--hakrawler-limit", str(self.hakrawler_limit_var.get())])
            
            if self.passive_only_var.get():
                cmd.append("--passive-only")
            if self.screenshots_var.get():
                cmd.append("--screenshots")
            if self.resume_var.get():
                cmd.append("--resume")
            if self.clean_tmp_var.get():
                cmd.append("--clean-tmp")
            if self.run_nuclei_var.get():
                cmd.append("--run-nuclei")
            if self.skip_port_scan_var.get():
                cmd.append("--skip-port-scan")
            if self.nuclei_templates_var.get():
                cmd.extend(["--nuclei-templates", self.nuclei_templates_var.get()])
            
            self._log_output(f"Starting scan for: {domain}")
            self._log_output(f"Command: {' '.join(cmd)}\n")
            self._log_output("=" * 80)
            
            # Execute command with streaming output
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            self.process = proc
            
            # Stream output
            while self.is_running and proc.poll() is None:
                line = proc.stdout.readline()
                if line:
                    self._log_output(line.rstrip())
            
            # Get any remaining output
            remaining = proc.stdout.read()
            if remaining:
                for line in remaining.split("\n"):
                    if line:
                        self._log_output(line)
            
            returncode = proc.wait()
            self._log_output("=" * 80)
            self._log_output(f"Scan completed with return code: {returncode}")
            
        except Exception as e:
            self._log_output(f"ERROR: {str(e)}")
        
        finally:
            self.is_running = False
            self.run_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.process = None
    
    def _stop_scan(self):
        """Stop the running scan."""
        if self.process:
            try:
                self.process.terminate()
                self._log_output("\n[STOPPED] Scan terminated by user")
            except Exception as e:
                self._log_output(f"ERROR stopping process: {e}")
        
        self.is_running = False
        self.run_button.config(state="normal")
        self.stop_button.config(state="disabled")


def main():
    root = Tk()
    app = BBReconGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
