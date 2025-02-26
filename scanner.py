import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from ttkthemes import ThemedTk
import threading
import queue
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.edge.options import Options as EdgeOptions
import aiohttp
import asyncio
import json
import csv
from cryptography.fernet import Fernet
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import logging
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
import psutil
import datetime
import webbrowser

# Setup logging
logging.basicConfig(filename='vuln_scanner.log', level=logging.INFO, 
                   format='%(asctime)s - %(levelname)s - %(message)s')

class VulnerabilityScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Vulnerability Scanner")
        self.root.geometry("1200x800")
        
        self.result_queue = queue.Queue()
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        
        self.payload_sets = {
            'xss': {
                'Basic': ["<script>alert('xss')</script>", "javascript:alert('xss')"],
                'Advanced': ["\"><script>alert('xss')</script>", "onerror=alert('xss')"],
                'DOM': ["document.write('<img src=x onerror=alert(1)>')"]
            },
            'sqli': {
                'Basic': ["' OR 1=1 --", "1'; DROP TABLE users; --"],
                'Blind': ["' AND SLEEP(5) --", "' AND IF(1=1, SLEEP(5), 0) --"],
                'Boolean': ["' AND 1=1 --", "' AND 1=2 --"]
            },
            'open_redirect': {
                'Basic': ["http://evil.com", "//evil.com"],
                'Advanced': ["/redirect?url=http://evil.com", "http://example.com%0d%0aLocation:http://evil.com"]
            }
        }
        
        self.vuln_mapping = {
            'xss': 'xss',
            'sql injection': 'sqli',
            'open redirect': 'open_redirect'
        }
        
        self.scan_config = {
            'timeout': 10,
            'retries': 3,
            'rate_limit': 1,
            'proxy': None,
            'proxy_user': '',
            'proxy_pass': '',
            'headers': {},
            'cookies': {},
            'chromedriver_path': "",
            'threads': 4,
            'profile': 'Quick Scan'
        }
        
        self.selected_vuln = None
        self.scanning = False
        self.urls_to_scan = []
        self.parameters_detected = []
        self.response_cache = {}
        self.custom_rules = {}
        self.scan_history = []
        self.errors = []
        
        self.setup_ui()
        self.monitor_resources()

    def setup_ui(self):
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        self.canvas = tk.Canvas(self.main_frame, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self.main_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        self.style = ttk.Style()
        self.current_theme = 'dark'
        self.apply_theme()
        
        self.notebook = ttk.Notebook(self.scrollable_frame)
        self.notebook.pack(fill='both', expand=True)
        
        self.scan_frame = ttk.Frame(self.notebook)
        self.config_frame = ttk.Frame(self.notebook)
        self.results_frame = ttk.Frame(self.notebook)
        self.dashboard_frame = ttk.Frame(self.notebook)
        self.history_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.scan_frame, text="Scanner")
        self.notebook.add(self.config_frame, text="Configuration")
        self.notebook.add(self.results_frame, text="Results")
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        self.notebook.add(self.history_frame, text="History")
        
        self.show_scan_selection()
        self.setup_config_tab()
        self.setup_results_tab()
        self.setup_dashboard_tab()
        self.setup_history_tab()

    def apply_theme(self):
        if self.current_theme == 'dark':
            bg, fg, btn_bg, entry_bg = "#1f2a44", "#e6e6e6", "#2d3b5a", "#2d3b5a"
        else:
            bg, fg, btn_bg, entry_bg = "#f0f0f0", "#333333", "#d9d9d9", "#ffffff"
        
        self.root.configure(bg=bg)
        self.canvas.configure(bg=bg)
        self.style.theme_use('clam')
        self.style.configure("TNotebook", background=bg, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=btn_bg, foreground=fg, 
                            padding=[15, 8], font=("Helvetica", 12, "bold"), borderwidth=2)
        self.style.map("TNotebook.Tab", background=[("selected", "#007acc")], 
                      foreground=[("selected", "white")])
        self.style.configure("TButton", background=btn_bg, foreground=fg, 
                            padding=10, font=("Helvetica", 11, "bold"), borderwidth=1)
        self.style.map("TButton", background=[("active", "#3f5485" if self.current_theme == 'dark' else "#b3b3b3")])
        self.style.configure("TLabel", background=bg, foreground=fg, font=("Helvetica", 11))
        self.style.configure("TEntry", fieldbackground=entry_bg, foreground=fg, 
                            insertcolor=fg, borderwidth=2)
        self.style.configure("TRadiobutton", background=bg, foreground=fg, font=("Helvetica", 11))
        self.style.configure("TProgressbar", background="#007acc", troughcolor=btn_bg, thickness=25)

    def toggle_theme(self):
        self.current_theme = 'light' if self.current_theme == 'dark' else 'dark'
        self.apply_theme()
        self.update_dashboard()

    def show_scan_selection(self):
        for widget in self.scan_frame.winfo_children():
            widget.destroy()
        
        ttk.Label(self.scan_frame, text="Select Vulnerability Type", 
                 font=("Helvetica", 18, "bold")).pack(pady=25)
        
        self.vuln_var = tk.StringVar(value="xss")
        for vuln in ["XSS", "SQL Injection", "Open Redirect"]:
            ttk.Radiobutton(self.scan_frame, text=vuln, value=vuln.lower(), 
                           variable=self.vuln_var, command=self.setup_scan_tab).pack(pady=10)

    def setup_scan_tab(self):
        for widget in self.scan_frame.winfo_children():
            widget.destroy()
        
        self.selected_vuln = self.vuln_mapping[self.vuln_var.get()]
        
        self.url_frame = ttk.LabelFrame(self.scan_frame, text="URL Settings", padding=10)
        self.url_frame.pack(fill='x', pady=5)
        ttk.Label(self.url_frame, text="Target URL(s):", 
                  textvariable=tk.StringVar(value="Enter or load URLs")).pack(pady=5)
        self.url_entry = ttk.Entry(self.url_frame, width=70)
        self.url_entry.pack(pady=5)
        ttk.Button(self.url_frame, text="Load URLs from File", 
                  command=self.load_urls).pack(pady=5)
        
        self.param_frame = ttk.LabelFrame(self.scan_frame, text="Parameters", padding=10)
        self.param_frame.pack(fill='x', pady=5)
        self.param_listbox = tk.Listbox(self.param_frame, height=5, width=50)
        self.param_listbox.pack(pady=5)
        param_btn_frame = ttk.Frame(self.param_frame)
        param_btn_frame.pack(pady=5)
        ttk.Button(param_btn_frame, text="Add", command=self.add_parameter).pack(side='left', padx=5)
        ttk.Button(param_btn_frame, text="Edit", command=self.edit_parameter).pack(side='left', padx=5)
        ttk.Button(param_btn_frame, text="Delete", command=self.delete_parameter).pack(side='left', padx=5)
        
        self.payload_frame = ttk.LabelFrame(self.scan_frame, text="Payload Settings", padding=10)
        self.payload_frame.pack(fill='x', pady=5)
        ttk.Label(self.payload_frame, text=f"{self.selected_vuln.upper()} Payloads:", 
                  textvariable=tk.StringVar(value=f"Enter or select {self.selected_vuln.upper()} payloads")).pack(pady=5)
        self.payload_entry = ttk.Entry(self.payload_frame, width=70)
        self.payload_entry.pack(pady=5)
        payload_btn_frame = ttk.Frame(self.payload_frame)
        payload_btn_frame.pack(pady=5)
        self.payload_set_var = tk.StringVar(value="Basic")
        ttk.Combobox(payload_btn_frame, textvariable=self.payload_set_var, 
                    values=list(self.payload_sets[self.selected_vuln].keys()), 
                    width=15).pack(side='left', padx=5)
        ttk.Button(payload_btn_frame, text="Apply Preset", 
                  command=self.apply_preset_payloads).pack(side='left', padx=5)
        if self.selected_vuln == 'xss':
            ttk.Button(payload_btn_frame, text="Load XSS Payloads", 
                      command=lambda: self.load_payloads('xss')).pack(side='left', padx=5)
        elif self.selected_vuln == 'sqli':
            ttk.Button(payload_btn_frame, text="Load SQLi Payloads", 
                      command=lambda: self.load_payloads('sqli')).pack(side='left', padx=5)
        elif self.selected_vuln == 'open_redirect':
            ttk.Button(payload_btn_frame, text="Load Open Redirect Payloads", 
                      command=lambda: self.load_payloads('open_redirect')).pack(side='left', padx=5)
        
        self.progress = ttk.Progressbar(self.scan_frame, length=500, mode='determinate')
        self.progress.pack(pady=15)
        self.status_label = ttk.Label(self.scan_frame, text="Status: Idle")
        self.status_label.pack(pady=5)
        
        button_frame = ttk.Frame(self.scan_frame)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Start Scan", 
                  command=self.start_scan).pack(side="left", padx=15)
        ttk.Button(button_frame, text="Stop Scan", 
                  command=self.stop_scan).pack(side="left", padx=15)
        ttk.Button(button_frame, text="Resume Scan", 
                  command=self.resume_scan).pack(side="left", padx=15)
        ttk.Button(button_frame, text="Back to Main Menu", 
                  command=self.show_scan_selection).pack(side="left", padx=15)

    def setup_config_tab(self):
        ttk.Label(self.config_frame, text="Scanner Configuration", 
                 font=("Helvetica", 18, "bold")).pack(pady=20)
        
        ttk.Button(self.config_frame, text="Toggle Theme", command=self.toggle_theme).pack(pady=5)
        
        ttk.Label(self.config_frame, text="Chromedriver Path:").pack(pady=5)
        self.chrome_entry = ttk.Entry(self.config_frame, width=70)
        self.chrome_entry.pack(pady=5)
        
        ttk.Label(self.config_frame, text="Proxy (e.g., http://proxy:port):").pack(pady=5)
        self.proxy_entry = ttk.Entry(self.config_frame, width=70)
        self.proxy_entry.pack(pady=5)
        
        ttk.Label(self.config_frame, text="Proxy Username:").pack(pady=5)
        self.proxy_user_entry = ttk.Entry(self.config_frame, width=70)
        self.proxy_user_entry.pack(pady=5)
        
        ttk.Label(self.config_frame, text="Proxy Password:").pack(pady=5)
        self.proxy_pass_entry = ttk.Entry(self.config_frame, width=70, show="*")
        self.proxy_pass_entry.pack(pady=5)
        
        ttk.Button(self.config_frame, text="Check Proxy Anonymity", 
                  command=self.check_proxy_anonymity).pack(pady=5)
        
        ttk.Label(self.config_frame, text="Auth Token:").pack(pady=5)
        self.auth_entry = ttk.Entry(self.config_frame, width=70, show="*")
        self.auth_entry.pack(pady=5)
        
        ttk.Label(self.config_frame, text="Cookies (JSON format):").pack(pady=5)
        self.cookies_entry = ttk.Entry(self.config_frame, width=70)
        self.cookies_entry.pack(pady=5)
        
        ttk.Label(self.config_frame, text="Rate Limit (req/s):").pack(pady=5)
        self.rate_entry = ttk.Entry(self.config_frame, width=10)
        self.rate_entry.insert(0, "1")
        self.rate_entry.pack(pady=5)
        
        ttk.Label(self.config_frame, text="Timeout (seconds):").pack(pady=5)
        self.timeout_entry = ttk.Entry(self.config_frame, width=10)
        self.timeout_entry.insert(0, "10")
        self.timeout_entry.pack(pady=5)
        
        ttk.Label(self.config_frame, text="Retries:").pack(pady=5)
        self.retries_entry = ttk.Entry(self.config_frame, width=10)
        self.retries_entry.insert(0, "3")
        self.retries_entry.pack(pady=5)
        
        ttk.Label(self.config_frame, text="Threads:").pack(pady=5)
        self.threads_entry = ttk.Entry(self.config_frame, width=10)
        self.threads_entry.insert(0, "4")
        self.threads_entry.pack(pady=5)
        
        config_button_frame = ttk.Frame(self.config_frame)
        config_button_frame.pack(pady=15)
        ttk.Button(config_button_frame, text="Save Profile", 
                  command=self.save_profile).pack(side='left', padx=5)
        ttk.Button(config_button_frame, text="Load Profile", 
                  command=self.load_profile).pack(side='left', padx=5)

    def setup_results_tab(self):
        ttk.Label(self.results_frame, text="Scan Results", 
                 font=("Helvetica", 18, "bold")).pack(pady=10)
        
        self.tree = ttk.Treeview(self.results_frame, columns=("URL", "Type", "Payload", "Status"), 
                                show="headings", height=20)
        self.tree.heading("URL", text="URL")
        self.tree.heading("Type", text="Vulnerability Type")
        self.tree.heading("Payload", text="Payload")
        self.tree.heading("Status", text="Status")
        self.tree.column("URL", width=400)
        self.tree.column("Type", width=150)
        self.tree.column("Payload", width=400)
        self.tree.column("Status", width=150)
        self.tree.pack(fill='x', padx=5, pady=5)
        
        # Context menu for right-click
        self.context_menu = tk.Menu(self.results_frame, tearoff=0)
        self.context_menu.add_command(label="Copy URL", command=self.copy_url)
        self.context_menu.add_command(label="Open in Browser", command=self.open_in_browser)
        self.tree.bind("<Button-3>", self.show_context_menu)
        
        button_frame = ttk.Frame(self.results_frame)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Export to JSON", 
                  command=lambda: self.export_results('json')).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Export to CSV", 
                  command=lambda: self.export_results('csv')).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Export HTML Report", 
                  command=self.export_html_report).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Clear Results", 
                  command=self.clear_results).pack(side='left', padx=5)
        
        self.error_summary_label = ttk.Label(self.results_frame, text="Errors: None")
        self.error_summary_label.pack(pady=5)

    def show_context_menu(self, event):
        selected = self.tree.identify_row(event.y)
        if selected:
            self.tree.selection_set(selected)
            self.context_menu.post(event.x_root, event.y_root)

    def copy_url(self):
        selected = self.tree.selection()
        if selected:
            url = self.tree.item(selected[0], 'values')[0]
            self.root.clipboard_clear()
            self.root.clipboard_append(url)
            messagebox.showinfo("Copy", "URL copied to clipboard")

    def open_in_browser(self):
        selected = self.tree.selection()
        if selected:
            url = self.tree.item(selected[0], 'values')[0]
            try:
                webbrowser.open(url)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open URL in browser: {str(e)}")
                self.errors.append(f"Open Browser: {str(e)}")

    def setup_dashboard_tab(self):
        ttk.Label(self.dashboard_frame, text="Vulnerability Dashboard", 
                 font=("Helvetica", 18, "bold")).pack(pady=10)
        
        self.fig, self.ax = plt.subplots(figsize=(10, 5), facecolor="#1f2a44" if self.current_theme == 'dark' else "#f0f0f0")
        self.ax.set_facecolor("#2d3b5a" if self.current_theme == 'dark' else "#e0e0e0")
        self.dashboard_canvas = FigureCanvasTkAgg(self.fig, master=self.dashboard_frame)
        self.dashboard_canvas.get_tk_widget().pack(fill='both', expand=True)
        
        self.resource_label = ttk.Label(self.dashboard_frame, text="Resources: CPU 0%, Memory 0%")
        self.resource_label.pack(pady=5)

    def setup_history_tab(self):
        ttk.Label(self.history_frame, text="Scan History", 
                 font=("Helvetica", 18, "bold")).pack(pady=10)
        
        self.history_tree = ttk.Treeview(self.history_frame, columns=("Timestamp", "Vuln Type", "URLs", "Results"), 
                                        show="headings", height=20)
        self.history_tree.heading("Timestamp", text="Timestamp")
        self.history_tree.heading("Vuln Type", text="Vulnerability Type")
        self.history_tree.heading("URLs", text="URLs Scanned")
        self.history_tree.heading("Results", text="Vulnerabilities Found")
        self.history_tree.column("Timestamp", width=200)
        self.history_tree.column("Vuln Type", width=150)
        self.history_tree.column("URLs", width=300)
        self.history_tree.column("Results", width=300)
        self.history_tree.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(self.history_frame, text="Reload Selected Scan", 
                  command=self.reload_scan).pack(pady=10)

    def add_parameter(self):
        param = simpledialog.askstring("Add Parameter", "Enter parameter name:")
        if param and param not in self.parameters_detected:
            self.parameters_detected.append(param)
            self.param_listbox.insert(tk.END, param)

    def edit_parameter(self):
        selected = self.param_listbox.curselection()
        if selected:
            old_param = self.param_listbox.get(selected[0])
            new_param = simpledialog.askstring("Edit Parameter", "Enter new parameter name:", initialvalue=old_param)
            if new_param:
                self.parameters_detected[self.parameters_detected.index(old_param)] = new_param
                self.param_listbox.delete(selected[0])
                self.param_listbox.insert(selected[0], new_param)

    def delete_parameter(self):
        selected = self.param_listbox.curselection()
        if selected:
            param = self.param_listbox.get(selected[0])
            self.parameters_detected.remove(param)
            self.param_listbox.delete(selected[0])

    def load_urls(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.urls_to_scan = f.read().splitlines()
                self.url_entry.delete(0, tk.END)
                self.url_entry.insert(0, self.urls_to_scan[0])
                self.detect_parameters()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load URLs: {str(e)}")
                self.errors.append(f"Load URLs: {str(e)}")

    def detect_parameters(self):
        self.parameters_detected = []
        for url in self.urls_to_scan:
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params.keys():
                if param not in self.parameters_detected:
                    self.parameters_detected.append(param)
        
        self.param_listbox.delete(0, tk.END)
        for param in self.parameters_detected:
            self.param_listbox.insert(tk.END, param)

    def load_payloads(self, vuln_type):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    payloads = f.read().splitlines()
                self.payload_entry.delete(0, tk.END)
                self.payload_entry.insert(0, ",".join(payloads))
                self.payload_sets[vuln_type][self.payload_set_var.get()] = payloads
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load payloads: {str(e)}")
                self.errors.append(f"Load Payloads: {str(e)}")

    def apply_preset_payloads(self):
        preset = self.payload_set_var.get()
        self.payload_entry.delete(0, tk.END)
        self.payload_entry.insert(0, ",".join(self.payload_sets[self.selected_vuln][preset]))

    def validate_inputs(self):
        url = self.url_entry.get()
        rate_limit = self.rate_entry.get()
        timeout = self.timeout_entry.get()
        retries = self.retries_entry.get()
        threads = self.threads_entry.get()
        cookies = self.cookies_entry.get()
        
        if not url or not re.match(r'^https?://', url):
            messagebox.showerror("Input Error", "Please enter a valid URL starting with http:// or https://")
            return False
        try:
            self.scan_config.update({
                'rate_limit': float(rate_limit or 1),
                'timeout': float(timeout or 10),
                'retries': int(retries or 3),
                'threads': int(threads or 4)
            })
            if any(v <= 0 for v in [self.scan_config['rate_limit'], self.scan_config['timeout'], self.scan_config['threads']]):
                raise ValueError
            if self.scan_config['retries'] < 0:
                raise ValueError
            if self.scan_config['threads'] > 16:
                messagebox.showwarning("Warning", "High thread count may impact performance")
            if cookies:
                json.loads(cookies)
        except ValueError:
            messagebox.showerror("Input Error", "Numeric fields must be positive (Retries can be 0)")
            return False
        except json.JSONDecodeError:
            messagebox.showerror("Input Error", "Cookies must be valid JSON")
            return False
        return True

    def save_profile(self):
        config = {
            'chromedriver_path': self.chrome_entry.get(),
            'proxy': self.proxy_entry.get(),
            'proxy_user': self.proxy_user_entry.get(),
            'proxy_pass': self.proxy_pass_entry.get(),
            'auth_token': self.auth_entry.get(),
            'cookies': self.cookies_entry.get(),
            'rate_limit': self.rate_entry.get(),
            'timeout': self.timeout_entry.get(),
            'retries': self.retries_entry.get(),
            'threads': self.threads_entry.get()
        }
        file_path = filedialog.asksaveasfilename(defaultextension=".json", 
                                                filetypes=[("JSON files", "*.json")])
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2)
                messagebox.showinfo("Success", "Profile saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save profile: {str(e)}")
                self.errors.append(f"Save Profile: {str(e)}")

    def load_profile(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                for entry, key in [(self.chrome_entry, 'chromedriver_path'), 
                                  (self.proxy_entry, 'proxy'), 
                                  (self.proxy_user_entry, 'proxy_user'), 
                                  (self.proxy_pass_entry, 'proxy_pass'), 
                                  (self.auth_entry, 'auth_token'), 
                                  (self.cookies_entry, 'cookies'), 
                                  (self.rate_entry, 'rate_limit'), 
                                  (self.timeout_entry, 'timeout'), 
                                  (self.retries_entry, 'retries'), 
                                  (self.threads_entry, 'threads')]:
                    entry.delete(0, tk.END)
                    entry.insert(0, config.get(key, ''))
                messagebox.showinfo("Success", "Profile loaded successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load profile: {str(e)}")
                self.errors.append(f"Load Profile: {str(e)}")

    def check_proxy_anonymity(self):
        proxy = self.proxy_entry.get()
        if not proxy:
            messagebox.showerror("Error", "Please enter a proxy")
            return
        try:
            async def fetch_ip():
                async with aiohttp.ClientSession() as session:
                    proxy_auth = aiohttp.BasicAuth(self.proxy_user_entry.get(), self.proxy_pass_entry.get()) if self.proxy_user_entry.get() else None
                    async with session.get("http://ipinfo.io/ip", proxy=proxy, proxy_auth=proxy_auth, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        return await resp.text()
            ip = asyncio.run(fetch_ip())
            messagebox.showinfo("Proxy Anonymity", f"Your IP via proxy: {ip}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to check proxy: {str(e)}")
            self.errors.append(f"Proxy Check: {str(e)}")

    def start_scan(self):
        if not self.validate_inputs():
            return
        
        self.scanning = True
        self.progress['value'] = 0
        self.status_label.config(text="Status: Starting scan...")
        self.errors = []
        urls = [self.url_entry.get()] if not self.urls_to_scan else self.urls_to_scan
        
        self.scan_config.update({
            'proxy': self.proxy_entry.get(),
            'proxy_user': self.proxy_user_entry.get(),
            'proxy_pass': self.proxy_pass_entry.get(),
            'cookies': json.loads(self.cookies_entry.get() or '{}'),
            'headers': {'Authorization': f"Bearer {self.auth_entry.get()}" if self.auth_entry.get() else ""}
        })
        
        threading.Thread(target=self.scan_urls, args=(urls,), daemon=True).start()
        self.root.after(100, self.process_queue)
        self.save_progress()

    def stop_scan(self):
        self.scanning = False
        self.progress['value'] = 0
        self.status_label.config(text="Status: Scan stopped")
        self.show_error_summary()

    def scan_urls(self, urls):
        browsers = [
            (webdriver.Chrome, ChromeOptions, self.scan_config['chromedriver_path']),
            (webdriver.Firefox, FirefoxOptions, None),
            (webdriver.Edge, EdgeOptions, None)
        ]
        browser_idx = 0
        try:
            browser_cls, options_cls, driver_path = browsers[browser_idx]
            options = options_cls()
            options.add_argument("--headless")
            if driver_path:
                service = Service(driver_path)
                driver = browser_cls(service=service, options=options)
            else:
                driver = browser_cls(options=options)
            
            total_tasks = len(urls) * len(self.payload_entry.get().split(",")) * (len(self.parameters_detected) or 1)
            completed_tasks = 0
            
            with ThreadPoolExecutor(max_workers=self.scan_config['threads']) as executor:
                futures = []
                for url in sorted(urls, key=lambda u: len(urllib.parse.parse_qs(urllib.parse.urlparse(u).query)), reverse=True):
                    if not self.scanning:
                        break
                    payloads = self.payload_entry.get().split(",")
                    parsed_url = urllib.parse.urlparse(url)
                    params = urllib.parse.parse_qs(parsed_url.query)
                    
                    for payload in payloads:
                        if not self.scanning:
                            break
                        if self.parameters_detected:
                            for param in self.parameters_detected:
                                if not self.scanning:
                                    break
                                new_params = params.copy()
                                new_params[param] = [payload]
                                new_query = urllib.parse.urlencode(new_params, doseq=True)
                                test_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
                                futures.append(executor.submit(self.scan_single_url, test_url, payload, driver, completed_tasks, total_tasks))
                                completed_tasks += 1
                        else:
                            test_url = url + "?" + payload if "?" not in url else url + "&" + payload
                            futures.append(executor.submit(self.scan_single_url, test_url, payload, driver, completed_tasks, total_tasks))
                            completed_tasks += 1
                
                for future in futures:
                    if self.scanning:
                        try:
                            future.result()
                        except Exception as e:
                            logging.error(f"Thread error: {str(e)}")
                            self.errors.append(f"Thread: {str(e)}")
                            driver = self.rotate_browser(browsers, browser_idx, driver)
                            browser_idx = (browser_idx + 1) % len(browsers)
            
            driver.quit()
            self.status_label.config(text="Status: Scan completed")
            self.show_error_summary()
            self.save_scan_history(urls)
            if os.path.exists("scan_progress.json"):
                os.remove("scan_progress.json")
        except Exception as e:
            logging.error(f"Failed to initialize WebDriver: {str(e)}")
            messagebox.showerror("Error", f"WebDriver error: {str(e)}")
            self.errors.append(f"WebDriver: {str(e)}")

    def rotate_browser(self, browsers, current_idx, driver):
        driver.quit()
        browser_cls, options_cls, driver_path = browsers[(current_idx + 1) % len(browsers)]
        options = options_cls()
        options.add_argument("--headless")
        if driver_path:
            service = Service(driver_path)
            return browser_cls(service=service, options=options)
        return browser_cls(options=options)

    async def async_request(self, url):
        async with aiohttp.ClientSession() as session:
            proxy_auth = aiohttp.BasicAuth(self.scan_config['proxy_user'], self.scan_config['proxy_pass']) if self.scan_config['proxy_user'] else None
            try:
                async with session.get(url, proxy=self.scan_config['proxy'], proxy_auth=proxy_auth, 
                                      timeout=aiohttp.ClientTimeout(total=self.scan_config['timeout']), 
                                      headers=self.scan_config['headers'], cookies=self.scan_config['cookies']) as resp:
                    return await resp.text()
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logging.error(f"Network error for {url}: {str(e)}")
                self.errors.append(f"Network: {str(e)}")
                return None

    def scan_single_url(self, url, payload, driver, completed_tasks, total_tasks):
        time.sleep(1/self.scan_config['rate_limit'])
        for _ in range(self.scan_config['retries']):
            try:
                result = self.test_vulnerability(url, self.selected_vuln, payload, driver)
                self.result_queue.put((url, self.selected_vuln, payload, result))
                self.progress['value'] = (completed_tasks / total_tasks) * 100
                self.status_label.config(text=f"Status: Testing {completed_tasks}/{total_tasks}")
                self.save_progress()
                break
            except Exception as e:
                logging.warning(f"Retry {_+1}/{self.scan_config['retries']} for {url}: {str(e)}")
                time.sleep(2 ** _)
        else:
            messagebox.showwarning("Network Error", f"Failed to scan {url} after {self.scan_config['retries']} retries")
            self.errors.append(f"Scan {url}: Max retries exceeded")

    def test_vulnerability(self, url, vuln_type, payload, driver):
        try:
            key = hashlib.md5(url.encode()).hexdigest()
            if key in self.response_cache:
                content = self.response_cache[key]
            else:
                content = asyncio.run(self.async_request(url))
                if content is None:
                    return "Network Error"
                self.response_cache[key] = content
            
            driver.get(url)
            if vuln_type == 'xss':
                page_source = driver.page_source.lower()
                if re.search(re.escape(payload.lower()), page_source):
                    if "document.write" in payload or "eval" in payload:
                        driver.execute_script(payload)
                        if "alert" in driver.page_source:
                            driver.save_screenshot(f"screenshots/vuln_{key}.png")
                            return "Vulnerable (DOM XSS)"
                    elif "<script" in page_source or "onerror=" in page_source:
                        driver.save_screenshot(f"screenshots/vuln_{key}.png")
                        return "Vulnerable (Reflected XSS)"
                return "Not Vulnerable"
            elif vuln_type == 'sqli':
                sql_errors = [
                    r"mysql_fetch", r"sql syntax", r"you have an error in your sql",
                    r"mysql_num_rows", r"ORA-[0-9]{5}", r"sqlite3"
                ]
                if any(re.search(err, content.lower()) for err in sql_errors) and payload.lower() in content:
                    driver.save_screenshot(f"screenshots/vuln_{key}.png")
                    return "Vulnerable (Error-Based)"
                if "SLEEP" in payload:
                    start_time = time.time()
                    asyncio.run(self.async_request(url))
                    if time.time() - start_time > 5:
                        driver.save_screenshot(f"screenshots/vuln_{key}.png")
                        return "Vulnerable (Time-Based)"
                if "AND 1=1" in payload:
                    true_content = content
                    false_url = url.replace("AND 1=1", "AND 1=2")
                    false_content = asyncio.run(self.async_request(false_url))
                    if true_content != false_content:
                        driver.save_screenshot(f"screenshots/vuln_{key}.png")
                        return "Vulnerable (Boolean-Based)"
                return "Not Vulnerable"
            elif vuln_type == 'open_redirect':
                final_url = driver.current_url
                if final_url != url and re.search(r'(evil\.com|http://[^/]*$)', final_url):
                    driver.save_screenshot(f"screenshots/vuln_{key}.png")
                    return "Vulnerable"
                return "Not Vulnerable"
            return "Not Vulnerable"
        except Exception as e:
            logging.error(f"Error scanning {url}: {str(e)}")
            self.errors.append(f"Scan {url}: {str(e)}")
            return f"Error: {str(e)}"

    def process_queue(self):
        try:
            while True:
                url, vuln_type, payload, status = self.result_queue.get_nowait()
                self.tree.insert("", tk.END, values=(url, vuln_type, payload, status))
                self.update_dashboard()
        except queue.Empty:
            pass
        if self.scanning:
            self.root.after(100, self.process_queue)

    def update_dashboard(self):
        vuln_counts = {self.selected_vuln.upper(): 0}
        for item in self.tree.get_children():
            vuln_type = self.tree.item(item, 'values')[1]
            if "Vulnerable" in self.tree.item(item, 'values')[3]:
                vuln_counts[vuln_type.upper()] += 1
        
        self.ax.clear()
        self.ax.bar(vuln_counts.keys(), vuln_counts.values(), color="#007acc")
        self.ax.set_title("Vulnerability Distribution", color="white" if self.current_theme == 'dark' else "black")
        self.ax.tick_params(colors="white" if self.current_theme == 'dark' else "black")
        self.dashboard_canvas.draw()

    def export_results(self, format_type):
        results = [self.tree.item(item, 'values') for item in self.tree.get_children()]
        password = simpledialog.askstring("Encryption", "Enter password for encryption (optional):", show='*')
        
        try:
            if format_type == 'json':
                file_path = 'scan_results.json'
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2)
            elif format_type == 'csv':
                file_path = 'scan_results.csv'
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["URL", "Type", "Payload", "Status"])
                    writer.writerows(results)
            
            if password:
                encrypted_file = file_path + '.enc'
                with open(file_path, 'rb') as f:
                    data = f.read()
                encrypted_data = self.cipher.encrypt(data)
                with open(encrypted_file, 'wb') as f:
                    f.write(encrypted_data)
                os.remove(file_path)
                messagebox.showinfo("Export", f"Results encrypted and exported as {encrypted_file}")
            else:
                messagebox.showinfo("Export", f"Results exported as {format_type.upper()}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export results: {str(e)}")
            self.errors.append(f"Export: {str(e)}")

    def export_html_report(self):
        results = [self.tree.item(item, 'values') for item in self.tree.get_children()]
        html_content = """
        <html>
        <head><title>Vulnerability Report</title>
        <style>
            body { font-family: Arial, sans-serif; background: #1f2a44; color: #e6e6e6; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th, td { border: 1px solid #007acc; padding: 10px; text-align: left; }
            th { background: #2d3b5a; }
            h1 { color: #007acc; }
            img { max-width: 200px; }
        </style>
        </head>
        <body>
        <h1>Vulnerability Scan Report</h1>
        <table>
            <tr><th>URL</th><th>Type</th><th>Payload</th><th>Status</th><th>Screenshot</th></tr>
        """
        for url, vuln_type, payload, status in results:
            key = hashlib.md5(url.encode()).hexdigest()
            screenshot = f"screenshots/vuln_{key}.png" if "Vulnerable" in status and os.path.exists(f"screenshots/vuln_{key}.png") else ""
            html_content += f"<tr><td>{url}</td><td>{vuln_type}</td><td>{payload}</td><td>{status}</td><td>{'<img src=\"' + screenshot + '\" />' if screenshot else ''}</td></tr>"
        
        html_content += """
        </table>
        </body>
        </html>
        """
        file_path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files", "*.html")])
        if file_path:
            os.makedirs("screenshots", exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            messagebox.showinfo("Export", "HTML report exported successfully")

    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.update_dashboard()
        self.error_summary_label.config(text="Errors: None")

    def show_error_summary(self):
        if self.errors:
            self.error_summary_label.config(text=f"Errors: {len(self.errors)} encountered (see log for details)")
        else:
            self.error_summary_label.config(text="Errors: None")

    def save_scan_history(self, urls):
        results = [self.tree.item(item, 'values') for item in self.tree.get_children()]
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.scan_history.append({"timestamp": timestamp, "vuln_type": self.selected_vuln, "urls": urls, "results": results})
        self.history_tree.insert("", tk.END, values=(timestamp, self.selected_vuln, len(urls), len([r for r in results if "Vulnerable" in r[3]])))

    def reload_scan(self):
        selected = self.history_tree.selection()
        if selected:
            index = self.history_tree.index(selected[0])
            scan = self.scan_history[index]
            self.selected_vuln = scan["vuln_type"]
            self.urls_to_scan = scan["urls"]
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, self.urls_to_scan[0])
            self.detect_parameters()
            self.clear_results()
            for url, vuln_type, payload, status in scan["results"]:
                self.tree.insert("", tk.END, values=(url, vuln_type, payload, status))
            self.update_dashboard()
            messagebox.showinfo("Reload", "Scan reloaded successfully")

    def save_progress(self):
        progress = {
            "urls": self.urls_to_scan,
            "vuln_type": self.selected_vuln,
            "payloads": self.payload_entry.get().split(","),
            "completed": [self.tree.item(item, 'values') for item in self.tree.get_children()]
        }
        try:
            with open("scan_progress.json", "w", encoding='utf-8') as f:
                json.dump(progress, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save progress: {str(e)}")
            self.errors.append(f"Save Progress: {str(e)}")

    def resume_scan(self):
        if os.path.exists("scan_progress.json"):
            try:
                with open("scan_progress.json", "r", encoding='utf-8') as f:
                    progress = json.load(f)
                self.urls_to_scan = progress["urls"]
                self.selected_vuln = progress["vuln_type"]
                self.payload_entry.delete(0, tk.END)
                self.payload_entry.insert(0, ",".join(progress["payloads"]))
                self.detect_parameters()
                self.clear_results()
                for url, vuln_type, payload, status in progress["completed"]:
                    self.tree.insert("", tk.END, values=(url, vuln_type, payload, status))
                self.start_scan()
                messagebox.showinfo("Resume", "Scan resumed successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to resume scan: {str(e)}")
                self.errors.append(f"Resume Scan: {str(e)}")
        else:
            messagebox.showinfo("Resume", "No previous scan progress found")

    def monitor_resources(self):
        cpu = psutil.cpu_percent()
        memory = psutil.virtual_memory().percent
        self.resource_label.config(text=f"Resources: CPU {cpu}%, Memory {memory}%")
        if cpu > 90 or memory > 90:
            messagebox.showwarning("Resource Warning", "High CPU or memory usage detected")
        self.root.after(5000, self.monitor_resources)

if __name__ == "__main__":
    root = ThemedTk(theme="clam")
    app = VulnerabilityScanner(root)
    root.mainloop()