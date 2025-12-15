# ==================== LINUX SEGFAULT FIX ====================
import os
os.environ['MPLCONFIGDIR'] = '/tmp'  # Prevent config conflicts

import matplotlib
matplotlib.use('TkAgg')  # Must set BEFORE importing pyplot

# Now import matplotlib components
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
# ===========================================================

# Continue with other imports...
import tkinter as tk
# ...
from tkinter import ttk, messagebox, filedialog, simpledialog, scrolledtext
import sqlite3
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
import hashlib
import csv
import threading
import queue
import webbrowser
from pathlib import Path
import zipfile
import shutil
import calendar
from collections import defaultdict
import matplotlib.dates as mdates
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import requests
import base64
import secrets
import string
import uuid
import logging
from logging.handlers import RotatingFileHandler
import configparser
import inspect
import traceback
import random
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any, Optional, Tuple
import statistics
from enum import Enum
import pickle
import html
import re
from openpyxl import load_workbook
import math

class Config:
    """Configuration manager"""
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config_file = 'config.ini'
        self.load_config()
        
    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self.create_default_config()
            
    def create_default_config(self):
        """Create default configuration"""
        self.config['DATABASE'] = {
            'name': 'site_management.db',
            'backup_path': 'backups/',
            'auto_backup': '1',
            'backup_interval': '24'  
        }
        
        self.config['SECURITY'] = {
            'password_min_length': '8',
            'password_require_special': '1',
            'max_login_attempts': '3',
            'session_timeout': '30' 
        }
        
        self.config['UI'] = {
            'theme': 'dark',
            'font_size': '11',
            'language': 'en'
        }
        
        self.config['EMAIL'] = {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': '587',
            'email_address': '',
            'email_password': ''
        }
        
        self.config['API'] = {
            'api_key': secrets.token_hex(32),
            'api_enabled': '0'
        }
        
        self.save_config()
        
    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            self.config.write(f)
            
    def get(self, section, key, default=None):
        """Get configuration value"""
        try:
            return self.config.get(section, key)
        except:
            return default

# ==================== LOGGING SYSTEM ====================

class Logger:
    """Advanced logging system with audit trail"""
    def __init__(self):
        self.logger = logging.getLogger('SiteManagement')
        self.logger.setLevel(logging.DEBUG)
        
        # File handler with rotation
        file_handler = RotatingFileHandler(
            'system.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Audit log
        self.audit_logger = logging.getLogger('Audit')
        audit_handler = logging.FileHandler('audit.log')
        audit_handler.setFormatter(formatter)
        self.audit_logger.addHandler(audit_handler)
        
    def info(self, message, user=None):
        """Log info message"""
        if user:
            message = f"[{user}] {message}"
        self.logger.info(message)
        
    def error(self, message, user=None):
        """Log error message"""
        if user:
            message = f"[{user}] {message}"
        self.logger.error(message)
        
    def audit(self, action, user, details=None):
        """Log audit trail"""
        log_msg = f"{action} by {user}"
        if details:
            log_msg += f" - {details}"
        self.audit_logger.info(log_msg)

# ==================== SECURITY SYSTEM ====================

class Security:
    """Enhanced security and authentication system"""
    def __init__(self):
        self.logger = Logger()
        self.config = Config()
        self.session_timeout = int(self.config.get('SECURITY', 'session_timeout', '30'))
        self.failed_attempts = {}
        
    def hash_password(self, password):
        """Hash password with salt"""
        salt = secrets.token_hex(16)
        hashed = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        )
        return f"{salt}${hashed.hex()}"
        
    def verify_password(self, password, hashed_password):
        """Verify password against hash"""
        try:
            salt, stored_hash = hashed_password.split('$')
            computed_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            ).hex()
            return stored_hash == computed_hash
        except:
            return False
            
    def validate_password_strength(self, password):
        """Validate password strength"""
        if len(password) < int(self.config.get('SECURITY', 'password_min_length', '8')):
            return False, "Password too short"
            
        if (self.config.get('SECURITY', 'password_require_special', '1') == '1' and
            not any(char in string.punctuation for char in password)):
            return False, "Password must contain special characters"
            
        if not any(char.isdigit() for char in password):
            return False, "Password must contain numbers"
            
        if not any(char.isupper() for char in password):
            return False, "Password must contain uppercase letters"
            
        return True, "Password is strong"
        
    def generate_api_key(self):
        """Generate secure API key"""
        return secrets.token_hex(32)
        
    def generate_session_token(self):
        """Generate session token"""
        return secrets.token_urlsafe(32)
        
    def check_rate_limit(self, ip_address):
        """Check rate limiting"""
        if ip_address not in self.failed_attempts:
            self.failed_attempts[ip_address] = {'count': 0, 'timestamp': datetime.now()}
            
        attempts = self.failed_attempts[ip_address]
        
        # Reset if more than 1 hour has passed
        if datetime.now() - attempts['timestamp'] > timedelta(hours=1):
            attempts['count'] = 0
            attempts['timestamp'] = datetime.now()
            
        max_attempts = int(self.config.get('SECURITY', 'max_login_attempts', '3'))
        
        if attempts['count'] >= max_attempts:
            return False
            
        return True

# ==================== DATABASE MODELS ====================

@dataclass
class User:
    """User model"""
    id: int = None
    username: str = ""
    password_hash: str = ""
    email: str = ""
    role: str = "user"
    permissions: str = "[]"
    department: str = ""
    last_login: str = ""
    is_active: bool = True
    created_at: str = ""
    
@dataclass
class Site:
    """Site model"""
    id: int = None
    site_id: str = ""
    name: str = ""
    province: str = ""
    district: str = ""
    location: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    status: str = ""
    operator: str = ""
    tower_type: str = ""
    tower_height: float = 0.0
    power_sources: str = ""
    monthly_revenue: float = 0.0
    investment_cost: float = 0.0
    coverage_radius: float = 0.0
    population_coverage: int = 0
    last_maintenance: str = ""
    next_maintenance: str = ""
    notes: str = ""
    created_by: str = ""
    created_at: str = ""
    updated_at: str = ""

@dataclass
class ExcelSite:
    """Enhanced Site model matching Excel structure"""
    id: int = None
    s_no: int = None
    site_id: str = ""
    knackrise_id: str = ""
    shared_with: str = ""
    province: str = ""
    location: str = ""
    introduced_date: str = ""
    operator_latitude: float = None
    operator_longitude: float = None
    surveyed: bool = False
    refered_to_aftel: bool = False
    applied_for_atra_license: bool = False
    received_atra_license: bool = False
    license_no: str = ""
    start_construction_work: str = ""
    rfi: str = ""
    on_air: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    status: str = ""
    tower_height: str = ""
    tower_type: str = ""
    power_sources: str = ""
    operator_site: str = ""
    operating_mnos: str = ""
    created_by: str = ""
    created_at: str = ""
    updated_at: str = ""
    
@dataclass
class Project:
    """Project model"""
    id: int = None
    project_code: str = ""
    name: str = ""
    description: str = ""
    start_date: str = ""
    end_date: str = ""
    budget: float = 0.0
    actual_cost: float = 0.0
    manager: str = ""
    status: str = ""
    progress: int = 0
    created_at: str = ""
    
@dataclass
class Equipment:
    """Equipment model"""
    id: int = None
    equipment_id: str = ""
    name: str = ""
    category: str = ""
    model: str = ""
    serial_no: str = ""
    site_id: str = ""
    purchase_date: str = ""
    purchase_cost: float = 0.0
    current_value: float = 0.0
    status: str = ""
    last_service: str = ""
    next_service: str = ""
    warranty_expiry: str = ""
    notes: str = ""
    
@dataclass
class MaintenanceTask:
    """Maintenance task model"""
    id: int = None
    task_id: str = ""
    site_id: str = ""
    equipment_id: str = ""
    task_type: str = ""
    description: str = ""
    assigned_to: str = ""
    priority: str = ""
    status: str = ""
    due_date: str = ""
    completed_date: str = ""
    estimated_hours: float = 0.0
    actual_hours: float = 0.0
    materials_used: str = ""
    cost: float = 0.0
    created_at: str = ""
    
@dataclass
class FinancialTransaction:
    """Financial transaction model"""
    id: int = None
    transaction_id: str = ""
    site_id: str = ""
    type: str = ""
    amount: float = 0.0
    currency: str = "USD"
    description: str = ""
    category: str = ""
    date: str = ""
    payment_method: str = ""
    reference_no: str = ""
    approved_by: str = ""
    created_at: str = ""
    
@dataclass
class Alert:
    """Alert model"""
    id: int = None
    alert_id: str = ""
    type: str = ""
    priority: str = ""
    message: str = ""
    entity_type: str = ""
    entity_id: str = ""
    status: str = "new"
    acknowledged_by: str = ""
    acknowledged_at: str = ""
    created_at: str = ""
    
    
class SerialNumberManager:
    """Manage automatic serial numbers for sites"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.logger = Logger()
        self.serial_cache = {}
        
    def get_next_serial(self, prefix='SITE', reset_per_year=True):
        """Get next serial number with optional prefix and year-based reset"""
        try:
            cursor = self.db.conn.cursor()
            
            # Get current year for reset logic
            current_year = datetime.now().year
            
            if reset_per_year:
                # Get max serial for current year
                cursor.execute("""
                    SELECT MAX(s_no) FROM excel_sites 
                    WHERE created_at LIKE ? OR updated_at LIKE ?
                """, (f"{current_year}%", f"{current_year}%"))
            else:
                # Get max serial overall
                cursor.execute("SELECT MAX(s_no) FROM excel_sites")
            
            result = cursor.fetchone()[0]
            
            if result is None:
                next_serial = 1
            else:
                next_serial = result + 1
            
            # Generate formatted serial number
            if reset_per_year:
                formatted_serial = f"{prefix}-{current_year}-{next_serial:04d}"
            else:
                formatted_serial = f"{prefix}-{next_serial:04d}"
            
            # Cache the serial number
            cache_key = f"{prefix}_{current_year}" if reset_per_year else prefix
            self.serial_cache[cache_key] = next_serial
            
            self.logger.info(f"Generated serial: {formatted_serial}")
            return next_serial, formatted_serial
            
        except Exception as e:
            self.logger.error(f"Error generating serial number: {e}")
            return 1, f"{prefix}-001"
    
    def validate_serial_consistency(self):
        """Validate and fix serial number inconsistencies"""
        try:
            cursor = self.db.conn.cursor()
            
            # Get all sites sorted by created_at
            cursor.execute("SELECT id, s_no, site_id FROM excel_sites ORDER BY created_at, id")
            sites = cursor.fetchall()
            
            inconsistencies = []
            expected_serial = 1
            
            # Check for gaps or duplicates
            for idx, (site_id, current_serial, site_identifier) in enumerate(sites, 1):
                if current_serial != expected_serial:
                    inconsistencies.append({
                        'site_id': site_identifier,
                        'current_serial': current_serial,
                        'expected_serial': expected_serial
                    })
                    
                    # Fix the inconsistency
                    cursor.execute("UPDATE excel_sites SET s_no = ? WHERE id = ?", 
                                 (expected_serial, site_id))
            
            if inconsistencies:
                self.db.conn.commit()
                self.logger.warning(f"Fixed {len(inconsistencies)} serial number inconsistencies")
                return True, f"Fixed {len(inconsistencies)} inconsistencies"
            else:
                return True, "Serial numbers are consistent"
                
        except Exception as e:
            self.logger.error(f"Error validating serial numbers: {e}")
            return False, str(e)
    
    def generate_bulk_serials(self, count, prefix='SITE'):
        """Generate multiple serial numbers at once"""
        serials = []
        try:
            next_serial, _ = self.get_next_serial(prefix, reset_per_year=False)
            
            for i in range(count):
                serial_number = next_serial + i
                formatted_serial = f"{prefix}-{serial_number:04d}"
                serials.append({
                    'numeric': serial_number,
                    'formatted': formatted_serial
                })
            
            return serials
            
        except Exception as e:
            self.logger.error(f"Error generating bulk serials: {e}")
            return []

# ==================== EXCEL INTEGRATION ====================

class ExcelIntegration:
    """Handle Excel data import and synchronization"""
    def __init__(self, db_manager):
        self.db = db_manager
        self.logger = Logger()
        
    def import_excel(self):
        """Enhanced Excel import with async support - Dashboard version"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
        
        # Clear main content area
        for widget in self.main_content.winfo_children():
            widget.destroy()
        
        # Create dashboard container
        dashboard_frame = tk.Frame(self.main_content, bg=self.bg_color)
        dashboard_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Dashboard header
        header_frame = tk.Frame(dashboard_frame, bg=self.bg_color)
        header_frame.pack(fill="x", pady=(0, 20))
        
        tk.Label(
            header_frame,
            text="📊 Excel Import Dashboard",
            font=(self.font_family, 24, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(side="left")
        
        # Back button
        tk.Button(
            header_frame,
            text="← Back to Main",
            font=(self.font_family, 10),
            bg="#4a5568",
            fg="white",
            relief="flat",
            command=self.show_main_page
        ).pack(side="right", padx=10)
        
        # Main dashboard content (2 columns)
        content_frame = tk.Frame(dashboard_frame, bg=self.bg_color)
        content_frame.pack(fill="both", expand=True)
        
        # Left panel - File Selection & Import
        left_panel = tk.Frame(content_frame, bg=self.bg_color, width=400)
        left_panel.pack(side="left", fill="both", padx=(0, 10))
        
        # Right panel - Statistics & Preview
        right_panel = tk.Frame(content_frame, bg=self.bg_color)
        right_panel.pack(side="right", fill="both", expand=True, padx=(10, 0))
        
        # === LEFT PANEL - Import Controls ===
        control_card = tk.LabelFrame(
            left_panel,
            text="Import Controls",
            font=(self.font_family, 12, "bold"),
            bg=self.bg_color,
            fg=self.fg_color,
            relief="solid",
            borderwidth=1,
            padx=15,
            pady=15
        )
        control_card.pack(fill="both", pady=(0, 15))
        
        # File selection section
        tk.Label(
            control_card,
            text="Select Excel File",
            font=(self.font_family, 10, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(anchor="w", pady=(0, 10))
        
        file_frame = tk.Frame(control_card, bg=self.bg_color)
        file_frame.pack(fill="x", pady=(0, 15))
        
        self.selected_file_var = tk.StringVar(value="No file selected")
        
        file_label = tk.Label(
            file_frame,
            textvariable=self.selected_file_var,
            font=(self.font_family, 9),
            bg="#2d3748",
            fg="#a0aec0",
            anchor="w",
            relief="sunken",
            padx=10,
            pady=8
        )
        file_label.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        def browse_file():
            filename = filedialog.askopenfilename(
                title="Select Excel File",
                filetypes=[
                    ("Excel files", "*.xlsx *.xls *.xlsm"),
                    ("CSV files", "*.csv"),
                    ("All files", "*.*")
                ]
            )
            if filename:
                self.selected_file_var.set(filename)
                # Preview file info
                self.preview_file_info(filename)
        
        tk.Button(
            file_frame,
            text="Browse",
            font=(self.font_family, 10),
            bg="#3182ce",
            fg="white",
            relief="flat",
            command=browse_file
        ).pack(side="right")
        
        # Import options
        options_frame = tk.Frame(control_card, bg=self.bg_color)
        options_frame.pack(fill="x", pady=(0, 20))
        
        self.update_existing_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            options_frame,
            text="Update existing records",
            variable=self.update_existing_var,
            font=(self.font_family, 9),
            bg=self.bg_color,
            fg=self.fg_color,
            selectcolor=self.bg_color,
            activebackground=self.bg_color,
            activeforeground=self.fg_color
        ).pack(anchor="w", pady=5)
        
        # Import button
        def start_import():
            filename = self.selected_file_var.get()
            if not filename or filename == "No file selected":
                messagebox.showwarning("No File", "Please select a file first")
                return
            
            # Show import progress in dashboard
            show_import_progress(filename, self.update_existing_var.get())
        
        import_btn = tk.Button(
            control_card,
            text="🚀 Start Import",
            font=(self.font_family, 12, "bold"),
            bg="#38a169",
            fg="white",
            relief="flat",
            padx=20,
            pady=10,
            command=start_import
        )
        import_btn.pack(pady=10)
        
        # Recent imports section
        recent_card = tk.LabelFrame(
            left_panel,
            text="Recent Imports",
            font=(self.font_family, 12, "bold"),
            bg=self.bg_color,
            fg=self.fg_color,
            relief="solid",
            borderwidth=1,
            padx=15,
            pady=15
        )
        recent_card.pack(fill="both", expand=True)
        
        # Create a canvas for recent imports with fixed height
        recent_canvas = tk.Canvas(recent_card, bg=self.bg_color, height=200, highlightthickness=0)
        recent_scrollbar = tk.Scrollbar(recent_card, orient="vertical", command=recent_canvas.yview)
        recent_scrollable_frame = tk.Frame(recent_canvas, bg=self.bg_color)
        
        recent_scrollable_frame.bind(
            "<Configure>",
            lambda e: recent_canvas.configure(scrollregion=recent_canvas.bbox("all"))
        )
        
        recent_canvas.create_window((0, 0), window=recent_scrollable_frame, anchor="nw")
        recent_canvas.configure(yscrollcommand=recent_scrollbar.set)
        
        recent_canvas.pack(side="left", fill="both", expand=True)
        recent_scrollbar.pack(side="right", fill="y")
        
        # Load recent imports
        self.load_recent_imports(recent_scrollable_frame)
        
        # === RIGHT PANEL - Statistics & Preview ===
        # Stats card
        stats_card = tk.LabelFrame(
            right_panel,
            text="Import Statistics",
            font=(self.font_family, 12, "bold"),
            bg=self.bg_color,
            fg=self.fg_color,
            relief="solid",
            borderwidth=1,
            padx=15,
            pady=15
        )
        stats_card.pack(fill="x", pady=(0, 15))
        
        # Stats grid
        stats_grid = tk.Frame(stats_card, bg=self.bg_color)
        stats_grid.pack(fill="x")
        
        # Stat items
        stat_items = [
            ("Total Imports", "0", "#3182ce"),
            ("Last Import", "Never", "#38a169"),
            ("Success Rate", "0%", "#d69e2e"),
            ("Total Records", "0", "#805ad5")
        ]
        
        for i, (label, value, color) in enumerate(stat_items):
            stat_frame = tk.Frame(stats_grid, bg=self.bg_color)
            stat_frame.grid(row=i//2, column=i%2, sticky="nsew", padx=5, pady=5)
            
            tk.Label(
                stat_frame,
                text=label,
                font=(self.font_family, 9),
                bg=self.bg_color,
                fg="#a0aec0"
            ).pack(anchor="w")
            
            tk.Label(
                stat_frame,
                text=value,
                font=(self.font_family, 16, "bold"),
                bg=self.bg_color,
                fg=color
            ).pack(anchor="w")
        
        # Make grid columns expand equally
        stats_grid.grid_columnconfigure(0, weight=1)
        stats_grid.grid_columnconfigure(1, weight=1)
        
        # Preview card
        preview_card = tk.LabelFrame(
            right_panel,
            text="File Preview",
            font=(self.font_family, 12, "bold"),
            bg=self.bg_color,
            fg=self.fg_color,
            relief="solid",
            borderwidth=1,
            padx=15,
            pady=15
        )
        preview_card.pack(fill="both", expand=True)
        
        # Preview content
        self.preview_text = tk.Text(
            preview_card,
            height=15,
            font=("Courier New", 9),
            bg="#1a202c",
            fg="#e2e8f0",
            relief="flat",
            wrap="none"
        )
        self.preview_text.pack(fill="both", expand=True)
        
        # Add scrollbars
        preview_scroll_y = tk.Scrollbar(preview_card, command=self.preview_text.yview)
        preview_scroll_y.pack(side="right", fill="y")
        preview_scroll_x = tk.Scrollbar(preview_card, orient="horizontal", command=self.preview_text.xview)
        preview_scroll_x.pack(side="bottom", fill="x")
        
        self.preview_text.configure(
            yscrollcommand=preview_scroll_y.set,
            xscrollcommand=preview_scroll_x.set
        )
        
        # Initial message in preview
        self.preview_text.insert("1.0", "Select a file to preview its contents...")
        self.preview_text.configure(state="disabled")
        
        def preview_file_info(filename):
            """Preview file information"""
            try:
                import os
                import pandas as pd
                
                self.preview_text.configure(state="normal")
                self.preview_text.delete("1.0", tk.END)
                
                file_size = os.path.getsize(filename) / (1024 * 1024)  # MB
                file_ext = os.path.splitext(filename)[1]
                file_name = os.path.basename(filename)
                
                # Show basic file info
                info = f"📄 File: {file_name}\n"
                info += f"📁 Type: {file_ext.upper()} file\n"
                info += f"📊 Size: {file_size:.2f} MB\n"
                info += "─" * 50 + "\n\n"
                
                # Try to read and preview first few rows
                try:
                    if file_ext.lower() in ['.xlsx', '.xls', '.xlsm']:
                        df = pd.read_excel(filename, nrows=10)
                    elif file_ext.lower() == '.csv':
                        df = pd.read_csv(filename, nrows=10)
                    else:
                        df = None
                    
                    if df is not None:
                        info += "Preview of first 10 rows:\n"
                        info += "─" * 50 + "\n"
                        info += df.to_string(index=False)
                        info += f"\n\nTotal columns: {len(df.columns)}"
                        info += f"\nTotal rows: {len(df)}"
                except Exception as e:
                    info += f"\n⚠️ Cannot preview content: {str(e)}"
                
                self.preview_text.insert("1.0", info)
                self.preview_text.configure(state="disabled")
                
            except Exception as e:
                self.preview_text.insert("1.0", f"Error reading file: {str(e)}")
                self.preview_text.configure(state="disabled")
        
        def load_recent_imports(parent_frame):
            """Load recent import history"""
            try:
                # Clear existing items
                for widget in parent_frame.winfo_children():
                    widget.destroy()
                
                # Get recent imports from database
                imports = self.db.excel_integration.get_import_history(limit=5)
                
                if not imports:
                    tk.Label(
                        parent_frame,
                        text="No recent imports",
                        font=(self.font_family, 9),
                        bg=self.bg_color,
                        fg="#718096"
                    ).pack(pady=20)
                    return
                
                for i, imp in enumerate(imports):
                    # Create import item frame
                    item_frame = tk.Frame(parent_frame, bg="#2d3748", relief="solid", borderwidth=1)
                    item_frame.pack(fill="x", pady=2, padx=2)
                    
                    # File name
                    tk.Label(
                        item_frame,
                        text=imp.get('filename', 'Unknown'),
                        font=(self.font_family, 9, "bold"),
                        bg="#2d3748",
                        fg="#e2e8f0"
                    ).pack(anchor="w", padx=10, pady=(5, 0))
                    
                    # Status and date
                    status_frame = tk.Frame(item_frame, bg="#2d3748")
                    status_frame.pack(fill="x", padx=10, pady=(0, 5))
                    
                    status = imp.get('status', 'unknown')
                    status_color = "#38a169" if status == 'success' else "#e53e3e"
                    
                    tk.Label(
                        status_frame,
                        text=status.upper(),
                        font=(self.font_family, 8),
                        bg=status_color,
                        fg="white",
                        padx=5,
                        pady=1
                    ).pack(side="left")
                    
                    tk.Label(
                        status_frame,
                        text=imp.get('created_at', ''),
                        font=(self.font_family, 8),
                        bg="#2d3748",
                        fg="#a0aec0"
                    ).pack(side="right")
                    
            except Exception as e:
                print(f"Error loading recent imports: {e}")
        
        def show_import_progress(filename, update_existing):
            """Show import progress in dashboard"""
            # Create progress overlay
            overlay = tk.Toplevel(self.root)
            overlay.title("Importing...")
            overlay.geometry("500x300")
            overlay.configure(bg=self.bg_color)
            overlay.transient(self.root)
            overlay.grab_set()
            
            # Center the window
            overlay.update_idletasks()
            width = overlay.winfo_width()
            height = overlay.winfo_height()
            x = (overlay.winfo_screenwidth() // 2) - (width // 2)
            y = (overlay.winfo_screenheight() // 2) - (height // 2)
            overlay.geometry(f'{width}x{height}+{x}+{y}')
            
            # Progress content
            tk.Label(
                overlay,
                text="🚀 Importing Excel Data",
                font=(self.font_family, 16, "bold"),
                bg=self.bg_color,
                fg=self.fg_color
            ).pack(pady=20)
            
            # File info
            file_name = os.path.basename(filename)
            tk.Label(
                overlay,
                text=f"File: {file_name}",
                font=(self.font_family, 10),
                bg=self.bg_color,
                fg="#a0aec0"
            ).pack(pady=5)
            
            # Progress bar
            progress_var = tk.DoubleVar()
            progress_bar = ttk.Progressbar(
                overlay,
                variable=progress_var,
                maximum=100,
                mode='indeterminate',
                length=400
            )
            progress_bar.pack(pady=20, padx=20)
            progress_bar.start()
            
            # Status label
            status_label = tk.Label(
                overlay,
                text="Reading file...",
                font=(self.font_family, 10),
                bg=self.bg_color,
                fg="#d69e2e"
            )
            status_label.pack(pady=10)
            
            def import_task():
                """Background import task"""
                try:
                    result = self.db.excel_integration.import_excel_file(filename, update_existing)
                    return result
                except Exception as e:
                    return {'error': str(e)}
            
            def on_import_complete(future):
                """Handle import completion"""
                try:
                    result = future.result()
                    
                    # Stop progress bar
                    progress_bar.stop()
                    
                    if 'error' in result:
                        status_label.config(text=f"❌ Error: {result['error']}", fg="#e53e3e")
                        # Close after 3 seconds
                        overlay.after(3000, overlay.destroy)
                    else:
                        imported = result.get('imported', 0)
                        updated = result.get('updated', 0)
                        
                        status_label.config(
                            text=f"✅ Import Complete!\nImported: {imported} | Updated: {updated}",
                            fg="#38a169",
                            font=(self.font_family, 11, "bold")
                        )
                        
                        # Add success animation
                        success_label = tk.Label(
                            overlay,
                            text="🎉",
                            font=(self.font_family, 24),
                            bg=self.bg_color
                        )
                        success_label.pack(pady=10)
                        
                        # Close after 3 seconds and refresh
                        overlay.after(3000, lambda: [overlay.destroy(), self.load_excel_sites(), load_recent_imports(recent_scrollable_frame)])
                        
                except Exception as e:
                    overlay.destroy()
                    messagebox.showerror("Error", f"Unexpected error: {e}")
            
            # Submit async task
            task_id = f"import_{datetime.now().strftime('%H%M%S')}"
            self.async_manager.submit_task(task_id, import_task)
            
            # Poll for completion
            def check_completion():
                future = self.async_manager.get_result(task_id)
                if future is not None:
                    if future.done():
                        on_import_complete(future)
                    else:
                        overlay.after(100, check_completion)
                else:
                    overlay.after(100, check_completion)
            
            overlay.after(100, check_completion)
        
        # Store functions as instance variables
        self.preview_file_info = preview_file_info
        self.show_import_progress = lambda f, u: show_import_progress(f, u)
        
        # Load initial statistics
        def load_statistics():
            try:
                stats = self.db.excel_integration.get_import_stats()
                # Update stats display here
            except:
                pass
        
        load_statistics()
    
    def clean_headers(self, header_row):
        """Clean Excel headers"""
        headers = []
        for header in header_row:
            if header:
                # Clean header name
                clean_header = str(header).strip().lower()
                clean_header = clean_header.replace(' ', '_').replace('.', '')
                clean_header = clean_header.replace('(', '').replace(')', '')
                clean_header = clean_header.replace('-', '_')
                headers.append(clean_header)
            else:
                headers.append(f"column_{len(headers)}")
        return headers
    
    def row_to_dict(self, row, headers):
        """Convert Excel row to dictionary"""
        site_data = {}
        for i, value in enumerate(row):
            if i < len(headers):
                header = headers[i]
                if value is not None:
                    # Clean the value
                    if isinstance(value, str):
                        value = value.strip()
                    elif isinstance(value, (int, float)):
                        # Handle numeric values
                        if math.isnan(value):
                            value = None
                    
                    # Special handling for specific columns
                    if header in ['latitude', 'longitude', 'operator_latitude', 'operator_longitude']:
                        if isinstance(value, str) and '°' in value:
                            # Convert degree format to decimal
                            value = self.convert_dms_to_decimal(value)
                        elif value == '':
                            value = None
                    
                    # Convert Yes/No to boolean
                    if header in ['surveyed', 'refered_to_aftel', 'applied_for_atra_license', 'received_atra_license']:
                        if isinstance(value, str):
                            value = value.strip().lower() in ['yes', 'true', '1', 'y']
                        elif isinstance(value, (int, float)):
                            value = bool(value)
                    
                    site_data[header] = value
        return site_data
    
    def convert_dms_to_decimal(self, dms_str):
        """Convert DMS format to decimal"""
        try:
            # Remove degree symbol and spaces
            dms_str = str(dms_str).replace('°', ' ').replace("'", ' ').replace('"', ' ').replace('  ', ' ')
            parts = dms_str.split()
            
            if len(parts) >= 1:
                degrees = float(parts[0])
                minutes = float(parts[1]) if len(parts) > 1 else 0
                seconds = float(parts[2]) if len(parts) > 2 else 0
                
                decimal = degrees + (minutes / 60) + (seconds / 3600)
                return round(decimal, 6)
        except:
            pass
        return 0.0
    
    def export_to_excel(self, sites_data, file_path):
        """Export data to Excel format"""
        try:
            # Create DataFrame with Excel structure
            df = pd.DataFrame(sites_data)
            
            # Reorder columns to match Excel format
            excel_columns = [
                'S. No', 'Site ID', 'KnackRise ID', 'Shared with', 'Province', 'Location',
                'Introduced Date', 'Operator_Latitude', 'Operator_Longitude', 'Surveyed',
                'Refered to AFTEL', 'Applied for ATRA License', 'Received ATRA License',
                'License NO.', 'Start Construction work', 'RFI', 'On-Air', 'Latitude',
                'Longitude', 'Status', 'Tower Height', 'Tower Type', 'Power Sources',
                'Operator Site', 'Operating MNOs'
            ]
            
            # Map internal column names to Excel column names
            column_mapping = {
                's_no': 'S. No',
                'site_id': 'Site ID',
                'knackrise_id': 'KnackRise ID',
                'shared_with': 'Shared with',
                'province': 'Province',
                'location': 'Location',
                'introduced_date': 'Introduced Date',
                'operator_latitude': 'Operator_Latitude',
                'operator_longitude': 'Operator_Longitude',
                'surveyed': 'Surveyed',
                'refered_to_aftel': 'Refered to AFTEL',
                'applied_for_atra_license': 'Applied for ATRA License',
                'received_atra_license': 'Received ATRA License',
                'license_no': 'License NO.',
                'start_construction_work': 'Start Construction work',
                'rfi': 'RFI',
                'on_air': 'On-Air',
                'latitude': 'Latitude',
                'longitude': 'Longitude',
                'status': 'Status',
                'tower_height': 'Tower Height',
                'tower_type': 'Tower Type',
                'power_sources': 'Power Sources',
                'operator_site': 'Operator Site',
                'operating_mnos': 'Operating MNOs'
            }
            
            # Rename columns
            df = df.rename(columns=column_mapping)
            
            # Add missing columns
            for col in excel_columns:
                if col not in df.columns:
                    df[col] = ''
            
            # Reorder columns
            df = df[excel_columns]
            
            # Export to Excel
            df.to_excel(file_path, index=False)
            self.logger.info(f"Exported {len(df)} sites to Excel: {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting to Excel: {e}")
            return False

# ==================== ENHANCED DATABASE MANAGER ====================
class EnhancedDatabaseManager:
    _instance = None
    _initialized = False  # Internal flag to prevent re-initialization

    def __new__(cls, *args, **kwargs):
        """Singleton pattern: ensure only one instance exists"""
        if cls._instance is None:
            cls._instance = super(EnhancedDatabaseManager, cls).__new__(cls)
        return cls._instance

    def __init__(self, db_path='site_management.db'):
        """Initialize only once"""
        if EnhancedDatabaseManager._initialized:
            return  # Already initialized – skip to prevent multiple connections

        EnhancedDatabaseManager._initialized = True

        self.db_path = db_path
        self.conn = None
        self.logger = Logger()
        self.security = Security()
        self.config = Config()
        self.excel_integration = ExcelIntegration(self)

        self.connect()
        self.create_tables()
        self.create_excel_tables()
        self.create_triggers()
        self.create_views()
        self.seed_data()

        self.logger.info("Database initialized successfully (singleton)")

    # ==================== CORE METHODS ====================
    def connect(self):
        """Connect to database"""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON")
            self.conn.execute("PRAGMA journal_mode = WAL")
            self.logger.info("Database connected successfully")
        except Exception as e:
            self.logger.error(f"Database connection failed: {e}")
            raise

    def create_tables(self):
        """Create all database tables"""
        cursor = self.conn.cursor()
        # [All your CREATE TABLE statements here – unchanged]
        # Users, sites, projects, equipment, maintenance_tasks, financial_transactions, alerts, audit_log
        # ... (keep exactly as you have them)
        self.conn.commit()
        self.logger.info("Database tables created successfully")

    def create_excel_tables(self):
        """Create tables for Excel structure"""
        cursor = self.conn.cursor()
        # excel_sites and dropdown_values tables
        # ... (keep exactly as you have them)
        self.conn.commit()

    def create_triggers(self):
        """Create database triggers"""
        cursor = self.conn.cursor()
        # update_excel_site_timestamp trigger
        # ... (keep as is)
        self.conn.commit()

    def create_views(self):
        """Create database views"""
        cursor = self.conn.cursor()
        # vw_excel_sites_summary view
        # ... (keep as is)
        self.conn.commit()

    def seed_data(self):
        """Seed database with initial data"""
        cursor = self.conn.cursor()
        # Admin user + dropdown values
        # ... (keep as is)
        self.conn.commit()

    def seed_dropdown_values(self):
        """Seed dropdown values from Excel structure"""
        # ... (keep as is)

    # ==================== YOUR EXISTING METHODS (unchanged) ====================
    def get_financial_transactions(self, site_id=None, type_filter=None):
        """Get financial transactions with optional filters"""
        try:
            cursor = self.conn.cursor()
            query = "SELECT * FROM financial_transactions WHERE 1=1"
            params = []
            if site_id:
                query += " AND site_id = ?"
                params.append(site_id)
            if type_filter and type_filter != "All":
                query += " AND type = ?"
                params.append(type_filter)
            query += " ORDER BY date DESC"
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        except:
            return []
       
    def get_financial_transactions(self, site_id=None, type_filter=None):
        """Get financial transactions with optional filters"""
        try:
            cursor = self.conn.cursor()
            query = "SELECT * FROM financial_transactions WHERE 1=1"
            params = []
            if site_id:
                query += " AND site_id = ?"
                params.append(site_id)
            if type_filter and type_filter != "All":
                query += " AND type = ?"
                params.append(type_filter)
            query += " ORDER BY date DESC"
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        except:
            return []
        
    def get_next_serial_number(self):
        """Get next available serial number"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT MAX(s_no) FROM excel_sites")
            result = cursor.fetchone()[0]
            return 1 if result is None else result + 1
        except Exception as e:
            self.logger.error(f"Error getting next serial: {e}")
            return 1

    def validate_serial_consistency(self):
        """Fix serial number gaps and duplicates"""
        try:
            cursor = self.conn.cursor()
            
            # Get all sites in order
            cursor.execute("SELECT id, s_no FROM excel_sites ORDER BY created_at, id")
            sites = cursor.fetchall()
            
            fixed_count = 0
            for index, (site_id, current_serial) in enumerate(sites, 1):
                if current_serial != index:
                    cursor.execute("UPDATE excel_sites SET s_no = ? WHERE id = ?", (index, site_id))
                    fixed_count += 1
            
            if fixed_count > 0:
                self.conn.commit()
                self.logger.info(f"Fixed {fixed_count} serial inconsistencies")
            
            return True, f"Fixed {fixed_count} inconsistencies"
            
        except Exception as e:
            self.logger.error(f"Error fixing serials: {e}")
            return False, str(e)

    def get_serial_statistics(self):
        """Get serial number statistics"""
        stats = {}
        try:
            cursor = self.conn.cursor()
            
            # Total count
            cursor.execute("SELECT COUNT(*) FROM excel_sites")
            stats['total'] = cursor.fetchone()[0]
            
            # Min/Max
            cursor.execute("SELECT MIN(s_no), MAX(s_no) FROM excel_sites")
            stats['min'], stats['max'] = cursor.fetchone()
            
            # Next serial
            stats['next'] = (stats['max'] + 1) if stats['max'] else 1
            
            # Gaps
            cursor.execute("""
                SELECT COUNT(*) FROM excel_sites s1 
                WHERE NOT EXISTS (
                    SELECT 1 FROM excel_sites s2 
                    WHERE s2.s_no = s1.s_no + 1
                ) AND s1.s_no < (SELECT MAX(s_no) FROM excel_sites)
            """)
            stats['gaps'] = cursor.fetchone()[0]
            
        except Exception as e:
            self.logger.error(f"Error getting serial stats: {e}")
        
        return stats
 
    def get_user_by_username(self, username):
        """Get user by username for authentication"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT id, username, password_hash, email, role, permissions, 
                    department, last_login, is_active, created_at
                FROM users 
                WHERE username = ? AND is_active = 1
            """, (username,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
        except Exception as e:
            self.logger.error(f"Error getting user by username: {e}")
            return None
    
    def add_excel_site(self, site_data):
        """Add site with Excel structure with automatic serial number"""
        try:
            cursor = self.conn.cursor()
            
            if 'site_id' in site_data and site_data['site_id']:
                cursor.execute("SELECT id FROM excel_sites WHERE site_id = ?", (site_data['site_id'],))
                existing = cursor.fetchone()
                
                if existing:
                    # Update - preserve existing serial number
                    set_clause = []
                    values = []
                    for key, value in site_data.items():
                        if key != 'site_id' and key != 's_no' and value is not None:
                            set_clause.append(f"{key} = ?")
                            values.append(value)
                    values.append(site_data['site_id'])
                    
                    query = f"UPDATE excel_sites SET {', '.join(set_clause)}, updated_at = CURRENT_TIMESTAMP WHERE site_id = ?"
                    cursor.execute(query, values)
                    action = "updated"
                else:
                    # Insert new - assign serial automatically
                    if 's_no' not in site_data or not site_data['s_no']:
                        site_data['s_no'] = self.get_next_serial_number()
                    
                    columns = []
                    placeholders = []
                    values = []
                    
                    for key, value in site_data.items():
                        if value is not None:
                            columns.append(key)
                            placeholders.append('?')
                            values.append(value)
                    
                    query = f"INSERT INTO excel_sites ({', '.join(columns)}, created_at, excel_import_date) VALUES ({', '.join(placeholders)}, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                    cursor.execute(query, values)
                    action = "added"
                
                self.conn.commit()
                return True, site_data.get('site_id', 'Unknown')
                
        except Exception as e:
            self.logger.error(f"Error adding Excel site: {e}")
            return False, str(e)
    
    def get_excel_sites(self, filters=None):
        """Get sites in Excel format"""
        try:
            cursor = self.conn.cursor()
            
            query = "SELECT * FROM excel_sites WHERE 1=1"
            values = []
            
            if filters:
                if filters.get('province'):
                    query += " AND province = ?"
                    values.append(filters['province'])
                    
                if filters.get('status'):
                    query += " AND status = ?"
                    values.append(filters['status'])
                    
                if filters.get('operator_site'):
                    query += " AND operator_site = ?"
                    values.append(filters['operator_site'])
                    
                if filters.get('tower_type'):
                    query += " AND tower_type = ?"
                    values.append(filters['tower_type'])
                    
                if filters.get('power_sources'):
                    query += " AND power_sources = ?"
                    values.append(filters['power_sources'])
                    
                if filters.get('search'):
                    search = f"%{filters['search']}%"
                    query += " AND (site_id LIKE ? OR location LIKE ? OR province LIKE ? OR knackrise_id LIKE ?)"
                    values.extend([search, search, search, search])
            
            query += " ORDER BY s_no, site_id"
            cursor.execute(query, values)
            
            sites = []
            for row in cursor.fetchall():
                sites.append(dict(row))
            
            return sites
            
        except Exception as e:
            self.logger.error(f"Error getting Excel sites: {e}")
            return []
    
    def get_excel_site(self, site_id):
        """Get single Excel site"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM excel_sites WHERE site_id = ?", (site_id,))
            row = cursor.fetchone()
            
            if row:
                return dict(row)
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting Excel site: {e}")
            return None
    
    def delete_excel_site(self, site_id):
        """Delete Excel site"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM excel_sites WHERE site_id = ?", (site_id,))
            self.conn.commit()
            
            self.logger.info(f"Excel site deleted: {site_id}")
            return True, "Site deleted"
            
        except Exception as e:
            self.logger.error(f"Error deleting Excel site: {e}")
            return False, str(e)
    
    def get_excel_dashboard_data(self):
        """Get data for Excel-style dashboard"""
        data = {
            'by_province': [],
            'by_operator': [],
            'by_status': [],
            'by_tower_type': [],
            'by_power_source': [],
            'maintenance_needed': []
        }
        
        try:
            cursor = self.conn.cursor()
            
            # Sites by province
            cursor.execute('''
            SELECT province, COUNT(*) as count,
                   SUM(CASE WHEN status = 'Active' THEN 1 ELSE 0 END) as active,
                   SUM(CASE WHEN status = 'Confirmed' THEN 1 ELSE 0 END) as confirmed,
                   SUM(CASE WHEN status IN ('Resurvey', 'Fresh Introduced', 'Surveyed') THEN 1 ELSE 0 END) as pending
            FROM excel_sites
            WHERE province IS NOT NULL AND province != ''
            GROUP BY province
            ORDER BY count DESC
            ''')
            data['by_province'] = [dict(row) for row in cursor.fetchall()]
            
            # Sites by operator
            cursor.execute('''
            SELECT operator_site, COUNT(*) as count
            FROM excel_sites
            WHERE operator_site IS NOT NULL AND operator_site != ''
            GROUP BY operator_site
            ORDER BY count DESC
            ''')
            data['by_operator'] = [dict(row) for row in cursor.fetchall()]
            
            # Status distribution
            cursor.execute('''
            SELECT status, COUNT(*) as count
            FROM excel_sites
            WHERE status IS NOT NULL AND status != ''
            GROUP BY status
            ORDER BY count DESC
            ''')
            data['by_status'] = [dict(row) for row in cursor.fetchall()]
            
            # Tower type distribution
            cursor.execute('''
            SELECT tower_type, COUNT(*) as count
            FROM excel_sites
            WHERE tower_type IS NOT NULL AND tower_type != ''
            GROUP BY tower_type
            ORDER BY count DESC
            ''')
            data['by_tower_type'] = [dict(row) for row in cursor.fetchall()]
            
            # Power source distribution
            cursor.execute('''
            SELECT power_sources, COUNT(*) as count
            FROM excel_sites
            WHERE power_sources IS NOT NULL AND power_sources != ''
            GROUP BY power_sources
            ORDER BY count DESC
            ''')
            data['by_power_source'] = [dict(row) for row in cursor.fetchall()]
            
            # Sites needing attention
            cursor.execute('''
            SELECT site_id, location, province, status, updated_at
            FROM excel_sites
            WHERE status IN ('Resurvey', 'Fresh Introduced', 'Surveyed')
               OR julianday('now') - julianday(updated_at) > 90
            ORDER BY updated_at ASC
            LIMIT 20
            ''')
            data['maintenance_needed'] = [dict(row) for row in cursor.fetchall()]
            
        except Exception as e:
            self.logger.error(f"Error getting Excel dashboard data: {e}")
        
        return data
    
    def get_dropdown_values(self, category):
        """Get dropdown values for a category"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
            SELECT value FROM dropdown_values 
            WHERE category = ? AND is_active = 1
            ORDER BY display_order, value
            ''', (category,))
            
            return [row[0] for row in cursor.fetchall()]
            
        except Exception as e:
            self.logger.error(f"Error getting dropdown values: {e}")
            return []
    
    def get_excel_statistics(self):
        """Get Excel data statistics"""
        stats = {}
        
        try:
            cursor = self.conn.cursor()
            
            # Total sites
            cursor.execute("SELECT COUNT(*) FROM excel_sites")
            stats['total_sites'] = cursor.fetchone()[0]
            
            # By status
            cursor.execute('''
            SELECT status, COUNT(*) as count 
            FROM excel_sites 
            WHERE status IS NOT NULL 
            GROUP BY status
            ''')
            stats['by_status'] = dict(cursor.fetchall())
            
            # By province
            cursor.execute('''
            SELECT province, COUNT(*) as count 
            FROM excel_sites 
            WHERE province IS NOT NULL 
            GROUP BY province
            ''')
            stats['by_province'] = dict(cursor.fetchall())
            
            # By operator
            cursor.execute('''
            SELECT operator_site, COUNT(*) as count 
            FROM excel_sites 
            WHERE operator_site IS NOT NULL 
            GROUP BY operator_site
            ''')
            stats['by_operator'] = dict(cursor.fetchall())
            
            # Last import date
            cursor.execute("SELECT MAX(excel_import_date) FROM excel_sites")
            last_import = cursor.fetchone()[0]
            stats['last_import'] = last_import if last_import else "Never"
            
        except Exception as e:
            self.logger.error(f"Error getting Excel statistics: {e}")
        
        return stats
    
    # ==================== MAINTENANCE METHODS ====================
    
    def add_maintenance_task(self, task_data):
        """Add maintenance task to database"""
        try:
            cursor = self.conn.cursor()
            
            if 'task_id' not in task_data:
                task_data['task_id'] = f"MT-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(4)}"
            
            columns = []
            placeholders = []
            values = []
            
            for key, value in task_data.items():
                if value is not None:
                    columns.append(key)
                    placeholders.append('?')
                    values.append(value)
            
            query = f"INSERT INTO maintenance_tasks ({', '.join(columns)}) VALUES ({', '.join(placeholders)})"
            cursor.execute(query, values)
            self.conn.commit()
            
            return True, task_data['task_id']
        except Exception as e:
            return False, str(e)

    def get_maintenance_tasks(self, site_id=None):
        """Get maintenance tasks for a site"""
        try:
            cursor = self.conn.cursor()
            
            if site_id:
                cursor.execute("SELECT * FROM maintenance_tasks WHERE site_id = ? ORDER BY due_date", (site_id,))
            else:
                cursor.execute("SELECT * FROM maintenance_tasks ORDER BY due_date DESC")
            
            return [dict(row) for row in cursor.fetchall()]
        except:
            return []

    def update_maintenance_task(self, task_id, status):
        """Update maintenance task status"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE maintenance_tasks 
                SET status = ?, completed_date = ?
                WHERE task_id = ?
            """, (status, datetime.now().strftime('%Y-%m-%d') if status == 'completed' else None, task_id))
            self.conn.commit()
            return True
        except:
            return False
    
    def get_maintenance_statistics(self):
        """Get maintenance statistics"""
        stats = {}
        try:
            cursor = self.conn.cursor()
            
            # Total maintenance tasks
            cursor.execute("SELECT COUNT(*) FROM maintenance_tasks")
            stats['total_tasks'] = cursor.fetchone()[0]
            
            # Tasks by status
            cursor.execute("SELECT status, COUNT(*) as count FROM maintenance_tasks GROUP BY status")
            stats['by_status'] = dict(cursor.fetchall())
            
            # Tasks by priority
            cursor.execute("SELECT priority, COUNT(*) as count FROM maintenance_tasks GROUP BY priority")
            stats['by_priority'] = dict(cursor.fetchall())
            
            # Tasks by type
            cursor.execute("SELECT task_type, COUNT(*) as count FROM maintenance_tasks GROUP BY task_type")
            stats['by_type'] = dict(cursor.fetchall())
            
            # Overdue tasks
            cursor.execute("SELECT COUNT(*) FROM maintenance_tasks WHERE status = 'pending' AND due_date < date('now')")
            stats['overdue_tasks'] = cursor.fetchone()[0]
            
            # Upcoming tasks (next 7 days)
            cursor.execute("SELECT COUNT(*) FROM maintenance_tasks WHERE status = 'pending' AND due_date BETWEEN date('now') AND date('now', '+7 days')")
            stats['upcoming_tasks'] = cursor.fetchone()[0]
            
        except Exception as e:
            self.logger.error(f"Error getting maintenance statistics: {e}")
        
        return stats
    
    def delete_maintenance_task(self, task_id):
        """Delete maintenance task"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM maintenance_tasks WHERE task_id = ?", (task_id,))
            self.conn.commit()
            return True
        except:
            return False
        
        
# ==================== MAIN GUI APPLICATION ====================

class SiteManagementSystem:
    
    
    """Main GUI application with Excel integration"""
    def setup_costs_tab(self):
        """Already exists in your code – now it will be called!"""
        # No change needed – just ensuring it's called
        pass  # Your existing setup_costs_tab() is perfect

    def setup_available_tools_tab(self):
        """New tab: Available Tools"""
        tab = self.tabs["📦 Tools"]
        
        main_frame = tk.Frame(tab, bg=self.bg_color)
        main_frame.pack(fill="both", expand=True, padx=30, pady=30)
        
        tk.Label(
            main_frame,
            text="📦 Tools ",
            font=("Arial", 20, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=(0, 30))
        
        tools = [
            ("🔢 Serial Number Tools", self.show_serial_tools, "#2196F3"),
            ("📊 Excel Statistics", self.show_excel_statistics, "#4CAF50"),
            ("🔧 Maintenance Statistics", self.show_maintenance_statistics, "#FF9800"),
            ("✅ Data Validation", self.validate_excel_data, "#9C27B0"),
            ("🧹 Data Cleanup", self.cleanup_excel_data, "#F44336"),
            ("🗄️ Backup Database", self.backup_database, "#607D8B"),
            ("📥 Restore Database", self.restore_database, "#795548"),
        ]
        
        for i, (text, command, color) in enumerate(tools):
            row = i // 3
            col = i % 3
            
            btn = tk.Button(
                main_frame,
                text=text,
                command=command,
                font=("Arial", 12),
                bg=color,
                fg="white",
                relief="flat",
                padx=20,
                pady=15,
                width=25,
                height=3
            )
            btn.grid(row=row, column=col, padx=15, pady=15)
        
        # Center the grid
        for i in range(3):
            main_frame.grid_columnconfigure(i, weight=1)

    def setup_report_tab(self):
        """New tab: Quick Reports"""
        tab = self.tabs["👥 Report"]
        
        main_frame = tk.Frame(tab, bg=self.bg_color)
        main_frame.pack(fill="both", expand=True, padx=30, pady=30)
        
        tk.Label(
            main_frame,
            text="👥 Quick Reports & Exports",
            font=("Arial", 20, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=(0, 30))
        
        reports = [
            ("📈 Generate Full Analysis Report", self.generate_analysis_report, "#1976D2"),
            ("📊 Excel Data Dashboard", self.show_excel_dashboard, "#4CAF50"),
            ("📤 Export All Sites to Excel", self.export_excel, "#2196F3"),
            ("💰 Financial Report (Costs Tab)", lambda: self.notebook.select(4), "#FF9800"),
            ("📋 Maintenance Report", self.show_all_maintenance, "#9C27B0"),
        ]
        
        for i, (text, command, color) in enumerate(reports):
            row = i // 2
            col = i % 2
            
            btn = tk.Button(
                main_frame,
                text=text,
                command=command,
                font=("Arial", 12),
                bg=color,
                fg="white",
                relief="flat",
                padx=20,
                pady=15,
                width=35,
                height=3
            )
            btn.grid(row=row, column=col, padx=30, pady=20)
        
        for i in range(2):
            main_frame.grid_columnconfigure(i, weight=1)
            
    def show_serial_tools(self):
        """Show serial number management tools"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
        
        tools_window = tk.Toplevel(self.root)
        tools_window.title("Serial Number Tools")
        tools_window.geometry("500x400")
        tools_window.configure(bg=self.bg_color)
        tools_window.transient(self.root)
        
        # Center window
        tools_window.update_idletasks()
        width = tools_window.winfo_width()
        height = tools_window.winfo_height()
        x = (tools_window.winfo_screenwidth() // 2) - (width // 2)
        y = (tools_window.winfo_screenheight() // 2) - (height // 2)
        tools_window.geometry(f'{width}x{height}+{x}+{y}')
        
        # Title
        tk.Label(
            tools_window,
            text="🔢 Serial Number Management",
            font=("Arial", 16, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=20)
        
        # Main frame
        main_frame = tk.Frame(tools_window, bg=self.bg_color)
        main_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        # 1. Check Consistency Button
        def check_and_fix():
            success, message = self.db.validate_serial_consistency()
            if success:
                messagebox.showinfo("Success", message)
                self.load_excel_sites()
            else:
                messagebox.showerror("Error", message)
        
        tk.Button(
            main_frame,
            text="🔍 Check & Fix Serial Numbers",
            command=check_and_fix,
            bg="#2196F3",
            fg="white",
            font=("Arial", 11),
            relief="flat",
            pady=10,
            width=30
        ).pack(pady=10)
        
        # 2. Show Statistics Button
        def show_stats():
            stats = self.db.get_serial_statistics()
            stats_text = f"""
            📊 Serial Number Statistics:
            
            Total Sites: {stats.get('total', 0)}
            Minimum S.No: {stats.get('min', 'N/A')}
            Maximum S.No: {stats.get('max', 'N/A')}
            Next Available: {stats.get('next', 1)}
            Gaps in Sequence: {stats.get('gaps', 0)}
            
            Status: {'✅ Consistent' if stats.get('gaps', 0) == 0 else '⚠️ Needs Attention'}
            """
            messagebox.showinfo("Serial Statistics", stats_text)
        
        tk.Button(
            main_frame,
            text="📊 Show Serial Statistics",
            command=show_stats,
            bg="#4CAF50",
            fg="white",
            font=("Arial", 11),
            relief="flat",
            pady=10,
            width=30
        ).pack(pady=10)
        
        # 3. Reset Serials (Danger Zone)
        def reset_serials():
            if messagebox.askyesno("Confirm Reset", 
                                "This will renumber ALL sites starting from 1.\n\n⚠️ This cannot be undone!",
                                icon='warning'):
                try:
                    cursor = self.db.conn.cursor()
                    cursor.execute("SELECT id FROM excel_sites ORDER BY created_at, id")
                    sites = cursor.fetchall()
                    
                    for index, (site_id,) in enumerate(sites, 1):
                        cursor.execute("UPDATE excel_sites SET s_no = ? WHERE id = ?", (index, site_id))
                    
                    self.db.conn.commit()
                    messagebox.showinfo("Success", f"Renumbered {len(sites)} sites")
                    self.load_excel_sites()
                    
                except Exception as e:
                    messagebox.showerror("Error", f"Failed: {e}")
        
        tk.Button(
            main_frame,
            text="⚠️ Reset All Serial Numbers",
            command=reset_serials,
            bg="#F44336",
            fg="white",
            font=("Arial", 11),
            relief="flat",
            pady=10,
            width=30
        ).pack(pady=10)
        
        # 4. Next Serial Info
        next_serial = self.db.get_next_serial_number() if hasattr(self.db, 'get_next_serial_number') else 1
        tk.Label(
            main_frame,
            text=f"Next available serial number: {next_serial}",
            font=("Arial", 10, "bold"),
            bg=self.bg_color,
            fg=self.accent_color
        ).pack(pady=20)
        
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🏢 Knackrise TTSP Project Management System")
        self.root.geometry("1600x900")
        
        # Initialize systems
        self.config = Config()
        self.logger = Logger()
        self.security = Security()
        self.db = EnhancedDatabaseManager()
        
        # Current user
        self.current_user = None
        self.user_permissions = []
        
        # Setup theme
        self.setup_theme()
        
        # Setup GUI
        self.setup_gui()
        
        # Start background tasks
        self.start_background_tasks()
        
    def setup_theme(self):
        """Setup application theme"""
        theme = self.config.get('UI', 'theme', 'light')
        
        if theme == 'dark':
            self.bg_color = "#8ec5d3"
            self.fg_color = "#090F0F"
            self.accent_color = '#007acc'
            self.secondary_bg = '#3c3c3c'
            self.highlight_color = '#4a4a4a'
            self.sidebar_bg = '#1e1e1e'
        else:
            self.bg_color = '#f0f0f0'
            self.fg_color = '#000000'
            self.accent_color = '#007acc'
            self.secondary_bg = '#ffffff'
            self.highlight_color = '#e0e0e0'
            self.sidebar_bg = '#e8e8e8'
            
        self.root.configure(bg=self.bg_color)
        
    def setup_gui(self):
        """Setup main GUI"""
        # Menu bar
        self.create_menu_bar()
        
        # Main container
        self.main_container = tk.Frame(self.root, bg=self.bg_color)
        self.main_container.pack(fill="both", expand=True, padx=2, pady=2)
        
        # Header
        self.create_header()
        
        # Main content area with tabs
        self.create_main_tabs()
        
        # Status bar
        self.create_status_bar()
        
    def create_menu_bar(self):
        """Create application menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Login", command=self.show_login)
        file_menu.add_command(label="Logout", command=self.logout)
        file_menu.add_separator()
        file_menu.add_command(label="Import Excel", command=self.import_excel)
        file_menu.add_command(label="Export Excel", command=self.export_excel)
        file_menu.add_separator()
        file_menu.add_command(label="Backup Database", command=self.backup_database)
        file_menu.add_command(label="Restore Database", command=self.restore_database)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Add Site", command=self.add_excel_site)
        edit_menu.add_command(label="Edit Site", command=self.edit_excel_site)
        edit_menu.add_command(label="Delete Site", command=self.delete_excel_site)
        edit_menu.add_separator()
        edit_menu.add_command(label="Find", command=self.search_sites)
        edit_menu.add_command(label="Refresh", command=self.refresh_dashboard)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Dashboard", command=lambda: self.notebook.select(0))
        view_menu.add_command(label="Excel Sites", command=lambda: self.notebook.select(1))
        view_menu.add_command(label="Maintenance", command=lambda: self.notebook.select(2))
        view_menu.add_command(label="Analyze", command=lambda: self.notebook.select(3))
        view_menu.add_command(label="Excel Dashboard", command=self.show_excel_dashboard)
        view_menu.add_separator()
        view_menu.add_command(label="Show Filters", command=self.toggle_filters)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Excel Statistics", command=self.show_excel_statistics)
        tools_menu.add_command(label="Maintenance Stats", command=self.show_maintenance_statistics)
        tools_menu.add_command(label="Data Validation", command=self.validate_excel_data)
        tools_menu.add_command(label="Data Cleanup", command=self.cleanup_excel_data)
        tools_menu.add_separator()
        tools_menu.add_command(label="System Settings", command=self.show_settings)
        
        
        # Analyze menu
        analyze_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Analyze", menu=analyze_menu)
        analyze_menu.add_command(label="Site Distribution", command=lambda: self.show_analysis('site_distribution'))
        analyze_menu.add_command(label="Status Analysis", command=lambda: self.show_analysis('status'))
        analyze_menu.add_command(label="Geographic Analysis", command=lambda: self.show_analysis('geographic'))
        analyze_menu.add_command(label="Timeline Analysis", command=lambda: self.show_analysis('timeline'))
        analyze_menu.add_command(label="Comparative Analysis", command=lambda: self.show_analysis('comparative'))
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="User Guide", command=self.show_user_guide)
        help_menu.add_command(label="About Excel Format", command=self.show_excel_format_info)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self.show_about)
        
    def create_header(self):
        """Create application header"""
        header = tk.Frame(self.main_container, bg=self.accent_color, height=60)
        header.pack(fill="x", pady=(0, 2))
        
        # Title with logo
        title_frame = tk.Frame(header, bg=self.accent_color)
        title_frame.pack(side="left", padx=20)
        
        # Logo/Icon
        tk.Label(
            title_frame,
            text="🏢",
            font=("Arial", 24),
            bg=self.accent_color,
            fg="white"
        ).pack(side="left", padx=(0, 10))
        
        # Title text
        tk.Label(
            title_frame,
            text="Knackrise TTSP Project",
            font=("Arial", 20, "bold"),
            bg=self.accent_color,
            fg="white"
        ).pack(side="left")
        
        # Subtitle
        tk.Label(
            title_frame,
            text=" Site Management System",
            font=("Arial", 12),
            bg=self.accent_color,
            fg="#e0e0e0"
        ).pack(side="left", padx=(10, 0))
        
        # User info and stats on right
        right_frame = tk.Frame(header, bg=self.accent_color)
        right_frame.pack(side="right", padx=20)
        
        # User info
        self.user_label = tk.Label(
            right_frame,
            text="👤 Not logged in",
            font=("Arial", 10, "bold"),
            bg=self.accent_color,
            fg="white"
        )
        self.user_label.pack(side="top", pady=(5, 0))
        
        # Quick stats
        self.stats_label = tk.Label(
            right_frame,
            text="Sites: 0 | Active: 0 | Pending: 0",
            font=("Arial", 9),
            bg=self.accent_color,
            fg="#e0e0e0"
        )
        self.stats_label.pack(side="bottom", pady=(0, 5))
        
    def create_main_tabs(self):
        """Create main tabbed interface"""
        # Create notebook
        style = ttk.Style()
        style.theme_use('clam')
        
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill="both", expand=True)
        
        # Create tabs
        self.tabs = {}
        
                
        excel_tab = ttk.Frame(self.notebook)
        self.notebook.add(excel_tab, text="📁 Excel Sites")
        self.tabs["📁 Excel Sites"] = excel_tab
        tab_names = [
            "📊 Dashboard",
            "📁 Sites",
            "🔧 Maintenance",
            "📈 Analyze",
            "💰 Costs",
            "📦 Available Tools",
            "👥 Report"
        ]
        
        for tab_name in tab_names:
            frame = tk.Frame(self.notebook, bg=self.bg_color)
            self.notebook.add(frame, text=tab_name)
            self.tabs[tab_name] = frame
            
        # Setup each tab
        self.setup_dashboard_tab()
        self.setup_excel_sites_tab()
        self.setup_maintenance_tab()
        self.setup_analyze_tab()
        self.setup_costs_tab()
        self.setup_available_tools_tab() # ← NEW
        self.setup_report_tab()
        
    def setup_dashboard_tab(self):
        """Setup dashboard tab with left sidebar and right content"""
        tab = self.tabs["📊 Dashboard"]
        
        # Create main container
        main_container = tk.Frame(tab, bg=self.bg_color)
        main_container.pack(fill="both", expand=True, padx=2, pady=2)
        
        # Left sidebar for buttons
        sidebar = tk.Frame(main_container, bg=self.sidebar_bg, width=250)
        sidebar.pack(side="left", fill="y", padx=(0, 2))
        sidebar.pack_propagate(False)
        
        # Right content area for dashboard
        content_area = tk.Frame(main_container, bg=self.bg_color)
        content_area.pack(side="right", fill="both", expand=True)
        
        # Create sidebar content
        self.create_dashboard_sidebar(sidebar)
        
        # Create enhanced dashboard content
        self.create_enhanced_dashboard_content(content_area)
        
    def create_dashboard_sidebar(self, parent):
        """Create left sidebar with buttons"""
        # Sidebar title
        tk.Label(
            parent,
            text="Quick Actions",
            font=("Arial", 14, "bold"),
            bg=self.sidebar_bg,
            fg='white',
            pady=10
        ).pack(fill="x")
        
        # Separator
        ttk.Separator(parent, orient='horizontal').pack(fill="x", padx=10, pady=5)
        
        # Define action buttons
        actions = [
            ("📥 Import From Excel", self.import_excel, "#1863c9"),
            ("📤 Export To Excel", self.export_excel, "#1863c9"),
            ("➕ Add New Site", self.add_excel_site, "#1863c9"),
            ("✏️ Edit Selected Site", self.edit_excel_site, "#1863c9"),
            ("🗑️ Delete Selected Site", self.delete_excel_site, "#1863c9"),
            ("🔍 Search Sites", self.search_sites, "#1863c9"),
            ("📊 View Dashboard", self.show_excel_dashboard, "#1863c9"),
            ("🧹 Cleanup Data", self.cleanup_excel_data, "#1863c9"),
            ("📋 View Maintenance", self.show_all_maintenance, "#1863c9"),
            ("📈 Generate Report", self.generate_analysis_report, "#1863c9")
        ]
        
        # Create buttons
        self.sidebar_buttons = {}
        for text, command, color in actions:
            btn = tk.Button(
                parent,
                text=text,
                command=command,
                bg="#1863c9",
                fg="white",
                font=("Arial", 10),
                relief="flat",
                padx=10,
                pady=12,
                cursor="hand2",
                anchor="w",
                width=20
            )
            btn.pack(fill="x", padx=10, pady=5)
            self.sidebar_buttons[text] = btn
            
            # Add hover effect
            btn.bind("<Enter>", lambda e, b=btn: b.configure(bg=self.lighten_color(b.cget('bg'))))
            btn.bind("<Leave>", lambda e, b=btn, c="#1863c9": b.configure(bg=c))
        
        # Add keyboard shortcuts info
        ttk.Separator(parent, orient='horizontal').pack(fill="x", padx=10, pady=10)
        
        shortcuts_frame = tk.Frame(parent, bg=self.sidebar_bg)
        shortcuts_frame.pack(fill="x", padx=10, pady=5)
        
        
    def create_enhanced_dashboard_content(self, parent):
        """Create enhanced dashboard – SINGLE PAGE, NO SCROLLING, Font Size 12"""
        # Main dashboard frame (no canvas/scrollbar needed)
        dashboard_frame = tk.Frame(parent, bg=self.bg_color)
        dashboard_frame.pack(fill="both", expand=True, padx=15, pady=10)

        # Configure grid weights for responsive layout
        for i in range(10):
            dashboard_frame.rowconfigure(i, weight=1 if i in [4, 6] else 0)  # Expand rows with tables/bars
        for i in range(4):
            dashboard_frame.columnconfigure(i, weight=1)

        # === ROW 0: Welcome & Refresh ===
        welcome_frame = tk.Frame(dashboard_frame, bg=self.bg_color)
        welcome_frame.grid(row=0, column=0, columnspan=4, sticky="ew", pady=(0, 10))

        tk.Label(
            welcome_frame,
            text="📊 Site Management Dashboard",
            font=("Arial", 16, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(side="left")

        tk.Label(
            welcome_frame,
            text="Real-time insights and system status",
            font=("Arial", 12),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(side="left", padx=(20, 0))

        tk.Button(
            welcome_frame,
            text="🔄 Refresh All",
            command=self.refresh_dashboard,
            bg=self.accent_color,
            fg="white",
            font=("Arial", 12),
            relief="flat",
            padx=15,
            pady=5
        ).pack(side="right")

        # === ROW 1: Key Metrics (4 cards in one row) ===
        metrics_container = tk.Frame(dashboard_frame, bg=self.bg_color)
        metrics_container.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(0, 10))

        self.metrics_cards = {}
        metric_definitions = [
            {"title": "TOTAL SITES", "icon": "🏢", "data_key": "total_sites"},
            {"title": "ACTIVE SITES", "icon": "✅", "data_key": "active_sites"},
            {"title": "PENDING REVIEW", "icon": "⏳", "data_key": "pending_sites"},
            {"title": "DATA COMPLETENESS", "icon": "📊", "data_key": "completeness", "suffix": "%"},
        ]

        for i, metric in enumerate(metric_definitions):
            card = tk.Frame(metrics_container, bg=self.secondary_bg, relief="flat", bd=1, height=100)
            card.pack(side="left", expand=True, fill="both", padx=5)
            card.pack_propagate(False)

            tk.Label(card, text=metric["icon"], font=("Arial", 20), bg=self.secondary_bg, fg="white").pack(pady=(10, 0))
            value_lbl = tk.Label(card, text="0", font=("Arial", 20, "bold"), bg=self.secondary_bg, fg=self.accent_color)
            value_lbl.pack()
            tk.Label(card, text=metric["title"], font=("Arial", 12), bg=self.secondary_bg, fg=self.fg_color).pack()
            self.metrics_cards[metric["data_key"]] = {"value": value_lbl, "suffix": metric.get("suffix", "")}

        # === ROW 2: System Health (left) + Quick Stats (right) ===
        health_frame = tk.Frame(dashboard_frame, bg=self.bg_color)
        health_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=(0, 5))

        tk.Label(health_frame, text="🔧 SYSTEM HEALTH", font=("Arial", 12, "bold"), bg=self.bg_color, fg=self.fg_color).pack(anchor="w")
        health_grid = tk.Frame(health_frame, bg=self.bg_color)
        health_grid.pack(fill="x", pady=5)

        self.health_indicators = {}
        indicators = [
            ("Database Status", "db_status", "💾"),
            ("Excel Sync", "excel_sync", "📁"),
            ("Maintenance Tasks", "maintenance_status", "🔧"),
            ("Data Backup", "backup_status", "🗄️")
        ]
        for i, (label, key, icon) in enumerate(indicators):
            row = tk.Frame(health_grid, bg=self.bg_color)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=icon, font=("Arial", 12), bg=self.bg_color, fg=self.fg_color, width=4).pack(side="left")
            tk.Label(row, text=label, font=("Arial", 12), bg=self.bg_color, fg=self.fg_color).pack(side="left", padx=10)
            status_lbl = tk.Label(row, text="●", font=("Arial", 12), bg=self.bg_color, fg="#FF9800")
            status_lbl.pack(side="right", padx=10)
            self.health_indicators[key] = {"status": status_lbl}

        # Quick Statistics (right side)
        quick_frame = tk.Frame(dashboard_frame, bg=self.bg_color)
        quick_frame.grid(row=2, column=2, columnspan=2, sticky="nsew", padx=(5, 0))

        tk.Label(quick_frame, text="📊 QUICK STATISTICS", font=("Arial", 12, "bold"), bg=self.bg_color, fg=self.fg_color).pack(anchor="w")
        quick_grid = tk.Frame(quick_frame, bg=self.bg_color)
        quick_grid.pack(fill="both", expand=True)

        self.stats_labels = {}
        quick_stats = [
            ("Top Province", "top_province", "🏛️"),
            ("Top Operator", "top_operator", "🏢"),
            ("Status Summary", "status_summary", "📈"),
            ("Top Tower Type", "top_tower", "🗼"),
            ("Top Power Source", "top_power", "⚡"),
            ("Maintenance", "maintenance_stats", "🔧")
        ]
        for i, (title, key, icon) in enumerate(quick_stats):
            r, c = divmod(i, 3)
            stat_card = tk.Frame(quick_grid, bg=self.secondary_bg, relief="flat", bd=1, height=70)
            stat_card.grid(row=r, column=c, padx=5, pady=5, sticky="nsew")
            stat_card.pack_propagate(False)
            tk.Label(stat_card, text=f"{icon} {title}", font=("Arial", 12), bg=self.secondary_bg, fg=self.fg_color, anchor="w").pack(padx=10, pady=(8, 2), anchor="w")
            val_lbl = tk.Label(stat_card, text="—", font=("Arial", 12), bg=self.secondary_bg, fg=self.accent_color, anchor="w")
            val_lbl.pack(padx=10, anchor="w")
            self.stats_labels[key] = val_lbl

        quick_grid.grid_columnconfigure((0,1,2), weight=1)

        # === ROW 3: Recent Activity (left) + Urgent Alerts (right) ===
        activity_frame = tk.Frame(dashboard_frame, bg=self.bg_color)
        activity_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=(0, 5), pady=10)

        tk.Label(activity_frame, text="📋 RECENT ACTIVITY", font=("Arial", 12, "bold"), bg=self.bg_color, fg=self.fg_color).pack(anchor="w")
        self.activity_listbox = tk.Listbox(activity_frame, font=("Arial", 12), height=5)
        self.activity_listbox.pack(fill="both", expand=True, pady=5)

        alerts_frame = tk.Frame(dashboard_frame, bg=self.bg_color)
        alerts_frame.grid(row=3, column=2, columnspan=2, sticky="nsew", padx=(5, 0), pady=10)

        header = tk.Frame(alerts_frame, bg=self.bg_color)
        header.pack(fill="x")
        tk.Label(header, text="🚨 URGENT ALERTS", font=("Arial", 12, "bold"), bg=self.bg_color, fg=self.fg_color).pack(side="left")
        self.alerts_count_label = tk.Label(header, text="0 alerts", font=("Arial", 12), bg=self.bg_color, fg="#F44336")
        self.alerts_count_label.pack(side="right")
        self.alerts_listbox = tk.Listbox(alerts_frame, font=("Arial", 12), height=5, bg="#FFF0F0")
        self.alerts_listbox.pack(fill="both", expand=True, pady=5)

        # === ROW 4: Recent Sites Table (full width) ===
        sites_frame = tk.Frame(dashboard_frame, bg=self.bg_color)
        sites_frame.grid(row=4, column=0, columnspan=4, sticky="nsew", pady=10)

        tk.Label(sites_frame, text="📋 RECENTLY UPDATED SITES", font=("Arial", 12, "bold"), bg=self.bg_color, fg=self.fg_color).pack(anchor="w")
        tree_container = tk.Frame(sites_frame)
        tree_container.pack(fill="both", expand=True)

        columns = ("Site ID", "Province", "Location", "Status", "Last Update", "Operator")
        self.recent_tree = ttk.Treeview(tree_container, columns=columns, show="headings", height=10)
        for col in columns:
            self.recent_tree.heading(col, text=col)
            self.recent_tree.column(col, width=150, anchor="w")
        self.recent_tree.grid(row=0, column=0, sticky="nsew")
        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=self.recent_tree.yview)
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=self.recent_tree.xview)
        self.recent_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)

        # Tag colors
        self.recent_tree.tag_configure('active', background='#e8f5e8')
        self.recent_tree.tag_configure('pending', background='#fff3e0')

        # === ROW 5: Performance Indicators ===
        perf_frame = tk.Frame(dashboard_frame, bg=self.bg_color)
        perf_frame.grid(row=5, column=0, columnspan=4, sticky="ew", pady=(0, 10))

        tk.Label(perf_frame, text="📈 PERFORMANCE INDICATORS", font=("Arial", 12, "bold"), bg=self.bg_color, fg=self.fg_color).pack(anchor="w")
        self.performance_bars = {}
        indicators = [
            ("Data Quality", "data_quality", "#4CAF50"),
            ("Update Frequency", "update_freq", "#2196F3"),
            ("Completeness", "completeness", "#FF9800"),
            ("Maintenance Rate", "maintenance_rate", "#9C27B0")
        ]
        for i, (label, key, color) in enumerate(indicators):
            bar_row = tk.Frame(perf_frame, bg=self.bg_color)
            bar_row.pack(fill="x", pady=4)
            tk.Label(bar_row, text=label, font=("Arial", 12), bg=self.bg_color, fg=self.fg_color, width=18, anchor="w").pack(side="left")
            bar_frame = tk.Frame(bar_row, bg="#e0e0e0", height=20)
            bar_frame.pack(side="left", fill="x", expand=True, padx=10)
            bar_frame.pack_propagate(False)
            progress = tk.Frame(bar_frame, bg=color)
            progress.pack(side="left", fill="y")
            percent_lbl = tk.Label(bar_row, text="0%", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)
            percent_lbl.pack(side="right")
            self.performance_bars[key] = {"bar": progress, "percent": percent_lbl}

        # Initial data load
        self.update_enhanced_dashboard()
        
    def create_metric_card(self, parent, metric, index):
        """Create a metric card"""
        card = tk.Frame(
            parent,
            bg=self.secondary_bg,
            relief="flat",
            bd=1,
            width=180,
            height=100
        )
        card.pack_propagate(False)
        
        # Card content
        icon_label = tk.Label(
            card,
            text=metric["icon"],
            font=("Arial", 24),
            bg=self.secondary_bg,
            fg=metric["color"]
        )
        icon_label.pack(anchor="nw", padx=15, pady=15)
        
        metric_value = tk.Label(
            card,
            text="0",
            font=("Arial", 20, "bold"),
            bg=self.secondary_bg,
            fg=metric["color"]
        )
        metric_value.pack(anchor="nw", padx=15, pady=(0, 5))
        
        metric_title = tk.Label(
            card,
            text=metric["title"],
            font=("Arial", 9),
            bg=self.secondary_bg,
            fg=self.fg_color
        )
        metric_title.pack(anchor="nw", padx=15)
        
        metric_desc = tk.Label(
            card,
            text=metric["description"],
            font=("Arial", 8),
            bg=self.secondary_bg,
            fg="#666666"
        )
        metric_desc.pack(anchor="nw", padx=15, pady=(0, 10))
        
        # Pack card
        if index % 2 == 0:
            card.pack(side="left", padx=(0, 10), pady=10, fill="y")
        else:
            card.pack(side="left", padx=(0, 10), pady=10, fill="y")
        
        return {"frame": card, "value": metric_value, "suffix": metric.get("suffix", "")}
    
    def create_health_indicator(self, parent, indicator, index):
        """Create health status indicator"""
        health_item = tk.Frame(parent, bg=self.bg_color)
        health_item.pack(fill="x", pady=5)
        
        icon_label = tk.Label(
            health_item,
            text=indicator["icon"],
            font=("Arial", 14),
            bg=self.bg_color,
            fg=self.fg_color,
            width=3
        )
        icon_label.pack(side="left")
        
        text_label = tk.Label(
            health_item,
            text=indicator["label"],
            font=("Arial", 10),
            bg=self.bg_color,
            fg=self.fg_color,
            anchor="w"
        )
        text_label.pack(side="left", padx=(5, 10), fill="x", expand=True)
        
        status_label = tk.Label(
            health_item,
            text="●",
            font=("Arial", 12),
            bg=self.bg_color,
            fg="#FF9800"  # Default yellow/orange
        )
        status_label.pack(side="right")
        
        return {"frame": health_item, "status": status_label}
    
    def create_performance_bar(self, parent, indicator, index):
        """Create performance bar with label"""
        bar_container = tk.Frame(parent, bg=self.bg_color)
        bar_container.pack(fill="x", pady=5)
        
        # Label
        tk.Label(
            bar_container,
            text=indicator["label"],
            font=("Arial", 10),
            bg=self.bg_color,
            fg=self.fg_color,
            width=15,
            anchor="w"
        ).pack(side="left", padx=(0, 10))
        
        # Bar frame
        bar_frame = tk.Frame(bar_container, bg="#e0e0e0", height=15)
        bar_frame.pack(side="left", fill="x", expand=True)
        bar_frame.pack_propagate(False)
        
        # Progress bar
        progress_bar = tk.Frame(bar_frame, bg=indicator["color"], width=0)
        progress_bar.pack(side="left", fill="y")
        
        # Percentage label
        percent_label = tk.Label(
            bar_container,
            text="0%",
            font=("Arial", 9),
            bg=self.bg_color,
            fg=self.fg_color,
            width=5
        )
        percent_label.pack(side="right", padx=(10, 0))
        
        return {"bar": progress_bar, "percent": percent_label, "color": indicator["color"]}
    
    def lighten_color(self, color, factor=0.2):
        """Lighten a color"""
        # Convert hex to RGB
        if color.startswith('#'):
            color = color[1:]
        r = int(color[0:2], 16)
        g = int(color[2:4], 16)
        b = int(color[4:6], 16)
        
        # Lighten
        r = min(255, int(r * (1 + factor)))
        g = min(255, int(g * (1 + factor)))
        b = min(255, int(b * (1 + factor)))
        
        # Convert back to hex
        return f'#{r:02x}{g:02x}{b:02x}'
    
    def refresh_dashboard(self):
        """Refresh all dashboard data"""
        self.update_status("Refreshing dashboard...")
        self.update_enhanced_dashboard()
        self.update_status("Dashboard refreshed")
        self.load_maintenance_tasks()
    
    def update_enhanced_dashboard(self):
        """Update all dashboard components"""
        try:
            if not self.current_user:
                return
            
            # Get all data
            excel_stats = self.db.get_excel_statistics()
            maint_stats = self.db.get_maintenance_statistics()
            dash_data = self.db.get_excel_dashboard_data()
            sites = self.db.get_excel_sites()
            
            # 1. Update metrics cards
            self.update_metrics_cards(excel_stats, maint_stats, sites)
            
            # 2. Update health indicators
            self.update_health_indicators(excel_stats, maint_stats)
            
            # 3. Update activity list
            self.update_activity_list(sites)
            
            # 4. Update alerts
            self.update_alerts_list(excel_stats, maint_stats)
            
            # 5. Update quick stats
            self.update_quick_stats(dash_data, excel_stats, maint_stats)
            
            # 6. Update recent sites
            self.update_recent_sites_table(sites)
            
            # 7. Update performance bars
            self.update_performance_bars(excel_stats, maint_stats, sites)
            
            # 8. Update header stats
            self.update_header_stats(excel_stats)
            
        except Exception as e:
            self.logger.error(f"Error updating dashboard: {e}")
    
    def update_metrics_cards(self, excel_stats, maint_stats, sites):
        """Update metric cards with data"""
        try:
            total_sites = excel_stats.get('total_sites', 0)
            
            # Calculate active sites
            active_sites = excel_stats.get('by_status', {}).get('Active', 0)
            
            # Calculate pending sites
            pending_statuses = ['Resurvey', 'Fresh Introduced', 'Surveyed']
            pending_sites = sum(excel_stats.get('by_status', {}).get(status, 0) 
                              for status in pending_statuses)
            
            # Calculate data completeness
            completeness = self.calculate_data_completeness()
            
            # Update cards
            cards_data = {
                'total_sites': str(total_sites),
                'active_sites': str(active_sites),
                'pending_sites': str(pending_sites),
                'completeness': f"{completeness:.1f}%"
            }
            
            for key, card in self.metrics_cards.items():
                if key in cards_data:
                    card["value"].config(text=cards_data[key])
                    
        except Exception as e:
            self.logger.error(f"Error updating metrics cards: {e}")
    
    def update_health_indicators(self, excel_stats, maint_stats):
        """Update system health indicators"""
        try:
            # Database status (always good if we got stats)
            self.update_health_indicator('db_status', 'good', '●')
            
            # Excel sync status (check last import)
            last_import = excel_stats.get('last_import', 'Never')
            if last_import == 'Never':
                self.update_health_indicator('excel_sync', 'warning', '⚠️')
            else:
                try:
                    last_import_date = datetime.strptime(str(last_import), '%Y-%m-%d %H:%M:%S')
                    days_since = (datetime.now() - last_import_date).days
                    if days_since > 7:
                        self.update_health_indicator('excel_sync', 'warning', '⚠️')
                    else:
                        self.update_health_indicator('excel_sync', 'good', '✅')
                except:
                    self.update_health_indicator('excel_sync', 'warning', '⚠️')
            
            # Maintenance status
            overdue_tasks = maint_stats.get('overdue_tasks', 0)
            if overdue_tasks > 0:
                self.update_health_indicator('maintenance_status', 'error', f'❗{overdue_tasks}')
            else:
                self.update_health_indicator('maintenance_status', 'good', '✅')
            
            # Backup status
            backup_dir = 'backups'
            if os.path.exists(backup_dir):
                backup_files = [f for f in os.listdir(backup_dir) if f.endswith('.db')]
                if backup_files:
                    self.update_health_indicator('backup_status', 'good', '✅')
                else:
                    self.update_health_indicator('backup_status', 'warning', '⚠️')
            else:
                self.update_health_indicator('backup_status', 'error', '❌')
                
        except Exception as e:
            self.logger.error(f"Error updating health indicators: {e}")
    
    def update_health_indicator(self, indicator_key, status, symbol):
        """Update individual health indicator"""
        if indicator_key in self.health_indicators:
            indicator = self.health_indicators[indicator_key]
            color_map = {
                'good': '#4CAF50',
                'warning': '#FF9800',
                'error': '#F44336'
            }
            indicator["status"].config(
                text=symbol,
                fg=color_map.get(status, '#FF9800')
            )
    
    def update_activity_list(self, sites):
        """Update recent activity list"""
        try:
            # Clear list
            self.activity_listbox.delete(0, tk.END)
            
            # Get recent sites (sorted by update date)
            recent_sites = sorted(
                sites,
                key=lambda x: x.get('updated_at', '') or x.get('created_at', ''),
                reverse=True
            )[:8]  # Show 8 most recent
            
            for site in recent_sites:
                site_id = site.get('site_id', 'Unknown')
                location = site.get('location', '')[:30]
                updated = site.get('updated_at', '')
                
                # Format date
                if updated:
                    try:
                        updated_date = datetime.strptime(str(updated), '%Y-%m-%d %H:%M:%S')
                        updated_str = updated_date.strftime('%b %d, %H:%M')
                    except:
                        updated_str = str(updated)[:16]
                else:
                    updated_str = "Unknown"
                
                activity_text = f"{updated_str} | {site_id} | {location}"
                self.activity_listbox.insert(tk.END, activity_text)
                
        except Exception as e:
            self.logger.error(f"Error updating activity list: {e}")
    
    def update_alerts_list(self, excel_stats, maint_stats):
        """Update alerts list"""
        try:
            # Clear list
            self.alerts_listbox.delete(0, tk.END)
            
            alerts = []
            
            # Check for overdue maintenance
            overdue_tasks = maint_stats.get('overdue_tasks', 0)
            if overdue_tasks > 0:
                alerts.append(f"🚨 {overdue_tasks} maintenance tasks are overdue")
            
            # Check for pending sites
            pending_statuses = ['Resurvey', 'Fresh Introduced', 'Surveyed']
            pending_sites = sum(excel_stats.get('by_status', {}).get(status, 0) 
                              for status in pending_statuses)
            if pending_sites > 0:
                alerts.append(f"📋 {pending_sites} sites need attention")
            
            # Check for no recent import
            last_import = excel_stats.get('last_import', 'Never')
            if last_import == 'Never':
                alerts.append("🔄 No Excel data has been imported yet")
            else:
                try:
                    last_import_date = datetime.strptime(str(last_import), '%Y-%m-%d %H:%M:%S')
                    days_since = (datetime.now() - last_import_date).days
                    if days_since > 30:
                        alerts.append(f"📅 Data is {days_since} days old - consider updating")
                except:
                    pass
            
            # Check for low data completeness
            completeness = self.calculate_data_completeness()
            if completeness < 70:
                alerts.append(f"📊 Low data completeness ({completeness:.1f}%)")
            
            # Add alerts to listbox
            for alert in alerts[:6]:  # Max 6 alerts
                self.alerts_listbox.insert(tk.END, alert)
            
            # Update alerts count
            alert_count = len(alerts)
            self.alerts_count_label.config(
                text=f"{alert_count} alert{'s' if alert_count != 1 else ''}",
                fg="#F44336" if alert_count > 0 else "#666666"
            )
            
        except Exception as e:
            self.logger.error(f"Error updating alerts list: {e}")
    
    def update_quick_stats(self, dash_data, excel_stats, maint_stats):
        """Update quick statistics labels"""
        try:
            # Top province
            if dash_data.get('by_province'):
                top_province = dash_data['by_province'][0]
                self.stats_labels['top_province'].config(
                    text=f"{top_province.get('province')}: {top_province.get('count')} sites"
                )
            
            # Top operator
            if dash_data.get('by_operator'):
                top_operator = dash_data['by_operator'][0]
                self.stats_labels['top_operator'].config(
                    text=f"{top_operator.get('operator_site')}: {top_operator.get('count')} sites"
                )
            
            # Status summary
            if excel_stats.get('by_status'):
                active = excel_stats['by_status'].get('Active', 0)
                total = excel_stats.get('total_sites', 0)
                if total > 0:
                    percent = (active / total) * 100
                    self.stats_labels['status_summary'].config(
                        text=f"{active}/{total} active ({percent:.1f}%)"
                    )
            
            # Top tower type
            if dash_data.get('by_tower_type'):
                top_tower = dash_data['by_tower_type'][0]
                self.stats_labels['top_tower'].config(
                    text=f"{top_tower.get('tower_type')}: {top_tower.get('count')}"
                )
            
            # Top power source
            if dash_data.get('by_power_source'):
                top_power = dash_data['by_power_source'][0]
                self.stats_labels['top_power'].config(
                    text=f"{top_power.get('power_sources')}: {top_power.get('count')}"
                )
            
            # Maintenance stats
            total_tasks = maint_stats.get('total_tasks', 0)
            completed = maint_stats.get('by_status', {}).get('completed', 0)
            if total_tasks > 0:
                completion_rate = (completed / total_tasks) * 100
                self.stats_labels['maintenance_stats'].config(
                    text=f"{completed}/{total_tasks} ({completion_rate:.1f}%)"
                )
            
        except Exception as e:
            self.logger.error(f"Error updating quick stats: {e}")
    
    def update_recent_sites_table(self, sites):
        """Update recent sites table"""
        try:
            # Clear existing items
            for item in self.recent_tree.get_children():
                self.recent_tree.delete(item)
            
            # Get recent sites sorted by update date
            recent_sites = sorted(
                sites,
                key=lambda x: x.get('updated_at', '') or x.get('created_at', ''),
                reverse=True
            )[:15]  # Show 15 most recent
            
            for site in recent_sites:
                site_id = site.get('site_id', '')
                province = site.get('province', '')
                location = site.get('location', '')
                status = site.get('status', '')
                updated = site.get('updated_at', '')
                operator = site.get('operator_site', '')
                
                # Format update date
                if updated:
                    try:
                        updated_date = datetime.strptime(str(updated), '%Y-%m-%d %H:%M:%S')
                        updated_str = updated_date.strftime('%Y-%m-%d')
                    except:
                        updated_str = str(updated)[:10]
                else:
                    updated_str = ""
                
                # Add to treeview
                tags = ()
                if status == 'Active':
                    tags = ('active',)
                elif status in ['Resurvey', 'Fresh Introduced', 'Surveyed']:
                    tags = ('pending',)
                
                self.recent_tree.insert("", "end", values=(
                    site_id,
                    province,
                    location[:30] + '...' if location and len(location) > 30 else location,
                    status,
                    updated_str,
                    operator
                ), tags=tags)
            
            # Configure tag colors
            self.recent_tree.tag_configure('active', background='#e8f5e8')
            self.recent_tree.tag_configure('pending', background='#fff3e0')
            
        except Exception as e:
            self.logger.error(f"Error updating recent sites table: {e}")
    
    def update_performance_bars(self, excel_stats, maint_stats, sites):
        """Update performance bars"""
        try:
            # Data quality (based on completeness and valid coordinates)
            completeness = self.calculate_data_completeness()
            self.update_performance_bar('data_quality', completeness)
            
            # Update frequency (based on last updates)
            update_freq = self.calculate_update_frequency(sites)
            self.update_performance_bar('update_freq', update_freq)
            
            # Completeness (already calculated)
            self.update_performance_bar('completeness', completeness)
            
            # Maintenance rate
            total_tasks = maint_stats.get('total_tasks', 0)
            completed = maint_stats.get('by_status', {}).get('completed', 0)
            if total_tasks > 0:
                maintenance_rate = (completed / total_tasks) * 100
            else:
                maintenance_rate = 100  # No tasks means 100% completion
            self.update_performance_bar('maintenance_rate', maintenance_rate)
            
        except Exception as e:
            self.logger.error(f"Error updating performance bars: {e}")
    
    def update_performance_bar(self, bar_key, percentage):
        """Update individual performance bar"""
        if bar_key in self.performance_bars:
            bar_data = self.performance_bars[bar_key]
            
            # Update percentage label
            bar_data["percent"].config(text=f"{percentage:.1f}%")
            
            # Update bar width (assuming max width of 300px)
            bar_width = max(5, int((percentage / 100) * 300))
            bar_data["bar"].config(width=bar_width)
    
    def update_header_stats(self, excel_stats):
        """Update header statistics"""
        try:
            total_sites = excel_stats.get('total_sites', 0)
            active_sites = excel_stats.get('by_status', {}).get('Active', 0)
            
            # Update stats label in header
            if hasattr(self, 'stats_label'):
                self.stats_label.config(
                    text=f"Sites: {total_sites} | Active: {active_sites}"
                )
            
            # Update Excel status
            if hasattr(self, 'excel_status_label'):
                self.excel_status_label.config(
                    text=f"📊 {total_sites} sites | {active_sites} active"
                )
                
        except Exception as e:
            self.logger.error(f"Error updating header stats: {e}")
    
    def calculate_data_completeness(self):
        """Calculate data completeness percentage"""
        try:
            sites = self.db.get_excel_sites()
            if not sites:
                return 0.0
            
            total_fields = 0
            completed_fields = 0
            
            for site in sites:
                # Check key fields
                key_fields = ['site_id', 'province', 'location', 'latitude', 'longitude', 'status']
                for field in key_fields:
                    total_fields += 1
                    if site.get(field):
                        completed_fields += 1
            
            return (completed_fields / total_fields) * 100 if total_fields > 0 else 0.0
            
        except:
            return 0.0
    
    def calculate_update_frequency(self, sites):
        """Calculate update frequency score"""
        try:
            if not sites:
                return 0.0
            
            recent_threshold = 30  # days
            recent_updates = 0
            
            for site in sites:
                updated = site.get('updated_at', '')
                if updated:
                    try:
                        updated_date = datetime.strptime(str(updated), '%Y-%m-%d %H:%M:%S')
                        days_since = (datetime.now() - updated_date).days
                        if days_since <= recent_threshold:
                            recent_updates += 1
                    except:
                        pass
            
            return (recent_updates / len(sites)) * 100 if sites else 0.0
            
        except Exception as e:
            self.logger.error(f"Error calculating update frequency: {e}")
            return 0.0
    
    def show_activity_log(self):
        """Show full activity log"""
        if not self.current_user:
            return
            
        # Get all sites sorted by update date
        sites = self.db.get_excel_sites()
        recent_sites = sorted(
            sites,
            key=lambda x: x.get('updated_at', '') or x.get('created_at', ''),
            reverse=True
        )
        
        # Create activity log window
        log_window = tk.Toplevel(self.root)
        log_window.title("Full Activity Log")
        log_window.geometry("800x500")
        log_window.configure(bg=self.bg_color)
        
        # Title
        tk.Label(
            log_window,
            text="📋 Full Activity Log",
            font=("Arial", 16, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=20)
        
        # Create treeview
        columns = ("Timestamp", "Site ID", "Location", "Status", "Action")
        
        tree = ttk.Treeview(
            log_window,
            columns=columns,
            show="headings",
            height=20
        )
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(log_window, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(log_window, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Add activities
        for site in recent_sites[:50]:  # Show 50 most recent
            site_id = site.get('site_id', '')
            location = site.get('location', '')
            status = site.get('status', '')
            updated = site.get('updated_at', '')
            
            # Determine action based on timestamps
            created = site.get('created_at', '')
            if created and updated:
                try:
                    created_date = datetime.strptime(str(created), '%Y-%m-%d %H:%M:%S')
                    updated_date = datetime.strptime(str(updated), '%Y-%m-%d %H:%M:%S')
                    if (updated_date - created_date).total_seconds() < 60:
                        action = "Created"
                        timestamp = created
                    else:
                        action = "Updated"
                        timestamp = updated
                except:
                    action = "Modified"
                    timestamp = updated
            else:
                action = "Modified"
                timestamp = updated or created
            
            # Format timestamp
            if timestamp:
                try:
                    ts_date = datetime.strptime(str(timestamp), '%Y-%m-%d %H:%M:%S')
                    timestamp_str = ts_date.strftime('%Y-%m-%d %H:%M')
                except:
                    timestamp_str = str(timestamp)[:16]
            else:
                timestamp_str = "Unknown"
            
            tree.insert("", "end", values=(
                timestamp_str,
                site_id,
                location[:30] + '...' if location and len(location) > 30 else location,
                status,
                action
            ))
        
        tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        vsb.pack(side="right", fill="y", pady=10)
        hsb.pack(side="bottom", fill="x", padx=10)
    
    def setup_excel_sites_tab(self):
        """Setup Excel sites management tab – SINGLE PAGE, NO SCROLLING, Font 12"""
        tab = self.tabs["📁 Excel Sites"]

        # Main container with grid
        main_frame = tk.Frame(tab, bg=self.bg_color)
        main_frame.pack(fill="both", expand=True, padx=10, pady=8)

        # Configure grid weights
        main_frame.rowconfigure(2, weight=1)  # Treeview row expands
        main_frame.columnconfigure(0, weight=1)

        # === ROW 0: Toolbar (Import/Export + CRUD buttons) ===
        toolbar = tk.Frame(main_frame, bg=self.bg_color)
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        # Left: Import/Export
        left_tools = tk.Frame(toolbar, bg=self.bg_color)
        left_tools.pack(side="left")

        tk.Button(left_tools, text="📥 Import From Excel", command=self.import_excel,
                bg="#1a3f67", fg="white", font=("Arial", 12), relief="flat", padx=12, pady=6)\
            .pack(side="left", padx=4)
        tk.Button(left_tools, text="📤 Export To Excel", command=self.export_excel,
                bg="#2196F3", fg="white", font=("Arial", 12), relief="flat", padx=12, pady=6)\
            .pack(side="left", padx=4)

        # Center: CRUD buttons
        crud_frame = tk.Frame(toolbar, bg=self.bg_color)
        crud_frame.pack(side="left", padx=40)

        tk.Button(crud_frame, text="➕ Add Site", command=self.add_excel_site,
                bg="#FF9800", fg="white", font=("Arial", 12), relief="flat", padx=12, pady=6)\
            .pack(side="left", padx=4)
        tk.Button(crud_frame, text="✏️ Edit", command=self.edit_excel_site,
                bg="#9C27B0", fg="white", font=("Arial", 12), relief="flat", padx=12, pady=6)\
            .pack(side="left", padx=4)
        tk.Button(crud_frame, text="🗑️ Delete", command=self.delete_excel_site,
                bg="#F44336", fg="white", font=("Arial", 12), relief="flat", padx=12, pady=6)\
            .pack(side="left", padx=4)

        # Right: Quick actions
        right_tools = tk.Frame(toolbar, bg=self.bg_color)
        right_tools.pack(side="right")

        tk.Button(right_tools, text="🔍 Search", command=self.search_sites,
                bg="#607D8B", fg="white", font=("Arial", 12), relief="flat", padx=12, pady=6)\
            .pack(side="right", padx=4)

        # === ROW 1: Search + Filters (compact single row) ===
        filter_frame = tk.Frame(main_frame, bg=self.bg_color)
        filter_frame.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        filter_frame.columnconfigure(1, weight=1)

        # Search box
        tk.Label(filter_frame, text="Search:", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=0, column=0, padx=(0, 8))
        self.site_search_var = tk.StringVar()
        self.site_search_entry = tk.Entry(filter_frame, textvariable=self.site_search_var,
                                        font=("Arial", 12), width=40)
        self.site_search_entry.grid(row=0, column=1, sticky="ew", padx=(0, 20))
        self.site_search_var.trace("w", lambda *args: self.filter_excel_sites())

        # Filters (compact horizontal)
        tk.Label(filter_frame, text="Province:", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=0, column=2, padx=(0, 5))
        self.province_filter_var = tk.StringVar()
        self.province_filter = ttk.Combobox(filter_frame, textvariable=self.province_filter_var,
                                            values=["All"], width=15, font=("Arial", 12), state="readonly")
        self.province_filter.grid(row=0, column=3, padx=(0, 15))
        self.province_filter.bind('<<ComboboxSelected>>', lambda e: self.filter_excel_sites())

        tk.Label(filter_frame, text="Status:", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=0, column=4, padx=(0, 5))
        self.status_filter_var = tk.StringVar(value="All")
        self.status_filter = ttk.Combobox(filter_frame, textvariable=self.status_filter_var,
                                        values=['All', 'Active', 'Confirmed', 'Resurvey', 'Fresh Introduced', 'Surveyed', 'Rejected'],
                                        width=15, font=("Arial", 12), state="readonly")
        self.status_filter.grid(row=0, column=5, padx=(0, 15))
        self.status_filter.bind('<<ComboboxSelected>>', lambda e: self.filter_excel_sites())

        tk.Label(filter_frame, text="Operator:", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=0, column=6, padx=(0, 5))
        self.operator_filter_var = tk.StringVar(value="All")
        self.operator_filter = ttk.Combobox(filter_frame, textvariable=self.operator_filter_var,
                                            width=15, font=("Arial", 12), state="readonly")
        self.operator_filter.grid(row=0, column=7, padx=(0, 15))
        self.operator_filter.bind('<<ComboboxSelected>>', lambda e: self.filter_excel_sites())

        # Clear button
        tk.Button(filter_frame, text="🧹 Clear Filters", command=self.clear_filters,
                font=("Arial", 12), bg="#78909C", fg="white", relief="flat", padx=12, pady=6)\
            .grid(row=0, column=8, padx=10)

        # === ROW 2: Sites Treeview (main content, fixed height) ===
        tree_frame = tk.Frame(main_frame, bg=self.bg_color)
        tree_frame.grid(row=2, column=0, sticky="nsew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        columns = ("S.No", "Site ID", "KnackRise ID", "Province", "Location",
                "Status", "Operator Site", "Tower Type", "Power Sources", "On-Air")

        self.sites_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=20)
        
        col_widths = {"S.No": 70, "Site ID": 120, "KnackRise ID": 120, "Province": 130, "Location": 200,
                    "Status": 110, "Operator Site": 130, "Tower Type": 110, "Power Sources": 150, "On-Air": 110}
        
        for col in columns:
            self.sites_tree.heading(col, text=col)
            self.sites_tree.column(col, width=col_widths.get(col, 120), anchor="w")

        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.sites_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.sites_tree.xview)
        self.sites_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.sites_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        # Bindings
        self.sites_tree.bind('<Double-1>', lambda e: self.edit_excel_site())
        self.sites_tree.bind('<Button-3>', self.show_site_maintenance_menu)
        self.sites_tree.bind('<Return>', lambda e: self.edit_excel_site())
        self.sites_tree.bind('<Delete>', lambda e: self.delete_excel_site())
        self.sites_tree.bind('<Control-f>', lambda e: self.site_search_entry.focus_set())

        # Load initial data
        self.load_excel_sites()
        self.update_filter_dropdowns()
    
    def setup_maintenance_tab(self):
        """Setup maintenance management tab"""
        tab = self.tabs["🔧 Maintenance"]
    
        # Title
        tk.Label(
            tab,
            text="🔧 Maintenance Management",
            font=("Arial", 16, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=20)
    
        # Quick actions frame
        actions_frame = tk.Frame(tab, bg=self.bg_color)
        actions_frame.pack(pady=10)
    
        tk.Button(
            actions_frame,
            text="➕ Add Maintenance Task",
            command=self.show_maintenance_form,
            bg="#4CAF50",
            fg="white",
            font=("Arial", 11),
            relief="flat",
            padx=20,
            pady=10,
            cursor="hand2"
        ).pack(side="left", padx=10)
    
        tk.Button(
            actions_frame,
            text="📋 View All Tasks",
            command=self.show_all_maintenance,
            bg="#2196F3",
            fg="white",
            font=("Arial", 11),
            relief="flat",
            padx=20,
            pady=10,
            cursor="hand2"
        ).pack(side="left", padx=10)
    
        # Statistics frame
        stats_frame = tk.Frame(tab, bg=self.bg_color)
        stats_frame.pack(pady=20)
    
        self.maintenance_stats_label = tk.Label(
            stats_frame,
            text="Total Maintenance Tasks: 0 | Pending: 0 | Completed: 0",
            font=("Arial", 12),
            bg=self.bg_color,
            fg=self.fg_color
        )
        self.maintenance_stats_label.pack()
    
        # Recent maintenance tasks - FIXED LAYOUT (from previous fix)
        recent_frame = tk.Frame(tab, bg=self.bg_color)
        recent_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
        tk.Label(
            recent_frame,
            text="Recent Maintenance Tasks",
            font=("Arial", 12, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(anchor="w", pady=(0, 10))
    
        # Container for treeview + scrollbars
        tree_container = tk.Frame(recent_frame, bg=self.bg_color)
        tree_container.pack(fill="both", expand=True)
    
        # Treeview
        columns = ("Task ID", "Site ID", "Description", "Priority", "Status", "Due Date")
        self.maintenance_tree = ttk.Treeview(
            tree_container,
            columns=columns,
            show="headings",
            height=12
        )
    
        col_widths = {
            "Task ID": 120, "Site ID": 120, "Description": 300,
            "Priority": 90, "Status": 100, "Due Date": 120
        }
        for col in columns:
            self.maintenance_tree.heading(col, text=col)
            self.maintenance_tree.column(col, width=col_widths.get(col, 150), anchor="w")
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=self.maintenance_tree.yview)
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=self.maintenance_tree.xview)
        self.maintenance_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    
        self.maintenance_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
    
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)
        
        # ← IMPORTANT: Load tasks immediately when tab is created
        self.load_maintenance_tasks()

    # ←←←← ADD THE METHOD HERE ←←←←
    def load_maintenance_tasks(self):
        """Load and refresh maintenance tasks in treeview"""
        try:
            # Clear existing
            for item in self.maintenance_tree.get_children():
                self.maintenance_tree.delete(item)
            
            # Load from DB
            tasks = self.db.get_maintenance_tasks()[:50]  # Limit to recent 50
        
            for task in tasks:
                desc = task.get('description', '')
                if len(desc) > 60:
                    desc = desc[:57] + "..."
                
                self.maintenance_tree.insert("", "end", values=(
                    task.get('task_id', ''),
                    task.get('site_id', ''),
                    desc,
                    task.get('priority', '').capitalize(),
                    task.get('status', '').capitalize(),
                    task.get('due_date', '')
                ))
            
            # Update stats label
            stats = self.db.get_maintenance_statistics()
            total = stats.get('total_tasks', 0)
            pending = stats.get('by_status', {}).get('pending', 0)
            completed = stats.get('by_status', {}).get('completed', 0)
        
            self.maintenance_stats_label.config(
                text=f"Total Tasks: {total} | Pending: {pending} | Completed: {completed} | Overdue: {stats.get('overdue_tasks', 0)}"
            )
        
        except Exception as e:
            self.logger.error(f"Error loading maintenance tasks: {e}")
            
    def setup_analyze_tab(self):
        """Setup stylish Analyze tab – Modern design, no scrolling, enhanced graphs"""
        tab = self.tabs["📈 Analyze"]

        # Main stylish background
        main_frame = tk.Frame(tab, bg='#e3f2fd')  # Light blue background
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title with style
        title_lbl = tk.Label(
            main_frame,
            text="📈 Advanced Data Analysis & Insights",
            font=("Arial", 20, "bold"),
            bg='#e3f2fd',
            fg='#1976D2'
        )
        title_lbl.pack(pady=(0, 30))

        # Card for analysis selection
        selection_card = tk.Frame(main_frame, bg='white', relief="solid", bd=1, padx=20, pady=20)
        selection_card.pack(fill="x", pady=(0, 20))

        tk.Label(
            selection_card,
            text="🔍 Select Analysis Type",
            font=("Arial", 14, "bold"),
            bg='white',
            fg='#424242'
        ).pack(anchor="w", pady=(0, 15))

        # Stylish radio buttons with icons and colors
        radio_frame = tk.Frame(selection_card, bg='white')
        radio_frame.pack(anchor="w")

        self.analysis_type_var = tk.StringVar(value="site_distribution")

        analysis_options = [
            ("🌍 Site Distribution", "site_distribution", "#4CAF50"),
            ("✅ Status Analysis", "status", "#2196F3"),
            ("🗺️ Geographic Analysis", "geographic", "#FF9800"),
            ("📅 Timeline Analysis", "timeline", "#9C27B0"),
            ("⚖️ Comparative Analysis", "comparative", "#E91E63"),
            ("🔧 Maintenance Analysis", "maintenance", "#00BCD4")
        ]

        for text, value, color in analysis_options:
            rb_frame = tk.Frame(radio_frame, bg='white')
            rb_frame.pack(side="left", padx=15)

            rb = tk.Radiobutton(
                rb_frame,
                text=text,
                variable=self.analysis_type_var,
                value=value,
                font=("Arial", 12),
                bg='white',
                fg=color,
                selectcolor='#bbdefb',
                activebackground='white',
                activeforeground=color,
                command=self.update_analysis
            )
            rb.pack()

        # Graph display area (large and centered)
        self.graph_frame = tk.Frame(main_frame, bg='white', relief="solid", bd=2, padx=10, pady=10)
        self.graph_frame.pack(fill="both", expand=True)

        # Default message
        default_lbl = tk.Label(
            self.graph_frame,
            text="Select an analysis type to view insights",
            font=("Arial", 14),
            bg='white',
            fg='#757575'
        )
        default_lbl.pack(expand=True)

        # Controls card (bottom)
        controls_card = tk.Frame(main_frame, bg='white', relief="solid", bd=1, padx=20, pady=15)
        controls_card.pack(fill="x", pady=(20, 0))

        tk.Button(
            controls_card,
            text="📊 Generate Detailed Report",
            command=self.generate_analysis_report,
            bg='#1976D2',
            fg="white",
            font=("Arial", 12, "bold"),
            relief="flat",
            padx=25,
            pady=12,
            cursor="hand2"
        ).pack(side="left", padx=10)

        tk.Button(
            controls_card,
            text="💾 Save Current Graph",
            command=self.save_analysis_graph,
            bg='#4CAF50',
            fg="white",
            font=("Arial", 12),
            relief="flat",
            padx=25,
            pady=12,
            cursor="hand2"
        ).pack(side="left", padx=10)

        tk.Button(
            controls_card,
            text="🔄 Refresh Analysis",
            command=self.update_analysis,
            bg='#FF9800',
            fg="white",
            font=("Arial", 12),
            relief="flat",
            padx=25,
            pady=12,
            cursor="hand2"
        ).pack(side="left", padx=10)

        # Initial load
        self.update_analysis()
    
    def create_status_bar(self):
        """Create status bar"""
        status_bar = tk.Frame(self.root, bg=self.highlight_color, height=25)
        status_bar.pack(fill="x", side="bottom")
        
        # Left side: Status messages
        self.status_label = tk.Label(
            status_bar,
            text="Ready",
            bg=self.highlight_color,
            fg=self.fg_color,
            anchor="w"
        )
        self.status_label.pack(side="left", padx=10)
        
        # Middle: Database status
        self.db_status_label = tk.Label(
            status_bar,
            text="✅ Database Connected",
            bg=self.highlight_color,
            fg="green",
            anchor="w"
        )
        self.db_status_label.pack(side="left", padx=10)
        
        # Right side: Excel data status and time
        right_frame = tk.Frame(status_bar, bg=self.highlight_color)
        right_frame.pack(side="right", padx=10)
        
        self.excel_status_label = tk.Label(
            right_frame,
            text="📁 Excel Data: 0 sites",
            bg=self.highlight_color,
            fg=self.fg_color,
            anchor="w"
        )
        self.excel_status_label.pack(side="left", padx=5)
        
        # Time display
        self.time_label = tk.Label(
            right_frame,
            text=datetime.now().strftime("%H:%M:%S"),
            bg=self.highlight_color,
            fg=self.fg_color,
            anchor="w"
        )
        self.time_label.pack(side="left", padx=5)
        
        # Update time every second
        self.update_time()
    
    def update_time(self):
        """Update time display"""
        self.time_label.config(text=datetime.now().strftime("%H:%M:%S"))
        self.root.after(1000, self.update_time)
        
    def start_background_tasks(self):
        """Start background tasks"""
        def update_tasks():
            self.update_enhanced_dashboard()
            # Schedule next update
            self.root.after(30000, update_tasks)  # 30 seconds
        
        # Start the periodic updates
        update_tasks()
        
    def update_status(self, message):
        """Update status bar message"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.status_label.config(text=f"{message} | {timestamp}")
        
    # ==================== MAINTENANCE FUNCTIONS ====================
    
    def show_maintenance_form(self, site_id=None):
        """Show form to add maintenance task"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
            
        form_window = tk.Toplevel(self.root)
        form_window.title("Add Maintenance Task")
        form_window.geometry("500x600")
        form_window.configure(bg=self.bg_color)
        form_window.transient(self.root)
        form_window.grab_set()
        
        # Center window
        form_window.update_idletasks()
        width = form_window.winfo_width()
        height = form_window.winfo_height()
        x = (form_window.winfo_screenwidth() // 2) - (width // 2)
        y = (form_window.winfo_screenheight() // 2) - (height // 2)
        form_window.geometry(f'{width}x{height}+{x}+{y}')
        
        # Title
        tk.Label(
            form_window,
            text="➕ Add Maintenance Task",
            font=("Arial", 14, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=20)
        
        # Form fields
        fields_frame = tk.Frame(form_window, bg=self.bg_color)
        fields_frame.pack(pady=10)
        
        # Site ID
        tk.Label(
            fields_frame,
            text="Site ID:",
            bg=self.bg_color,
            fg=self.fg_color
        ).grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        site_var = tk.StringVar(value=site_id if site_id else "")
        site_entry = tk.Entry(
            fields_frame,
            textvariable=site_var,
            bg="white",
            fg="black",
            width=30
        )
        site_entry.grid(row=0, column=1, padx=10, pady=10)
        
        # Task Description
        tk.Label(
            fields_frame,
            text="Description*:",
            bg=self.bg_color,
            fg=self.fg_color
        ).grid(row=1, column=0, padx=10, pady=10, sticky="w")
        
        desc_text = tk.Text(
            fields_frame,
            bg="white",
            fg="black",
            width=30,
            height=4
        )
        desc_text.grid(row=1, column=1, padx=10, pady=10)
        
        # Task Type
        tk.Label(
            fields_frame,
            text="Task Type:",
            bg=self.bg_color,
            fg=self.fg_color
        ).grid(row=2, column=0, padx=10, pady=10, sticky="w")
        
        type_var = tk.StringVar(value="Preventive")
        type_combo = ttk.Combobox(
            fields_frame,
            textvariable=type_var,
            values=["Preventive", "Corrective", "Emergency", "Routine"],
            state="readonly",
            width=28
        )
        type_combo.grid(row=2, column=1, padx=10, pady=10)
        
        # Priority
        tk.Label(
            fields_frame,
            text="Priority:",
            bg=self.bg_color,
            fg=self.fg_color
        ).grid(row=3, column=0, padx=10, pady=10, sticky="w")
        
        priority_var = tk.StringVar(value="medium")
        priority_combo = ttk.Combobox(
            fields_frame,
            textvariable=priority_var,
            values=["low", "medium", "high"],
            state="readonly",
            width=28
        )
        priority_combo.grid(row=3, column=1, padx=10, pady=10)
        
        # Due Date
        tk.Label(
            fields_frame,
            text="Due Date (YYYY-MM-DD):",
            bg=self.bg_color,
            fg=self.fg_color
        ).grid(row=4, column=0, padx=10, pady=10, sticky="w")
        
        due_date_var = tk.StringVar(value=datetime.now().strftime('%Y-%m-%d'))
        due_date_entry = tk.Entry(
            fields_frame,
            textvariable=due_date_var,
            bg="white",
            fg="black",
            width=30
        )
        due_date_entry.grid(row=4, column=1, padx=10, pady=10)
        
        # Assigned To
        tk.Label(
            fields_frame,
            text="",
            bg=self.bg_color,
            fg=self.fg_color
        ).grid(row=5, column=0, padx=10, pady=10, sticky="w")
        
        assigned_var = tk.StringVar()
        assigned_entry = tk.Entry(
            fields_frame,
            textvariable=assigned_var,
            bg="white",
            fg="black",
            width=30
        )
        assigned_entry.grid(row=5, column=1, padx=10, pady=10)
        
        def save_task():
            """Save the maintenance task"""
            task_data = {
                'site_id': site_var.get().strip(),
                'task_type': type_var.get(),
                'description': desc_text.get("1.0", tk.END).strip(),
                'priority': priority_var.get(),
                'status': 'pending',
                'assigned_to': assigned_var.get().strip(),
                'due_date': due_date_var.get(),
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            self.load_maintenance_tasks()
            
            if not task_data['description']:
                messagebox.showerror("Error", "Description is required")
                return
            
            success, result = self.db.add_maintenance_task(task_data)
            
            if success:
                messagebox.showinfo("Success", f"Task added successfully\nTask ID: {result}")
                form_window.destroy()
                self.refresh_dashboard()
                self.update_status(f"Maintenance task added: {result}")
            else:
                messagebox.showerror("Error", f"Failed to add task: {result}")
        
        # Buttons
        button_frame = tk.Frame(form_window, bg=self.bg_color)
        button_frame.pack(pady=20)
        
        tk.Button(
            button_frame,
            text="💾 Save Task",
            command=save_task,
            bg="#4CAF50",
            fg="white",
            font=("Arial", 11),
            relief="flat",
            padx=30,
            pady=10,
            cursor="hand2"
        ).pack(side="left", padx=10)
        
        tk.Button(
            button_frame,
            text="Cancel",
            command=form_window.destroy,
            bg=self.secondary_bg,
            fg=self.fg_color,
            font=("Arial", 11),
            relief="flat",
            padx=30,
            pady=10
        ).pack(side="left", padx=10)
    
    def show_all_maintenance(self):
        """Show all maintenance tasks"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
            
        tasks_window = tk.Toplevel(self.root)
        tasks_window.title("All Maintenance Tasks")
        tasks_window.geometry("900x500")
        tasks_window.configure(bg=self.bg_color)
        tasks_window.transient(self.root)
        
        # Title
        tk.Label(
            tasks_window,
            text="📋 All Maintenance Tasks",
            font=("Arial", 14, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=20)
        
        # Get all tasks
        tasks = self.db.get_maintenance_tasks()
        
        # Create treeview
        columns = ("Task ID", "Site ID", "Description", "Type", "Priority", "Status", "Due Date", "Assigned To")
        
        tree = ttk.Treeview(
            tasks_window,
            columns=columns,
            show="headings",
            height=15
        )
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=100)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(tasks_window, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(tasks_window, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Add tasks
        for task in tasks:
            tree.insert("", "end", values=(
                task.get('task_id', ''),
                task.get('site_id', ''),
                task.get('description', '')[:40] + '...' if task.get('description') and len(task.get('description')) > 40 else task.get('description', ''),
                task.get('task_type', ''),
                task.get('priority', ''),
                task.get('status', ''),
                task.get('due_date', ''),
                task.get('assigned_to', '')
            ))
        
        tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        vsb.pack(side="right", fill="y", pady=10)
        hsb.pack(side="bottom", fill="x", padx=10)
        
        # Status update buttons
        button_frame = tk.Frame(tasks_window, bg=self.bg_color)
        button_frame.pack(pady=10)
        
        def mark_complete():
            selection = tree.selection()
            if not selection:
                messagebox.showwarning("No Selection", "Please select a task")
                return
            
            task_id = tree.item(selection[0])['values'][0]
            if messagebox.askyesno("Confirm", f"Mark task {task_id} as completed?"):
                if self.db.update_maintenance_task(task_id, 'completed'):
                    messagebox.showinfo("Success", "Task marked as completed")
                    tasks_window.destroy()
                    self.show_all_maintenance()
                    self.refresh_dashboard()
                    self.load_maintenance_tasks()
        tk.Button(
            button_frame,
            text="✅ Mark as Complete",
            command=mark_complete,
            bg="#4CAF50",
            fg="white",
            relief="flat",
            padx=20,
            pady=5
        ).pack(side="left", padx=5)
        
        def delete_task():
            selection = tree.selection()
            if not selection:
                return
            
            task_id = tree.item(selection[0])['values'][0]
            if messagebox.askyesno("Delete", f"Delete task {task_id}?"):
                if self.db.delete_maintenance_task(task_id):
                    messagebox.showinfo("Deleted", "Task deleted")
                    tasks_window.destroy()
                    self.show_all_maintenance()
                    self.refresh_dashboard()
                else:
                    messagebox.showerror("Error", "Failed to delete task")
        
        tk.Button(
            button_frame,
            text="🗑️ Delete Task",
            command=delete_task,
            bg="#F44336",
            fg="white",
            relief="flat",
            padx=20,
            pady=5
        ).pack(side="left", padx=5)
    
    def show_site_maintenance_menu(self, event):
        """Show maintenance context menu for selected site"""
        selection = self.sites_tree.selection()
        if not selection:
            return
            
        item = self.sites_tree.item(selection[0])
        site_id = item['values'][1]
        
        # Create context menu
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label=f"Add Maintenance for {site_id}", 
                        command=lambda: self.show_maintenance_form(site_id))
        menu.add_command(label=f"View Maintenance History", 
                        command=lambda: self.show_site_maintenance_history(site_id))
        
        # Show menu at cursor position
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
    
    def show_site_maintenance_history(self, site_id):
        """Show maintenance history for a specific site"""
        if not self.current_user:
            return
            
        history_window = tk.Toplevel(self.root)
        history_window.title(f"Maintenance History - {site_id}")
        history_window.geometry("800x400")
        history_window.configure(bg=self.bg_color)
        
        # Title
        tk.Label(
            history_window,
            text=f"🔧 Maintenance History for Site: {site_id}",
            font=("Arial", 14, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=20)
        
        # Add new task button
        tk.Button(
            history_window,
            text="➕ Add New Task",
            command=lambda: self.show_maintenance_form(site_id),
            bg="#4CAF50",
            fg="white",
            relief="flat",
            padx=15,
            pady=5
        ).pack(pady=10)
        
        # Get tasks for this site
        tasks = self.db.get_maintenance_tasks(site_id)
        
        if tasks:
            # Create treeview
            columns = ("Task ID", "Description", "Type", "Priority", "Status", "Due Date", "Completed")
            
            tree = ttk.Treeview(
                history_window,
                columns=columns,
                show="headings",
                height=10
            )
            
            for col in columns:
                tree.heading(col, text=col)
                tree.column(col, width=100)
            
            # Add tasks
            for task in tasks:
                tree.insert("", "end", values=(
                    task.get('task_id', ''),
                    task.get('description', '')[:30] + '...' if task.get('description') and len(task.get('description')) > 30 else task.get('description', ''),
                    task.get('task_type', ''),
                    task.get('priority', ''),
                    task.get('status', ''),
                    task.get('due_date', ''),
                    task.get('completed_date', '')
                ))
            
            # Add scrollbars
            vsb = ttk.Scrollbar(history_window, orient="vertical", command=tree.yview)
            hsb = ttk.Scrollbar(history_window, orient="horizontal", command=tree.xview)
            tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
            
            tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)
            vsb.pack(side="right", fill="y", pady=10)
            hsb.pack(side="bottom", fill="x", padx=10)
        else:
            tk.Label(
                history_window,
                text="No maintenance tasks found for this site",
                font=("Arial", 12),
                bg=self.bg_color,
                fg=self.fg_color
            ).pack(pady=50)
    
    def show_maintenance_statistics(self):
        """Show maintenance statistics"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
            
        stats = self.db.get_maintenance_statistics()
        
        stats_text = f"""
        🔧 MAINTENANCE STATISTICS
        
        Total Tasks: {stats.get('total_tasks', 0)}
        Overdue Tasks: {stats.get('overdue_tasks', 0)}
        Upcoming Tasks (Next 7 Days): {stats.get('upcoming_tasks', 0)}
        
        By Status:
        """
        
        for status, count in stats.get('by_status', {}).items():
            stats_text += f"  {status.capitalize()}: {count}\n"
        
        stats_text += f"""
        By Priority:
        """
        
        for priority, count in stats.get('by_priority', {}).items():
            stats_text += f"  {priority.capitalize()}: {count}\n"
        
        stats_text += f"""
        By Task Type:
        """
        
        for task_type, count in stats.get('by_type', {}).items():
            stats_text += f"  {task_type}: {count}\n"
        
        messagebox.showinfo("Maintenance Statistics", stats_text)
    
    # ==================== ANALYZE FUNCTIONS ====================
    
    def update_analysis(self):
        """Update analysis based on selected type"""
        if not self.current_user:
            return
            
        analysis_type = self.analysis_type_var.get()
        
        # Clear previous graph
        for widget in self.graph_frame.winfo_children():
            widget.destroy()
        
        # Create new graph based on analysis type
        if analysis_type == "site_distribution":
            self.create_site_distribution_graph()
        elif analysis_type == "status":
            self.create_status_analysis_graph()
        elif analysis_type == "geographic":
            self.create_geographic_analysis_graph()
        elif analysis_type == "timeline":
            self.create_timeline_analysis_graph()
        elif analysis_type == "comparative":
            self.create_comparative_analysis_graph()
        elif analysis_type == "maintenance":
            self.create_maintenance_analysis_graph()
    
    def create_site_distribution_graph(self):
        """Create site distribution graph with modern styling"""
        try:
            dash_data = self.db.get_excel_dashboard_data()

            fig, axes = plt.subplots(2, 2, figsize=(14, 10))
            fig.suptitle('Site Distribution Overview', fontsize=18, fontweight='bold', color='#1976D2')

            # Common modern styling
            fig.patch.set_facecolor('#e3f2fd')
            for ax in axes.flat:
                ax.set_facecolor('white')
                ax.grid(True, linestyle='--', alpha=0.5, color='#bbdefb')
                ax.spines['top'].set_visible(False)
                ax.spines['right'].set_visible(False)
                ax.tick_params(colors='#424242')
                current_title = ax.get_title()
                if current_title:
                    ax.set_title(current_title, fontsize=14, fontweight='bold', color='#1976D2', pad=20)

            # 1. Top Provinces
            if dash_data['by_province']:
                provinces = [item['province'] for item in dash_data['by_province'][:10]]
                counts = [item['count'] for item in dash_data['by_province'][:10]]
                bars = axes[0, 0].barh(provinces, counts, color='#4CAF50', edgecolor='white')
                axes[0, 0].set_title('Top 10 Provinces by Site Count')
                axes[0, 0].set_xlabel('Number of Sites')
                axes[0, 0].invert_yaxis()
                for bar in bars:
                    width = bar.get_width()
                    axes[0, 0].text(width + max(counts)*0.01, bar.get_y() + bar.get_height()/2,
                                    f'{int(width)}', ha='left', va='center', fontweight='bold', fontsize=10)

            # 2. Status Pie
            if dash_data['by_status']:
                statuses = [item['status'] for item in dash_data['by_status']]
                counts = [item['count'] for item in dash_data['by_status']]
                colors = plt.cm.Set3(np.linspace(0, 1, len(statuses)))
                wedges, texts, autotexts = axes[0, 1].pie(counts, labels=statuses, colors=colors,
                                                        autopct='%1.1f%%', startangle=90,
                                                        wedgeprops={'edgecolor': 'white', 'linewidth': 2})
                axes[0, 1].set_title('Site Status Distribution')
                for autotext in autotexts:
                    autotext.set_color('white')
                    autotext.set_fontweight('bold')

            # 3. Operator Bar
            if dash_data['by_operator']:
                operators = [item['operator_site'] for item in dash_data['by_operator']]
                counts = [item['count'] for item in dash_data['by_operator']]
                bars = axes[1, 0].bar(operators, counts, color='#2196F3', edgecolor='white')
                axes[1, 0].set_title('Sites by Operator')
                axes[1, 0].set_ylabel('Number of Sites')
                axes[1, 0].tick_params(axis='x', rotation=45)
                for bar in bars:
                    height = bar.get_height()
                    axes[1, 0].text(bar.get_x() + bar.get_width()/2., height + max(counts)*0.01,
                                    f'{int(height)}', ha='center', va='bottom', fontweight='bold', fontsize=10)

            # 4. Tower Type Donut
            if dash_data['by_tower_type']:
                tower_types = [item['tower_type'] for item in dash_data['by_tower_type']]
                counts = [item['count'] for item in dash_data['by_tower_type']]
                colors = plt.cm.Pastel1(np.linspace(0, 1, len(tower_types)))
                wedges, texts, autotexts = axes[1, 1].pie(counts, labels=tower_types, colors=colors,
                                                        autopct='%1.1f%%',
                                                        wedgeprops=dict(width=0.3, edgecolor='white', linewidth=2))
                axes[1, 1].set_title('Tower Type Distribution')
                for autotext in autotexts:
                    autotext.set_fontweight('bold')

            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            canvas = FigureCanvasTkAgg(fig, self.graph_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True)

        except Exception as e:
            self.logger.error(f"Error creating site distribution graph: {e}")
            tk.Label(self.graph_frame, text=f"Error: {e}", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color).pack(pady=50)

    def setup_costs_tab(self):
        """Setup stylish Costs tab – Financial tracking with charts and transactions"""
        tab = self.tabs["💰 Costs"]

        # Main frame with light blue background
        main_frame = tk.Frame(tab, bg='#e3f2fd')
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        tk.Label(
            main_frame,
            text="💰 Financial Overview & Cost Management",
            font=("Arial", 20, "bold"),
            bg='#e3f2fd',
            fg='#1976D2'
        ).pack(pady=(0, 25))

        # === ROW 1: Summary Cards ===
        cards_frame = tk.Frame(main_frame, bg='#e3f2fd')
        cards_frame.pack(fill="x", pady=(0, 20))

        self.cost_summary_cards = {}
        card_defs = [
            ("Total Revenue", "total_revenue", "💵", "#4CAF50"),
            ("Total Costs", "total_costs", "💸", "#F44336"),
            ("Net Profit", "net_profit", "📈", "#2196F3"),
            ("ROI %", "roi", "📊", "#FF9800")
        ]

        for title, key, icon, color in card_defs:
            card = tk.Frame(cards_frame, bg='white', relief="solid", bd=1, padx=15, pady=15, width=200)
            card.pack(side="left", expand=True, fill="x", padx=10)
            card.pack_propagate(False)

            tk.Label(card, text=icon, font=("Arial", 24), bg='white', fg=color).pack()
            value_lbl = tk.Label(card, text="0 AFN", font=("Arial", 18, "bold"), bg='white', fg=color)
            value_lbl.pack(pady=(5, 0))
            tk.Label(card, text=title, font=("Arial", 12), bg='white', fg='#424242').pack()
            self.cost_summary_cards[key] = value_lbl

        # === ROW 2: Controls + Filters ===
        controls_frame = tk.Frame(main_frame, bg='#e3f2fd')
        controls_frame.pack(fill="x", pady=(0, 20))

        # Left: Add transaction button
        tk.Button(
            controls_frame,
            text="➕ Add Transaction",
            command=self.add_financial_transaction,
            bg='#1976D2',
            fg="white",
            font=("Arial", 12, "bold"),
            relief="flat",
            padx=20,
            pady=10
        ).pack(side="left")

        # Right: Filters
        filter_frame = tk.Frame(controls_frame, bg='#e3f2fd')
        filter_frame.pack(side="right")

        tk.Label(filter_frame, text="Site:", font=("Arial", 12), bg='#e3f2fd', fg='#424242').pack(side="left", padx=(0, 5))
        self.cost_site_filter_var = tk.StringVar()
        self.cost_site_filter = ttk.Combobox(filter_frame, textvariable=self.cost_site_filter_var, width=20, font=("Arial", 12))
        self.cost_site_filter.pack(side="left", padx=(0, 15))
        self.cost_site_filter.bind('<<ComboboxSelected>>', lambda e: self.load_financial_data())

        tk.Label(filter_frame, text="Type:", font=("Arial", 12), bg='#e3f2fd', fg='#424242').pack(side="left", padx=(0, 5))
        self.cost_type_filter_var = tk.StringVar(value="All")
        ttk.Combobox(filter_frame, textvariable=self.cost_type_filter_var,
                    values=["All", "Revenue", "Expense", "Investment"], width=15, font=("Arial", 12), state="readonly")\
            .pack(side="left", padx=(0, 15))
        self.cost_type_filter_var.trace("w", lambda *args: self.load_financial_data())

        tk.Button(filter_frame, text="🔄 Refresh", command=self.load_financial_data,
                bg='#4CAF50', fg="white", font=("Arial", 12), relief="flat", padx=15, pady=8)\
            .pack(side="left")

        # === ROW 3: Charts Side-by-Side ===
        charts_frame = tk.Frame(main_frame, bg='#e3f2fd')
        charts_frame.pack(fill="both", expand=True, pady=(0, 20))

        # Left: Monthly Revenue vs Cost
        self.monthly_chart_frame = tk.Frame(charts_frame, bg='white', relief="solid", bd=1)
        self.monthly_chart_frame.pack(side="left", expand=True, fill="both", padx=(0, 10))

        tk.Label(self.monthly_chart_frame, text="📊 Monthly Revenue vs Costs", font=("Arial", 14, "bold"),
                bg='white', fg='#1976D2').pack(pady=(10, 5))

        # Right: Cost Breakdown Pie
        self.pie_chart_frame = tk.Frame(charts_frame, bg='white', relief="solid", bd=1)
        self.pie_chart_frame.pack(side="right", expand=True, fill="both", padx=(10, 0))

        tk.Label(self.pie_chart_frame, text="🥧 Cost Categories", font=("Arial", 14, "bold"),
                bg='white', fg='#1976D2').pack(pady=(10, 5))

        # === ROW 4: Recent Transactions Table ===
        transactions_frame = tk.Frame(main_frame, bg='#e3f2fd')
        transactions_frame.pack(fill="x")

        tk.Label(transactions_frame, text="📋 Recent Transactions", font=("Arial", 14, "bold"),
                bg='#e3f2fd', fg='#1976D2').pack(anchor="w", pady=(0, 10))

        table_container = tk.Frame(transactions_frame, bg='white', relief="solid", bd=1)
        table_container.pack(fill="x")

        columns = ("Date", "Site ID", "Type", "Category", "Amount (AFN)", "Description")
        self.transactions_tree = ttk.Treeview(table_container, columns=columns, show="headings", height=8)
        for col in columns:
            self.transactions_tree.heading(col, text=col)
            self.transactions_tree.column(col, width=150, anchor="w")
        self.transactions_tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        vsb = ttk.Scrollbar(table_container, orient="vertical", command=self.transactions_tree.yview)
        vsb.pack(side="right", fill="y")
        self.transactions_tree.configure(yscrollcommand=vsb.set)

        # Initial load
        self.load_financial_data()
        self.update_cost_site_filter()
        
    def update_cost_site_filter(self):
        """Update site filter dropdown in Costs tab"""
        sites = self.db.get_excel_sites()
        site_ids = sorted(set(site.get('site_id') for site in sites if site.get('site_id')))
        self.cost_site_filter['values'] = ["All"] + site_ids
        self.cost_site_filter.set("All")

    def load_financial_data(self):
        """Load and display financial data with charts"""
        try:
            # Get transactions (implement this in your DB if not exists)
            transactions = self.db.get_financial_transactions(
                site_id=self.cost_site_filter_var.get() if self.cost_site_filter_var.get() != "All" else None,
                type_filter=self.cost_type_filter_var.get() if self.cost_type_filter_var.get() != "All" else None
            )

            total_revenue = sum(t['amount'] for t in transactions if t['type'] == 'Revenue')
            total_costs = sum(t['amount'] for t in transactions if t['type'] in ['Expense', 'Investment'])
            net_profit = total_revenue - total_costs
            roi = (net_profit / total_costs * 100) if total_costs > 0 else 0

            # Update summary cards
            self.cost_summary_cards['total_revenue'].config(text=f"{total_revenue:,.0f} AFN")
            self.cost_summary_cards['total_costs'].config(text=f"{total_costs:,.0f} AFN")
            self.cost_summary_cards['net_profit'].config(text=f"{net_profit:,.0f} AFN",
                                                        fg="#4CAF50" if net_profit >= 0 else "#F44336")
            self.cost_summary_cards['roi'].config(text=f"{roi:.1f}%")

            # Clear charts
            for widget in self.monthly_chart_frame.winfo_children():
                if isinstance(widget, tk.Canvas):
                    widget.destroy()
            for widget in self.pie_chart_frame.winfo_children():
                if isinstance(widget, tk.Canvas):
                    widget.destroy()

            # Monthly chart
            if transactions:
                monthly_data = {}
                for t in transactions:
                    month = t['date'][:7] if t['date'] else "Unknown"
                    if t['type'] == 'Revenue':
                        monthly_data.setdefault(month, {'rev': 0, 'cost': 0})['rev'] += t['amount']
                    else:
                        monthly_data.setdefault(month, {'rev': 0, 'cost': 0})['cost'] += t['amount']

                if monthly_data:
                    months = sorted(monthly_data.keys())
                    rev = [monthly_data[m]['rev'] for m in months]
                    cost = [monthly_data[m]['cost'] for m in months]

                    fig, ax = plt.subplots(figsize=(8, 4))
                    fig.patch.set_facecolor('white')
                    x = range(len(months))
                    ax.bar([i - 0.2 for i in x], rev, width=0.4, label='Revenue', color='#4CAF50')
                    ax.bar([i + 0.2 for i in x], cost, width=0.4, label='Costs', color='#F44336')
                    ax.set_xticks(x)
                    ax.set_xticklabels(months, rotation=45)
                    ax.set_ylabel('Amount (AFN)')
                    ax.set_title('Monthly Financial Trend')
                    ax.legend()
                    ax.grid(True, alpha=0.3)

                    canvas = FigureCanvasTkAgg(fig, self.monthly_chart_frame)
                    canvas.draw()
                    canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)

            # Pie chart (cost categories)
            categories = {}
            for t in transactions:
                if t['type'] in ['Expense', 'Investment']:
                    cat = t.get('category', 'Other')
                    categories[cat] = categories.get(cat, 0) + t['amount']

            if categories:
                fig, ax = plt.subplots(figsize=(6, 6))
                fig.patch.set_facecolor('white')
                colors = plt.cm.Set3(np.linspace(0, 1, len(categories)))
                ax.pie(categories.values(), labels=categories.keys(), colors=colors, autopct='%1.1f%%',
                    wedgeprops={'edgecolor': 'white'})
                ax.set_title('Cost Breakdown by Category')

                canvas = FigureCanvasTkAgg(fig, self.pie_chart_frame)
                canvas.draw()
                canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)

            # Update transactions table
            for item in self.transactions_tree.get_children():
                self.transactions_tree.delete(item)
            for t in transactions[-20:]:  # Last 20
                self.transactions_tree.insert("", "end", values=(
                    t.get('date', ''),
                    t.get('site_id', ''),
                    t.get('type', ''),
                    t.get('category', ''),
                    f"{t.get('amount', 0):,.0f}",
                    t.get('description', '')[:40]
                ))

        except Exception as e:
            self.logger.error(f"Error loading financial data: {e}")

    def add_financial_transaction(self):
        """Open form to add financial transaction"""
        # Similar to show_site_form – implement with fields: Site ID, Type, Amount, Category, Date, Description
        # For now, placeholder
        messagebox.showinfo("Feature", "Add Transaction form coming soon!\n(Implement similar to show_site_form)")
    def create_status_analysis_graph(self):
        """Create status analysis graph with modern styling"""
        try:
            stats = self.db.get_excel_statistics()

            fig, axes = plt.subplots(1, 2, figsize=(14, 6))
            fig.suptitle('Status Analysis', fontsize=18, fontweight='bold', color='#1976D2')

            fig.patch.set_facecolor('#e3f2fd')
            for ax in axes:
                ax.set_facecolor('white')
                ax.grid(True, linestyle='--', alpha=0.5, color='#bbdefb')
                ax.spines['top'].set_visible(False)
                ax.spines['right'].set_visible(False)
                ax.tick_params(colors='#424242')
                current_title = ax.get_title()
                if current_title:
                    ax.set_title(current_title, fontsize=14, fontweight='bold', color='#1976D2', pad=20)

            # Bar
            if stats.get('by_status'):
                statuses = list(stats['by_status'].keys())
                counts = list(stats['by_status'].values())
                colors = ['#4CAF50' if s == 'Active' else '#FF9800' if s == 'Confirmed' else '#F44336' for s in statuses]
                bars = axes[0].bar(statuses, counts, color=colors, edgecolor='white')
                axes[0].set_title('Site Status Distribution')
                axes[0].set_ylabel('Number of Sites')
                axes[0].tick_params(axis='x', rotation=45)
                for bar in bars:
                    height = bar.get_height()
                    axes[0].text(bar.get_x() + bar.get_width()/2., height + max(counts)*0.01,
                                f'{int(height)}', ha='center', va='bottom', fontweight='bold')

            # Pie
            if stats.get('by_status'):
                statuses = list(stats['by_status'].keys())
                counts = list(stats['by_status'].values())
                colors = plt.cm.Set3(np.linspace(0, 1, len(statuses)))
                wedges, texts, autotexts = axes[1].pie(counts, labels=statuses, colors=colors,
                                                    autopct='%1.1f%%', startangle=90,
                                                    wedgeprops={'edgecolor': 'white', 'linewidth': 2})
                axes[1].set_title('Status Percentage Distribution')
                for autotext in autotexts:
                    autotext.set_color('white')
                    autotext.set_fontweight('bold')

            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            canvas = FigureCanvasTkAgg(fig, self.graph_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True)

        except Exception as e:
            self.logger.error(f"Error creating status analysis graph: {e}")
            tk.Label(self.graph_frame, text=f"Error: {e}", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color).pack(pady=50)


    def create_geographic_analysis_graph(self):
        """Create geographic analysis graph with modern styling"""
        try:
            sites = self.db.get_excel_sites()
            if not sites:
                tk.Label(self.graph_frame, text="No geographic data available", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color).pack(pady=50)
                return

            province_counts = {}
            for site in sites:
                province = site.get('province', 'Unknown')
                if province:
                    province_counts[province] = province_counts.get(province, 0) + 1

            fig, axes = plt.subplots(1, 2, figsize=(14, 6))
            fig.suptitle('Geographic Analysis', fontsize=18, fontweight='bold', color='#1976D2')

            fig.patch.set_facecolor('#e3f2fd')
            for ax in axes:
                ax.set_facecolor('white')
                ax.grid(True, linestyle='--', alpha=0.5, color='#bbdefb')
                ax.spines['top'].set_visible(False)
                ax.spines['right'].set_visible(False)
                ax.tick_params(colors='#424242')
                current_title = ax.get_title()
                if current_title:
                    ax.set_title(current_title, fontsize=14, fontweight='bold', color='#1976D2', pad=20)

            # Horizontal Bar
            if province_counts:
                sorted_provinces = sorted(province_counts.items(), key=lambda x: x[1], reverse=True)[:15]
                names = [p[0] for p in sorted_provinces]
                values = [p[1] for p in sorted_provinces]
                bars = axes[0].barh(names, values, color='#2196F3', edgecolor='white')
                axes[0].set_title('Top 15 Provinces by Site Count')
                axes[0].set_xlabel('Number of Sites')
                axes[0].invert_yaxis()
                for bar in bars:
                    width = bar.get_width()
                    axes[0].text(width + max(values)*0.01, bar.get_y() + bar.get_height()/2,
                                f'{int(width)}', ha='left', va='center', fontweight='bold', fontsize=10)

            # Simulated Heatmap/Text
            axes[1].text(0.5, 0.5, 'Geographic Distribution Summary\n\nTop Provinces:',
                        ha='center', va='center', fontsize=12, fontweight='bold')
            y_pos = 0.4
            for province, count in list(province_counts.items())[:10]:
                axes[1].text(0.5, y_pos, f'{province}: {count} sites',
                            ha='center', va='center', fontsize=11)
                y_pos -= 0.05
            axes[1].axis('off')
            axes[1].set_title('Province Overview')

            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            canvas = FigureCanvasTkAgg(fig, self.graph_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True)

        except Exception as e:
            self.logger.error(f"Error creating geographic analysis graph: {e}")
            tk.Label(self.graph_frame, text=f"Error: {e}", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color).pack(pady=50)


    def create_timeline_analysis_graph(self):
        """Create timeline analysis graph with modern styling"""
        try:
            sites = self.db.get_excel_sites()
            if not sites:
                tk.Label(self.graph_frame, text="No timeline data available", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color).pack(pady=50)
                return

            months = {}
            status_changes = {}
            for site in sites:
                created_at = site.get('created_at', '')
                if created_at:
                    try:
                        month = created_at[:7]
                        months[month] = months.get(month, 0) + 1
                    except:
                        pass
                status = site.get('status', 'Unknown')
                status_changes[status] = status_changes.get(status, 0) + 1

            fig, axes = plt.subplots(1, 2, figsize=(14, 6))
            fig.suptitle('Timeline Analysis', fontsize=18, fontweight='bold', color='#1976D2')

            fig.patch.set_facecolor('#e3f2fd')
            for ax in axes:
                ax.set_facecolor('white')
                ax.grid(True, linestyle='--', alpha=0.5, color='#bbdefb')
                ax.spines['top'].set_visible(False)
                ax.spines['right'].set_visible(False)
                ax.tick_params(colors='#424242')
                current_title = ax.get_title()
                if current_title:
                    ax.set_title(current_title, fontsize=14, fontweight='bold', color='#1976D2', pad=20)

            # Line Chart
            if months:
                sorted_months = sorted(months.items())
                labels = [m[0] for m in sorted_months]
                values = [m[1] for m in sorted_months]
                axes[0].plot(labels, values, marker='o', color='#FF9800', linewidth=3, markersize=8)
                axes[0].set_title('Monthly Site Additions')
                axes[0].set_xlabel('Month')
                axes[0].set_ylabel('Number of Sites')
                axes[0].tick_params(axis='x', rotation=45)
                for i, v in enumerate(values):
                    axes[0].text(i, v + max(values)*0.02, str(v), ha='center', fontweight='bold')

            # Status Summary Text
            axes[1].text(0.5, 0.5, 'Status Trend Summary\n\nCurrent Distribution:',
                        ha='center', va='center', fontsize=12, fontweight='bold')
            y_pos = 0.4
            for status, count in list(status_changes.items())[:8]:
                axes[1].text(0.5, y_pos, f'{status}: {count} sites',
                            ha='center', va='center', fontsize=11)
                y_pos -= 0.05
            axes[1].axis('off')
            axes[1].set_title('Status Distribution Over Time')

            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            canvas = FigureCanvasTkAgg(fig, self.graph_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True)

        except Exception as e:
            self.logger.error(f"Error creating timeline analysis graph: {e}")
            tk.Label(self.graph_frame, text=f"Error: {e}", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color).pack(pady=50)


    def create_comparative_analysis_graph(self):
        """Create comparative analysis graph with modern styling"""
        try:
            dash_data = self.db.get_excel_dashboard_data()

            fig, axes = plt.subplots(2, 2, figsize=(14, 10))
            fig.suptitle('Comparative Analysis', fontsize=18, fontweight='bold', color='#1976D2')

            fig.patch.set_facecolor('#e3f2fd')
            for ax in axes.flat:
                ax.set_facecolor('white')
                ax.grid(True, linestyle='--', alpha=0.5, color='#bbdefb')
                ax.spines['top'].set_visible(False)
                ax.spines['right'].set_visible(False)
                ax.tick_params(colors='#424242')
                current_title = ax.get_title()
                if current_title:
                    ax.set_title(current_title, fontsize=14, fontweight='bold', color='#1976D2', pad=20)

            # Stacked Bar
            if dash_data['by_province'][:5]:
                provinces = [item['province'] for item in dash_data['by_province'][:5]]
                active = [item.get('active', 0) for item in dash_data['by_province'][:5]]
                confirmed = [item.get('confirmed', 0) for item in dash_data['by_province'][:5]]
                pending = [item.get('pending', 0) for item in dash_data['by_province'][:5]]
                x = range(len(provinces))
                axes[0, 0].bar(x, active, label='Active', color='#4CAF50', edgecolor='white')
                axes[0, 0].bar(x, confirmed, bottom=active, label='Confirmed', color='#2196F3', edgecolor='white')
                axes[0, 0].bar(x, pending, bottom=[a+c for a,c in zip(active, confirmed)],
                            label='Pending', color='#FF9800', edgecolor='white')
                axes[0, 0].set_xticks(x)
                axes[0, 0].set_xticklabels(provinces, rotation=45)
                axes[0, 0].set_ylabel('Number of Sites')
                axes[0, 0].set_title('Top 5 Provinces - Status Comparison')
                axes[0, 0].legend()

            # Text placeholders with style
            axes[0, 1].text(0.5, 0.5, 'Power Source vs Tower Type\nCorrelation Insights', ha='center', va='center', fontsize=12)
            axes[0, 1].axis('off')
            axes[0, 1].set_title('Infrastructure Correlation')

            axes[1, 0].text(0.5, 0.5, 'Operator Performance Metrics\n(Top Operators Shown)', ha='center', va='center', fontsize=12)
            if dash_data['by_operator']:
                y_pos = 0.4
                for item in dash_data['by_operator'][:6]:
                    axes[1, 0].text(0.5, y_pos, f"{item['operator_site']}: {item['count']} sites",
                                    ha='center', va='center', fontsize=11)
                    y_pos -= 0.05
            axes[1, 0].axis('off')
            axes[1, 0].set_title('Operator Comparison')

            axes[1, 1].text(0.5, 0.5, 'System Efficiency Metrics\n\nData Completeness: High\nAccuracy: Excellent\nUpdate Frequency: Good',
                            ha='center', va='center', fontsize=12)
            axes[1, 1].axis('off')
            axes[1, 1].set_title('System Efficiency')

            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            canvas = FigureCanvasTkAgg(fig, self.graph_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True)

        except Exception as e:
            self.logger.error(f"Error creating comparative analysis graph: {e}")
            tk.Label(self.graph_frame, text=f"Error: {e}", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color).pack(pady=50)


    def create_maintenance_analysis_graph(self):
        """Create maintenance analysis graph with modern styling"""
        try:
            stats = self.db.get_maintenance_statistics()

            fig, axes = plt.subplots(2, 2, figsize=(14, 10))
            fig.suptitle('Maintenance Analysis', fontsize=18, fontweight='bold', color='#1976D2')

            fig.patch.set_facecolor('#e3f2fd')
            for ax in axes.flat:
                ax.set_facecolor('white')
                ax.grid(True, linestyle='--', alpha=0.5, color='#bbdefb')
                ax.spines['top'].set_visible(False)
                ax.spines['right'].set_visible(False)
                ax.tick_params(colors='#424242')
                current_title = ax.get_title()
                if current_title:
                    ax.set_title(current_title, fontsize=14, fontweight='bold', color='#1976D2', pad=20)

            # Tasks by Status
            if stats.get('by_status'):
                statuses = list(stats['by_status'].keys())
                counts = list(stats['by_status'].values())
                colors = ['#4CAF50' if s == 'completed' else '#FF9800' if s == 'pending' else '#F44336' for s in statuses]
                bars = axes[0, 0].bar(statuses, counts, color=colors, edgecolor='white')
                axes[0, 0].set_title('Maintenance Tasks by Status')
                axes[0, 0].set_ylabel('Number of Tasks')
                axes[0, 0].tick_params(axis='x', rotation=45)
                for bar in bars:
                    height = bar.get_height()
                    axes[0, 0].text(bar.get_x() + bar.get_width()/2., height + max(counts)*0.01,
                                    f'{int(height)}', ha='center', va='bottom', fontweight='bold')

            # Priority Pie
            if stats.get('by_priority'):
                priorities = list(stats['by_priority'].keys())
                counts = list(stats['by_priority'].values())
                colors = ['#F44336' if p == 'high' else '#FF9800' if p == 'medium' else '#4CAF50' for p in priorities]
                wedges, texts, autotexts = axes[0, 1].pie(counts, labels=priorities, colors=colors,
                                                        autopct='%1.1f%%', wedgeprops={'edgecolor': 'white', 'linewidth': 2})
                axes[0, 1].set_title('Tasks by Priority Level')
                for autotext in autotexts:
                    autotext.set_color('white')
                    autotext.set_fontweight('bold')

            # Tasks by Type
            if stats.get('by_type'):
                types = list(stats['by_type'].keys())
                counts = list(stats['by_type'].values())
                bars = axes[1, 0].bar(types, counts, color='#2196F3', edgecolor='white')
                axes[1, 0].set_title('Maintenance Tasks by Type')
                axes[1, 0].set_ylabel('Number of Tasks')
                axes[1, 0].tick_params(axis='x', rotation=45)
                for bar in bars:
                    height = bar.get_height()
                    axes[1, 0].text(bar.get_x() + bar.get_width()/2., height + max(counts)*0.01,
                                    f'{int(height)}', ha='center', va='bottom', fontweight='bold')

            # Summary Text
            summary = f"""Maintenance Summary
    Total Tasks: {stats.get('total_tasks', 0)}
    Overdue: {stats.get('overdue_tasks', 0)}
    Upcoming (7 days): {stats.get('upcoming_tasks', 0)}

    Completion Rate: {stats.get('by_status', {}).get('completed', 0) / max(stats.get('total_tasks', 1), 1) * 100:.1f}%
    Pending Rate: {stats.get('by_status', {}).get('pending', 0) / max(stats.get('total_tasks', 1), 1) * 100:.1f}%"""
            axes[1, 1].text(0.5, 0.5, summary, ha='center', va='center', fontsize=12, fontweight='bold')
            axes[1, 1].axis('off')
            axes[1, 1].set_title('Maintenance Performance')

            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            canvas = FigureCanvasTkAgg(fig, self.graph_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True)

        except Exception as e:
            self.logger.error(f"Error creating maintenance analysis graph: {e}")
            tk.Label(self.graph_frame, text=f"Error: {e}", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color).pack(pady=50)
    
    def generate_analysis_report(self):
        """Generate analysis report"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
            
        # Create report window
        report_window = tk.Toplevel(self.root)
        report_window.title("Analysis Report")
        report_window.geometry("800x600")
        report_window.configure(bg=self.bg_color)
        
        # Title
        tk.Label(
            report_window,
            text="📊 Data Analysis Report",
            font=("Arial", 16, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=20)
        
        # Create scrolled text widget for report
        report_text = scrolledtext.ScrolledText(
            report_window,
            width=90,
            height=30,
            bg="white",
            fg="black",
            font=("Courier", 10)
        )
        report_text.pack(padx=10, pady=10)
        
        # Generate report content
        report_content = self.generate_report_content()
        report_text.insert("1.0", report_content)
        report_text.config(state="disabled")
        
        # Save button
        tk.Button(
            report_window,
            text="💾 Save Report",
            command=lambda: self.save_report(report_content),
            bg="#4CAF50",
            fg="white",
            font=("Arial", 11),
            relief="flat",
            padx=20,
            pady=10,
            cursor="hand2"
        ).pack(pady=10)
    
    def generate_report_content(self):
        """Generate report content"""
        try:
            # Get data
            excel_stats = self.db.get_excel_statistics()
            maint_stats = self.db.get_maintenance_statistics()
            dash_data = self.db.get_excel_dashboard_data()
            
            # Generate report
            report = "=" * 80 + "\n"
            report += "SITE MANAGEMENT SYSTEM - ANALYSIS REPORT\n"
            report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            report += "=" * 80 + "\n\n"
            
            # 1. Executive Summary
            report += "1. EXECUTIVE SUMMARY\n"
            report += "-" * 40 + "\n"
            report += f"Total Sites: {excel_stats.get('total_sites', 0)}\n"
            report += f"Active Sites: {excel_stats.get('by_status', {}).get('Active', 0)}\n"
            report += f"Total Maintenance Tasks: {maint_stats.get('total_tasks', 0)}\n"
            report += f"Data Import Date: {excel_stats.get('last_import', 'Never')}\n\n"
            
            # 2. Site Distribution
            report += "2. SITE DISTRIBUTION\n"
            report += "-" * 40 + "\n"
            if dash_data['by_province']:
                report += "By Province (Top 10):\n"
                for item in dash_data['by_province'][:10]:
                    report += f"  {item['province']}: {item['count']} sites (Active: {item.get('active', 0)}, Pending: {item.get('pending', 0)})\n"
            report += "\n"
            
            # 3. Status Analysis
            report += "3. STATUS ANALYSIS\n"
            report += "-" * 40 + "\n"
            if excel_stats.get('by_status'):
                for status, count in excel_stats['by_status'].items():
                    percentage = (count / max(excel_stats.get('total_sites', 1), 1)) * 100
                    report += f"  {status}: {count} sites ({percentage:.1f}%)\n"
            report += "\n"
            
            # 4. Maintenance Analysis
            report += "4. MAINTENANCE ANALYSIS\n"
            report += "-" * 40 + "\n"
            report += f"Total Maintenance Tasks: {maint_stats.get('total_tasks', 0)}\n"
            report += f"Overdue Tasks: {maint_stats.get('overdue_tasks', 0)}\n"
            report += f"Upcoming Tasks (7 days): {maint_stats.get('upcoming_tasks', 0)}\n\n"
            
            if maint_stats.get('by_status'):
                report += "By Status:\n"
                for status, count in maint_stats['by_status'].items():
                    report += f"  {status.capitalize()}: {count} tasks\n"
            
            report += "\n"
            
            # 5. Recommendations
            report += "5. RECOMMENDATIONS\n"
            report += "-" * 40 + "\n"
            
            # Generate recommendations based on data
            if maint_stats.get('overdue_tasks', 0) > 0:
                report += f"⚠️  Urgent: {maint_stats.get('overdue_tasks', 0)} maintenance tasks are overdue\n"
            
            pending_sites = excel_stats.get('by_status', {}).get('Resurvey', 0) + \
                           excel_stats.get('by_status', {}).get('Fresh Introduced', 0) + \
                           excel_stats.get('by_status', {}).get('Surveyed', 0)
            
            if pending_sites > 0:
                report += f"📋  Action Required: {pending_sites} sites need attention (Resurvey/Fresh/Surveyed)\n"
            
            if excel_stats.get('last_import') == "Never":
                report += "🔄  Data Update Needed: No Excel data has been imported yet\n"
            else:
                report += f"✅  Data Status: Last import was {excel_stats.get('last_import')}\n"
            
            report += "\n"
            
            # 6. System Metrics
            report += "6. SYSTEM METRICS\n"
            report += "-" * 40 + "\n"
            report += f"Data Completeness: {self.calculate_data_completeness():.1f}%\n"
            report += f"Data Accuracy Score: {self.calculate_data_accuracy():.1f}%\n"
            report += f"System Performance: Good\n"
            
            report += "\n" + "=" * 80 + "\n"
            report += "END OF REPORT\n"
            report += "=" * 80 + "\n"
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating report: {e}")
            return f"Error generating report: {e}"
    
    def calculate_data_accuracy(self):
        """Calculate data accuracy percentage"""
        try:
            sites = self.db.get_excel_sites()
            if not sites:
                return 0.0
            
            valid_sites = 0
            for site in sites:
                # Check if site has valid coordinates
                lat = site.get('latitude', 0)
                lon = site.get('longitude', 0)
                
                if -90 <= lat <= 90 and -180 <= lon <= 180:
                    valid_sites += 1
            
            return (valid_sites / len(sites)) * 100 if sites else 0.0
            
        except:
            return 0.0
    
    def save_report(self, report_content):
        """Save analysis report to file"""
        filename = filedialog.asksaveasfilename(
            title="Save Analysis Report",
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                
                messagebox.showinfo("Success", f"Report saved to:\n{filename}")
                self.update_status(f"Analysis report saved")
                
            except Exception as e:
                self.logger.error(f"Error saving report: {e}")
                messagebox.showerror("Error", f"Failed to save report: {e}")
    
    def save_analysis_graph(self):
        """Save current analysis graph to file"""
        if not hasattr(self, 'current_figure'):
            messagebox.showwarning("No Graph", "No graph to save")
            return
            
        filename = filedialog.asksaveasfilename(
            title="Save Graph",
            defaultextension=".png",
            filetypes=[
                ("PNG files", "*.png"),
                ("PDF files", "*.pdf"),
                ("All files", "*.*")
            ]
        )
        
        if filename:
            try:
                self.current_figure.savefig(filename, dpi=300, bbox_inches='tight')
                messagebox.showinfo("Success", f"Graph saved to:\n{filename}")
                self.update_status(f"Graph saved: {filename}")
                
            except Exception as e:
                self.logger.error(f"Error saving graph: {e}")
                messagebox.showerror("Error", f"Failed to save graph: {e}")
    
    def show_analysis(self, analysis_type):
        """Show specific analysis type"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
            
        self.analysis_type_var.set(analysis_type)
        self.update_analysis()
        self.notebook.select(3)  # Switch to Analyze tab
    
    # ==================== MAIN FUNCTIONS ====================
    
    def show_login(self):
        """Show login dialog"""
        if self.current_user:
            messagebox.showinfo("Already Logged In", f"You are already logged in as {self.current_user}")
            return
        
        login_window = tk.Toplevel(self.root)
        login_window.title("Login to System")
        login_window.geometry("350x250")
        login_window.configure(bg=self.bg_color)
        login_window.transient(self.root)
        login_window.grab_set()
        
        # Center the login window
        login_window.update_idletasks()
        width = login_window.winfo_width()
        height = login_window.winfo_height()
        x = (login_window.winfo_screenwidth() // 2) - (width // 2)
        y = (login_window.winfo_screenheight() // 2) - (height // 2)
        login_window.geometry(f'{width}x{height}+{x}+{y}')
    
        # Title
        tk.Label(
            login_window,
            text=" Knackrise TTSP Project",
            font=("Arial", 14, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=(20, 10))
    
        # Login frame
        login_frame = tk.Frame(login_window, bg=self.bg_color)
        login_frame.pack(pady=10)
    
        # Username
        tk.Label(
            login_frame,
            text="Username",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10)
        ).grid(row=0, column=0, padx=10, pady=10, sticky="w")
    
        username_var = tk.StringVar()
        username_entry = tk.Entry(
            login_frame,
            textvariable=username_var,
            bg="white",
            fg="black",
            width=25,
            font=("Arial", 10)
        )
        username_entry.grid(row=0, column=1, padx=10, pady=10)
    
        # Password
        tk.Label(
            login_frame,
            text="Password",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10)
        ).grid(row=1, column=0, padx=10, pady=10, sticky="w")
    
        password_var = tk.StringVar()
        password_entry = tk.Entry(
            login_frame,
            textvariable=password_var,
            show="*",
            bg="black",
            fg="white",
            width=25,
            font=("Arial", 10)
        )
        password_entry.grid(row=1, column=1, padx=10, pady=10)
    
        # Credentials hint
        hint_label = tk.Label(
            login_window,
            text="Mr.Enginner Mustafa ERSHAD",
            bg=self.bg_color,
            fg="gray",
            font=("Arial", 9)
        )
        hint_label.pack(pady=(0, 10))
    
        def attempt_login():
            username = username_var.get()
            password = password_var.get()
        
            # Simple authentication
            if username == "MEMA" and password == "MEMA_LOGIN":
                self.current_user = "admin"
                self.user_permissions = ['all']
                self.user_label.config(text=f"👤 {username} (Admin)")
                self.update_status(f"Welcome {username}")
            
                # Load Excel data
                self.load_excel_sites()
                self.refresh_dashboard()
            
                # Update filter dropdowns
                self.update_filter_dropdowns()
            
                login_window.destroy()
                messagebox.showinfo("Login Successful", "Welcome to Site Management System!")
            else:
                messagebox.showerror("Login Failed", "Invalid username or password")
                password_var.set("")  # Clear password field
    
        # Login button
        login_button = tk.Button(
            login_window,
            text="🔓 LOGIN",
            command=attempt_login,
            bg="#007acc",
            fg="white",
            font=("Arial", 11, "bold"),
            relief="raised",
            padx=30,
            pady=10,
            cursor="hand2"
        )
        login_button.pack(pady=20)
    
        # Bind Enter key to login
        login_window.bind('<Return>', lambda e: attempt_login())
    
        # Focus on username field
        username_entry.focus_set()
    
        # Make sure window stays on top
        login_window.lift()
        login_window.focus_force()
        
    def logout(self):
        """Logout current user"""
        self.current_user = None
        self.user_permissions = []
        self.user_label.config(text="Not logged in")
        self.update_status("Logged out")
        
    def load_excel_sites(self):
        """Load Excel sites into treeview"""
        if not self.current_user:
            return
            
        try:
            # Clear existing items
            for item in self.sites_tree.get_children():
                self.sites_tree.delete(item)
                
            # Get sites from database
            sites = self.db.get_excel_sites()
            
            # Add to treeview
            for site in sites:
                on_air = site.get('on_air', '')
                if on_air:
                    try:
                        on_air_date = datetime.strptime(str(on_air), '%Y-%m-%d')
                        on_air = on_air_date.strftime('%Y-%m-%d')
                    except:
                        pass
                        
                self.sites_tree.insert("", "end", values=(
                    site.get('s_no', ''),
                    site.get('site_id', ''),
                    site.get('knackrise_id', ''),
                    site.get('province', ''),
                    site.get('location', ''),
                    site.get('status', ''),
                    site.get('operator_site', ''),
                    site.get('tower_type', ''),
                    site.get('power_sources', ''),
                    on_air
                ))
                
            self.update_status(f"Loaded {len(sites)} Excel sites")
            self.refresh_dashboard()
            
        except Exception as e:
            self.logger.error(f"Error loading Excel sites: {e}")
            messagebox.showerror("Error", f"Failed to load Excel sites: {e}")
    
    def update_filter_dropdowns(self):
        """Update filter dropdown values"""
        try:
            # Get unique values from database
            sites = self.db.get_excel_sites()
            
            # Provinces
            provinces = list(set(site['province'] for site in sites if site.get('province')))
            self.province_filter['values'] = ['All'] + sorted(provinces)
            
            # Operators
            operators = list(set(site['operator_site'] for site in sites if site.get('operator_site')))
            self.operator_filter['values'] = ['All'] + sorted(operators)
            
        except Exception as e:
            self.logger.error(f"Error updating filter dropdowns: {e}")
    
    def filter_excel_sites(self):
        """Filter Excel sites based on criteria"""
        if not self.current_user:
            return
            
        try:
            # Get filter values
            search_text = self.site_search_var.get().lower()
            province = self.province_filter_var.get()
            status = self.status_filter_var.get()
            operator = self.operator_filter_var.get()
            
            # Clear treeview
            for item in self.sites_tree.get_children():
                self.sites_tree.delete(item)
                
            # Build filters
            filters = {}
            if province and province != 'All':
                filters['province'] = province
            if status and status != 'All':
                filters['status'] = status
            if operator and operator != 'All':
                filters['operator_site'] = operator
            if search_text:
                filters['search'] = search_text
                
            sites = self.db.get_excel_sites(filters)
            
            # Add filtered sites
            for site in sites:
                on_air = site.get('on_air', '')
                if on_air:
                    try:
                        on_air_date = datetime.strptime(str(on_air), '%Y-%m-%d')
                        on_air = on_air_date.strftime('%Y-%m-%d')
                    except:
                        pass
                        
                self.sites_tree.insert("", "end", values=(
                    site.get('s_no', ''),
                    site.get('site_id', ''),
                    site.get('knackrise_id', ''),
                    site.get('province', ''),
                    site.get('location', ''),
                    site.get('status', ''),
                    site.get('operator_site', ''),
                    site.get('tower_type', ''),
                    site.get('power_sources', ''),
                    on_air
                ))
                
            self.update_status(f"Showing {len(sites)} Excel sites")
            
        except Exception as e:
            self.logger.error(f"Error filtering Excel sites: {e}")
    
    def clear_filters(self):
        """Clear all filters"""
        self.site_search_var.set('')
        self.province_filter_var.set('')
        self.status_filter_var.set('All')
        self.operator_filter_var.set('All')
        self.filter_excel_sites()
    
    def import_excel(self):
        """Import data from Excel file"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
        
        filename = filedialog.askopenfilename(
            title="Select Excel File",
            filetypes=[
                ("Excel files", "*.xlsx *.xls"),
                ("All files", "*.*")
            ]
        )
        
        if filename:
            try:
                # Show progress
                progress_window = tk.Toplevel(self.root)
                progress_window.title("Importing Excel Data")
                progress_window.geometry("300x150")
                progress_window.configure(bg=self.bg_color)
                progress_window.transient(self.root)
                
                tk.Label(
                    progress_window,
                    text="Importing Excel data...",
                    font=("Arial", 12),
                    bg=self.bg_color,
                    fg=self.fg_color
                ).pack(pady=20)
                
                progress_var = tk.DoubleVar()
                progress_bar = ttk.Progressbar(
                    progress_window,
                    variable=progress_var,
                    maximum=100,
                    mode='indeterminate'
                )
                progress_bar.pack(pady=10)
                progress_bar.start()
                
                # Update window
                progress_window.update()
                
                # Import data
                imported = self.db.excel_integration.import_excel_file(filename)
                
                progress_window.destroy()
                if imported > 0:
                    messagebox.showinfo("Import Successful", 
                                      f"Imported {imported} sites from Excel")
                    self.load_excel_sites()
                    self.update_filter_dropdowns()
                    self.refresh_dashboard()
                    self.update_status(f"Imported {imported} sites from Excel")
                else:
                    messagebox.showwarning("Import Failed", 
                                         "No data was imported. Check the Excel format.")
                
            except Exception as e:
                self.logger.error(f"Error importing Excel: {e}")
                messagebox.showerror("Import Error", f"Failed to import Excel file:\n{str(e)}")
    
    def export_excel(self):
        """Export data to Excel format"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Export to Excel",
            defaultextension=".xlsx",
            filetypes=[
                ("Excel files", "*.xlsx"),
                ("All files", "*.*")
            ]
        )
        
        if filename:
            try:
                # Get current filter settings
                filters = {}
                province = self.province_filter_var.get()
                status = self.status_filter_var.get()
                operator = self.operator_filter_var.get()
                
                if province and province != 'All':
                    filters['province'] = province
                if status and status != 'All':
                    filters['status'] = status
                if operator and operator != 'All':
                    filters['operator_site'] = operator
                
                # Get sites with current filters
                sites = self.db.get_excel_sites(filters)
                
                if not sites:
                    messagebox.showwarning("No Data", "No data to export")
                    return
                
                # Export to Excel
                success = self.db.excel_integration.export_to_excel(sites, filename)
                
                if success:
                    messagebox.showinfo("Export Successful", 
                                      f"Exported {len(sites)} sites to Excel:\n{filename}")
                    self.update_status(f"Exported {len(sites)} sites to Excel")
                else:
                    messagebox.showerror("Export Failed", "Failed to export data")
                    
            except Exception as e:
                self.logger.error(f"Error exporting to Excel: {e}")
                messagebox.showerror("Export Error", f"Failed to export Excel file:\n{str(e)}")
    
    def add_excel_site(self):
        """Add new Excel site"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
        
        self.show_site_form()
    
    def edit_excel_site(self):
        """Edit selected Excel site"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
        
        # Check which treeview to use based on current tab
        if self.notebook.index(self.notebook.select()) == 0:  # Dashboard tab
            tree = self.recent_tree
        else:  # Excel Sites tab
            tree = self.sites_tree
        
        selection = tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a site to edit")
            return
        
        item = tree.item(selection[0])
        
        # Get site ID from appropriate column based on treeview
        if tree == self.recent_tree:
            site_id = item['values'][0]  # Site ID is first column in recent_tree
        else:
            site_id = item['values'][1]  # Site ID is second column in sites_tree
        
        # Get site data
        site = self.db.get_excel_site(site_id)
        if not site:
            messagebox.showerror("Error", "Site not found")
            return
        
        self.show_site_form(site)
    
    def show_site_form(self, site_data=None):
        """Show site form for add/edit – SINGLE PAGE FIT, NO SCROLLING, Font 12"""
        form_window = tk.Toplevel(self.root)
        form_window.title("Add/Edit Excel Site" if not site_data else f"Edit Site: {site_data['site_id']}")
        form_window.geometry("1250x720")
        form_window.configure(bg=self.bg_color)
        form_window.transient(self.root)
        form_window.grab_set()

        # Center window
        form_window.update_idletasks()
        x = (form_window.winfo_screenwidth() // 2) - (form_window.winfo_width() // 2)
        y = (form_window.winfo_screenheight() // 2) - (form_window.winfo_height() // 2)
        form_window.geometry(f"+{x}+{y}")

        # Main container
        main_container = tk.Frame(form_window, bg=self.bg_color)
        main_container.pack(fill="both", expand=True, padx=20, pady=15)

        # Title
        title = "➕ Add New Excel Site" if not site_data else f"✏️ Edit Site: {site_data['site_id']}"
        tk.Label(
            main_container,
            text=title,
            font=("Arial", 16, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=(0, 10))

        # Notebook with two tabs
        notebook = ttk.Notebook(main_container)
        notebook.pack(fill="both", expand=True)

        # === TAB 1: KnackRise Information ===
        knackrise_tab = tk.Frame(notebook, bg=self.bg_color)
        notebook.add(knackrise_tab, text="📋 KnackRise Information")

        # Single canvas for minimal scrolling only if needed
        canvas = tk.Canvas(knackrise_tab, bg=self.bg_color, highlightthickness=0)
        scrollbar = ttk.Scrollbar(knackrise_tab, orient="vertical", command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg=self.bg_color)

        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # 4-column compact grid
        for i in range(20):
            scroll_frame.rowconfigure(i, pad=8)

        form_entries = {}

        # --- Row 0: Title ---
        tk.Label(scroll_frame, text="BASIC INFORMATION", font=("Arial", 14, "bold"), bg=self.bg_color, fg="#1976D2")\
            .grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 10))

        # --- Row 1: S.No + Site ID ---
        tk.Label(scroll_frame, text="S.No (Auto):", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=1, column=0, sticky="w", padx=5)
        s_no_entry = tk.Entry(scroll_frame, font=("Arial", 12), width=18, bg="#F5F5F5")
        s_no_entry.grid(row=1, column=1, sticky="w", padx=5)
        if not site_data:
            next_serial = self.db.get_next_serial_number() if hasattr(self.db, 'get_next_serial_number') else 1
            s_no_entry.insert(0, str(next_serial))
            s_no_entry.config(state='readonly')
        else:
            s_no_entry.insert(0, str(site_data.get('s_no', '')))
        form_entries['s_no'] = s_no_entry

        tk.Label(scroll_frame, text="Site ID*:", font=("Arial", 12, "bold"), bg=self.bg_color, fg="red")\
            .grid(row=1, column=2, sticky="w", padx=(40, 5))
        site_id_entry = tk.Entry(scroll_frame, font=("Arial", 12), width=25)
        site_id_entry.grid(row=1, column=3, sticky="w", padx=5)
        form_entries['site_id'] = site_id_entry

        # --- Row 2: KnackRise ID + Shared With ---
        tk.Label(scroll_frame, text="KnackRise ID:", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=2, column=0, sticky="w", padx=5)
        knackrise_id_entry = tk.Entry(scroll_frame, font=("Arial", 12), width=18)
        knackrise_id_entry.grid(row=2, column=1, sticky="w", padx=5)
        form_entries['knackrise_id'] = knackrise_id_entry

        tk.Label(scroll_frame, text="Shared with:", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=2, column=2, sticky="w", padx=(40, 5))
        shared_with_entry = tk.Entry(scroll_frame, font=("Arial", 12), width=25)
        shared_with_entry.grid(row=2, column=3, sticky="w", padx=5)
        form_entries['shared_with'] = shared_with_entry

        # --- Row 3: Province + Location ---
        tk.Label(scroll_frame, text="Province*:", font=("Arial", 12, "bold"), bg=self.bg_color, fg="red")\
            .grid(row=3, column=0, sticky="w", padx=5)
        province_combo = ttk.Combobox(scroll_frame, values=self.db.get_dropdown_values('province'), font=("Arial", 12), width=16)
        province_combo.grid(row=3, column=1, sticky="w", padx=5)
        form_entries['province'] = province_combo

        tk.Label(scroll_frame, text="Location*:", font=("Arial", 12, "bold"), bg=self.bg_color, fg="red")\
            .grid(row=3, column=2, sticky="w", padx=(40, 5))
        location_entry = tk.Entry(scroll_frame, font=("Arial", 12), width=25)
        location_entry.grid(row=3, column=3, sticky="w", padx=5)
        form_entries['location'] = location_entry

        # --- Row 4: Introduced Date + Status ---
        tk.Label(scroll_frame, text="Introduced Date:", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=4, column=0, sticky="w", padx=5)
        introduced_entry = tk.Entry(scroll_frame, font=("Arial", 12), width=18)
        introduced_entry.grid(row=4, column=1, sticky="w", padx=5)
        form_entries['introduced_date'] = introduced_entry

        tk.Label(scroll_frame, text="Status:", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=4, column=2, sticky="w", padx=(40, 5))
        status_combo = ttk.Combobox(scroll_frame, values=self.db.get_dropdown_values('status'), font=("Arial", 12), width=23)
        status_combo.grid(row=4, column=3, sticky="w", padx=5)
        form_entries['status'] = status_combo

        # --- Row 5: Coordinates ---
        tk.Label(scroll_frame, text="COORDINATES", font=("Arial", 14, "bold"), bg=self.bg_color, fg="#1976D2")\
            .grid(row=5, column=0, columnspan=4, sticky="w", pady=(15, 8))

        tk.Label(scroll_frame, text="Latitude*:", font=("Arial", 12, "bold"), bg=self.bg_color, fg="red")\
            .grid(row=6, column=0, sticky="w", padx=5)
        latitude_entry = tk.Entry(scroll_frame, font=("Arial", 12), width=18)
        latitude_entry.grid(row=6, column=1, sticky="w", padx=5)
        form_entries['latitude'] = latitude_entry

        tk.Label(scroll_frame, text="Longitude*:", font=("Arial", 12, "bold"), bg=self.bg_color, fg="red")\
            .grid(row=6, column=2, sticky="w", padx=(40, 5))
        longitude_entry = tk.Entry(scroll_frame, font=("Arial", 12), width=25)
        longitude_entry.grid(row=6, column=3, sticky="w", padx=5)
        form_entries['longitude'] = longitude_entry

        # --- Row 7: Tower Info ---
        tk.Label(scroll_frame, text="TOWER & POWER", font=("Arial", 14, "bold"), bg=self.bg_color, fg="#1976D2")\
            .grid(row=7, column=0, columnspan=4, sticky="w", pady=(15, 8))

        tk.Label(scroll_frame, text="Tower Height:", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=8, column=0, sticky="w", padx=5)
        tower_height_entry = tk.Entry(scroll_frame, font=("Arial", 12), width=18)
        tower_height_entry.grid(row=8, column=1, sticky="w", padx=5)
        form_entries['tower_height'] = tower_height_entry

        tk.Label(scroll_frame, text="Tower Type:", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=8, column=2, sticky="w", padx=(40, 5))
        tower_type_combo = ttk.Combobox(scroll_frame, values=self.db.get_dropdown_values('tower_type'), font=("Arial", 12), width=23)
        tower_type_combo.grid(row=8, column=3, sticky="w", padx=5)
        form_entries['tower_type'] = tower_type_combo

        tk.Label(scroll_frame, text="Power Sources:", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=9, column=0, sticky="w", padx=5, pady=8)
        power_combo = ttk.Combobox(scroll_frame, values=self.db.get_dropdown_values('power_sources'), font=("Arial", 12), width=16)
        power_combo.grid(row=9, column=1, sticky="w", padx=5, pady=8)
        form_entries['power_sources'] = power_combo

        # --- Row 10: Timeline ---
        tk.Label(scroll_frame, text="TIMELINE & LICENSES", font=("Arial", 14, "bold"), bg=self.bg_color, fg="#1976D2")\
            .grid(row=10, column=0, columnspan=4, sticky="w", pady=(15, 8))

        tk.Label(scroll_frame, text="License NO:", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=11, column=0, sticky="w", padx=5)
        license_entry = tk.Entry(scroll_frame, font=("Arial", 12), width=18)
        license_entry.grid(row=11, column=1, sticky="w", padx=5)
        form_entries['license_no'] = license_entry

        tk.Label(scroll_frame, text="Start Construction:", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=11, column=2, sticky="w", padx=(40, 5))
        start_const_entry = tk.Entry(scroll_frame, font=("Arial", 12), width=25)
        start_const_entry.grid(row=11, column=3, sticky="w", padx=5)
        form_entries['start_construction_work'] = start_const_entry

        tk.Label(scroll_frame, text="RFI:", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=12, column=0, sticky="w", padx=5, pady=8)
        rfi_entry = tk.Entry(scroll_frame, font=("Arial", 12), width=18)
        rfi_entry.grid(row=12, column=1, sticky="w", padx=5, pady=8)
        form_entries['rfi'] = rfi_entry

        tk.Label(scroll_frame, text="On-Air Date:", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=12, column=2, sticky="w", padx=(40, 5), pady=8)
        on_air_entry = tk.Entry(scroll_frame, font=("Arial", 12), width=25)
        on_air_entry.grid(row=12, column=3, sticky="w", padx=5, pady=8)
        form_entries['on_air'] = on_air_entry

        # --- Row 13: Checklist ---
        tk.Label(scroll_frame, text="STATUS CHECKLIST", font=("Arial", 14, "bold"), bg=self.bg_color, fg="#1976D2")\
            .grid(row=13, column=0, columnspan=4, sticky="w", pady=(15, 5))

        check_frame = tk.Frame(scroll_frame, bg=self.bg_color)
        check_frame.grid(row=14, column=0, columnspan=4, pady=5)

        boolean_fields = [
            ("Surveyed", "surveyed"),
            ("Refered to AFTEL", "refered_to_aftel"),
            ("Applied for ATRA License", "applied_for_atra_license"),
            ("Received ATRA License", "received_atra_license")
        ]
        for i, (label, field) in enumerate(boolean_fields):
            var = tk.BooleanVar()
            tk.Checkbutton(check_frame, text=label, variable=var, font=("Arial", 12), bg=self.bg_color, fg=self.fg_color,
                        selectcolor=self.secondary_bg).grid(row=i//2, column=i%2, sticky="w", padx=30)
            form_entries[field] = var

        # === TAB 2: Operator Information ===
        operator_tab = tk.Frame(notebook, bg=self.bg_color)
        notebook.add(operator_tab, text="🏢 Operator Information")

        op_canvas = tk.Canvas(operator_tab, bg=self.bg_color, highlightthickness=0)
        op_scrollbar = ttk.Scrollbar(operator_tab, orient="vertical", command=op_canvas.yview)
        op_frame = tk.Frame(op_canvas, bg=self.bg_color)

        op_canvas.configure(yscrollcommand=op_scrollbar.set)
        op_canvas.create_window((0, 0), window=op_frame, anchor="nw")
        op_frame.bind("<Configure>", lambda e: op_canvas.configure(scrollregion=op_canvas.bbox("all")))

        op_canvas.pack(side="left", fill="both", expand=True)
        op_scrollbar.pack(side="right", fill="y")

        tk.Label(op_frame, text="OPERATOR DETAILS", font=("Arial", 14, "bold"), bg=self.bg_color, fg="#FF9800")\
            .grid(row=0, column=0, columnspan=4, pady=(20, 15), sticky="w")

        tk.Label(op_frame, text="Operator Site:", font=("Arial", 12, "bold"), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=1, column=0, sticky="w", padx=20, pady=10)
        operator_combo = ttk.Combobox(op_frame, values=self.db.get_dropdown_values('operator_site'), font=("Arial", 12), width=30)
        operator_combo.grid(row=1, column=1, columnspan=3, sticky="w", padx=20, pady=10)
        form_entries['operator_site'] = operator_combo

        tk.Label(op_frame, text="Operating MNOs:", font=("Arial", 12, "bold"), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=2, column=0, sticky="w", padx=20, pady=10)
        operating_entry = tk.Entry(op_frame, font=("Arial", 12), width=40)
        operating_entry.grid(row=2, column=1, columnspan=3, sticky="w", padx=20, pady=10)
        form_entries['operating_mnos'] = operating_entry

        tk.Label(op_frame, text="OPERATOR COORDINATES", font=("Arial", 14, "bold"), bg=self.bg_color, fg="#1976D2")\
            .grid(row=3, column=0, columnspan=4, pady=(20, 10), sticky="w")

        tk.Label(op_frame, text="Operator Latitude:", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=4, column=0, sticky="w", padx=20, pady=8)
        op_lat_entry = tk.Entry(op_frame, font=("Arial", 12), width=30)
        op_lat_entry.grid(row=4, column=1, sticky="w", padx=20, pady=8)
        form_entries['operator_latitude'] = op_lat_entry

        tk.Label(op_frame, text="Operator Longitude:", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)\
            .grid(row=5, column=0, sticky="w", padx=20, pady=8)
        op_lon_entry = tk.Entry(op_frame, font=("Arial", 12), width=30)
        op_lon_entry.grid(row=5, column=1, sticky="w", padx=20, pady=8)
        form_entries['operator_longitude'] = op_lon_entry

        # Note
        note = tk.Label(op_frame,
                        text="📝 Note: Operator information is provided by the telecom operator and may differ from KnackRise records.",
                        font=("Arial", 10), bg="#E3F2FD", fg="#1565C0", justify="left", padx=10, pady=10, relief="groove", bd=2)
        note.grid(row=6, column=0, columnspan=4, pady=20, sticky="ew", padx=20)

        # === BOTTOM BUTTONS ===
        button_frame = tk.Frame(main_container, bg=self.bg_color)
        button_frame.pack(pady=15)

        def save_site():
            try:
                site_data_dict = {}
                for field, widget in form_entries.items():
                    if isinstance(widget, tk.BooleanVar):
                        site_data_dict[field] = widget.get()
                    elif isinstance(widget, (tk.Entry, ttk.Combobox)):
                        val = widget.get().strip()
                        if field in ['latitude', 'longitude', 'operator_latitude', 'operator_longitude']:
                            try:
                                site_data_dict[field] = float(val) if val else None
                            except:
                                if field in ['latitude', 'longitude']:
                                    messagebox.showerror("Invalid", f"{field} must be numeric")
                                    return
                                site_data_dict[field] = None
                        else:
                            site_data_dict[field] = val

                required = ['site_id', 'province', 'location', 'latitude', 'longitude']
                for req in required:
                    if not site_data_dict.get(req):
                        messagebox.showerror("Required", f"{req.replace('_', ' ').title()} is required")
                        return

                site_data_dict['created_by'] = self.current_user
                success, result = self.db.add_excel_site(site_data_dict)
                if success:
                    messagebox.showinfo("Success", f"Site saved: {result}")
                    form_window.destroy()
                    self.load_excel_sites()
                    self.refresh_dashboard()
                else:
                    messagebox.showerror("Error", f"Save failed: {result}")
            except Exception as e:
                messagebox.showerror("Error", str(e))

        tk.Button(button_frame, text="💾 Save Site", command=save_site,
                bg="#4CAF50", fg="white", font=("Arial", 12, "bold"), padx=30, pady=10).pack(side="left", padx=10)
        tk.Button(button_frame, text="❌ Cancel", command=form_window.destroy,
                bg="#F44336", fg="white", font=("Arial", 12), padx=30, pady=10).pack(side="left", padx=10)
        tk.Button(button_frame, text="🧹 Clear Form", command=lambda: [w.delete(0, tk.END) if isinstance(w, tk.Entry) else w.set('') for w in form_entries.values() if not isinstance(w, tk.BooleanVar)],
                bg="#FF9800", fg="white", font=("Arial", 12), padx=30, pady=10).pack(side="left", padx=10)

        # Load existing data
        if site_data:
            for field, widget in form_entries.items():
                val = site_data.get(field)
                if val is not None:
                    if isinstance(widget, tk.BooleanVar):
                        widget.set(bool(val))
                    elif isinstance(widget, tk.Entry):
                        widget.insert(0, str(val))
                    elif isinstance(widget, ttk.Combobox):
                        widget.set(str(val))

        # Focus first field
        if 'site_id' in form_entries:
            form_entries['site_id'].focus_set()
        
    def delete_excel_site(self):
        """Delete selected Excel site"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
        
        # Check which treeview to use based on current tab
        if self.notebook.index(self.notebook.select()) == 0:  # Dashboard tab
            tree = self.recent_tree
        else:  # Excel Sites tab
            tree = self.sites_tree
        
        selection = tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a site to delete")
            return
        
        item = tree.item(selection[0])
        
        # Get site ID from appropriate column based on treeview
        if tree == self.recent_tree:
            site_id = item['values'][0]  # Site ID is first column in recent_tree
            site_name = item['values'][2] if len(item['values']) > 2 else site_id
        else:
            site_id = item['values'][1]  # Site ID is second column in sites_tree
            site_name = item['values'][4] if len(item['values']) > 4 else site_id
        
        if messagebox.askyesno("Confirm Delete", 
                              f"Are you sure you want to delete site:\n{site_id} - {site_name}?"):
            success, message = self.db.delete_excel_site(site_id)
            
            if success:
                messagebox.showinfo("Success", f"Site {site_id} deleted successfully")
                self.load_excel_sites()
                self.refresh_dashboard()
                self.update_status(f"Site {site_id} deleted")
            else:
                messagebox.showerror("Error", f"Failed to delete site: {message}")
    
    def search_sites(self):
        """Show search dialog"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
        
        # Focus on search box
        self.site_search_entry.focus_set()
        self.notebook.select(1)  # Switch to Excel Sites tab
    
    def show_excel_dashboard(self):
        """Show Excel data dashboard"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
        
        dash_window = tk.Toplevel(self.root)
        dash_window.title("Data Dashboard")
        dash_window.geometry("1000x700")
        dash_window.configure(bg=self.bg_color)
        dash_window.transient(self.root)
        
        # Center window
        dash_window.update_idletasks()
        width = dash_window.winfo_width()
        height = dash_window.winfo_height()
        x = (dash_window.winfo_screenwidth() // 2) - (width // 2)
        y = (dash_window.winfo_screenheight() // 2) - (height // 2)
        dash_window.geometry(f'{width}x{height}+{x}+{y}')
        
        # Title
        tk.Label(
            dash_window,
            text="📊 Data Dashboard",
            font=("Arial", 18, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=20)
        
        # Get dashboard data
        dash_data = self.db.get_excel_dashboard_data()
        
        # Create notebook for different views
        dash_notebook = ttk.Notebook(dash_window)
        dash_notebook.pack(fill="both", expand=True, padx=20, pady=20)
        
        # 1. Province Summary
        province_frame = tk.Frame(dash_notebook, bg=self.bg_color)
        dash_notebook.add(province_frame, text="By Province")
        
        self.create_province_summary(province_frame, dash_data['by_province'])
        
        # 2. Status Summary
        status_frame = tk.Frame(dash_notebook, bg=self.bg_color)
        dash_notebook.add(status_frame, text="By Status")
        
        self.create_status_summary(status_frame, dash_data['by_status'])
        
        # 3. Operator Summary
        operator_frame = tk.Frame(dash_notebook, bg=self.bg_color)
        dash_notebook.add(operator_frame, text="By Operator")
        
        self.create_operator_summary(operator_frame, dash_data['by_operator'])
        
        # 4. Tower Type Summary
        tower_frame = tk.Frame(dash_notebook, bg=self.bg_color)
        dash_notebook.add(tower_frame, text="By Tower Type")
        
        self.create_tower_summary(tower_frame, dash_data['by_tower_type'])
        
        # 5. Maintenance Needed
        maint_frame = tk.Frame(dash_notebook, bg=self.bg_color)
        dash_notebook.add(maint_frame, text="Attention Needed")
        
        self.create_maintenance_summary(maint_frame, dash_data['maintenance_needed'])
    
    def create_province_summary(self, parent, data):
        """Create province summary view"""
        # Title
        tk.Label(
            parent,
            text="Site Distribution by Province",
            font=("Arial", 14, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=10)
        
        if not data:
            tk.Label(
                parent,
                text="No data available",
                font=("Arial", 12),
                bg=self.bg_color,
                fg=self.fg_color
            ).pack(pady=50)
            return
        
        # Create treeview
        columns = ("Province", "Total Sites", "Active", "Confirmed", "Pending")
        
        tree = ttk.Treeview(
            parent,
            columns=columns,
            show="headings",
            height=min(20, len(data))
        )
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=120)
        
        # Add data
        for row in data:
            tree.insert("", "end", values=(
                row.get('province', ''),
                row.get('count', 0),
                row.get('active', 0),
                row.get('confirmed', 0),
                row.get('pending', 0)
            ))
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y", pady=10)
    
    def create_status_summary(self, parent, data):
        """Create status summary view"""
        # Title
        tk.Label(
            parent,
            text="Site Distribution by Status",
            font=("Arial", 14, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=10)
        
        if not data:
            tk.Label(
                parent,
                text="No data available",
                font=("Arial", 12),
                bg=self.bg_color,
                fg=self.fg_color
            ).pack(pady=50)
            return
        
        # Create treeview
        columns = ("Status", "Count")
        
        tree = ttk.Treeview(
            parent,
            columns=columns,
            show="headings",
            height=min(20, len(data))
        )
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=200)
        
        # Add data
        for row in data:
            tree.insert("", "end", values=(
                row.get('status', ''),
                row.get('count', 0)
            ))
        
        tree.pack(fill="both", expand=True, padx=50, pady=10)
    
    def create_operator_summary(self, parent, data):
        """Create operator summary view"""
        # Title
        tk.Label(
            parent,
            text="Site Distribution by Operator",
            font=("Arial", 14, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=10)
        
        if not data:
            tk.Label(
                parent,
                text="No data available",
                font=("Arial", 12),
                bg=self.bg_color,
                fg=self.fg_color
            ).pack(pady=50)
            return
        
        # Create treeview
        columns = ("Operator", "Site Count")
        
        tree = ttk.Treeview(
            parent,
            columns=columns,
            show="headings",
            height=min(20, len(data))
        )
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=200)
        
        # Add data
        for row in data:
            tree.insert("", "end", values=(
                row.get('operator_site', ''),
                row.get('count', 0)
            ))
        
        tree.pack(fill="both", expand=True, padx=50, pady=10)
    
    def create_tower_summary(self, parent, data):
        """Create tower type summary view"""
        # Title
        tk.Label(
            parent,
            text="Site Distribution by Tower Type",
            font=("Arial", 14, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=10)
        
        if not data:
            tk.Label(
                parent,
                text="No data available",
                font=("Arial", 12),
                bg=self.bg_color,
                fg=self.fg_color
            ).pack(pady=50)
            return
        
        # Create treeview
        columns = ("Tower Type", "Site Count")
        
        tree = ttk.Treeview(
            parent,
            columns=columns,
            show="headings",
            height=min(20, len(data))
        )
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=200)
        
        # Add data
        for row in data:
            tree.insert("", "end", values=(
                row.get('tower_type', ''),
                row.get('count', 0)
            ))
        
        tree.pack(fill="both", expand=True, padx=50, pady=10)
    
    def create_maintenance_summary(self, parent, data):
        """Create maintenance summary view"""
        # Title
        tk.Label(
            parent,
            text="Sites Needing Attention",
            font=("Arial", 14, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=10)
        
        if not data:
            tk.Label(
                parent,
                text="No sites need attention",
                font=("Arial", 12),
                bg=self.bg_color,
                fg=self.fg_color
            ).pack(pady=50)
            return
        
        # Create treeview
        columns = ("Site ID", "Location", "Province", "Status", "Last Updated")
        
        tree = ttk.Treeview(
            parent,
            columns=columns,
            show="headings",
            height=min(20, len(data))
        )
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=120)
        
        # Add data
        for row in data:
            updated = row.get('updated_at', '')
            if updated:
                try:
                    updated_date = datetime.strptime(str(updated), '%Y-%m-%d %H:%M:%S')
                    updated = updated_date.strftime('%Y-%m-%d')
                except:
                    pass
            
            tree.insert("", "end", values=(
                row.get('site_id', ''),
                row.get('location', '')[:30] + '...' if row.get('location') and len(row.get('location')) > 30 else row.get('location', ''),
                row.get('province', ''),
                row.get('status', ''),
                updated
            ))
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y", pady=10)
    
    def show_excel_statistics(self):
        """Show Excel statistics"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
        
        stats = self.db.get_excel_statistics()
        
        stats_text = f"""
        📊 EXCEL DATA STATISTICS
        
        Total Sites: {stats.get('total_sites', 0)}
        
        By Status:
        """
        
        for status, count in stats.get('by_status', {}).items():
            stats_text += f"  {status}: {count}\n"
        
        stats_text += f"""
        By Province: {len(stats.get('by_province', {}))} provinces
        By Operator: {len(stats.get('by_operator', {}))} operators
        
        Last Import: {stats.get('last_import', 'Never')}
        """
        
        messagebox.showinfo("Excel Statistics", stats_text)
    
    def validate_excel_data(self):
        """Validate Excel data integrity"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
        
        try:
            cursor = self.db.conn.cursor()
            
            issues = []
            
            # Check for sites without required fields
            cursor.execute("""
            SELECT site_id, location 
            FROM excel_sites 
            WHERE site_id IS NULL OR site_id = '' 
               OR location IS NULL OR location = ''
            """)
            missing_required = cursor.fetchall()
            
            if missing_required:
                issues.append(f"Sites missing required fields: {len(missing_required)}")
            
            # Check for duplicate site IDs
            cursor.execute("""
            SELECT site_id, COUNT(*) as count
            FROM excel_sites
            WHERE site_id IS NOT NULL AND site_id != ''
            GROUP BY site_id
            HAVING COUNT(*) > 1
            """)
            duplicates = cursor.fetchall()
            
            if duplicates:
                issues.append(f"Duplicate site IDs: {len(duplicates)}")
            
            # Check for invalid coordinates
            cursor.execute("""
            SELECT site_id, latitude, longitude 
            FROM excel_sites 
            WHERE (latitude < -90 OR latitude > 90)
               OR (longitude < -180 OR longitude > 180)
            """)
            invalid_coords = cursor.fetchall()
            
            if invalid_coords:
                issues.append(f"Sites with invalid coordinates: {len(invalid_coords)}")
            
            if issues:
                message = "Data validation found issues:\n\n" + "\n".join(issues)
                messagebox.showwarning("Data Issues Found", message)
            else:
                messagebox.showinfo("Data Validation", "No data issues found")
            
            self.update_status("Data validation completed")
            
        except Exception as e:
            self.logger.error(f"Error validating data: {e}")
            messagebox.showerror("Error", f"Data validation failed: {e}")
    
    def cleanup_excel_data(self):
        """Clean up Excel data"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
        
        if messagebox.askyesno("Confirm Cleanup", 
                              "This will remove sites with empty Site IDs. Continue?"):
            try:
                cursor = self.db.conn.cursor()
                
                cursor.execute("DELETE FROM excel_sites WHERE site_id IS NULL OR site_id = ''")
                deleted_count = cursor.rowcount
                
                self.db.conn.commit()
                
                if deleted_count > 0:
                    messagebox.showinfo("Cleanup Complete", f"Removed {deleted_count} invalid sites")
                    self.load_excel_sites()
                    self.refresh_dashboard()
                else:
                    messagebox.showinfo("Cleanup Complete", "No data needed cleanup")
                
                self.update_status("Data cleanup completed")
                
            except Exception as e:
                self.logger.error(f"Error cleaning up data: {e}")
                messagebox.showerror("Error", f"Data cleanup failed: {e}")
    
    def backup_database(self):
        """Backup database"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
        
        try:
            # Create backup directory if it doesn't exist
            backup_dir = self.config.get('DATABASE', 'backup_path', 'backups')
            os.makedirs(backup_dir, exist_ok=True)
            
            # Generate backup filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = os.path.join(backup_dir, f'db_backup_{timestamp}.db')
            
            # Create backup
            backup_conn = sqlite3.connect(backup_file)
            self.db.conn.backup(backup_conn)
            backup_conn.close()
            
            messagebox.showinfo("Backup Successful", f"Database backed up to:\n{backup_file}")
            self.update_status("Database backup created")
            
        except Exception as e:
            self.logger.error(f"Error backing up database: {e}")
            messagebox.showerror("Error", f"Backup failed: {e}")
    
    def restore_database(self):
        """Restore database from backup"""
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please login first")
            return
        
        filename = filedialog.askopenfilename(
            title="Select Backup File",
            filetypes=[("Database files", "*.db"), ("All files", "*.*")]
        )
        
        if filename:
            if messagebox.askyesno("Confirm Restore", 
                                  "Restoring will replace current database. Continue?"):
                try:
                    # Close current connection
                    self.db.conn.close()
                    
                    # Copy backup file
                    shutil.copy2(filename, self.db.db_path)
                    
                    # Reconnect
                    self.db.connect()
                    
                    messagebox.showinfo("Restore Successful", "Database restored successfully")
                    self.update_status("Database restored")
                    
                    # Reload data
                    self.load_excel_sites()
                    self.refresh_dashboard()
                    
                except Exception as e:
                    self.logger.error(f"Error restoring database: {e}")
                    messagebox.showerror("Error", f"Restore failed: {e}")
    
    def show_settings(self):
        """Show system settings"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("System Settings")
        settings_window.geometry("500x400")
        settings_window.configure(bg=self.bg_color)
        settings_window.transient(self.root)
        
        tk.Label(
            settings_window,
            text="System Settings",
            font=("Arial", 16, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=20)
        
        # Simple settings for now
        tk.Label(
            settings_window,
            text="Settings will be implemented in future version",
            font=("Arial", 12),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=50)
    
    def toggle_filters(self):
        """Toggle filter visibility"""
        # This would show/hide filters in a real implementation
        messagebox.showinfo("Filters", "Filter visibility toggled")
    
    def show_excel_format_info(self):
        """Show Excel format information"""
        info = """
        EXCEL FILE FORMAT INFORMATION
        
        Required Columns:
        - S. No: Serial number
        - Site ID: Unique site identifier
        - Province: Site province
        - Location: Site location
        - Latitude: Decimal latitude
        - Longitude: Decimal longitude
        - Status: Site status
        
        Optional Columns:
        - KnackRise ID: Internal ID
        - Shared with: Sharing information
        - Introduced Date: Date introduced
        - Operator Site: Operating company
        - Tower Type: Type of tower
        - Power Sources: Power supply type
        - On-Air Date: When site went live
        
        File Format: .xlsx or .xls
        Sheet Name: AllSites (exactly)
        First Row: Headers
        """
        
        messagebox.showinfo("Excel Format Information", info)
    
    def show_user_guide(self):
        """Show user guide"""
        guide = """
        USER GUIDE - SITE MANAGEMENT SYSTEM
        
        1. LOGIN:
           - Username: MEMA
           - Password: MEMA_LOGIN
        
        2. IMPORT DATA:
           - Click 'Import Excel' or use Quick Actions
           - Select Excel file with site data
           - File must have 'AllSites' sheet
        
        3. MANAGE SITES:
           - View all sites in Excel Sites tab
           - Add/Edit/Delete sites using buttons
           - Search and filter sites
           - Export data to Excel
        
        4. MAINTENANCE:
           - Add maintenance tasks for sites
           - View maintenance history
           - Mark tasks as complete
        
        5. ANALYZE DATA:
           - View graphs and charts
           - Generate reports
           - Save analysis results
        
        6. SYSTEM FUNCTIONS:
           - Backup database
           - Restore from backup
           - Validate data integrity
        
        Tips:
        - Right-click on sites for quick maintenance
        - Use filters to find specific sites
        - Check dashboard for quick overview
        """
        
        messagebox.showinfo("User Guide", guide)
    
    def show_about(self):
        """Show about dialog"""
        about = """
        SITE MANAGEMENT SYSTEM
        Version: 2.0
        Developed for: Knackrise TTSP Project
        
        Features:
        ✅ Excel Import/Export
        ✅ Site Management
        ✅ Maintenance Tracking
        ✅ Data Analysis
        ✅ Reporting
        ✅ Database Backup
        
        Contact: Mr. Engineer Mustafa ERSHAD
        
        This system helps manage telecom sites
        with Excel integration and maintenance
        tracking capabilities.
        """
        
        messagebox.showinfo("About", about)
    
    def run(self):
        """Run the application"""
        # Center window on screen
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
        # Show login dialog
        self.show_login()
        
        # Bind global keyboard shortcuts
        self.root.bind('<F1>', lambda e: self.show_user_guide())
        self.root.bind('<Control-f>', lambda e: self.search_sites())
        self.root.bind('<Control-n>', lambda e: self.add_excel_site())
        self.root.bind('<Control-r>', lambda e: self.refresh_dashboard())
        self.root.bind('<Control-q>', lambda e: self.root.quit())
        
        # Run main loop
        self.root.mainloop()

# ==================== MAIN EXECUTION ====================

def main():
    """Main entry point"""
    print("🚀  Knackrise TTSP Project Management System")
    print("=" * 60)
    print("Initializing systems...")
    
    try:
        # Create necessary directories
        os.makedirs('backups', exist_ok=True)
        os.makedirs('logs', exist_ok=True)
        
        # Start application
        app = SiteManagementSystem()
        app.run()
        
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
    
    