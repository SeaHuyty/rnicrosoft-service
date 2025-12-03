import os
import psutil
import winreg  # Windows only, for registry monitoring
from pathlib import Path
import json
from datetime import datetime
import shutil

class WormDetector:
    def __init__(self):
        self.suspicious_names = ["Windows_Update_Service.exe", "Adobe_Flash_Update.exe", 
                                 "system_service.exe", "update_service.exe", "system_update.exe"]
        self.usb_drives = ['D:', 'E:', 'F:', 'G:', 'H:']
        self.autorun_paths = []
        self.blocked_processes = set()
        self.quarantine_dir = "C:/QuarantineZone/"
        self.create_quarantine_dir()
    
    def create_quarantine_dir(self):
        """Create quarantine directory"""
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir, exist_ok=True)
        
    def monitor_removable_drives(self):
        """Detect and block worm spreading via USB"""
        alerts = []
        
        for drive in self.usb_drives:
            if os.path.exists(drive):
                # Check for suspicious executables and quarantine them
                for suspicious_name in self.suspicious_names:
                    suspect_path = os.path.join(drive, suspicious_name)
                    if os.path.exists(suspect_path):
                        alert = f"THREAT: Suspicious worm file detected on {drive}: {suspicious_name}"
                        alerts.append(alert)
                        # Quarantine the file
                        self.quarantine_file(suspect_path)
                
                # Check for and neutralize autorun.inf
                autorun_path = os.path.join(drive, "autorun.inf")
                if os.path.exists(autorun_path):
                    try:
                        with open(autorun_path, 'r') as f:
                            content = f.read()
                        
                        # Check for worm-like autorun configurations
                        if any(suspicious in content.lower() for suspicious in self.suspicious_names):
                            alert = f"CRITICAL: Worm autorun configuration found on {drive} - BLOCKING"
                            alerts.append(alert)
                            # Delete the malicious autorun.inf
                            self.quarantine_file(autorun_path)
                            # Create immunized autorun.inf
                            self.immunize_usb_drive(drive)
                        else:
                            alerts.append(f"Autorun.inf detected on {drive} (monitoring)")
                    except Exception as e:
                        alerts.append(f"Error reading autorun.inf on {drive}: {e}")
        
        return alerts
    
    def immunize_usb_drive(self, drive):
        """Create protective autorun.inf to prevent worm infection"""
        try:
            immunize_content = """[AutoRun]
open=
action=
"""
            autorun_path = os.path.join(drive, "autorun.inf")
            # Make file read-only to prevent modification
            with open(autorun_path, 'w') as f:
                f.write(immunize_content)
            os.chmod(autorun_path, 0o444)  # Read-only
            print(f"[+] USB drive {drive} immunized")
        except Exception as e:
            print(f"[-] Failed to immunize {drive}: {e}")
    
    def quarantine_file(self, filepath):
        """Move suspicious file to quarantine"""
        try:
            filename = os.path.basename(filepath)
            quarantine_path = os.path.join(self.quarantine_dir, filename)
            shutil.move(filepath, quarantine_path)
            print(f"[!] QUARANTINED: {filepath}")
            return True
        except Exception as e:
            print(f"[-] Failed to quarantine {filepath}: {e}")
            return False
    
    def check_autostart_locations(self):
        """Monitor and block persistence locations"""
        alerts = []
        autostart_locations = [
            os.path.expanduser("~/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"),
            os.path.expanduser("~/AppData/Local/Temp"),
            "C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"
        ]
        
        for location in autostart_locations:
            if os.path.exists(location):
                try:
                    for file in os.listdir(location):
                        full_path = os.path.join(location, file)
                        
                        # Check for suspicious names or patterns
                        if any(suspicious in file.lower() for suspicious in [n.lower() for n in self.suspicious_names]):
                            alert = f"THREAT: Worm persistence file found: {full_path}"
                            alerts.append(alert)
                            # Quarantine immediately
                            self.quarantine_file(full_path)
                        
                        # Check for files modified very recently (worm signature)
                        if file.endswith(('.exe', '.vbs', '.bat', '.ps1')):
                            try:
                                mtime = os.path.getmtime(full_path)
                                import time
                                if (time.time() - mtime) < 60:  # Modified in last minute
                                    alert = f"ALERT: Recently modified executable in autostart: {full_path}"
                                    alerts.append(alert)
                            except:
                                pass
                except Exception as e:
                    alerts.append(f"Error scanning {location}: {e}")
        
        return alerts
    
    def monitor_process_spawning(self):
        """Detect and block processes with worm-like behavior"""
        alerts = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                proc_info = proc.info
                proc_name = proc_info.get('name', '').lower()
                proc_id = proc_info.get('pid', 'Unknown')
                
                # Check for processes with suspicious names
                suspicious_match = any(sus_name.lower() in proc_name for sus_name in self.suspicious_names)
                if suspicious_match and proc_id not in self.blocked_processes:
                    alert = f"CRITICAL: Worm process detected: {proc_info['name']} (PID: {proc_id}) - BLOCKING"
                    alerts.append(alert)
                    self.blocked_processes.add(proc_id)
                    # Terminate the suspicious process
                    self.terminate_process(proc_id, proc_info['name'])
                
                # Check for processes copying or spreading files
                cmdline_str = proc_info.get('cmdline', [])
                if cmdline_str:
                    cmdline = ' '.join(cmdline_str).lower()
                    if 'copy' in cmdline and '.exe' in cmdline:
                        alert = f"THREAT: Process performing file replication: {proc_info['name']} - BLOCKING"
                        alerts.append(alert)
                        if proc_id not in self.blocked_processes:
                            self.blocked_processes.add(proc_id)
                            self.terminate_process(proc_id, proc_info['name'])
                    
                    # Check for worm spreading patterns
                    if any(x in cmdline for x in ['shutil.copy', 'copyfile', 'xcopy', 'robocopy']) and '.inf' in cmdline:
                        alert = f"THREAT: Possible USB infection attempt: {proc_info['name']}"
                        alerts.append(alert)
                        if proc_id not in self.blocked_processes:
                            self.blocked_processes.add(proc_id)
                            self.terminate_process(proc_id, proc_info['name'])
            
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                pass
        
        return alerts
    
    def terminate_process(self, pid, process_name):
        """Safely terminate a suspicious process"""
        try:
            process = psutil.Process(pid)
            process.terminate()
            process.wait(timeout=3)
            print(f"[+] Terminated suspicious process: {process_name} (PID: {pid})")
            return True
        except psutil.NoSuchProcess:
            pass
        except Exception as e:
            try:
                # Force kill if normal termination fails
                process = psutil.Process(pid)
                process.kill()
                print(f"[!] Force-killed process: {process_name} (PID: {pid})")
            except:
                print(f"[-] Failed to terminate {process_name} (PID: {pid})")
            return False# Usage
detector = WormDetector()
usb_alerts = detector.monitor_removable_drives()
autostart_alerts = detector.check_autostart_locations()
process_alerts = detector.monitor_process_spawning()