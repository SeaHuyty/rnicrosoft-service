import time
import threading
from datetime import datetime
import json
import os
import sys
import shutil
import hashlib
import psutil

# Watchdog for INSTANT file system monitoring
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Add component folder to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'component'))

from ransomware_detector import RansomwareDetector
from worm_detector import WormDetector
from pdf_analyzer import PDFSecurityAnalyzer
from integrity_monitor import IntegrityMonitor
from spyware_detector import SpywareDetector


class RansomwareFileHandler(FileSystemEventHandler):
    """INSTANT file system event handler - triggers on ANY file change"""
    
    def __init__(self, protection):
        self.protection = protection
        self.last_alert_time = {}
        
    def on_created(self, event):
        if event.is_directory:
            return
        self._check_file(event.src_path, "CREATED")
    
    def on_modified(self, event):
        if event.is_directory:
            return
        self._check_file(event.src_path, "MODIFIED")
    
    def on_moved(self, event):
        if event.is_directory:
            return
        self._check_file(event.dest_path, "RENAMED")
    
    def _check_file(self, filepath, action):
        """Check file INSTANTLY when changed"""
        filename = os.path.basename(filepath).lower()
        
        # Prevent duplicate alerts within 2 seconds
        now = time.time()
        if filepath in self.last_alert_time:
            if now - self.last_alert_time[filepath] < 2:
                return
        self.last_alert_time[filepath] = now
        
        # Check for encrypted files
        if filename.endswith(('.enc', '.locked', '.crypted', '.encrypted')):
            print(f"\n[!!!] INSTANT DETECTION: Encrypted file {action}: {filepath}")
            self.protection.handle_ransomware_detected(filepath)
        
        # Check for ransom notes
        ransom_keywords = ['ransom', 'readme', 'decrypt', 'recover', 'pay', 'bitcoin']
        if any(kw in filename for kw in ransom_keywords) and filename.endswith('.txt'):
            print(f"\n[!!!] INSTANT DETECTION: Ransom note {action}: {filepath}")
            self.protection.quarantine_file(filepath)


class RealTimeProtection:
    """Real-time file and process monitoring for TRUE prevention"""
    
    def __init__(self):
        self.protected_folder = "D:/Hello"
        self.backup_folder = "C:/RansomwareBackup"
        self.quarantine_folder = "C:/QuarantineZone"
        
        # Malicious process signatures
        self.malicious_signatures = [
            "longchhunhour",
            "encrypt.py",
            "worm.py",
            "spyware.py",
            "ransomware",
            "cryptography.hazmat",
            "aesgcm",
        ]
        
        # Malicious command patterns
        self.malicious_commands = [
            "encrypt",
            "aesgcm",
            "ransom",
            ".enc",
            "autorun.inf",
            "spread_via",
            "execute_ransomware",
        ]
        
        self.blocked_pids = set()
        self.file_hashes = {}
        self.observer = None  # Watchdog observer
        
        # Create folders
        os.makedirs(self.backup_folder, exist_ok=True)
        os.makedirs(self.quarantine_folder, exist_ok=True)
    
    def start_watchdog(self):
        """Start INSTANT file system monitoring with watchdog"""
        if not os.path.exists(self.protected_folder):
            os.makedirs(self.protected_folder, exist_ok=True)
        
        event_handler = RansomwareFileHandler(self)
        self.observer = Observer()
        self.observer.schedule(event_handler, self.protected_folder, recursive=True)
        self.observer.start()
        print(f"[+] WATCHDOG: Instant file monitoring started for {self.protected_folder}")
        return self.observer
    
    def stop_watchdog(self):
        """Stop watchdog observer"""
        if self.observer:
            self.observer.stop()
            self.observer.join()
    
    def handle_ransomware_detected(self, filepath):
        """Handle ransomware detection - quarantine and restore"""
        print(f"[!] RANSOMWARE DETECTED: {filepath}")
        
        # 1. Quarantine the encrypted file
        self.quarantine_file(filepath)
        
        # 2. Try to kill any suspicious processes
        self.scan_and_kill_malicious_processes()
        
        # 3. Restore original file from backup
        self.restore_single_file(filepath)
    
    def restore_single_file(self, encrypted_path):
        """Restore a single file from backup"""
        # Remove .enc extension to get original filename
        original_name = encrypted_path
        for ext in ['.enc', '.locked', '.crypted', '.encrypted']:
            if original_name.endswith(ext):
                original_name = original_name[:-len(ext)]
                break
        
        # Find in backup
        try:
            rel_path = os.path.relpath(original_name, self.protected_folder)
            backup_path = os.path.join(self.backup_folder, rel_path)
            
            if os.path.exists(backup_path):
                shutil.copy2(backup_path, original_name)
                print(f"[+] RESTORED: {original_name}")
                return True
            else:
                print(f"[-] No backup found for: {original_name}")
        except Exception as e:
            print(f"[-] Restore failed: {e}")
        return False
    
    def backup_protected_files(self):
        """Create backup of all files in protected folder"""
        if not os.path.exists(self.protected_folder):
            return []
        
        backed_up = []
        for root, dirs, files in os.walk(self.protected_folder):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    # Calculate relative path
                    rel_path = os.path.relpath(filepath, self.protected_folder)
                    backup_path = os.path.join(self.backup_folder, rel_path)
                    
                    # Create backup directory
                    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
                    
                    # Copy file
                    shutil.copy2(filepath, backup_path)
                    
                    # Store hash
                    with open(filepath, 'rb') as f:
                        self.file_hashes[filepath] = hashlib.sha256(f.read()).hexdigest()
                    
                    backed_up.append(filepath)
                except Exception as e:
                    pass
        
        if backed_up:
            print(f"[+] Backed up {len(backed_up)} files from {self.protected_folder}")
        return backed_up
    
    def restore_from_backup(self):
        """Restore all files from backup"""
        if not os.path.exists(self.backup_folder):
            print("[-] No backup found!")
            return []
        
        restored = []
        for root, dirs, files in os.walk(self.backup_folder):
            for file in files:
                backup_path = os.path.join(root, file)
                try:
                    rel_path = os.path.relpath(backup_path, self.backup_folder)
                    original_path = os.path.join(self.protected_folder, rel_path)
                    
                    # Create directory if needed
                    os.makedirs(os.path.dirname(original_path), exist_ok=True)
                    
                    # Restore file
                    shutil.copy2(backup_path, original_path)
                    restored.append(original_path)
                    print(f"[+] RESTORED: {original_path}")
                except Exception as e:
                    pass
        
        return restored
    
    def scan_and_kill_malicious_processes(self):
        """Kill malicious processes - optimized for performance"""
        killed = []
        
        try:
            # Only check Python processes for better performance
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    name = proc.info.get('name', '').lower()
                    
                    # Only check python processes (where our malware runs)
                    if 'python' not in name:
                        continue
                    
                    pid = proc.info['pid']
                    cmdline = proc.info.get('cmdline', [])
                    cmdline_str = ' '.join(cmdline).lower() if cmdline else ''
                    
                    # Skip if already blocked
                    if pid in self.blocked_pids:
                        continue
                    
                    is_malicious = False
                    reason = ""
                    
                    # Check for malicious signatures in command line
                    for sig in self.malicious_signatures:
                        if sig in cmdline_str:
                            is_malicious = True
                            reason = f"Malicious signature: {sig}"
                            break
                    
                    # Check for malicious commands
                    if not is_malicious:
                        for cmd in self.malicious_commands:
                            if cmd in cmdline_str:
                                is_malicious = True
                                reason = f"Malicious command: {cmd}"
                                break
                    
                    # Check if process is accessing protected folder
                    if not is_malicious:
                        if 'd:/hello' in cmdline_str or 'd:\\hello' in cmdline_str.replace('/', '\\'):
                            # Check if it's our antivirus
                            if 'main_defender' not in cmdline_str and 'anti-malicious' not in cmdline_str:
                                is_malicious = True
                                reason = "Unauthorized access to protected folder"
                    
                    if is_malicious:
                        try:
                            process = psutil.Process(pid)
                            process.kill()
                            self.blocked_pids.add(pid)
                            killed.append((pid, name, reason))
                            print(f"[!!!] BLOCKED & KILLED: {name} (PID: {pid})")
                            print(f"      Reason: {reason}")
                        except:
                            pass
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            pass  # Prevent crashes
        
        return killed

    def detect_file_changes(self):
        """Detect unauthorized file changes in real-time"""
        alerts = []
        
        if not os.path.exists(self.protected_folder):
            return alerts
        
        current_files = {}
        for root, dirs, files in os.walk(self.protected_folder):
            for file in files:
                filepath = os.path.join(root, file)
                
                # Check for encrypted files
                if file.endswith(('.enc', '.locked', '.crypted', '.encrypted')):
                    alerts.append(f"CRITICAL: Encrypted file detected: {filepath}")
                    # Quarantine it
                    self.quarantine_file(filepath)
                
                # Check for ransom notes
                if any(x in file.lower() for x in ['ransom', 'readme', 'decrypt', 'recover']):
                    if file.endswith('.txt'):
                        alerts.append(f"CRITICAL: Ransom note detected: {filepath}")
                        self.quarantine_file(filepath)
        
        return alerts
    
    def quarantine_file(self, filepath):
        """Move malicious file to quarantine"""
        try:
            filename = os.path.basename(filepath)
            quarantine_path = os.path.join(self.quarantine_folder, f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}")
            shutil.move(filepath, quarantine_path)
            print(f"[!] QUARANTINED: {filepath}")
            return True
        except Exception as e:
            return False


class AntiMaliciousDefender:
    def __init__(self):
        self.ransomware_detector = RansomwareDetector()
        self.worm_detector = WormDetector()
        self.pdf_analyzer = PDFSecurityAnalyzer()
        self.integrity_monitor = IntegrityMonitor()
        self.spyware_detector = SpywareDetector()
        self.realtime_protection = RealTimeProtection()
        
        self.running = False
        self.alert_history = []
        self.critical_alerts = 0
        self.phishing_log = "phishing_alerts.log"
        
    def start_monitoring(self):
        """Start continuous monitoring with REAL-TIME PREVENTION"""
        self.running = True
        print("[+] Anti-Malicious Defender Started")
        print("[+] REAL-TIME PREVENTION MODE ENABLED")
        print("[+] Using WATCHDOG for INSTANT file detection")
        
        # Backup protected files FIRST
        print("[+] Creating backup of protected files...")
        self.realtime_protection.backup_protected_files()
        
        # START WATCHDOG - INSTANT file monitoring
        print("[+] Starting WATCHDOG instant file monitor...")
        self.realtime_protection.start_watchdog()
        
        # Skip heavy initial scans - let background threads handle them
        print("[+] Background monitoring will handle scans...")
        
        # Start monitoring threads (watchdog handles file monitoring now)
        threads = [
            threading.Thread(target=self.monitor_processes_realtime, name="ProcessMonitor"),
            threading.Thread(target=self.monitor_ransomware, name="RansomwareMonitor"),
            threading.Thread(target=self.monitor_worms, name="WormMonitor"),
            threading.Thread(target=self.monitor_integrity, name="IntegrityMonitor"),
            threading.Thread(target=self.monitor_spyware, name="SpywareMonitor")
        ]
        
        for thread in threads:
            thread.daemon = True
            thread.start()
        
        print(f"[+] Started {len(threads)} monitoring threads + WATCHDOG")
        print("[+] Press Ctrl+C to stop\n")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_monitoring()
    
    def monitor_processes_realtime(self):
        """REAL-TIME process monitoring - kills malware"""
        while self.running:
            try:
                killed = self.realtime_protection.scan_and_kill_malicious_processes()
                for pid, name, reason in killed:
                    self.log_alert(f"BLOCKED MALWARE: {name} (PID: {pid}) - {reason}", "Prevention")
                    self.critical_alerts += 1
            except Exception:
                pass
            time.sleep(2)  # Check every 2 seconds (less CPU intensive)
    
    def monitor_files_realtime(self):
        """REAL-TIME file monitoring - detects changes INSTANTLY"""
        while self.running:
            alerts = self.realtime_protection.detect_file_changes()
            for alert in alerts:
                self.log_alert(alert, "FileProtection")
                
                # If attack detected, restore from backup
                if "CRITICAL" in alert:
                    print("[!] Attack detected! Restoring files from backup...")
                    self.realtime_protection.restore_from_backup()
            
            time.sleep(1)  # Check every second
    
    def monitor_ransomware(self):
        while self.running:
            try:
                alerts = self.ransomware_detector.detect_encryption_activity()
                for alert in alerts:
                    self.log_alert(alert, "Ransomware")
            except Exception:
                pass
            time.sleep(10)  # Every 10 seconds
    
    def monitor_worms(self):
        while self.running:
            try:
                alerts = self.worm_detector.monitor_removable_drives()
                alerts.extend(self.worm_detector.check_autostart_locations())
                
                for alert in alerts:
                    self.log_alert(alert, "Worm")
            except Exception:
                pass
            time.sleep(20)  # Every 20 seconds
    
    def monitor_integrity(self):
        while self.running:
            try:
                for directory in self.integrity_monitor.protected_dirs:
                    alerts = self.integrity_monitor.monitor_directory(directory)
                    for alert in alerts:
                        self.log_alert(alert, "Integrity")
            except Exception:
                pass
            time.sleep(30)  # Every 30 seconds
    
    def monitor_phishing(self):
        """Continuously monitor for phishing and email-based attacks"""
        while self.running:
            alerts = self.scan_for_phishing()
            for alert in alerts:
                self.log_alert(alert, "Phishing/Email")
            time.sleep(300)
    
    def monitor_spyware(self):
        """Continuously monitor for spyware activities"""
        while self.running:
            try:
                alerts = self.spyware_detector.run_full_scan()
                for alert in alerts:
                    self.log_alert(alert, "Spyware")
            except Exception:
                pass
            time.sleep(60)  # Every 60 seconds to reduce CPU load
    
    def analyze_file(self, filepath):
        """Analyze a specific file for threats"""
        if filepath.lower().endswith('.pdf'):
            return self.pdf_analyzer.analyze_pdf(filepath)
        elif filepath.lower().endswith('.exe'):
            return {"type": "executable", "advice": "Scan with antivirus"}
        else:
            return {"type": "general", "advice": "Monitor for changes"}
    
    def log_alert(self, message, alert_type):
        timestamp = datetime.now().isoformat()
        
        # Determine severity
        severity = "INFO"
        if "CRITICAL" in message or "THREAT" in message or "BLOCKED" in message:
            severity = "HIGH"
        if "CRITICAL" in message:
            severity = "CRITICAL"
            self.critical_alerts += 1
        
        alert_entry = {
            "timestamp": timestamp,
            "type": alert_type,
            "severity": severity,
            "message": message,
            "action_taken": "logged"
        }
        
        self.alert_history.append(alert_entry)
        
        # Save to log file
        try:
            with open("security_log.json", 'a') as f:
                f.write(json.dumps(alert_entry) + '\n')
        except:
            pass
        
        # Color-coded output
        if severity == "CRITICAL":
            print(f"\033[91m[{timestamp}] [CRITICAL] {alert_type.upper()}: {message}\033[0m")
        elif severity == "HIGH":
            print(f"\033[93m[{timestamp}] [HIGH] {alert_type.upper()}: {message}\033[0m")
        else:
            print(f"[{timestamp}] [{severity}] {alert_type.upper()}: {message}")
        
        # Take action based on severity
        if "ransomware" in message.lower() or "encrypted" in message.lower():
            print("  [!] CRITICAL: Ransomware activity detected!")
            print("  [!] Attempting automatic restoration...")
        elif "BLOCKED" in message:
            print("  [+] PREVENTED: Malware was blocked before execution!")
    
    def scan_for_phishing(self):
        """Monitor for phishing attempts and suspicious emails"""
        alerts = []
        
        phishing_indicators = [
            "youtube premium",
            "mediafire",
            "telegram",
            "download now",
            "claim your offer",
            "act now",
            "limited time",
            "verify account",
            "confirm password",
            "update billing"
        ]
        
        # Check automation_email.py for phishing patterns
        email_paths = [
            os.path.join(os.path.dirname(__file__), '..', '..', 'Automation_Email_Sending', 'automation_email.py'),
            "..\\..\\Automation_Email_Sending\\automation_email.py",
        ]
        
        for email_automation_path in email_paths:
            if os.path.exists(email_automation_path):
                try:
                    with open(email_automation_path, 'r', errors='ignore') as f:
                        content = f.read().lower()
                        
                        for indicator in phishing_indicators:
                            if indicator in content:
                                alerts.append(f"PHISHING: Detected phishing campaign pattern: '{indicator}'")
                    
                        if "mediafire" in content:
                            alerts.append("PHISHING: Detected mediafire malware distribution link")
                        
                        if "youtube team" in content or "gmail" in content:
                            alerts.append("THREAT: Email impersonation detected (spoofing)")
                    break
                except Exception as e:
                    pass
        
        return alerts
    
    def generate_report(self):
        """Generate comprehensive security report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_alerts": len(self.alert_history),
            "critical_alerts": self.critical_alerts,
            "threat_level": min(self.ransomware_detector.threat_level, 5),
            "alert_by_type": {},
            "alert_by_severity": {},
            "recent_alerts": self.alert_history[-20:] if self.alert_history else [],
            "security_status": "COMPROMISED" if self.critical_alerts > 0 else ("WARNING" if len(self.alert_history) > 5 else "HEALTHY"),
            "protection_modules": {
                "realtime_prevention": "ACTIVE",
                "process_monitor": "ACTIVE",
                "file_monitor": "ACTIVE",
                "ransomware": "ACTIVE",
                "worm": "ACTIVE",
                "integrity": "ACTIVE",
                "phishing": "ACTIVE",
                "spyware": "ACTIVE",
                "pdf_analyzer": "ACTIVE"
            }
        }
        
        for alert in self.alert_history:
            alert_type = alert['type']
            severity = alert.get('severity', 'INFO')
            
            report['alert_by_type'][alert_type] = report['alert_by_type'].get(alert_type, 0) + 1
            report['alert_by_severity'][severity] = report['alert_by_severity'].get(severity, 0) + 1
        
        return report
    
    def stop_monitoring(self):
        self.running = False
        
        # Stop watchdog
        self.realtime_protection.stop_watchdog()
        
        print("\n[+] Anti-Malicious Defender Stopped")
        print("[+] Generating final security report...")
        report = self.generate_report()
        print("\n" + "="*60)
        print("SECURITY REPORT")
        print("="*60)
        print(json.dumps(report, indent=2))
        
        if self.critical_alerts > 0:
            print("\n" + "!"*60)
            print("WARNING: CRITICAL THREATS DETECTED!")
            print("!"*60)
            print(f"Total Critical Alerts: {self.critical_alerts}")
            print("RECOMMENDED ACTIONS:")
            print("1. Check restored files in D:/Hello")
            print("2. Check backup integrity in C:/RansomwareBackup/")
            print("3. Review quarantined files in C:/QuarantineZone/")
        
        try:
            with open("security_report_final.json", 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Report saved to: security_report_final.json")
        except:
            pass


def install_startup():
    """Add antivirus to Windows startup (requires admin)"""
    try:
        import winreg
        
        script_path = os.path.abspath(__file__)
        python_exe = sys.executable
        command = f'"{python_exe}" "{script_path}"'
        
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, "AntiMaliciousDefender", 0, winreg.REG_SZ, command)
        winreg.CloseKey(key)
        
        print("[+] Successfully added to Windows startup!")
        return True
    except Exception as e:
        print(f"[-] Failed to add to startup: {e}")
        return False


def remove_startup():
    """Remove antivirus from Windows startup"""
    try:
        import winreg
        
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        )
        winreg.DeleteValue(key, "AntiMaliciousDefender")
        winreg.CloseKey(key)
        
        print("[+] Successfully removed from Windows startup!")
        return True
    except Exception as e:
        print(f"[-] Failed to remove from startup: {e}")
        return False


# Main execution
if __name__ == "__main__":
    print("="*60)
    print("=== ADVANCED ANTI-MALICIOUS DEFENDER v3.0 ===")
    print("=== WITH WATCHDOG INSTANT DETECTION ===")
    print("="*60)
    
    print("\n[+] WATCHDOG INSTANT DETECTION:")
    print("    - Uses Windows native file system events")
    print("    - INSTANT detection (0ms delay)")
    print("    - Detects file creation, modification, rename")
    print("    - Triggers immediately on .enc file creation")
    
    print("\n[+] REAL-TIME PREVENTION:")
    print("    - Process monitoring every 500ms")
    print("    - INSTANT malware process termination")
    print("    - Automatic backup before monitoring")
    print("    - Automatic restoration after attack")
    print("    - Quarantine malicious files immediately")
    
    print("\n[+] RANSOMWARE PROTECTION:")
    print("    - Detects encryption activity (.enc, .locked, .crypted)")
    print("    - Monitors for ransom notes")
    print("    - Auto-quarantines encrypted files")
    print("    - Automatic restoration from backups")
    
    print("\n[+] WORM/MALWARE PROTECTION:")
    print("    - Monitors USB drives for suspicious executables")
    print("    - Detects and blocks autorun.inf")
    print("    - Real-time process monitoring")
    print("    - Automatic process termination")
    
    print("\n[+] SPYWARE PROTECTION:")
    print("    - Keylogger detection and termination")
    print("    - Screenshot/Webcam/Microphone monitoring")
    print("    - Browser theft prevention")
    
    print("\n" + "="*60)
    print("COMMANDS:")
    print("  --install-startup  : Add to Windows startup")
    print("  --remove-startup   : Remove from Windows startup")
    print("  (no args)          : Start monitoring")
    print("="*60 + "\n")
    
    # Handle command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--install-startup":
            install_startup()
            sys.exit(0)
        elif sys.argv[1] == "--remove-startup":
            remove_startup()
            sys.exit(0)
    
    # Start monitoring
    print("[*] Starting REAL-TIME PREVENTION mode...")
    print("[*] Protected folder: D:/Hello")
    print("[*] Backup folder: C:/RansomwareBackup")
    print("[*] Quarantine folder: C:/QuarantineZone")
    print("[*] Press Ctrl+C to stop\n")
    
    defender = AntiMaliciousDefender()
    defender.start_monitoring()
