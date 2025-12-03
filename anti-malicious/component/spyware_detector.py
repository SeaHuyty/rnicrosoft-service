import os
import psutil
import winreg
from pathlib import Path
import json
from datetime import datetime
import shutil

class SpywareDetector:
    """
    Detects and prevents spyware activities including:
    - Keyloggers
    - Screenshot capture
    - Webcam/Microphone access
    - Browser history theft
    - WiFi credential theft
    - Data exfiltration via email
    """
    
    def __init__(self):
        self.suspicious_processes = []
        self.blocked_processes = set()
        self.alert_log = "spyware_alerts.log"
        self.quarantine_dir = "C:/QuarantineZone/"
        
        # Whitelist legitimate Windows/System processes
        self.whitelisted_processes = [
            "msedge.exe", "msedgewebview2.exe", "chrome.exe", "firefox.exe",
            "explorer.exe", "svchost.exe", "system", "csrss.exe", "dwm.exe",
            "taskhostw.exe", "searchhost.exe", "runtimebroker.exe",
            "applicationframehost.exe", "shellexperiencehost.exe",
            "startmenuexperiencehost.exe", "windowsterminal.exe", "code.exe",
            "python.exe", "pythonw.exe", "powershell.exe", "cmd.exe",
            "conhost.exe", "windowsterminal.exe", "vscode.exe"
        ]
        
        # Suspicious process names that indicate spyware
        self.spyware_indicators = [
            "pynput", "keyboard", "keylogger", "keystroke",
            "screenshot", "imagegrab", "screencapture",
            "webcam", "camera", "videocapture", "cv2",
            "microphone", "sounddevice", "audiorecord",
            "browserhistory", "browser_history",
        ]
        
        # Suspicious file patterns
        self.suspicious_file_patterns = [
            "key_logs.txt", "keylog", "keystroke",
            "screenshot", "screencap",
            "mic_recording", "audio_record",
            "webcam", "camera_capture",
            "browser_history", "wifi_password",
            "network_wifi.txt", "credentials"
        ]
        
        # Known spyware log locations - only check temp folder
        self.spyware_log_locations = [
            os.path.expanduser("~/AppData/Local/Temp"),
        ]
        
        # Suspicious registry keys (persistence)
        self.suspicious_registry_keys = [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ]
        
        self.create_quarantine_dir()
    
    def create_quarantine_dir(self):
        """Create quarantine directory"""
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir, exist_ok=True)
    
    def detect_keylogger_activity(self):
        """Detect keylogger processes and files"""
        alerts = []
        
        # Check for keylogger processes
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_info = proc.info
                proc_name = proc_info.get('name', '').lower()
                
                # Skip whitelisted processes
                if proc_name in self.whitelisted_processes:
                    continue
                
                cmdline = proc_info.get('cmdline', [])
                cmdline_str = ' '.join(cmdline).lower() if cmdline else ''
                
                # Check for pynput/keyboard monitoring
                if 'pynput' in cmdline_str or 'keyboard' in cmdline_str:
                    if 'listener' in cmdline_str or 'on_press' in cmdline_str:
                        alert = f"CRITICAL: Keylogger detected! Process: {proc_name} (PID: {proc_info['pid']})"
                        alerts.append(alert)
                        self.terminate_process(proc_info['pid'], proc_name)
                
                # Check for logging to key_logs files
                if 'key_log' in cmdline_str or 'keystroke' in cmdline_str:
                    alert = f"THREAT: Keystroke logging detected: {proc_name}"
                    alerts.append(alert)
                    self.terminate_process(proc_info['pid'], proc_name)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Check for keylog files in common locations
        for location in self.spyware_log_locations:
            if os.path.exists(location):
                try:
                    for root, dirs, files in os.walk(location):
                        for file in files:
                            if 'key_log' in file.lower() or 'keystroke' in file.lower():
                                filepath = os.path.join(root, file)
                                alert = f"THREAT: Keylogger file found: {filepath}"
                                alerts.append(alert)
                                self.quarantine_file(filepath)
                except Exception as e:
                    pass
        
        return alerts
    
    def detect_screenshot_capture(self):
        """Detect screenshot capture activities"""
        alerts = []
        
        # Check for screenshot capture processes
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_info = proc.info
                proc_name = proc_info.get('name', '').lower()
                
                # Skip whitelisted processes
                if proc_name in self.whitelisted_processes:
                    continue
                
                cmdline = proc_info.get('cmdline', [])
                cmdline_str = ' '.join(cmdline).lower() if cmdline else ''
                
                # Check for PIL ImageGrab or screenshot tools
                if 'imagegrab' in cmdline_str or 'screenshot' in cmdline_str:
                    if 'grab' in cmdline_str or 'save' in cmdline_str:
                        alert = f"THREAT: Screenshot capture detected: {proc_info['name']} (PID: {proc_info['pid']})"
                        alerts.append(alert)
                        self.terminate_process(proc_info['pid'], proc_info['name'])
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Check for mass screenshot files
        for location in self.spyware_log_locations:
            if os.path.exists(location):
                try:
                    screenshot_count = 0
                    screenshot_files = []
                    
                    for root, dirs, files in os.walk(location):
                        for file in files:
                            if 'screenshot' in file.lower() and file.endswith(('.png', '.jpg', '.jpeg')):
                                screenshot_count += 1
                                screenshot_files.append(os.path.join(root, file))
                    
                    if screenshot_count > 3:  # Suspicious if many screenshots
                        alert = f"CRITICAL: Mass screenshot capture detected! {screenshot_count} screenshots in {location}"
                        alerts.append(alert)
                        for sf in screenshot_files[:10]:
                            self.quarantine_file(sf)
                            
                except Exception as e:
                    pass
        
        return alerts
    
    def detect_webcam_access(self):
        """Detect unauthorized webcam access"""
        alerts = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_info = proc.info
                proc_name = proc_info.get('name', '').lower()
                
                # Skip whitelisted processes
                if proc_name in self.whitelisted_processes:
                    continue
                
                cmdline = proc_info.get('cmdline', [])
                cmdline_str = ' '.join(cmdline).lower() if cmdline else ''
                
                # Check for cv2/OpenCV webcam access
                if 'cv2' in cmdline_str or 'videocapture' in cmdline_str:
                    if 'read' in cmdline_str or 'capture' in cmdline_str:
                        alert = f"CRITICAL: Webcam access detected: {proc_info['name']} (PID: {proc_info['pid']})"
                        alerts.append(alert)
                        self.terminate_process(proc_info['pid'], proc_info['name'])
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Check for webcam image files
        for location in self.spyware_log_locations:
            webcam_path = os.path.join(location, "WebcamPics")
            if os.path.exists(webcam_path):
                alert = f"CRITICAL: Webcam spyware folder found: {webcam_path}"
                alerts.append(alert)
                # Quarantine entire folder contents
                try:
                    for file in os.listdir(webcam_path):
                        self.quarantine_file(os.path.join(webcam_path, file))
                except:
                    pass
        
        return alerts
    
    def detect_microphone_recording(self):
        """Detect unauthorized microphone recording"""
        alerts = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_info = proc.info
                proc_name = proc_info.get('name', '').lower()
                
                # Skip whitelisted processes
                if proc_name in self.whitelisted_processes:
                    continue
                
                cmdline = proc_info.get('cmdline', [])
                cmdline_str = ' '.join(cmdline).lower() if cmdline else ''
                
                # Check for sounddevice/audio recording
                if 'sounddevice' in cmdline_str or 'audiorecord' in cmdline_str:
                    if 'rec' in cmdline_str or 'record' in cmdline_str:
                        alert = f"CRITICAL: Microphone recording detected: {proc_info['name']} (PID: {proc_info['pid']})"
                        alerts.append(alert)
                        self.terminate_process(proc_info['pid'], proc_info['name'])
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Check for suspicious audio files
        for location in self.spyware_log_locations:
            if os.path.exists(location):
                try:
                    for root, dirs, files in os.walk(location):
                        for file in files:
                            if 'mic_recording' in file.lower() or 'audio_record' in file.lower():
                                if file.endswith('.wav'):
                                    filepath = os.path.join(root, file)
                                    alert = f"THREAT: Microphone recording file found: {filepath}"
                                    alerts.append(alert)
                                    self.quarantine_file(filepath)
                except:
                    pass
        
        return alerts
    
    def detect_browser_theft(self):
        """Detect browser history/credential theft"""
        alerts = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_info = proc.info
                proc_name = proc_info.get('name', '').lower()
                
                # Skip whitelisted processes
                if proc_name in self.whitelisted_processes:
                    continue
                
                cmdline = proc_info.get('cmdline', [])
                cmdline_str = ' '.join(cmdline).lower() if cmdline else ''
                
                # Check for browserhistory module
                if 'browserhistory' in cmdline_str or 'browser_history' in cmdline_str:
                    alert = f"CRITICAL: Browser history theft detected: {proc_info['name']} (PID: {proc_info['pid']})"
                    alerts.append(alert)
                    self.terminate_process(proc_info['pid'], proc_info['name'])
                
                # Check for credential access
                if 'credential' in cmdline_str or 'password' in cmdline_str:
                    if 'sqlite' in cmdline_str or 'chrome' in cmdline_str or 'firefox' in cmdline_str:
                        alert = f"CRITICAL: Browser credential theft detected: {proc_info['name']}"
                        alerts.append(alert)
                        self.terminate_process(proc_info['pid'], proc_info['name'])
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return alerts
    
    def detect_wifi_theft(self):
        """Detect WiFi credential theft"""
        alerts = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_info = proc.info
                proc_name = proc_info.get('name', '').lower()
                
                # Skip whitelisted processes
                if proc_name in self.whitelisted_processes:
                    continue
                
                cmdline = proc_info.get('cmdline', [])
                cmdline_str = ' '.join(cmdline).lower() if cmdline else ''
                
                # Check for netsh WLAN export (WiFi password extraction)
                if 'netsh' in cmdline_str and 'wlan' in cmdline_str:
                    if 'export' in cmdline_str or 'key=clear' in cmdline_str:
                        alert = f"CRITICAL: WiFi password theft detected: {proc_info['name']} (PID: {proc_info['pid']})"
                        alerts.append(alert)
                        self.terminate_process(proc_info['pid'], proc_info['name'])
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Check for WiFi credential files
        for location in self.spyware_log_locations:
            if os.path.exists(location):
                try:
                    for file in os.listdir(location):
                        if 'network_wifi' in file.lower() or 'wifi' in file.lower():
                            if file.endswith(('.txt', '.xml')):
                                filepath = os.path.join(location, file)
                                alert = f"THREAT: WiFi credential file found: {filepath}"
                                alerts.append(alert)
                                self.quarantine_file(filepath)
                except:
                    pass
        
        return alerts
    
    def detect_data_exfiltration(self):
        """Detect data exfiltration via email"""
        alerts = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_info = proc.info
                proc_name = proc_info.get('name', '').lower()
                
                # Skip whitelisted processes
                if proc_name in self.whitelisted_processes:
                    continue
                
                cmdline = proc_info.get('cmdline', [])
                cmdline_str = ' '.join(cmdline).lower() if cmdline else ''
                
                # Check for SMTP email sending with attachments
                if 'smtplib' in cmdline_str or 'smtp' in cmdline_str:
                    if 'mimebase' in cmdline_str or 'attachment' in cmdline_str:
                        alert = f"CRITICAL: Data exfiltration via email detected: {proc_info['name']} (PID: {proc_info['pid']})"
                        alerts.append(alert)
                        self.terminate_process(proc_info['pid'], proc_info['name'])
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return alerts
    
    def detect_spyware_logs(self):
        """Scan for spyware log directories"""
        alerts = []
        
        # Check for typical spyware log folder structure
        temp_logs = os.path.expanduser("~/AppData/Local/Temp/Logs")
        if os.path.exists(temp_logs):
            # Check for spyware indicators
            has_keylog = os.path.exists(os.path.join(temp_logs, "key_logs.txt"))
            has_screenshots = os.path.exists(os.path.join(temp_logs, "Screenshots"))
            has_webcam = os.path.exists(os.path.join(temp_logs, "WebcamPics"))
            has_wifi = os.path.exists(os.path.join(temp_logs, "network_wifi.txt"))
            
            if has_keylog or has_screenshots or has_webcam or has_wifi:
                alert = f"CRITICAL: Spyware log directory detected: {temp_logs}"
                alerts.append(alert)
                
                # Quarantine entire spyware directory
                try:
                    quarantine_dest = os.path.join(self.quarantine_dir, "SpywareLogs")
                    if os.path.exists(temp_logs):
                        shutil.move(temp_logs, quarantine_dest)
                        print(f"[!] QUARANTINED spyware folder: {temp_logs}")
                except Exception as e:
                    print(f"[-] Failed to quarantine spyware folder: {e}")
        
        return alerts
    
    def run_full_scan(self):
        """Run lightweight spyware detection scan - optimized for performance"""
        all_alerts = []
        
        try:
            # Single process iteration for all checks
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info.get('name', '').lower()
                    
                    # Skip whitelisted processes
                    if proc_name in self.whitelisted_processes:
                        continue
                    
                    cmdline = proc_info.get('cmdline', [])
                    cmdline_str = ' '.join(cmdline).lower() if cmdline else ''
                    
                    # Check all spyware indicators in one pass
                    for indicator in self.spyware_indicators:
                        if indicator in cmdline_str:
                            alert = f"THREAT: Spyware activity detected ({indicator}): {proc_name} (PID: {proc_info['pid']})"
                            all_alerts.append(alert)
                            self.terminate_process(proc_info['pid'], proc_name)
                            break
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            pass
        
        return all_alerts
    
    def terminate_process(self, pid, process_name):
        """Terminate a suspicious process"""
        try:
            if pid in self.blocked_processes:
                return False
            
            # Final safety check - never terminate whitelisted processes
            if process_name.lower() in self.whitelisted_processes:
                return False
            
            process = psutil.Process(pid)
            process.terminate()
            process.wait(timeout=3)
            self.blocked_processes.add(pid)
            print(f"[+] Terminated spyware process: {process_name} (PID: {pid})")
            return True
        except psutil.NoSuchProcess:
            pass
        except Exception as e:
            try:
                process = psutil.Process(pid)
                process.kill()
                self.blocked_processes.add(pid)
                print(f"[!] Force-killed spyware process: {process_name} (PID: {pid})")
            except:
                print(f"[-] Failed to terminate {process_name}: {e}")
            return False
    
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
    
    def log_alert(self, message, severity="HIGH"):
        """Log spyware alert"""
        timestamp = datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "severity": severity,
            "message": message,
            "detection_type": "Spyware"
        }
        
        try:
            with open(self.alert_log, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except:
            pass
        
        print(f"[{severity}] {message}")


# Usage
if __name__ == "__main__":
    print("="*60)
    print("SPYWARE DETECTOR - Full System Scan")
    print("="*60 + "\n")
    
    detector = SpywareDetector()
    alerts = detector.run_full_scan()
    
    print("\n" + "="*60)
    print(f"Scan Complete! Found {len(alerts)} threats")
    print("="*60)
    
    for alert in alerts:
        detector.log_alert(alert)
