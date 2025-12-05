import os
import hashlib
from pathlib import Path
import json
from datetime import datetime
import logging
import shutil

class RansomwareDetector:
    def __init__(self):
        self.monitored_dirs = ["D:/Hello"]  # Only monitor test folder for better performance
        self.suspicious_extensions = [".enc", ".locked", ".crypted", ".ransom", ".encrypted"]
        self.file_baseline = {}
        self.alert_log = "security_alerts.log"
        self.backup_dir = "C:/RansomwareBackup/"
        self.quarantine_dir = "C:/QuarantineZone/"
        self.threat_level = 0
        self.create_backup_directories()
    
    def create_backup_directories(self):
        """Create backup and quarantine directories"""
        for directory in [self.backup_dir, self.quarantine_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
                print(f"[+] Created backup directory: {directory}")
    
    def quarantine_file(self, filepath):
        """Move suspicious file to quarantine zone"""
        try:
            filename = os.path.basename(filepath)
            quarantine_path = os.path.join(self.quarantine_dir, filename)
            shutil.move(filepath, quarantine_path)
            print(f"[!] QUARANTINED: {filepath} -> {quarantine_path}")
            return True
        except Exception as e:
            print(f"[-] Failed to quarantine: {e}")
            return False
    
    def restore_from_backup(self, filepath, backup_path):
        """Restore file from backup if encryption detected"""
        try:
            # Remove encrypted file
            if os.path.exists(filepath):
                os.remove(filepath)
            # Restore from backup
            shutil.copy2(backup_path, filepath)
            print(f"[+] RESTORED: {filepath} from backup")
            return True
        except Exception as e:
            print(f"[-] Restore failed: {e}")
            return False
        
    def establish_baseline(self):
        """Create baseline of file states and backup important files"""
        print("[+] Establishing baseline and creating backups...")
        for directory in self.monitored_dirs:
            if os.path.exists(directory):
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        filepath = Path(root) / file
                        if filepath.suffix not in self.suspicious_extensions:
                            try:
                                file_info = {
                                    'size': os.path.getsize(filepath),
                                    'modified': os.path.getmtime(filepath),
                                    'hash': self.calculate_hash(filepath)
                                }
                                self.file_baseline[str(filepath)] = file_info
                                
                                # Create backup for critical files
                                if filepath.suffix in ['.doc', '.docx', '.xls', '.xlsx', '.pdf', '.jpg', '.png']:
                                    self.create_file_backup(str(filepath))
                            except Exception as e:
                                print(f"[-] Error processing {filepath}: {e}")
    
    def create_file_backup(self, filepath):
        """Create backup copy of important files"""
        try:
            filename = os.path.basename(filepath)
            backup_path = os.path.join(self.backup_dir, filename)
            if not os.path.exists(backup_path):
                shutil.copy2(filepath, backup_path)
        except Exception as e:
            pass
    
    def calculate_hash(self, filepath):
        """Calculate file hash for integrity checking"""
        try:
            with open(filepath, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return None
    
    def detect_encryption_activity(self):
        """Monitor for signs of encryption and take preventive action"""
        alerts = []
        threat_detected = False
        
        for directory in self.monitored_dirs:
            if os.path.exists(directory):
                # Check for mass file extension changes (.enc, .locked, .crypted, etc)
                suspicious_files = []
                for ext in self.suspicious_extensions:
                    suspicious_files.extend(list(Path(directory).rglob(f"*{ext}")))
                
                if len(suspicious_files) > 2:  # Sensitive threshold
                    alert = f"CRITICAL: Found {len(suspicious_files)} encrypted files in {directory}"
                    alerts.append(alert)
                    threat_detected = True
                    
                    # Quarantine suspicious files
                    for enc_file in suspicious_files[:10]:
                        self.quarantine_file(str(enc_file))
                
                # Check for ransom notes
                ransom_note_patterns = ["READ_ME", "DECRYPT", "YOUR_FILES", "RECOVERY", "RANSOM"]
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        if any(pattern in file.upper() for pattern in ransom_note_patterns):
                            alert = f"THREAT: Ransom Note Found: {Path(root)/file}"
                            alerts.append(alert)
                            threat_detected = True
                            # Quarantine ransom note
                            self.quarantine_file(str(Path(root)/file))
                
                # Check for rapid file modifications (sign of encryption)
                if self.detect_mass_modification(directory):
                    alert = f"CRITICAL: Mass file modification detected in {directory} - possible encryption in progress"
                    alerts.append(alert)
                    threat_detected = True
        
        if threat_detected:
            self.threat_level = min(self.threat_level + 1, 5)
        
        return alerts
    
    def detect_mass_modification(self, directory):
        """Detect if many files were recently modified"""
        try:
            import time
            current_time = time.time()
            recent_changes = 0
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    filepath = Path(root) / file
                    if str(filepath) in self.file_baseline:
                        try:
                            mtime = os.path.getmtime(filepath)
                            # If file modified in last 10 seconds
                            if (current_time - mtime) < 10:
                                recent_changes += 1
                        except:
                            pass
            
            # If more than 5 files modified recently, it's suspicious
            return recent_changes > 5
        except:
            return False
    
    def check_file_integrity(self):
        """Detect unauthorized file modifications and restore from backup if needed"""
        integrity_alerts = []
        for filepath_str, baseline_info in self.file_baseline.items():
            if os.path.exists(filepath_str):
                try:
                    current_hash = self.calculate_hash(filepath_str)
                    if current_hash and current_hash != baseline_info['hash']:
                        # Check if file size changed drastically (encryption indicator)
                        current_size = os.path.getsize(filepath_str)
                        original_size = baseline_info.get('size', 0)
                        size_change_percent = abs(current_size - original_size) / max(original_size, 1) * 100
                        
                        if size_change_percent > 10:  # More than 10% change
                            alert = f"THREAT: File integrity compromised: {filepath_str} (size changed {size_change_percent:.1f}%)"
                            integrity_alerts.append(alert)
                            
                            # Try to restore from backup
                            filename = os.path.basename(filepath_str)
                            backup_path = os.path.join(self.backup_dir, filename)
                            if os.path.exists(backup_path):
                                self.restore_from_backup(filepath_str, backup_path)
                        else:
                            integrity_alerts.append(f"File modified: {filepath_str}")
                except Exception as e:
                    integrity_alerts.append(f"Error checking {filepath_str}: {e}")
        
        return integrity_alerts
    
    def log_alert(self, message, severity="MEDIUM"):
        timestamp = datetime.now().isoformat()
        
        # Determine severity based on message content
        if "CRITICAL" in message:
            severity = "CRITICAL"
        elif "THREAT" in message:
            severity = "HIGH"
        
        log_entry = {
            "timestamp": timestamp,
            "severity": severity,
            "message": message,
            "detection_type": "Ransomware",
            "threat_level": self.threat_level
        }
        
        try:
            with open(self.alert_log, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except:
            pass
        
        print(f"[{severity}] {message}")

# Usage
detector = RansomwareDetector()
detector.establish_baseline()
alerts = detector.detect_encryption_activity()
for alert in alerts:
    detector.log_alert(alert)