"""
Guardian Antivirus - Configuration Manager
Handles settings persistence and protected directories management
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime


class ConfigManager:
    """Manages application configuration and settings persistence"""
    
    DEFAULT_CONFIG = {
        "version": "1.0.0",
        "protection": {
            "enabled": True,
            "auto_start": True,
            "start_minimized": True,
            "scan_interval": 5,  # seconds
            "process_scan_interval": 3,  # seconds
        },
        "protected_directories": [],
        "backup_directory": "C:/RansomwareBackup",
        "quarantine_directory": "C:/QuarantineZone",
        "notifications": {
            "enabled": True,
            "sound": True,
            "threat_alerts": True,
            "status_updates": False,
        },
        "scanning": {
            "ransomware_detection": True,
            "worm_detection": True,
            "spyware_detection": True,
            "usb_monitoring": True,
            "autorun_blocking": True,
        },
        "performance": {
            "low_resource_mode": False,
            "max_cpu_percent": 25,
            "scan_delay_ms": 100,
        },
        "ui": {
            "theme": "dark",
            "minimize_to_tray": True,
            "show_in_taskbar": True,
        },
        "statistics": {
            "threats_detected": 0,
            "threats_blocked": 0,
            "files_quarantined": 0,
            "files_restored": 0,
            "last_full_scan": None,
        }
    }
    
    def __init__(self, config_dir: str = None):
        if config_dir is None:
            # Use AppData/Local for config storage
            config_dir = os.path.join(
                os.environ.get('LOCALAPPDATA', os.path.expanduser('~')),
                'GuardianAV'
            )
        
        self.config_dir = Path(config_dir)
        self.config_file = self.config_dir / "config.json"
        self.alerts_file = self.config_dir / "alerts.json"
        self.quarantine_log = self.config_dir / "quarantine.json"
        
        # Ensure directories exist
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Load or create config
        self.config = self._load_config()
        
        # Initialize default protected directories if none set
        if not self.config["protected_directories"]:
            self._set_default_directories()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    # Merge with defaults to ensure all keys exist
                    return self._merge_config(self.DEFAULT_CONFIG.copy(), loaded)
            except Exception as e:
                print(f"Error loading config: {e}")
        
        # Return default config
        return self.DEFAULT_CONFIG.copy()
    
    def _merge_config(self, default: Dict, loaded: Dict) -> Dict:
        """Recursively merge loaded config with defaults"""
        result = default.copy()
        for key, value in loaded.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_config(result[key], value)
            else:
                result[key] = value
        return result
    
    def _set_default_directories(self):
        """Set default protected directories (common user folders)"""
        user_home = Path.home()
        default_dirs = [
            str(user_home / "Documents"),
            str(user_home / "Desktop"),
            str(user_home / "Downloads"),
            str(user_home / "Pictures"),
        ]
        
        # Add D:/Hello for testing if it exists
        if Path("D:/Hello").exists():
            default_dirs.append("D:/Hello")
        
        # Only add directories that exist
        self.config["protected_directories"] = [
            d for d in default_dirs if Path(d).exists()
        ]
        self.save()
    
    def save(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    # Property accessors
    @property
    def protection_enabled(self) -> bool:
        return self.config["protection"]["enabled"]
    
    @protection_enabled.setter
    def protection_enabled(self, value: bool):
        self.config["protection"]["enabled"] = value
        self.save()
    
    @property
    def auto_start(self) -> bool:
        return self.config["protection"]["auto_start"]
    
    @auto_start.setter
    def auto_start(self, value: bool):
        self.config["protection"]["auto_start"] = value
        self.save()
    
    @property
    def protected_directories(self) -> List[str]:
        return self.config["protected_directories"]
    
    def add_protected_directory(self, directory: str) -> bool:
        """Add a directory to protection list"""
        directory = str(Path(directory).resolve())
        if directory not in self.config["protected_directories"]:
            if Path(directory).exists():
                self.config["protected_directories"].append(directory)
                self.save()
                return True
        return False
    
    def remove_protected_directory(self, directory: str) -> bool:
        """Remove a directory from protection list"""
        directory = str(Path(directory).resolve())
        if directory in self.config["protected_directories"]:
            self.config["protected_directories"].remove(directory)
            self.save()
            return True
        return False
    
    @property
    def backup_directory(self) -> str:
        return self.config["backup_directory"]
    
    @backup_directory.setter
    def backup_directory(self, value: str):
        self.config["backup_directory"] = value
        Path(value).mkdir(parents=True, exist_ok=True)
        self.save()
    
    @property
    def quarantine_directory(self) -> str:
        return self.config["quarantine_directory"]
    
    @quarantine_directory.setter
    def quarantine_directory(self, value: str):
        self.config["quarantine_directory"] = value
        Path(value).mkdir(parents=True, exist_ok=True)
        self.save()
    
    @property
    def notifications_enabled(self) -> bool:
        return self.config["notifications"]["enabled"]
    
    @notifications_enabled.setter
    def notifications_enabled(self, value: bool):
        self.config["notifications"]["enabled"] = value
        self.save()
    
    @property
    def minimize_to_tray(self) -> bool:
        return self.config["ui"]["minimize_to_tray"]
    
    @minimize_to_tray.setter
    def minimize_to_tray(self, value: bool):
        self.config["ui"]["minimize_to_tray"] = value
        self.save()
    
    @property
    def start_minimized(self) -> bool:
        return self.config["protection"]["start_minimized"]
    
    @start_minimized.setter
    def start_minimized(self, value: bool):
        self.config["protection"]["start_minimized"] = value
        self.save()
    
    # Statistics methods
    def increment_stat(self, stat_name: str, amount: int = 1):
        """Increment a statistics counter"""
        if stat_name in self.config["statistics"]:
            if self.config["statistics"][stat_name] is None:
                self.config["statistics"][stat_name] = 0
            self.config["statistics"][stat_name] += amount
            self.save()
    
    def get_stat(self, stat_name: str) -> Any:
        """Get a statistics value"""
        return self.config["statistics"].get(stat_name, 0)
    
    def update_last_scan(self):
        """Update last full scan timestamp"""
        self.config["statistics"]["last_full_scan"] = datetime.now().isoformat()
        self.save()
    
    # Alert history management
    def save_alert(self, alert: Dict):
        """Save an alert to history"""
        alerts = self.load_alerts()
        alerts.append({
            **alert,
            "timestamp": datetime.now().isoformat()
        })
        # Keep only last 1000 alerts
        alerts = alerts[-1000:]
        try:
            with open(self.alerts_file, 'w', encoding='utf-8') as f:
                json.dump(alerts, f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving alert: {e}")
    
    def load_alerts(self) -> List[Dict]:
        """Load alert history"""
        if self.alerts_file.exists():
            try:
                with open(self.alerts_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        return []
    
    def clear_alerts(self):
        """Clear alert history"""
        try:
            with open(self.alerts_file, 'w', encoding='utf-8') as f:
                json.dump([], f)
        except:
            pass
    
    # Quarantine log management
    def log_quarantine(self, original_path: str, quarantine_path: str, reason: str):
        """Log a quarantined file"""
        log = self.load_quarantine_log()
        log.append({
            "original_path": original_path,
            "quarantine_path": quarantine_path,
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
            "restored": False
        })
        try:
            with open(self.quarantine_log, 'w', encoding='utf-8') as f:
                json.dump(log, f, indent=2, default=str)
        except:
            pass
    
    def load_quarantine_log(self) -> List[Dict]:
        """Load quarantine log"""
        if self.quarantine_log.exists():
            try:
                with open(self.quarantine_log, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        return []
    
    def get_scanning_config(self) -> Dict:
        """Get scanning configuration"""
        return self.config["scanning"]
    
    def get_performance_config(self) -> Dict:
        """Get performance configuration"""
        return self.config["performance"]
