"""
Guardian Antivirus - Windows Notification System
Handles Windows toast notifications for threat alerts
"""

import threading
from typing import Optional
from dataclasses import dataclass

# Try to import win10toast for notifications
try:
    from win10toast import ToastNotifier
    HAS_TOAST = True
except ImportError:
    HAS_TOAST = False
    ToastNotifier = None


@dataclass
class NotificationConfig:
    """Configuration for notifications"""
    enabled: bool = True
    sound: bool = True
    duration: int = 5  # seconds


class NotificationManager:
    """Manages Windows toast notifications"""
    
    APP_NAME = "Someth Antivirus"
    ICON_PATH = None  # Can be set to a custom icon path
    
    def __init__(self, config: Optional[NotificationConfig] = None):
        self.config = config or NotificationConfig()
        self._toaster: Optional[ToastNotifier] = None
        self._lock = threading.Lock()
        
        if HAS_TOAST:
            try:
                self._toaster = ToastNotifier()
            except:
                pass
    
    def _show_notification(self, title: str, message: str, duration: int = None):
        """Internal method to show notification (runs in thread)"""
        if not HAS_TOAST or not self._toaster:
            return
        
        if not self.config.enabled:
            return
        
        with self._lock:
            try:
                self._toaster.show_toast(
                    title=title,
                    msg=message,
                    icon_path=self.ICON_PATH,
                    duration=duration or self.config.duration,
                    threaded=False  # Already in thread
                )
            except Exception as e:
                print(f"Notification error: {e}")
    
    def show(self, title: str, message: str, duration: int = None):
        """Show a notification (non-blocking)"""
        thread = threading.Thread(
            target=self._show_notification,
            args=(title, message, duration),
            daemon=True
        )
        thread.start()
    
    def show_threat_alert(self, threat_type: str, description: str, severity: str = "high"):
        """Show a threat alert notification"""
        if severity.lower() == "critical":
            title = f"🚨 CRITICAL: {threat_type.upper()} DETECTED!"
        elif severity.lower() == "high":
            title = f"⚠️ ALERT: {threat_type.capitalize()} Detected"
        else:
            title = f"ℹ️ {threat_type.capitalize()} Detected"
        
        self.show(title, description, duration=8)
    
    def show_protection_status(self, enabled: bool):
        """Show protection status notification"""
        if enabled:
            self.show(
                f"✅ {self.APP_NAME}",
                "Real-time protection is now active.",
                duration=3
            )
        else:
            self.show(
                f"⚠️ {self.APP_NAME}",
                "Real-time protection has been disabled.",
                duration=5
            )
    
    def show_scan_complete(self, threats_found: int):
        """Show scan complete notification"""
        if threats_found > 0:
            self.show(
                f"🔍 Scan Complete",
                f"Found and blocked {threats_found} threat(s).",
                duration=5
            )
        else:
            self.show(
                f"✅ Scan Complete",
                "No threats detected. Your system is clean.",
                duration=3
            )
    
    def show_quarantine_action(self, filename: str, action: str):
        """Show quarantine action notification"""
        if action == "quarantined":
            self.show(
                "🔒 File Quarantined",
                f"Threat blocked: {filename}",
                duration=5
            )
        elif action == "restored":
            self.show(
                "📂 File Restored",
                f"Restored from backup: {filename}",
                duration=3
            )
    
    def is_available(self) -> bool:
        """Check if notifications are available"""
        return HAS_TOAST and self._toaster is not None


# Alternative notification using Windows message box (fallback)
def show_message_box(title: str, message: str, error: bool = False):
    """Show a Windows message box (fallback notification)"""
    try:
        import ctypes
        style = 0x10 if error else 0x40  # MB_ICONERROR or MB_ICONINFORMATION
        ctypes.windll.user32.MessageBoxW(0, message, title, style)
    except:
        pass
