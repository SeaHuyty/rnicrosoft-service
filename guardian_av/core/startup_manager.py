"""
Guardian Antivirus - Windows Startup Manager
Handles Windows startup integration via registry
"""

import os
import sys
import winreg
from pathlib import Path


class StartupManager:
    """Manages Windows startup integration"""
    
    APP_NAME = "SomethAntivirus"
    REGISTRY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
    
    def __init__(self):
        self.app_path = self._get_app_path()
    
    def _get_app_path(self) -> str:
        """Get the path to the main application"""
        if getattr(sys, 'frozen', False):
            # Running as compiled executable
            return sys.executable
        else:
            # Running as script
            main_script = Path(__file__).parent.parent / "main.py"
            python_exe = sys.executable
            return f'"{python_exe}" "{main_script}"'
    
    def is_enabled(self) -> bool:
        """Check if auto-start is enabled"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                self.REGISTRY_PATH,
                0,
                winreg.KEY_READ
            )
            try:
                winreg.QueryValueEx(key, self.APP_NAME)
                winreg.CloseKey(key)
                return True
            except WindowsError:
                winreg.CloseKey(key)
                return False
        except WindowsError:
            return False
    
    def enable(self, start_minimized: bool = True) -> bool:
        """Enable auto-start with Windows"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                self.REGISTRY_PATH,
                0,
                winreg.KEY_SET_VALUE
            )
            
            # Add --minimized flag if starting minimized
            command = self.app_path
            if start_minimized:
                if getattr(sys, 'frozen', False):
                    command = f'"{self.app_path}" --minimized'
                else:
                    command = f'{self.app_path} --minimized'
            
            winreg.SetValueEx(
                key,
                self.APP_NAME,
                0,
                winreg.REG_SZ,
                command
            )
            winreg.CloseKey(key)
            return True
        except WindowsError as e:
            print(f"Failed to enable startup: {e}")
            return False
    
    def disable(self) -> bool:
        """Disable auto-start with Windows"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                self.REGISTRY_PATH,
                0,
                winreg.KEY_SET_VALUE
            )
            try:
                winreg.DeleteValue(key, self.APP_NAME)
            except WindowsError:
                pass  # Value doesn't exist
            winreg.CloseKey(key)
            return True
        except WindowsError as e:
            print(f"Failed to disable startup: {e}")
            return False
    
    def toggle(self, enable: bool, start_minimized: bool = True) -> bool:
        """Toggle auto-start setting"""
        if enable:
            return self.enable(start_minimized)
        else:
            return self.disable()
