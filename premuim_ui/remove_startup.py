import tkinter as tk
from tkinter import messagebox
import winreg
import os
import sys
import subprocess

class ComprehensiveRemovalTool:
    """Comprehensive tool to remove background service completely"""
    
    @staticmethod
    def remove_all_persistence():
        """Remove all persistence methods and kill service"""
        success = True
        messages = []
        
        try:
            # 1. Remove registry startup entry
            try:
                key = winreg.HKEY_CURRENT_USER
                subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as reg_key:
                    try:
                        winreg.DeleteValue(reg_key, "WindowsSystemUpdate")
                        messages.append("✅ Registry startup entry removed")
                    except FileNotFoundError:
                        messages.append("ℹ️ No registry startup entry found")
            except Exception as e:
                messages.append(f"❌ Registry removal failed: {e}")
                success = False
            
            # 2. Kill any running Python processes (service)
            try:
                # Kill pythonw.exe processes (background service)
                subprocess.run(['taskkill', '/f', '/im', 'pythonw.exe'], 
                             capture_output=True, text=True)
                messages.append("✅ Background service processes killed")
            except Exception as e:
                messages.append(f"⚠️ Process kill: {e}")
            
            # 3. Remove VBS script
            try:
                vbs_path = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'WindowsUpdate.vbs')
                if os.path.exists(vbs_path):
                    os.remove(vbs_path)
                    messages.append("✅ VBS service script removed")
                else:
                    messages.append("ℹ️ No VBS script found")
            except Exception as e:
                messages.append(f"❌ VBS removal failed: {e}")
            
            # 4. Remove batch file
            try:
                batch_path = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'WindowsUpdate.bat')
                if os.path.exists(batch_path):
                    os.remove(batch_path)
                    messages.append("✅ Batch file removed")
                else:
                    messages.append("ℹ️ No batch file found")
            except Exception as e:
                messages.append(f"❌ Batch file removal failed: {e}")
            
            # 5. Remove any executable copies
            try:
                exe_path = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'SystemUpdate.exe')
                if os.path.exists(exe_path):
                    os.remove(exe_path)
                    messages.append("✅ Executable copy removed")
                else:
                    messages.append("ℹ️ No executable copy found")
            except Exception as e:
                messages.append(f"❌ Executable removal failed: {e}")
            
            return success, messages
            
        except Exception as e:
            return False, [f"❌ Removal failed: {e}"]
    
    @staticmethod
    def show_removal_dialog():
        """Show comprehensive removal dialog"""
        root = tk.Tk()
        root.withdraw()
        
        result = messagebox.askyesno(
            "KILL BACKGROUND SERVICE",
            "This will COMPLETELY remove the background service:\n\n"
            "• Kill all running service processes\n"
            "• Remove registry startup entries\n"
            "• Delete all service script files\n"
            "• Prevent auto-restart\n\n"
            "This will permanently disable the simulation.\n\n"
            "Continue with service termination?"
        )
        
        if not result:
            messagebox.showinfo("Cancelled", "Service is still running.")
            root.destroy()
            return
        
        success, messages = ComprehensiveRemovalTool.remove_all_persistence()
        
        # Show results
        result_text = "\n".join(messages)
        
        if success:
            messagebox.showinfo("Service Terminated", 
                              f"✅ BACKGROUND SERVICE COMPLETELY REMOVED\n\n{result_text}")
        else:
            messagebox.showwarning("Partial Removal", 
                                 f"⚠️ SOME SERVICE COMPONENTS MAY REMAIN\n\n{result_text}")
        
        root.destroy()

if __name__ == "__main__":
    ComprehensiveRemovalTool.show_removal_dialog()