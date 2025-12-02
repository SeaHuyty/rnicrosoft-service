import tkinter as tk
from tkinter import messagebox, ttk
import winreg
import os
import sys
import subprocess
import tempfile
import shutil
import time

class ComprehensiveRemovalTool:
    """Complete removal tool for ransomware simulation"""
    
    @staticmethod
    def remove_all_components():
        messages = []
        messages.append("=== STARTING COMPLETE REMOVAL ===")
        
        try:
            # 1. Kill processes
            messages.append("\n[1] Terminating processes...")
            for proc in ['pythonw.exe', 'wscript.exe', 'cmd.exe']:
                try:
                    subprocess.run(['taskkill', '/f', '/im', proc], 
                                 capture_output=True, timeout=5)
                    messages.append(f"  ✓ Killed {proc}")
                except:
                    pass
            
            time.sleep(2)
            
            # 2. Clean registry
            messages.append("\n[2] Cleaning registry...")
            registry_targets = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "WindowsSystemService"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "WindowsSystemService"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "load"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell"),
            ]
            
            for key, subkey, value_name in registry_targets:
                try:
                    with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as reg_key:
                        winreg.DeleteValue(reg_key, value_name)
                        messages.append(f"  ✓ Removed {subkey}\\{value_name}")
                except:
                    pass
            
            # 3. Remove tasks
            messages.append("\n[3] Removing scheduled tasks...")
            for task in ["WindowsSystemService", "SystemUpdateTask", "SystemMaintenance"]:
                try:
                    subprocess.run(f'schtasks /delete /tn "{task}" /f', 
                                 shell=True, capture_output=True)
                    messages.append(f"  ✓ Removed {task}")
                except:
                    pass
            
            # 4. Clean WMI
            messages.append("\n[4] Cleaning WMI...")
            try:
                subprocess.run('wmic /namespace:\\\\root\\subscription path __EventFilter delete', 
                             shell=True, capture_output=True)
                messages.append("  ✓ Cleaned WMI")
            except:
                pass
            
            # 5. Delete files
            messages.append("\n[5] Deleting files...")
            paths = [
                os.path.join(os.getenv('APPDATA'), 'Windows', 'SystemUpdate'),
                os.path.join(os.getenv('APPDATA'), 'SystemService.bat'),
                os.path.join(os.getenv('APPDATA'), 'SystemService.vbs'),
                os.path.join(tempfile.gettempdir(), 'system_task.xml'),
                os.path.join(tempfile.gettempdir(), 'system_wmi.mof'),
                os.path.join(tempfile.gettempdir(), 'system_service.log'),
            ]
            
            for path in paths:
                try:
                    if os.path.exists(path):
                        if os.path.isfile(path):
                            os.remove(path)
                        else:
                            shutil.rmtree(path)
                        messages.append(f"  ✓ Deleted {os.path.basename(path)}")
                except:
                    pass
            
            messages.append("\n=== REMOVAL COMPLETE ===")
            messages.append("All simulation components have been removed.")
            messages.append("Restart your computer to ensure complete cleanup.")
            
            return True, messages
            
        except Exception as e:
            return False, [f"Error: {str(e)}"]
    
    @staticmethod
    def show_gui():
        root = tk.Tk()
        root.title("Remove Simulation")
        root.geometry("500x400")
        
        tk.Label(root, text="Remove Ransomware Simulation", 
                font=("Arial", 14, "bold")).pack(pady=10)
        
        text = tk.Text(root, height=15, width=60)
        scrollbar = tk.Scrollbar(root, command=text.yview)
        text.config(yscrollcommand=scrollbar.set)
        
        text.pack(padx=10, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        def remove():
            if messagebox.askyesno("Confirm", "Remove all simulation components?"):
                text.delete(1.0, tk.END)
                success, messages = ComprehensiveRemovalTool.remove_all_components()
                for msg in messages:
                    text.insert(tk.END, msg + "\n")
        
        tk.Button(root, text="Remove All", command=remove, 
                 bg="red", fg="white", font=("Arial", 11)).pack(pady=10)
        tk.Button(root, text="Close", command=root.destroy).pack()
        
        root.mainloop()

if __name__ == "__main__":
    ComprehensiveRemovalTool.show_gui()