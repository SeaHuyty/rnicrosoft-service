import os
import sys
import time
import ctypes
import winreg
import subprocess
import tempfile
import json
import platform

def run_as_admin():
    """Restart as administrator if not already"""
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Restarting as Administrator...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

def kill_all_python_processes():
    """Kill all Python processes except this one"""
    print("\n[1/8] Killing malicious processes...")
    
    current_pid = os.getpid()
    processes_to_kill = ['python.exe', 'pythonw.exe', 'wscript.exe', 'cmd.exe']
    
    for proc_name in processes_to_kill:
        try:
            # Get all processes
            result = subprocess.run(
                ['tasklist', '/FI', f'IMAGENAME eq {proc_name}', '/FO', 'CSV', '/NH'],
                capture_output=True, 
                text=True, 
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip():
                        parts = line.strip('"').split('","')
                        if len(parts) >= 2:
                            pid = int(parts[1])
                            if pid != current_pid:
                                # Check if it's our malicious process
                                try:
                                    cmd_result = subprocess.run(
                                        ['wmic', 'process', 'where', f'ProcessId={pid}', 'get', 'CommandLine', '/format:csv'],
                                        capture_output=True,
                                        text=True,
                                        creationflags=subprocess.CREATE_NO_WINDOW,
                                        timeout=2
                                    )
                                    if 'system_service' in cmd_result.stdout.lower() or 'systemupdate' in cmd_result.stdout.lower():
                                        print(f"  Killing process {pid} ({proc_name})...")
                                        subprocess.run(['taskkill', '/F', '/PID', str(pid)], 
                                                     capture_output=True,
                                                     creationflags=subprocess.CREATE_NO_WINDOW)
                                except:
                                    # If we can't check command line, kill it anyway
                                    subprocess.run(['taskkill', '/F', '/PID', str(pid)], 
                                                 capture_output=True,
                                                 creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception as e:
            print(f"  Error killing {proc_name}: {e}")
    
    time.sleep(2)

def remove_scheduled_tasks():
    """Remove all scheduled tasks created by the ransomware"""
    print("\n[2/8] Removing scheduled tasks...")
    
    # List of known task names
    task_names = ['WindowsSystemService', 'SystemUpdateTask', 'SystemMaintenance', 'SystemUpdate']
    
    for task in task_names:
        try:
            # Check if task exists
            check_result = subprocess.run(
                f'schtasks /query /tn "{task}"',
                shell=True,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if check_result.returncode == 0:
                print(f"  Removing task: {task}")
                subprocess.run(
                    f'schtasks /delete /tn "{task}" /f',
                    shell=True,
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
        except Exception as e:
            print(f"  Error removing task {task}: {e}")
    
    # Also search for any tasks containing suspicious strings
    try:
        result = subprocess.run(
            'schtasks /query /fo list',
            shell=True,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        suspicious_keywords = ['systemupdate', 'windowsystem', 'ransomware', 'premium']
        lines = result.stdout.split('\n')
        current_task = ""
        
        for line in lines:
            if 'TaskName:' in line:
                current_task = line.split(':')[1].strip()
            elif any(keyword in current_task.lower() for keyword in suspicious_keywords):
                if current_task and '\\' in current_task:
                    print(f"  Removing suspicious task: {current_task}")
                    subprocess.run(
                        f'schtasks /delete /tn "{current_task}" /f',
                        shell=True,
                        capture_output=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )

    except Exception as e:
        print(f"  Error searching for suspicious tasks: {e}")

def clean_registry():
    """Clean all registry entries created by the ransomware"""
    print("\n[3/8] Cleaning registry entries...")
    
    registry_locations = [
        # HKCU locations
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        
        # Special locations that were modified
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "load"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell"),
    ]
    
    values_to_remove = ["WindowsSystemService", "SystemUpdate", "YouTubePremium"]
    
    for location in registry_locations:
        try:
            if len(location) == 3:
                key, subkey, value_name = location
                with winreg.OpenKey(key, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE) as reg_key:
                    try:
                        current_value, reg_type = winreg.QueryValueEx(reg_key, value_name)
                        
                        # Check if our malicious path is in the value
                        if 'systemupdate' in current_value.lower() or 'wscript' in current_value.lower():
                            # Remove our part from the string
                            import re
                            # Remove paths containing systemupdate
                            cleaned_value = re.sub(r'"?[^"]*systemupdate[^"]*"?\s*', '', current_value, flags=re.IGNORECASE)
                            cleaned_value = re.sub(r'wscript\.exe\s+"[^"]*"', '', cleaned_value, flags=re.IGNORECASE)
                            cleaned_value = cleaned_value.strip()
                            
                            if cleaned_value:
                                print(f"  Cleaning {subkey}\\{value_name}")
                                winreg.SetValueEx(reg_key, value_name, 0, reg_type, cleaned_value)
                            else:
                                print(f"  Deleting empty value {subkey}\\{value_name}")
                                winreg.DeleteValue(reg_key, value_name)
                    except FileNotFoundError:
                        pass  # Value doesn't exist, which is fine
            else:
                key, subkey = location
                with winreg.OpenKey(key, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE) as reg_key:
                    for value_name in values_to_remove:
                        try:
                            winreg.DeleteValue(reg_key, value_name)
                            print(f"  Removed {subkey}\\{value_name}")
                        except FileNotFoundError:
                            pass
        except Exception as e:
            print(f"  Error cleaning {location}: {e}")
    
    # Try HKLM as well
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                          r"Software\Microsoft\Windows\CurrentVersion\Run",
                          0, winreg.KEY_READ | winreg.KEY_WRITE) as reg_key:
            for value_name in values_to_remove:
                try:
                    winreg.DeleteValue(reg_key, value_name)
                    print(f"  Removed HKLM\\Run\\{value_name}")
                except FileNotFoundError:
                    pass
    except PermissionError:
        print("  Note: Some HKLM entries require TrustedInstaller privileges")
    except Exception as e:
        print(f"  Error cleaning HKLM: {e}")

def remove_wmi_subscriptions():
    """Remove WMI event subscriptions"""
    print("\n[4/8] Removing WMI event subscriptions...")
    
    try:
        # List WMI event filters
        result = subprocess.run(
            'wmic /namespace:\\\\root\\subscription path __EventFilter get Name',
            shell=True,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        suspicious_filters = ['SystemStartupFilter', 'SystemUpdateFilter']
        for filter_name in suspicious_filters:
            if filter_name in result.stdout:
                print(f"  Removing WMI filter: {filter_name}")
                subprocess.run(
                    f'wmic /namespace:\\\\root\\subscription path __EventFilter where Name="{filter_name}" delete',
                    shell=True,
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
        
        # Remove consumer
        subprocess.run(
            'wmic /namespace:\\\\root\\subscription path ActiveScriptEventConsumer where Name="SystemStartupConsumer" delete',
            shell=True,
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
    except Exception as e:
        print(f"  Error removing WMI subscriptions: {e}")

def remove_windows_service():
    """Remove Windows service if created"""
    print("\n[5/8] Removing Windows service...")
    
    service_names = ['SystemUpdate', 'WindowsSystemService']
    
    for service in service_names:
        try:
            # Check if service exists
            result = subprocess.run(
                f'sc query {service}',
                shell=True,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                print(f"  Stopping and deleting service: {service}")
                # Stop service first
                subprocess.run(f'sc stop {service}', 
                             shell=True,
                             capture_output=True,
                             creationflags=subprocess.CREATE_NO_WINDOW)
                time.sleep(2)
                # Delete service
                subprocess.run(f'sc delete {service}', 
                             shell=True,
                             capture_output=True,
                             creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception as e:
            print(f"  Error removing service {service}: {e}")

def delete_malicious_files():
    """Delete all files and folders created by the ransomware"""
    print("\n[6/8] Deleting malicious files...")
    
    # Common locations where the ransomware might have installed itself
    locations_to_clean = [
        os.path.join(os.getenv('APPDATA'), 'Windows', 'SystemUpdate'),
        os.path.join(os.getenv('APPDATA'), 'SystemUpdate'),
        os.path.join(os.getenv('APPDATA'), 'WindowsSystemService'),
        os.path.join(os.getenv('LOCALAPPDATA'), 'Windows', 'SystemUpdate'),
        os.path.join(os.getenv('PROGRAMDATA'), 'Windows', 'SystemUpdate'),
        os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming', 'Windows', 'SystemUpdate'),
    ]
    
    files_to_delete = [
        os.path.join(os.getenv('APPDATA'), 'SystemService.bat'),
        os.path.join(os.getenv('APPDATA'), 'SystemService.vbs'),
        os.path.join(os.getenv('APPDATA'), 'StartupLauncher.bat'),
        os.path.join(os.getenv('APPDATA'), 'service_wrapper.bat'),
        os.path.join(tempfile.gettempdir(), 'system_task.xml'),
        os.path.join(tempfile.gettempdir(), 'system_wmi.mof'),
    ]
    
    # Delete directories
    for location in locations_to_clean:
        try:
            if os.path.exists(location):
                print(f"  Deleting directory: {location}")
                import shutil
                shutil.rmtree(location, ignore_errors=True)
        except Exception as e:
            print(f"  Error deleting {location}: {e}")
    
    # Delete files
    for file_path in files_to_delete:
        try:
            if os.path.exists(file_path):
                print(f"  Deleting file: {file_path}")
                os.remove(file_path)
        except Exception as e:
            print(f"  Error deleting {file_path}: {e}")
    
    # Also search for any .bat or .vbs files referencing our script
    user_profile = os.path.expanduser('~')
    for root, dirs, files in os.walk(user_profile):
        for file in files:
            if file.endswith(('.bat', '.vbs', '.ps1')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if 'systemupdate' in content.lower() or 'premium_ui' in content.lower():
                            print(f"  Deleting suspicious file: {file_path}")
                            os.remove(file_path)
                except:
                    pass

def clean_startup_folder():
    """Clean startup folder entries"""
    print("\n[7/8] Cleaning startup folder...")
    
    startup_folders = [
        os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
        os.path.join(os.getenv('PROGRAMDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
    ]
    
    for folder in startup_folders:
        try:
            if os.path.exists(folder):
                for file in os.listdir(folder):
                    file_path = os.path.join(folder, file)
                    if file.lower().endswith(('.bat', '.vbs', '.cmd', '.ps1')):
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                if 'systemupdate' in content.lower() or 'pythonw' in content.lower():
                                    print(f"  Deleting startup entry: {file_path}")
                                    os.remove(file_path)
                        except:
                            # If we can't read it, delete it if name is suspicious
                            if any(keyword in file.lower() for keyword in ['system', 'update', 'service', 'windows']):
                                os.remove(file_path)
        except Exception as e:
            print(f"  Error cleaning startup folder {folder}: {e}")

def run_final_checks():
    """Run final checks and provide instructions"""
    print("\n[8/8] Running final checks...")
    
    print("\n" + "="*60)
    print("REMOVAL COMPLETE!")
    print("="*60)
    
    # Verify removal
    checks = [
        ("Checking for running processes...", 
         'tasklist | findstr /i "systemupdate"', 
         False),
        ("Checking scheduled tasks...",
         'schtasks /query | findstr /i "systemupdate"',
         False),
        ("Checking registry...",
         'reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run | findstr /i "windowsystem"',
         False),
    ]
    
    all_clean = True
    for check_name, command, should_find in checks:
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if (should_find and result.returncode != 0) or (not should_find and result.returncode == 0):
                print(f"  ⚠️  {check_name} - Still detected!")
                all_clean = False
            else:
                print(f"  ✓ {check_name} - Clean")
        except:
            print(f"  ? {check_name} - Could not verify")
    
    if all_clean:
        print("\n✅ System appears to be clean!")
    else:
        print("\n⚠️  Some traces may remain. A restart is required.")
    
    print("\n" + "="*60)
    print("IMPORTANT NEXT STEPS:")
    print("="*60)
    print("1. DELETE the original ransomware script:")
    print("   Location: D:\\Year_3_Software_Engineering\\Term_I\\Cyber_Security\\rnicrosoft-service\\premuim_ui\\main.py")
    print("\n2. RESTART your computer to complete the removal")
    print("\n3. After restart, run this removal tool again to ensure everything is clean")
    print("\n4. Consider running a full antivirus scan")
    
    choice = input("\nDo you want to restart now? (y/n): ").lower()
    if choice == 'y':
        print("\nComputer will restart in 30 seconds...")
        print("Save any work before it restarts!")
        subprocess.run(['shutdown', '/r', '/t', '30'])
    else:
        print("\nPlease restart manually as soon as possible!")

def create_prevention_file():
    """Create a file to prevent re-infection"""
    print("\nCreating prevention measures...")
    
    # Create a dummy folder to prevent re-creation
    system_update_path = os.path.join(os.getenv('APPDATA'), 'Windows', 'SystemUpdate')
    try:
        os.makedirs(system_update_path, exist_ok=True)
        # Create a read-only file to block installation
        block_file = os.path.join(system_update_path, 'DO_NOT_REMOVE_ANTIMALWARE.txt')
        with open(block_file, 'w') as f:
            f.write("This folder is protected by malware removal tool.\n")
            f.write("Do not delete this file - it prevents ransomware reinstallation.\n")
        # Make it read-only
        import stat
        os.chmod(block_file, stat.S_IREAD)
        print("  ✓ Created protection file")
    except:
        print("  ⚠️  Could not create protection file")

def main():
    print("="*60)
    print("COMPREHENSIVE RANSOMWARE REMOVAL TOOL")
    print("="*60)
    print("This tool will attempt to remove all persistence mechanisms")
    print("created by the malicious ransomware.")
    print("\nPlease make sure you have administrative privileges.")
    
    input("\nPress Enter to begin removal...")
    
    # Run all removal steps
    kill_all_python_processes()
    remove_scheduled_tasks()
    clean_registry()
    remove_wmi_subscriptions()
    remove_windows_service()
    delete_malicious_files()
    clean_startup_folder()
    create_prevention_file()
    run_final_checks()

if __name__ == "__main__":
    run_as_admin()
    main()