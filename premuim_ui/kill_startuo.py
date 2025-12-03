import subprocess
import os

# 1. Disable ALL scheduled tasks immediately
subprocess.run('schtasks /change /tn "WindowsSystemService" /disable', shell=True)
subprocess.run('schtasks /change /tn "SystemUpdateTask" /disable', shell=True)
subprocess.run('schtasks /change /tn "SystemMaintenance" /disable', shell=True)

# 2. Kill with extreme prejudice
os.system('taskkill /F /IM pythonw.exe')
os.system('taskkill /F /IM wscript.exe')
os.system('taskkill /F /IM cmd.exe')

# 3. Delete the main files immediately
import shutil
ransomware_path = r"D:\Year_3_Software_Engineering\Term_I\Cyber_Security\rnicrosoft-service\premuim_ui\main.py"
if os.path.exists(ransomware_path):
    os.remove(ransomware_path)
    print("Deleted main ransomware file")