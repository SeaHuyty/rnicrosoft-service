================================================================================
                        GUARDIAN ANTIVIRUS - README
================================================================================

WHAT IS THIS?
-------------
Guardian Antivirus is a Python-based security tool that protects your computer
against spyware, ransomware, and worms. It was specifically designed to detect
and block the malware created by our team (spyware.py, screen locker, worm).


WHAT IT CAN DO:
---------------
✅ Detect keyloggers (pynput keyboard capture)
✅ Detect screenshot/webcam spyware
✅ Detect Chrome password stealers
✅ Detect Telegram data exfiltration
✅ Detect screen locker ransomware
✅ Detect registry persistence (WindowsSystemUpdate)
✅ Detect USB worms and autorun.inf
✅ Real-time file monitoring
✅ Manual scanning
✅ Emergency removal tools
✅ Quarantine malicious files


HOW TO RUN:
-----------
1. Open terminal/command prompt
2. Navigate to the project folder:
   cd D:\Someth\Cyber\rnicrosoft-service

3. Run the antivirus GUI:
   python guardian_av/main.py

4. Click "Enable Protection" to start real-time monitoring
5. Click "Scan Now" to scan for threats


QUICK TEST (to see detection working):
--------------------------------------
Run this command to see threat detection:
   python test_detection.py

This will show Guardian detecting 28 threats in the malware files.


DEMO SCRIPTS:
-------------
- python test_detection.py      -> Shows pattern detection (28 threats)
- python full_demo.py           -> Complete feature demo
- python malware_explained.py   -> Explains what each malware does
- python verify_before_push.py  -> Verifies everything works


PROJECT STRUCTURE:
------------------
guardian_av/
├── main.py              <- Run this for the GUI
├── core/
│   ├── protection_engine.py   <- Detection engine
│   └── config_manager.py      <- Settings
└── ui/
    ├── dashboard.py           <- Main screen
    ├── alerts.py              <- Threat alerts
    ├── quarantine.py          <- Isolated threats
    └── emergency_tools.py     <- Emergency removal


REQUIREMENTS:
-------------
pip install PyQt5 watchdog psutil pywin32


CREATED BY:
-----------
Someth Anti-Virus Team
December 2025

================================================================================
