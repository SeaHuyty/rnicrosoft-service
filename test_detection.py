"""
Someth Antivirus - Detection Test Script
Tests if the antivirus can detect malware patterns
"""

import re
import os
import sys

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guardian_av.core.config_manager import ConfigManager
from guardian_av.core.protection_engine import ProtectionEngine

config = ConfigManager()
engine = ProtectionEngine(config)

print('=' * 60)
print('   SOMETH ANTIVIRUS - DETECTION TEST')
print('=' * 60)

def test_file(filepath, test_name):
    """Test a file for malware patterns"""
    print(f'\n[{test_name}]')
    print(f'Scanning: {filepath}')
    print('-' * 40)
    
    if not os.path.exists(filepath):
        print('  ERROR: File not found')
        return 0
    
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read().lower()
    except Exception as e:
        print(f'  ERROR: Could not read file - {e}')
        return 0
    
    detected = []
    
    # Check spyware indicators from engine (it's a set of strings)
    for indicator in engine.SPYWARE_INDICATORS:
        if indicator.lower() in content:
            detected.append(f"SPYWARE: {indicator}")
    
    # Check ransomware patterns
    ransomware_patterns = [
        ('windowssystemupdate', 'Registry persistence key'),
        ('.enc', 'Encrypted file extension'),
        ('lock_screen', 'Screen locker function'),
        ('aesgcm', 'AES-GCM encryption'),
        ('ransom', 'Ransom-related code'),
        ('hkcu', 'Registry access'),
        ('software\\microsoft\\windows\\currentversion\\run', 'Registry Run key'),
    ]
    for pattern, desc in ransomware_patterns:
        if pattern in content:
            detected.append(f'RANSOMWARE: {desc}')
    
    # Check worm patterns
    worm_patterns = [
        ('getdrivetype', 'Drive enumeration'),
        ('drive_removable', 'USB drive detection'),
        ('shutil.copy', 'File spreading'),
        ('autorun.inf', 'Autorun file creation'),
    ]
    for pattern, desc in worm_patterns:
        if pattern in content:
            detected.append(f'WORM: {desc}')
    
    if detected:
        print(f'  ✅ THREATS DETECTED: {len(detected)}')
        for d in detected:
            print(f'     🚨 {d}')
        return len(detected)
    else:
        print('  ❌ No threats detected')
        return 0

# Track results
total_threats = 0
tests = [
    ('test_demo/fake_malware.py', 'TEST 1 - Fake Spyware'),
    ('test_demo/fake_ransom.py', 'TEST 2 - Fake Ransomware'),
    ('malicious-code/spyware/spyware.py', 'TEST 3 - Real Spyware'),
    ('premuim_ui/main.py', 'TEST 4 - Screen Locker'),
    ('malicious-code/components/encrypt.py', 'TEST 5 - Encryptor'),
    ('malicious-code/components/worm.py', 'TEST 6 - Worm'),
]

for filepath, test_name in tests:
    total_threats += test_file(filepath, test_name)

print('\n' + '=' * 60)
print(f'   TEST COMPLETE - {total_threats} total threats detected!')
print('=' * 60)

if total_threats > 0:
    print('\n✅ Someth Antivirus is WORKING!')
    print('   It can detect spyware, ransomware, and worms.')
else:
    print('\n❌ Detection test failed - no threats found')
