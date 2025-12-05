"""
Live Malware Simulation Test
Tests if Guardian AV can detect threats in real-time
"""

import os
import time

print('=' * 50)
print('  LIVE MALWARE SIMULATION TEST')
print('=' * 50)
print()
print('This test creates a FAKE malware file to see')
print('if Guardian AV detects it in real-time.')
print()

# Create a fake malware file
test_file = 'test_demo/live_test_malware.py'

fake_malware_content = """
# SIMULATED SPYWARE - HARMLESS TEST FILE
import pynput.keyboard
BOT_TOKEN = "test_token_12345"
from PIL import ImageGrab
def steal_passwords(): pass
# This file is safe - just contains text patterns
"""

print('[1] Creating fake malware file...')
os.makedirs('test_demo', exist_ok=True)
with open(test_file, 'w') as f:
    f.write(fake_malware_content)
print(f'    Created: {test_file}')

print()
print('[2] File contains these malware patterns:')
print('    - pynput.keyboard (keylogger)')
print('    - BOT_TOKEN (data exfiltration)')
print('    - ImageGrab (screenshot capture)')

print()
print('=' * 50)
print('CHECK YOUR GUARDIAN AV GUI NOW!')
print('=' * 50)
print()
print('If protection is ENABLED, Guardian should:')
print('  1. Detect the new file')
print('  2. Show a threat notification')
print('  3. Add alert to the Alerts tab')
print()

# Wait and then cleanup
print('Waiting 30 seconds... Press Ctrl+C to cleanup early.')
try:
    time.sleep(30)
except KeyboardInterrupt:
    pass

print()
print('[3] Cleaning up test file...')
if os.path.exists(test_file):
    os.remove(test_file)
    print('    Test file removed.')
print()
print('Test complete!')
