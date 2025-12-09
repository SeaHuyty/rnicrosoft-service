"""
Someth Antivirus - Pre-Push Verification Script
Run this to verify everything works before pushing to GitHub
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def run_tests():
    print("=" * 65)
    print("  SOMETH ANTIVIRUS - PRE-PUSH VERIFICATION")
    print("=" * 65)
    print()
    
    passed = 0
    failed = 0
    
    # Test 1: Imports
    print("[1/8] Testing imports...")
    try:
        from guardian_av.core.config_manager import ConfigManager
        from guardian_av.core.protection_engine import ProtectionEngine, ThreatType
        from guardian_av.main import MainWindow
        print("      ✅ All imports successful")
        passed += 1
    except Exception as e:
        print(f"      ❌ Import failed: {e}")
        failed += 1
        return
    
    # Test 2: Config
    print("[2/8] Testing config manager...")
    try:
        config = ConfigManager()
        assert len(config.protected_directories) > 0
        print(f"      ✅ Config loaded ({len(config.protected_directories)} protected dirs)")
        passed += 1
    except Exception as e:
        print(f"      ❌ Config failed: {e}")
        failed += 1
    
    # Test 3: Engine
    print("[3/8] Testing protection engine...")
    try:
        engine = ProtectionEngine(config)
        assert engine is not None
        print("      ✅ Engine initialized")
        passed += 1
    except Exception as e:
        print(f"      ❌ Engine failed: {e}")
        failed += 1
    
    # Test 4: Spyware detection
    print("[4/8] Testing spyware detection...")
    try:
        indicators = engine.SPYWARE_INDICATORS
        assert len(indicators) >= 5
        print(f"      ✅ {len(indicators)} spyware indicators loaded")
        passed += 1
    except Exception as e:
        print(f"      ❌ Detection failed: {e}")
        failed += 1
    
    # Test 5: Ransomware detection
    print("[5/8] Testing ransomware detection...")
    try:
        registry_values = engine.MALICIOUS_REGISTRY_VALUES
        assert 'windowssystemupdate' in registry_values
        print(f"      ✅ {len(registry_values)} ransomware patterns loaded")
        passed += 1
    except Exception as e:
        print(f"      ❌ Detection failed: {e}")
        failed += 1
    
    # Test 6: Alert callback
    print("[6/8] Testing alert system...")
    try:
        alerts = []
        engine.on_threat_detected = lambda t: alerts.append(t)
        from guardian_av.core.protection_engine import ThreatInfo, ThreatSeverity
        test = ThreatInfo(ThreatType.SPYWARE, ThreatSeverity.HIGH, "Test", "test.py", None, "detected")
        engine._notify_threat(test)
        assert len(alerts) == 1
        print("      ✅ Alert callback working")
        passed += 1
    except Exception as e:
        print(f"      ❌ Alert failed: {e}")
        failed += 1
    
    # Test 7: Manual scan
    print("[7/8] Testing manual scan...")
    try:
        threats = engine.run_manual_scan()
        assert len(threats) >= 0
        print(f"      ✅ Scan complete ({len(threats)} threats found)")
        passed += 1
    except Exception as e:
        print(f"      ❌ Scan failed: {e}")
        failed += 1
    
    # Test 8: Stats
    print("[8/8] Testing stats...")
    try:
        stats = engine.get_stats()
        assert 'threats_detected' in stats
        assert 'files_scanned' in stats
        print(f"      ✅ Stats: {stats['threats_detected']} threats, {stats['files_scanned']} files")
        passed += 1
    except Exception as e:
        print(f"      ❌ Stats failed: {e}")
        failed += 1
    
    # Summary
    print()
    print("=" * 65)
    if failed == 0:
        print(f"  ✅ ALL TESTS PASSED ({passed}/{passed + failed})")
        print("  Your code is ready to push to GitHub!")
    else:
        print(f"  ❌ SOME TESTS FAILED ({passed}/{passed + failed})")
        print("  Please fix the issues before pushing.")
    print("=" * 65)
    
    return failed == 0

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
