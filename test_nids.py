#!/usr/bin/env python3
"""
Network Intrusion Detection System - Test Script
Demonstrates and validates NIDS functionality optimized for Windows
"""

import time
import threading
import subprocess
import sys
import os
import platform
from datetime import datetime

def test_imports():
    """Test if all required modules can be imported"""
    print("🔍 Testing module imports...")
    
    try:
        from nids_core import NIDSEngine, PacketAnalyzer
        print("✅ nids_core imported successfully")
    except ImportError as e:
        print(f"❌ Error importing nids_core: {e}")
        return False
    
    try:
        from rule_engine import RuleEngine, Rule
        print("✅ rule_engine imported successfully")
    except ImportError as e:
        print(f"❌ Error importing rule_engine: {e}")
        return False
    
    try:
        from response_system import ResponseSystem, ResponseAction
        print("✅ response_system imported successfully")
    except ImportError as e:
        print(f"❌ Error importing response_system: {e}")
        return False
    
    try:
        from dashboard import app, socketio, dashboard_data
        print("✅ dashboard imported successfully")
    except ImportError as e:
        print(f"❌ Error importing dashboard: {e}")
        return False
    
    try:
        from config import NIDSConfig
        print("✅ config imported successfully")
    except ImportError as e:
        print(f"❌ Error importing config: {e}")
        return False
    
    return True

def test_windows_specific():
    """Test Windows-specific functionality"""
    print("\n🪟 Testing Windows-specific features...")
    
    is_windows = platform.system() == 'Windows'
    if not is_windows:
        print("⚠️  Not a Windows system, skipping Windows-specific tests")
        return True
    
    try:
        # Test Windows privilege detection
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        print(f"✅ Administrator privileges: {'Yes' if is_admin else 'No'}")
        
        # Test Windows interface detection
        import psutil
        interfaces = psutil.net_if_addrs()
        active_interfaces = [name for name, addrs in interfaces.items() 
                           if any(addr.family == 2 for addr in addrs)]
        print(f"✅ Active network interfaces: {len(active_interfaces)} found")
        
        # Test Windows configuration
        from config import config
        windows_config = config.get_windows_config()
        print(f"✅ Windows configuration: {len(windows_config)} settings")
        
        return True
    except Exception as e:
        print(f"❌ Windows-specific test failed: {e}")
        return False

def test_configuration():
    """Test configuration system"""
    print("\n⚙️  Testing configuration system...")
    
    try:
        from config import config
        
        # Test basic configuration
        interface = config.get('network.default_interface')
        print(f"✅ Default interface: {interface}")
        
        # Test configuration summary
        summary = config.get_config_summary()
        print(f"✅ Configuration summary: {len(summary)} items")
        print(f"   Platform: {summary.get('platform', 'Unknown')}")
        print(f"   Windows Optimized: {summary.get('windows_optimized', False)}")
        
        # Test validation
        errors = config.validate_config()
        if errors:
            print(f"⚠️  Configuration validation errors: {errors}")
        else:
            print("✅ Configuration validation passed")
        
        # Test Windows optimization
        if platform.system() == 'Windows':
            config.optimize_for_windows()
            print("✅ Windows optimization applied")
        
        return True
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def test_rule_engine():
    """Test rule engine functionality"""
    print("\n🔍 Testing rule engine...")
    
    try:
        from rule_engine import RuleEngine
        
        engine = RuleEngine()
        
        # Test rule loading
        rules = engine.get_rules()
        print(f"✅ Loaded {len(rules)} rules")
        
        # Test rule statistics
        stats = engine.get_rule_stats()
        print(f"✅ Rule statistics: {stats['total_rules']} total rules")
        
        # Test adding custom rule
        custom_rule = {
            'name': 'Test Rule',
            'description': 'Test rule for validation',
            'conditions': {
                'type': 'port_scan',
                'threshold': 5,
                'time_window': 30
            },
            'enabled': True
        }
        
        rule_id = engine.add_rule(custom_rule)
        print(f"✅ Added custom rule with ID: {rule_id}")
        
        # Test rule evaluation
        test_packet = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'tcp'
        }
        
        threats = engine.evaluate_packet(test_packet)
        print(f"✅ Rule evaluation completed: {len(threats)} threats detected")
        
        return True
    except Exception as e:
        print(f"❌ Rule engine test failed: {e}")
        return False

def test_response_system():
    """Test response system functionality"""
    print("\n🛡️  Testing response system...")
    
    try:
        from response_system import ResponseSystem
        
        response = ResponseSystem()
        
        # Test action loading
        actions = response.get_actions()
        print(f"✅ Loaded {len(actions)} response actions")
        
        # Test action statistics
        stats = response.get_action_stats()
        print(f"✅ Action statistics: {stats['total_actions']} total actions")
        
        # Test response execution
        test_alert = {
            'threat': 'Test threat',
            'severity': 'HIGH',
            'packet_info': {
                'src_ip': '192.168.1.100',
                'dst_ip': '192.168.1.1'
            }
        }
        
        executed_actions = response.execute_response(test_alert)
        print(f"✅ Response execution: {len(executed_actions)} actions executed")
        
        # Test Windows-specific responses
        if platform.system() == 'Windows':
            print("✅ Windows response system ready")
        
        return True
    except Exception as e:
        print(f"❌ Response system test failed: {e}")
        return False

def test_packet_analyzer():
    """Test packet analyzer functionality"""
    print("\n📦 Testing packet analyzer...")
    
    try:
        from nids_core import PacketAnalyzer
        from scapy.all import IP, TCP
        
        analyzer = PacketAnalyzer()
        
        # Create test packet
        test_packet = IP(src='192.168.1.100', dst='192.168.1.1') / TCP(sport=12345, dport=80)
        
        # Test packet analysis
        threats = analyzer.analyze_packet(test_packet)
        print(f"✅ Packet analysis completed: {len(threats)} threats detected")
        
        # Test statistics
        stats = analyzer.get_statistics()
        print(f"✅ Analyzer statistics: {stats['packet_count']} packets processed")
        
        return True
    except Exception as e:
        print(f"❌ Packet analyzer test failed: {e}")
        return False

def test_dashboard():
    """Test dashboard functionality"""
    print("\n🌐 Testing dashboard...")
    
    try:
        from dashboard import app, dashboard_data
        
        # Test dashboard data
        data = dashboard_data.get_dashboard_data()
        print(f"✅ Dashboard data: {len(data)} data points")
        
        # Test system information
        system_info = dashboard_data.system_info
        print(f"✅ System info: {system_info['platform']} {system_info['python_version']}")
        
        # Test Windows-specific dashboard features
        if platform.system() == 'Windows':
            print("✅ Windows dashboard features available")
        
        return True
    except Exception as e:
        print(f"❌ Dashboard test failed: {e}")
        return False

def test_network_interface():
    """Test network interface detection"""
    print("\n📡 Testing network interface detection...")
    
    try:
        from nids_core import NIDSEngine
        
        # Test interface auto-detection
        nids = NIDSEngine()
        print(f"✅ Auto-detected interface: {nids.interface}")
        
        # Test interface status
        status = nids.get_status()
        print(f"✅ NIDS status: {status['is_running']}")
        
        # Test Windows interface detection
        if platform.system() == 'Windows':
            import psutil
            interfaces = psutil.net_if_addrs()
            print(f"✅ Windows interfaces: {len(interfaces)} found")
            
            # Show interface details
            for name, addrs in list(interfaces.items())[:3]:  # Show first 3
                ip_addrs = [addr.address for addr in addrs if addr.family == 2]
                if ip_addrs:
                    print(f"   • {name}: {', '.join(ip_addrs)}")
        
        return True
    except Exception as e:
        print(f"❌ Network interface test failed: {e}")
        return False

def test_permissions():
    """Test system permissions"""
    print("\n🔐 Testing system permissions...")
    
    try:
        if platform.system() == 'Windows':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            print(f"✅ Administrator privileges: {'Yes' if is_admin else 'No'}")
            
            if not is_admin:
                print("⚠️  Running without administrator privileges")
                print("   Some features may not work properly")
        else:
            is_root = os.geteuid() == 0
            print(f"✅ Root privileges: {'Yes' if is_root else 'No'}")
        
        # Test file permissions
        test_file = 'test_permissions.tmp'
        try:
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            print("✅ File write permissions: OK")
        except Exception as e:
            print(f"❌ File write permissions failed: {e}")
            return False
        
        return True
    except Exception as e:
        print(f"❌ Permissions test failed: {e}")
        return False

def test_windows_integration():
    """Test Windows-specific integrations"""
    print("\n🪟 Testing Windows integrations...")
    
    if platform.system() != 'Windows':
        print("⚠️  Not a Windows system, skipping Windows integration tests")
        return True
    
    try:
        # Test Windows Firewall integration
        try:
            import subprocess
            result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print("✅ Windows Firewall accessible")
            else:
                print("⚠️  Windows Firewall not accessible")
        except Exception as e:
            print(f"⚠️  Windows Firewall test failed: {e}")
        
        # Test Windows Event Log
        try:
            import winreg
            print("✅ Windows Registry accessible")
        except Exception as e:
            print(f"⚠️  Windows Registry test failed: {e}")
        
        # Test PowerShell execution
        try:
            result = subprocess.run(['powershell', '-Command', 'Get-Process'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print("✅ PowerShell execution: OK")
            else:
                print("⚠️  PowerShell execution failed")
        except Exception as e:
            print(f"⚠️  PowerShell test failed: {e}")
        
        return True
    except Exception as e:
        print(f"❌ Windows integration test failed: {e}")
        return False

def run_comprehensive_test():
    """Run comprehensive NIDS test suite"""
    print("🚀 Starting Comprehensive NIDS Test Suite")
    print("=" * 60)
    print(f"Platform: {platform.system()} {platform.version()}")
    print(f"Python: {platform.python_version()}")
    print(f"Architecture: {platform.architecture()[0]}")
    print("=" * 60)
    
    tests = [
        ("Module Imports", test_imports),
        ("Windows-Specific Features", test_windows_specific),
        ("Configuration System", test_configuration),
        ("Rule Engine", test_rule_engine),
        ("Response System", test_response_system),
        ("Packet Analyzer", test_packet_analyzer),
        ("Dashboard", test_dashboard),
        ("Network Interface", test_network_interface),
        ("System Permissions", test_permissions),
        ("Windows Integration", test_windows_integration)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            print(f"❌ {test_name}: ERROR - {e}")
    
    print("\n" + "=" * 60)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! NIDS is ready to use.")
        if platform.system() == 'Windows':
            print("🪟 Windows optimization complete!")
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
    
    return passed == total

def quick_test():
    """Run quick functionality test"""
    print("⚡ Quick NIDS Test")
    print("=" * 40)
    
    tests = [
        test_imports,
        test_configuration,
        test_network_interface,
        test_permissions
    ]
    
    passed = 0
    for test_func in tests:
        if test_func():
            passed += 1
    
    print(f"\n📊 Quick Test Results: {passed}/{len(tests)} tests passed")
    return passed == len(tests)

def main():
    """Main test function"""
    if len(sys.argv) > 1:
        if sys.argv[1] == '--quick':
            return quick_test()
        elif sys.argv[1] == '--help':
            print("NIDS Test Suite")
            print("Usage:")
            print("  python test_nids.py          # Run comprehensive tests")
            print("  python test_nids.py --quick  # Run quick tests")
            print("  python test_nids.py --help   # Show this help")
            return True
    
    return run_comprehensive_test()

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 