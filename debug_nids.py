#!/usr/bin/env python3
"""
NIDS Debug Script - Identifies packet capture issues
"""

import time
import sys
import os
from scapy.all import *

def check_privileges():
    """Check if running with admin privileges"""
    print("🔐 Checking privileges...")
    
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if is_admin:
                print("✅ Running as Administrator")
            else:
                print("❌ NOT running as Administrator")
                print("   → Right-click PowerShell → 'Run as Administrator'")
            return is_admin
        except:
            print("⚠️  Could not check privileges")
            return False
    else:  # Unix/Linux
        is_root = os.geteuid() == 0
        if is_root:
            print("✅ Running as root")
        else:
            print("❌ NOT running as root")
        return is_root

def check_interfaces():
    """Check available network interfaces"""
    print("\n🌐 Checking network interfaces...")
    
    try:
        # Get Scapy interfaces
        scapy_interfaces = get_if_list()
        print(f"📡 Scapy found {len(scapy_interfaces)} interfaces:")
        for i, iface in enumerate(scapy_interfaces):
            print(f"   {i+1}. {iface}")
        
        # Test specific interfaces
        test_interfaces = ["Ethernet", "Wi-Fi", "Local Area Connection"]
        for test_iface in test_interfaces:
            if test_iface in scapy_interfaces:
                print(f"✅ '{test_iface}' found in Scapy interfaces")
            else:
                print(f"❌ '{test_iface}' NOT found in Scapy interfaces")
        
        return scapy_interfaces
        
    except Exception as e:
        print(f"❌ Error checking interfaces: {e}")
        return []

def test_packet_capture(interface="Ethernet"):
    """Test packet capture on specific interface"""
    print(f"\n🔍 Testing packet capture on '{interface}'...")
    
    try:
        print("📡 Attempting to capture 5 packets (10 second timeout)...")
        packets = sniff(iface=interface, count=5, timeout=10)
        
        if packets:
            print(f"✅ Successfully captured {len(packets)} packets!")
            for i, packet in enumerate(packets):
                if IP in packet:
                    print(f"   Packet {i+1}: {packet[IP].src} -> {packet[IP].dst}")
                else:
                    print(f"   Packet {i+1}: Non-IP packet")
        else:
            print("⚠️  No packets captured")
            print("   → This could be normal if network is quiet")
            print("   → Or interface might not be active")
            
    except Exception as e:
        print(f"❌ Packet capture error: {e}")
        if "permission" in str(e).lower():
            print("   → This is a permissions issue - run as Administrator")
        elif "interface" in str(e).lower():
            print("   → Interface not found or not accessible")
        elif "timeout" in str(e).lower():
            print("   → Timeout - interface might not be active")

def test_nids_components():
    """Test NIDS components"""
    print("\n🧪 Testing NIDS components...")
    
    try:
        # Test imports
        from nids_core import NIDSEngine
        print("✅ nids_core imports successfully")
        
        from rule_engine import RuleEngine
        print("✅ rule_engine imports successfully")
        
        from response_system import ResponseSystem
        print("✅ response_system imports successfully")
        
        from dashboard import app, socketio
        print("✅ dashboard imports successfully")
        
        # Test NIDS initialization
        nids = NIDSEngine(interface="Ethernet")
        print("✅ NIDSEngine initializes successfully")
        
        # Test rule engine
        rule_engine = RuleEngine()
        print("✅ RuleEngine initializes successfully")
        
        # Test response system
        response_system = ResponseSystem()
        print("✅ ResponseSystem initializes successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Component test error: {e}")
        return False

def main():
    """Main debug function"""
    print("🔧 NIDS Debug Script")
    print("=" * 50)
    
    # Check privileges
    has_privileges = check_privileges()
    
    # Check interfaces
    interfaces = check_interfaces()
    
    # Test components
    components_ok = test_nids_components()
    
    # Test packet capture
    if interfaces:
        test_packet_capture("Ethernet")
    
    # Summary
    print("\n📋 SUMMARY:")
    print("=" * 50)
    
    if not has_privileges:
        print("❌ MAIN ISSUE: Not running as Administrator")
        print("   → This prevents packet capture on Windows")
        print("   → Solution: Run PowerShell as Administrator")
    
    if not components_ok:
        print("❌ ISSUE: NIDS components not loading")
        print("   → Check if all dependencies are installed")
        print("   → Run: pip install -r requirements.txt")
    
    if not interfaces:
        print("❌ ISSUE: No network interfaces found")
        print("   → Check network adapter drivers")
    
    if has_privileges and components_ok and interfaces:
        print("✅ All basic checks passed!")
        print("   → Try running: python main.py --test")
        print("   → Or test with: python test_threats.py")

if __name__ == "__main__":
    main() 