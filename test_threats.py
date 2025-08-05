#!/usr/bin/env python3
"""
Test Threat Generator for NIDS
Generates various types of threats to test the detection system
"""

import time
import random
from scapy.all import *

def generate_port_scan(iface=None):
    """Generate a port scan attack"""
    print("🔍 Generating port scan attack...")
    
    src_ip = f"192.168.1.{random.randint(100, 200)}"
    target_ports = [22, 23, 80, 443, 3389, 8080, 21, 25, 53, 110, 143, 993, 995]
    
    for port in target_ports:
        packet = IP(src=src_ip, dst="192.168.1.1") / TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
        send(packet, iface=iface, verbose=False)
        time.sleep(0.1)
    
    print(f"✅ Port scan generated from {src_ip}")

def generate_syn_flood(iface=None):
    """Generate a SYN flood attack"""
    print("🌊 Generating SYN flood attack...")
    
    src_ip = f"10.0.0.{random.randint(50, 100)}"
    
    for i in range(60):  # Send 60 SYN packets
        packet = IP(src=src_ip, dst="192.168.1.1") / TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
        send(packet, iface=iface, verbose=False)
        time.sleep(0.05)
    
    print(f"✅ SYN flood generated from {src_ip}")

def generate_large_packets(iface=None):
    """Generate large packets"""
    print("📦 Generating large packet attack...")
    
    src_ip = f"172.16.0.{random.randint(1, 50)}"
    
    # Create large payload
    large_payload = "A" * 2000  # 2000 byte payload
    
    packet = IP(src=src_ip, dst="192.168.1.1") / TCP(sport=random.randint(1024, 65535), dport=80) / Raw(load=large_payload)
    send(packet, iface=iface, verbose=False)
    
    print(f"✅ Large packet generated from {src_ip}")

def generate_icmp_flood(iface=None):
    """Generate ICMP flood attack"""
    print("🏓 Generating ICMP flood attack...")
    
    src_ip = f"203.0.113.{random.randint(1, 100)}"
    
    for i in range(120):  # Send 120 ICMP packets
        packet = IP(src=src_ip, dst="192.168.1.1") / ICMP()
        send(packet, iface=iface, verbose=False)
        time.sleep(0.05)
    
    print(f"✅ ICMP flood generated from {src_ip}")

def generate_suspicious_ip(iface=None):
    """Generate traffic from suspicious IP"""
    print("⚠️  Generating traffic from suspicious IP...")
    
    suspicious_ips = ["192.168.1.100", "10.0.0.50"]
    src_ip = random.choice(suspicious_ips)
    
    packet = IP(src=src_ip, dst="192.168.1.1") / TCP(sport=random.randint(1024, 65535), dport=80)
    send(packet, iface=iface, verbose=False)
    
    print(f"✅ Suspicious IP traffic generated from {src_ip}")

def generate_dns_amplification(iface=None):
    """Generate DNS amplification attack"""
    print("🔍 Generating DNS amplification attack...")
    
    src_ip = f"198.51.100.{random.randint(1, 50)}"
    
    # Create large DNS query
    large_query = "A" * 1000  # Large DNS query
    packet = IP(src=src_ip, dst="8.8.8.8") / UDP(sport=random.randint(1024, 65535), dport=53) / Raw(load=large_query)
    send(packet, iface=iface, verbose=False)
    
    print(f"✅ DNS amplification attack generated from {src_ip}")

def generate_http_anomaly(iface=None):
    """Generate suspicious HTTP traffic"""
    print("🌐 Generating HTTP anomaly...")
    
    src_ip = f"192.168.1.{random.randint(200, 254)}"
    
    # Create suspicious HTTP request
    suspicious_headers = "GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n"
    packet = IP(src=src_ip, dst="192.168.1.1") / TCP(sport=random.randint(1024, 65535), dport=80) / Raw(load=suspicious_headers)
    send(packet, iface=iface, verbose=False)
    
    print(f"✅ HTTP anomaly generated from {src_ip}")

def run_all_tests(iface=None):
    """Run all threat tests"""
    print("🧪 Starting NIDS Threat Test Suite")
    print("=" * 50)
    
    tests = [
        ("Port Scan", generate_port_scan),
        ("SYN Flood", generate_syn_flood),
        ("Large Packets", generate_large_packets),
        ("ICMP Flood", generate_icmp_flood),
        ("Suspicious IP", generate_suspicious_ip),
        ("DNS Amplification", generate_dns_amplification),
        ("HTTP Anomaly", generate_http_anomaly)
    ]
    
    for test_name, test_func in tests:
        print(f"\n🎯 Testing: {test_name}")
        try:
            test_func(iface=iface)
            time.sleep(2)  # Wait between tests
        except Exception as e:
            print(f"❌ Error in {test_name}: {e}")
    
    print("\n✅ All threat tests completed!")
    print("📊 Check your dashboard for alerts: http://localhost:5000")

def run_single_test(test_type, iface=None):
    """Run a single threat test"""
    test_map = {
        'port_scan': generate_port_scan,
        'syn_flood': generate_syn_flood,
        'large_packets': generate_large_packets,
        'icmp_flood': generate_icmp_flood,
        'suspicious_ip': generate_suspicious_ip,
        'dns_amplification': generate_dns_amplification,
        'http_anomaly': generate_http_anomaly
    }
    
    if test_type in test_map:
        print(f"🎯 Running {test_type} test...")
        test_map[test_type](iface=iface)
    else:
        print(f"❌ Unknown test type: {test_type}")
        print("Available tests: " + ", ".join(test_map.keys()))

if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Test Threat Generator for NIDS")
    parser.add_argument('--test', type=str, default='all', help='Type of test to run')
    parser.add_argument('--iface', type=str, default=None, help='Network interface to use')
    args = parser.parse_args()

    if args.test == 'all':
        run_all_tests(iface=args.iface)
    else:
        run_single_test(args.test, iface=args.iface) 