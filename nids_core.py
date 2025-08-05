#!/usr/bin/env python3
"""
Network Intrusion Detection System - Core Engine
Handles packet capture, analysis, and threat detection
"""

import time
import threading
import json
import logging
import os
from datetime import datetime
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP, HTTPRequest
import psutil
import colorama
from colorama import Fore, Style

# Initialize colorama for colored output
colorama.init()

class PacketAnalyzer:
    """Analyzes individual packets for suspicious patterns"""
    
    def __init__(self):
        self.suspicious_patterns = {
            'port_scan': set(),
            'syn_flood': 0,
            'large_packets': 0,
            'suspicious_ips': set()
        }
        self.packet_count = 0
        self.start_time = time.time()
    
    def analyze_packet(self, packet):
        """Analyze a single packet for suspicious activity"""
        self.packet_count += 1
        threats = []
        
        if IP in packet:
            # Basic packet analysis
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Check for suspicious IP patterns
            if self._is_suspicious_ip(src_ip):
                threats.append(f"Suspicious source IP: {src_ip}")
            
            # Check packet size
            if len(packet) > 1500:  # Large packet threshold
                self.suspicious_patterns['large_packets'] += 1
                if self.suspicious_patterns['large_packets'] > 10:
                    threats.append("Large packet flood detected")
            
            # TCP analysis
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # Port scan detection
                if dst_port in [22, 23, 80, 443, 3389, 8080]:  # Common target ports
                    self.suspicious_patterns['port_scan'].add(src_ip)
                    if len(self.suspicious_patterns['port_scan']) > 5:
                        threats.append(f"Port scan detected from {src_ip}")
                
                # SYN flood detection
                if packet[TCP].flags == 2:  # SYN flag
                    self.suspicious_patterns['syn_flood'] += 1
                    if self.suspicious_patterns['syn_flood'] > 10:  # Lowered from 50 for easier testing
                        threats.append("SYN flood attack detected")
            
            # UDP analysis
            elif UDP in packet:
                if packet[UDP].dport == 53:  # DNS
                    # Check for DNS amplification attacks
                    if len(packet) > 512:
                        threats.append("Potential DNS amplification attack")
            
            # ICMP analysis
            elif ICMP in packet:
                if packet[ICMP].type == 8:  # Echo request
                    if len(packet) > 1000:
                        threats.append("Large ICMP packet - potential ping flood")
        
        return threats
    
    def _is_suspicious_ip(self, ip):
        """Check if IP is suspicious based on patterns"""
        # Add your suspicious IP detection logic here
        suspicious_ranges = [
            "192.168.1.100",  # Example suspicious IP
            "10.0.0.50"       # Example suspicious IP
        ]
        return ip in suspicious_ranges
    
    def get_statistics(self):
        """Get current analysis statistics"""
        return {
            'packet_count': self.packet_count,
            'suspicious_patterns': dict(self.suspicious_patterns),
            'uptime': time.time() - self.start_time
        }

def get_windows_interface():
    """Get a working Windows interface for packet capture"""
    try:
        # Try to get interfaces using psutil (more reliable on Windows)
        import psutil
        interfaces = psutil.net_if_addrs()
        # Look for active interfaces with friendly names
        for interface_name in interfaces.keys():
            if interface_name.lower() not in ['loopback', 'lo']:
                try:
                    test_packets = sniff(iface=interface_name, count=1, timeout=1)
                    if test_packets:
                        return interface_name
                except:
                    continue
        # Fallback: try common interface names
        common_names = ['Ethernet', 'Wi-Fi', 'Local Area Connection', 'Wireless Network Connection']
        for name in common_names:
            try:
                test_packets = sniff(iface=name, count=1, timeout=1)
                if test_packets:
                    return name
            except:
                continue
        # If still not found, try GUID-like interfaces (auto-select first available)
        for interface_name in interfaces.keys():
            if interface_name.startswith('{') and interface_name.endswith('}'):
                try:
                    test_packets = sniff(iface=interface_name, count=1, timeout=1)
                    if test_packets is not None:
                        return interface_name
                except:
                    continue
        return None
    except Exception as e:
        print(f"Warning: Could not detect Windows interface: {e}")
        return None

class NIDSEngine:
    """Main NIDS engine for packet capture and analysis"""
    
    def __init__(self, interface=None, alert_callback=None):
        # Auto-detect interface if not specified
        if interface is None:
            if os.name == 'nt':  # Windows
                interface = get_windows_interface()
                if interface:
                    print(f"🔍 Auto-detected Windows interface: {interface}")
                else:
                    print("⚠️  Could not auto-detect Windows interface")
                    interface = "Ethernet"  # Fallback
            else:  # Unix/Linux
                available_interfaces = get_if_list()
                # Filter out loopback and use first available interface
                real_interfaces = [iface for iface in available_interfaces 
                                 if 'loopback' not in iface.lower() and 
                                 not iface.startswith('\\Device\\NPF_')]
                if real_interfaces:
                    interface = real_interfaces[0]
                    print(f"🔍 Auto-detected interface: {interface}")
                else:
                    interface = "eth0"  # Fallback
        
        self.interface = interface
        self.alert_callback = alert_callback
        self.is_running = False
        self.packet_queue = []
        self.alert_history = []
        
        # Initialize components
        self.analyzer = PacketAnalyzer()
        
        # Setup logging
        self.logger = logging.getLogger('NIDS')
        self.logger.setLevel(logging.INFO)
        
        # Create handlers
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def start_monitoring(self):
        """Start packet monitoring"""
        self.is_running = True
        self.logger.info(f"Starting NIDS monitoring on interface {self.interface}")
        
        # Start packet capture thread
        capture_thread = threading.Thread(target=self._capture_packets, daemon=True)
        capture_thread.start()
        
        # Start analysis thread
        analysis_thread = threading.Thread(target=self._analyze_packets, daemon=True)
        analysis_thread.start()
        
        print(f"[+] NIDS monitoring started on interface {self.interface}")
    
    def stop_monitoring(self):
        """Stop packet monitoring"""
        self.is_running = False
        self.logger.info("Stopping NIDS monitoring")
    
    def _capture_packets(self):
        """Capture packets from the network interface"""
        try:
            # Use a more robust packet capture method
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                store=0,
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            self.logger.error(f"Error capturing packets: {e}")
            print(f"{Fore.RED}[ERROR] Packet capture error: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[INFO] This is normal on Windows without proper interface configuration{Style.RESET_ALL}")
    
    def _packet_callback(self, packet):
        """Callback for each captured packet"""
        if self.is_running:
            self.packet_queue.append(packet)
            # Removed queue limit for unlimited packet capture
            # if len(self.packet_queue) > 1000:  # Prevent memory overflow
            #     self.packet_queue.pop(0)
    
    def _analyze_packets(self):
        """Analyze packets in the queue"""
        while self.is_running:
            if self.packet_queue:
                packet = self.packet_queue.pop(0)
                threats = self.analyzer.analyze_packet(packet)
                
                if threats:
                    self._handle_threats(threats, packet)
            
            time.sleep(0.01)  # Small delay to prevent CPU overload
    
    def _handle_threats(self, threats, packet):
        """Handle detected threats"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        for threat in threats:
            alert = {
                'timestamp': timestamp,
                'threat': threat,
                'packet_info': self._get_packet_info(packet),
                'severity': self._determine_severity(threat)
            }
            
            self.alert_history.append(alert)
            
            # Log the threat
            self.logger.warning(f"THREAT DETECTED: {threat}")
            
            # Print colored alert
            severity_color = Fore.RED if alert['severity'] == 'HIGH' else Fore.YELLOW
            print(f"{severity_color}[ALERT] {timestamp} - {threat}{Style.RESET_ALL}")
            
            # Call alert callback if provided
            if self.alert_callback:
                self.alert_callback(alert)
    
    def _get_packet_info(self, packet):
        """Extract relevant packet information"""
        info = {}
        
        if IP in packet:
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['protocol'] = packet[IP].proto
            info['length'] = len(packet)
        
        if TCP in packet:
            info['src_port'] = packet[TCP].sport
            info['dst_port'] = packet[TCP].dport
            info['flags'] = packet[TCP].flags
        
        return info
    
    def _determine_severity(self, threat):
        """Determine threat severity level"""
        high_severity_keywords = ['flood', 'attack', 'scan']
        if any(keyword in threat.lower() for keyword in high_severity_keywords):
            return 'HIGH'
        return 'MEDIUM'
    
    def get_status(self):
        """Get current NIDS status"""
        return {
            'is_running': self.is_running,
            'interface': self.interface,
            'statistics': self.analyzer.get_statistics(),
            'alert_count': len(self.alert_history),
            'queue_size': len(self.packet_queue)
        }
    
    def get_alerts(self, limit=50):
        """Get recent alerts"""
        return self.alert_history[-limit:] if self.alert_history else []

if __name__ == "__main__":
    # Example usage
    nids = NIDSEngine()
    
    try:
        nids.start_monitoring()
        time.sleep(30)  # Monitor for 30 seconds
    except KeyboardInterrupt:
        print("\nStopping NIDS...")
    finally:
        nids.stop_monitoring() 