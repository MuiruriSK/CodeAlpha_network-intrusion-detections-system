#!/usr/bin/env python3
"""
Network Intrusion Detection System - Main Application
Integrates all NIDS components and provides unified interface
Optimized for Windows systems
"""

import time
import threading
import argparse
import signal
import sys
import os
from datetime import datetime
from nids_core import NIDSEngine
from rule_engine import RuleEngine
from response_system import ResponseSystem
from dashboard import app, socketio, dashboard_data

class NIDSApplication:
    """Main NIDS application that coordinates all components"""
    
    def __init__(self, interface=None, dashboard_port=5000):
        self.interface = interface
        self.dashboard_port = dashboard_port
        self.is_running = False
        
        # Initialize components
        self.rule_engine = RuleEngine()
        self.response_system = ResponseSystem()
        self.nids_engine = NIDSEngine(interface=interface, alert_callback=self._handle_alert)
        
        # Statistics
        self.stats = {
            'start_time': None,
            'total_alerts': 0,
            'total_packets': 0,
            'total_responses': 0
        }
        
        # Setup signal handlers (Windows compatible)
        try:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        except (AttributeError, OSError):
            # Windows doesn't support SIGTERM
            pass
    
    def start(self):
        """Start the NIDS application"""
        print("=" * 70)
        print("🚀 Starting Network Intrusion Detection System for Windows")
        print("=" * 70)
        
        self.is_running = True
        self.stats['start_time'] = datetime.now()
        
        # Start NIDS monitoring
        print(f"📡 Starting packet monitoring on interface: {self.interface}")
        self.nids_engine.start_monitoring()
        
        # Start dashboard in a separate thread
        print(f"🌐 Starting dashboard on port: {self.dashboard_port}")
        dashboard_thread = threading.Thread(target=self._start_dashboard, daemon=True)
        dashboard_thread.start()
        
        # Start statistics update thread
        stats_thread = threading.Thread(target=self._update_statistics, daemon=True)
        stats_thread.start()
        
        print("\n✅ NIDS is now running!")
        print(f"📊 Dashboard available at: http://localhost:{self.dashboard_port}")
        print("🛑 Press Ctrl+C to stop")
        print("-" * 70)
        
        try:
            while self.is_running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop the NIDS application"""
        print("\n🛑 Stopping NIDS...")
        self.is_running = False
        
        # Stop NIDS engine
        self.nids_engine.stop_monitoring()
        
        # Save configuration
        self._save_configuration()
        
        print("✅ NIDS stopped successfully")
        sys.exit(0)
    
    def _handle_alert(self, alert):
        """Handle alerts from the NIDS engine"""
        self.stats['total_alerts'] += 1
        
        # Update dashboard
        dashboard_data.add_alert(alert)
        
        # Execute response actions
        executed_actions = self.response_system.execute_response(alert)
        self.stats['total_responses'] += len(executed_actions)
        
        # Print alert information
        severity_color = "🔴" if alert['severity'] == 'HIGH' else "🟡"
        print(f"{severity_color} ALERT: {alert['threat']}")
        print(f"   📍 Source: {alert.get('packet_info', {}).get('src_ip', 'Unknown')}")
        print(f"   🎯 Actions: {len(executed_actions)} executed")
    
    def _start_dashboard(self):
        """Start the dashboard server"""
        try:
            socketio.run(app, host='0.0.0.0', port=self.dashboard_port, debug=False)
        except Exception as e:
            print(f"❌ Error starting dashboard: {e}")
    
    def _update_statistics(self):
        """Update statistics periodically"""
        while self.is_running:
            try:
                # Get NIDS status
                nids_status = self.nids_engine.get_status()
                
                # Update packet statistics
                packet_stats = nids_status['statistics']
                dashboard_data.update_packet_stats({
                    'total_packets': packet_stats['packet_count'],
                    'tcp_packets': packet_stats['packet_count'] // 3,  # Simulated
                    'udp_packets': packet_stats['packet_count'] // 4,  # Simulated
                    'icmp_packets': packet_stats['packet_count'] // 10,  # Simulated
                    'suspicious_packets': len(self.nids_engine.get_alerts())
                })
                
                # Update response statistics
                response_stats = self.response_system.get_action_stats()
                dashboard_data.update_response_stats({
                    'total_responses': response_stats['total_executions'],
                    'blocked_ips': response_stats['blocked_ips'],
                    'rate_limited': response_stats['total_executions'] // 2,  # Simulated
                    'connections_killed': response_stats['total_executions'] // 4  # Simulated
                })
                
                time.sleep(5)  # Update every 5 seconds
                
            except Exception as e:
                print(f"❌ Error updating statistics: {e}")
                time.sleep(10)
    
    def _save_configuration(self):
        """Save current configuration"""
        try:
            # Save rules
            self.rule_engine.save_rules('nids_rules.json')
            
            # Save response actions
            self.response_system.save_actions('nids_actions.json')
            
            print("💾 Configuration saved")
        except Exception as e:
            print(f"❌ Error saving configuration: {e}")
    
    def _signal_handler(self, signum, frame):
        """Handle system signals"""
        print(f"\n📡 Received signal {signum}")
        self.stop()
    
    def get_status(self):
        """Get current application status"""
        uptime = datetime.now() - self.stats['start_time'] if self.stats['start_time'] else None
        
        return {
            'is_running': self.is_running,
            'interface': self.interface,
            'uptime': str(uptime) if uptime else None,
            'total_alerts': self.stats['total_alerts'],
            'total_packets': self.nids_engine.get_status()['statistics']['packet_count'],
            'total_responses': self.stats['total_responses'],
            'dashboard_url': f"http://localhost:{self.dashboard_port}"
        }

def print_banner():
    """Print application banner optimized for Windows"""
    banner = """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║                    🛡️  NIDS - Network Intrusion Detection System        ║
    ║                              Windows Edition                             ║
    ║                                                                          ║
    ║  Features:                                                              ║
    ║  • Real-time packet monitoring on Windows networks                     ║
    ║  • Automatic interface detection for Wi-Fi and Ethernet               ║
    ║  • Configurable detection rules                                        ║
    ║  • Automated threat response                                           ║
    ║  • Web-based dashboard accessible via browser                          ║
    ║  • Threat visualization and real-time alerts                          ║
    ║                                                                          ║
    ║  Requirements:                                                          ║
    ║  • Administrator privileges (recommended)                              ║
    ║  • Active network connection                                           ║
    ║  • Windows 10/11 compatible                                            ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_windows_requirements():
    """Check Windows-specific requirements"""
    print("🔍 Checking Windows system requirements...")
    
    # Check OS
    if os.name != 'nt':
        print("⚠️  This system is optimized for Windows")
        return False
    
    # Check administrator privileges
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("⚠️  Warning: Running without administrator privileges")
            print("   Some features may not work properly")
            print("   Consider running as Administrator for full functionality")
        else:
            print("✅ Running with administrator privileges")
    except:
        print("⚠️  Could not verify administrator privileges")
    
    # Check network interfaces
    try:
        import psutil
        interfaces = psutil.net_if_addrs()
        active_interfaces = [name for name, addrs in interfaces.items() 
                           if any(addr.family == 2 for addr in addrs)]  # IPv4
        if active_interfaces:
            print(f"✅ Found {len(active_interfaces)} active network interfaces")
        else:
            print("⚠️  No active network interfaces found")
    except ImportError:
        print("⚠️  psutil not available, cannot check network interfaces")
    
    return True

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Network Intrusion Detection System - Windows Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Start with auto-detected interface
  python main.py --test            # Start with test traffic
  python main.py --list-interfaces # List available interfaces
  python main.py -p 8080           # Use custom port 8080
        """
    )
    parser.add_argument('-i', '--interface', default=None, 
                       help='Network interface to monitor (auto-detected if not specified)')
    parser.add_argument('-p', '--port', type=int, default=5000,
                       help='Dashboard port (default: 5000)')
    parser.add_argument('--list-interfaces', action='store_true',
                       help='List available network interfaces')
    parser.add_argument('--test', action='store_true',
                       help='Run in test mode with simulated traffic')
    parser.add_argument('--check-system', action='store_true',
                       help='Check system requirements and exit')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Check system requirements
    if args.check_system:
        check_windows_requirements()
        return
    
    # Check Windows requirements
    check_windows_requirements()
    
    # List interfaces if requested
    if args.list_interfaces:
        print("\n📡 Available network interfaces:")
        try:
            import psutil
            interfaces = psutil.net_if_addrs()
            for i, (interface, addrs) in enumerate(interfaces.items(), 1):
                ip_addrs = [addr.address for addr in addrs if addr.family == 2]  # IPv4
                ip_str = f" ({', '.join(ip_addrs)})" if ip_addrs else ""
                print(f"   {i}. {interface}{ip_str}")
        except ImportError:
            print("   ❌ psutil not available, cannot list interfaces")
        return
    
    # Create and start NIDS application
    try:
        nids = NIDSApplication(interface=args.interface, dashboard_port=args.port)
        
        if args.test:
            print("🧪 Running in test mode with simulated traffic")
            # Start test traffic generator
            test_thread = threading.Thread(target=generate_test_traffic, daemon=True)
            test_thread.start()
        
        nids.start()
        
    except KeyboardInterrupt:
        print("\n🛑 NIDS stopped by user")
    except Exception as e:
        print(f"❌ Error starting NIDS: {e}")
        sys.exit(1)

def generate_test_traffic():
    """Generate test traffic for demonstration"""
    import random
    from scapy.all import IP, TCP, UDP, ICMP, send
    
    print("🧪 Generating test traffic...")
    
    while True:
        try:
            # Generate random packets
            src_ip = f"192.168.1.{random.randint(1, 254)}"
            dst_ip = f"192.168.1.{random.randint(1, 254)}"
            
            # Random packet type
            packet_type = random.choice(['tcp', 'udp', 'icmp'])
            
            if packet_type == 'tcp':
                packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=random.randint(1, 65535))
            elif packet_type == 'udp':
                packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024, 65535), dport=random.randint(1, 65535))
            else:
                packet = IP(src=src_ip, dst=dst_ip) / ICMP()
            
            send(packet, verbose=False)
            time.sleep(random.uniform(0.1, 1.0))
            
        except Exception as e:
            print(f"❌ Error generating test traffic: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main() 