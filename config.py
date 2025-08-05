#!/usr/bin/env python3
"""
Network Intrusion Detection System - Configuration
Centralized configuration management optimized for Windows
"""

import json
import os
import platform
from pathlib import Path

class NIDSConfig:
    """Configuration management for NIDS"""
    
    def __init__(self, config_file='nids_config.json'):
        self.config_file = config_file
        self.config = self._load_default_config()
        self._load_config()
    
    def _load_default_config(self):
        """Load default configuration optimized for Windows"""
        # Detect OS for appropriate defaults
        is_windows = platform.system() == 'Windows'
        
        return {
            # Network Configuration
            'network': {
                'default_interface': 'Wi-Fi' if is_windows else 'eth0',
                'promiscuous_mode': True,
                'packet_timeout': 1.0,
                'max_packet_size': 65535,
                'auto_detect_interface': True,
                'fallback_interfaces': ['Ethernet', 'Wi-Fi', 'Local Area Connection'] if is_windows else ['eth0', 'wlan0']
            },
            
            # Detection Configuration
            'detection': {
                'port_scan_threshold': 10,
                'port_scan_time_window': 60,
                'syn_flood_threshold': 50,
                'syn_flood_time_window': 30,
                'large_packet_threshold': 1500,
                'icmp_flood_threshold': 100,
                'icmp_flood_time_window': 60,
                'dns_amplification_threshold': 512,
                'suspicious_ips': [
                    '192.168.1.100',
                    '10.0.0.50'
                ],
                'windows_specific_rules': is_windows
            },
            
            # Response Configuration
            'response': {
                'auto_block_duration': 3600,  # 1 hour
                'rate_limit_window': 300,      # 5 minutes
                'rate_limit_max_requests': 100,
                'email_notifications': True,
                'email_recipient': 'admin@example.com',
                'log_responses': True,
                'windows_firewall_integration': is_windows
            },
            
            # Dashboard Configuration
            'dashboard': {
                'host': '0.0.0.0',
                'port': 5000,
                'debug': False,
                'auto_reload': False,
                'max_alerts_display': 1000,
                'update_interval': 5,  # seconds
                'browser_auto_open': is_windows,
                'windows_theme': is_windows
            },
            
            # Logging Configuration
            'logging': {
                'level': 'INFO',
                'file_logging': True,
                'console_logging': True,
                'log_rotation': True,
                'max_log_size': 10485760,  # 10MB
                'backup_count': 5,
                'log_directory': 'logs' if is_windows else '/var/log/nids',
                'windows_event_log': is_windows
            },
            
            # Performance Configuration
            'performance': {
                'packet_queue_size': 1000,
                'alert_history_size': 1000,
                'rule_evaluation_interval': 0.01,
                'statistics_update_interval': 5,
                'memory_limit_mb': 512,
                'windows_optimization': is_windows
            },
            
            # Security Configuration
            'security': {
                'require_admin_privileges': True,
                'allowed_interfaces': [],
                'blocked_networks': [],
                'whitelist_ips': [],
                'dashboard_authentication': False,
                'dashboard_username': 'admin',
                'dashboard_password': 'nids123',
                'windows_defender_integration': is_windows
            },
            
            # Advanced Configuration
            'advanced': {
                'custom_rules_file': 'custom_rules.json',
                'custom_actions_file': 'custom_actions.json',
                'backup_configuration': True,
                'auto_update_rules': True,
                'test_mode': False,
                'windows_compatibility_mode': is_windows
            },
            
            # Windows-Specific Configuration
            'windows': {
                'use_windows_firewall': True,
                'use_windows_event_log': True,
                'auto_detect_network_adapters': True,
                'preferred_interfaces': ['Wi-Fi', 'Ethernet', 'Local Area Connection'],
                'exclude_virtual_adapters': True,
                'use_npcap': True,
                'admin_privilege_check': True
            } if is_windows else {},
            
            # System Information
            'system': {
                'platform': platform.system(),
                'platform_version': platform.version(),
                'python_version': platform.python_version(),
                'architecture': platform.architecture()[0]
            }
        }
    
    def _load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                self._merge_config(file_config)
                print(f"✅ Configuration loaded from {self.config_file}")
            else:
                print(f"📝 Creating new configuration file: {self.config_file}")
                self.save_config()
        except Exception as e:
            print(f"⚠️  Error loading configuration: {e}")
            print("   Using default configuration")
    
    def _merge_config(self, file_config):
        """Merge file configuration with defaults"""
        def deep_merge(default, override):
            for key, value in override.items():
                if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                    deep_merge(default[key], value)
                else:
                    default[key] = value
        
        deep_merge(self.config, file_config)
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            # Create logs directory if it doesn't exist
            log_dir = self.config['logging']['log_directory']
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            print(f"💾 Configuration saved to {self.config_file}")
        except Exception as e:
            print(f"❌ Error saving configuration: {e}")
    
    def get(self, key, default=None):
        """Get configuration value by key (supports dot notation)"""
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key, value):
        """Set configuration value by key (supports dot notation)"""
        keys = key.split('.')
        config = self.config
        
        # Navigate to the parent of the target key
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Set the value
        config[keys[-1]] = value
    
    def get_network_config(self):
        """Get network configuration"""
        return self.config['network']
    
    def get_detection_config(self):
        """Get detection configuration"""
        return self.config['detection']
    
    def get_response_config(self):
        """Get response configuration"""
        return self.config['response']
    
    def get_dashboard_config(self):
        """Get dashboard configuration"""
        return self.config['dashboard']
    
    def get_logging_config(self):
        """Get logging configuration"""
        return self.config['logging']
    
    def get_performance_config(self):
        """Get performance configuration"""
        return self.config['performance']
    
    def get_security_config(self):
        """Get security configuration"""
        return self.config['security']
    
    def get_advanced_config(self):
        """Get advanced configuration"""
        return self.config['advanced']
    
    def get_windows_config(self):
        """Get Windows-specific configuration"""
        return self.config.get('windows', {})
    
    def update_detection_rules(self, rules):
        """Update detection rules"""
        self.config['detection'].update(rules)
        self.save_config()
    
    def update_response_actions(self, actions):
        """Update response actions"""
        self.config['response'].update(actions)
        self.save_config()
    
    def add_suspicious_ip(self, ip):
        """Add IP to suspicious list"""
        if ip not in self.config['detection']['suspicious_ips']:
            self.config['detection']['suspicious_ips'].append(ip)
            self.save_config()
    
    def remove_suspicious_ip(self, ip):
        """Remove IP from suspicious list"""
        if ip in self.config['detection']['suspicious_ips']:
            self.config['detection']['suspicious_ips'].remove(ip)
            self.save_config()
    
    def add_whitelist_ip(self, ip):
        """Add IP to whitelist"""
        if ip not in self.config['security']['whitelist_ips']:
            self.config['security']['whitelist_ips'].append(ip)
            self.save_config()
    
    def remove_whitelist_ip(self, ip):
        """Remove IP from whitelist"""
        if ip in self.config['security']['whitelist_ips']:
            self.config['security']['whitelist_ips'].remove(ip)
            self.save_config()
    
    def enable_test_mode(self):
        """Enable test mode"""
        self.config['advanced']['test_mode'] = True
        self.save_config()
    
    def disable_test_mode(self):
        """Disable test mode"""
        self.config['advanced']['test_mode'] = False
        self.save_config()
    
    def set_interface(self, interface):
        """Set default network interface"""
        self.config['network']['default_interface'] = interface
        self.save_config()
    
    def set_dashboard_port(self, port):
        """Set dashboard port"""
        self.config['dashboard']['port'] = port
        self.save_config()
    
    def enable_email_notifications(self, recipient=None):
        """Enable email notifications"""
        self.config['response']['email_notifications'] = True
        if recipient:
            self.config['response']['email_recipient'] = recipient
        self.save_config()
    
    def disable_email_notifications(self):
        """Disable email notifications"""
        self.config['response']['email_notifications'] = False
        self.save_config()
    
    def get_config_summary(self):
        """Get configuration summary"""
        return {
            'platform': self.config['system']['platform'],
            'interface': self.config['network']['default_interface'],
            'dashboard_port': self.config['dashboard']['port'],
            'test_mode': self.config['advanced']['test_mode'],
            'admin_required': self.config['security']['require_admin_privileges'],
            'windows_optimized': self.config['system']['platform'] == 'Windows'
        }
    
    def validate_config(self):
        """Validate configuration"""
        errors = []
        
        # Check required fields
        required_sections = ['network', 'detection', 'response', 'dashboard', 'logging']
        for section in required_sections:
            if section not in self.config:
                errors.append(f"Missing required section: {section}")
        
        # Check network configuration
        if 'network' in self.config:
            network = self.config['network']
            if not network.get('default_interface'):
                errors.append("No default interface specified")
        
        # Check dashboard configuration
        if 'dashboard' in self.config:
            dashboard = self.config['dashboard']
            port = dashboard.get('port', 0)
            if not (1024 <= port <= 65535):
                errors.append(f"Invalid dashboard port: {port}")
        
        # Check Windows-specific requirements
        if self.config['system']['platform'] == 'Windows':
            if not self.config.get('windows'):
                errors.append("Missing Windows-specific configuration")
        
        return errors
    
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        self.config = self._load_default_config()
        self.save_config()
        print("🔄 Configuration reset to defaults")
    
    def optimize_for_windows(self):
        """Optimize configuration for Windows"""
        if self.config['system']['platform'] == 'Windows':
            # Enable Windows-specific features
            self.config['windows']['use_windows_firewall'] = True
            self.config['windows']['use_windows_event_log'] = True
            self.config['windows']['auto_detect_network_adapters'] = True
            
            # Set Windows-friendly defaults
            self.config['network']['default_interface'] = 'Wi-Fi'
            self.config['dashboard']['browser_auto_open'] = True
            self.config['dashboard']['windows_theme'] = True
            
            self.save_config()
            print("🪟 Configuration optimized for Windows")
        else:
            print("⚠️  This system is not Windows, optimization skipped")

# Global configuration instance
config = NIDSConfig()

if __name__ == "__main__":
    # Test configuration
    print("🔧 Testing NIDS Configuration")
    print("=" * 50)
    
    # Print system info
    system_info = config.get_config_summary()
    print(f"Platform: {system_info['platform']}")
    print(f"Windows Optimized: {system_info['windows_optimized']}")
    print(f"Default Interface: {system_info['interface']}")
    print(f"Dashboard Port: {system_info['dashboard_port']}")
    
    # Validate configuration
    errors = config.validate_config()
    if errors:
        print(f"❌ Configuration errors: {errors}")
    else:
        print("✅ Configuration is valid")
    
    # Optimize for Windows if applicable
    config.optimize_for_windows() 