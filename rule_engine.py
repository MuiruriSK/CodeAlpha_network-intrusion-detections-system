#!/usr/bin/env python3
"""
Network Intrusion Detection System - Rule Engine
Handles configurable detection rules and patterns
"""

import json
import re
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict, deque

class Rule:
    """Represents a single detection rule"""
    
    def __init__(self, rule_id, name, description, conditions, action="alert", enabled=True):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.conditions = conditions
        self.action = action
        self.enabled = enabled
        self.hit_count = 0
        self.last_hit = None
    
    def to_dict(self):
        """Convert rule to dictionary"""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'conditions': self.conditions,
            'action': self.action,
            'enabled': self.enabled,
            'hit_count': self.hit_count,
            'last_hit': self.last_hit.isoformat() if self.last_hit else None
        }
    
    @classmethod
    def from_dict(cls, data):
        """Create rule from dictionary"""
        rule = cls(
            rule_id=data['rule_id'],
            name=data['name'],
            description=data['description'],
            conditions=data['conditions'],
            action=data['action'],
            enabled=data['enabled']
        )
        rule.hit_count = data.get('hit_count', 0)
        if data.get('last_hit'):
            rule.last_hit = datetime.fromisoformat(data['last_hit'])
        return rule

class RuleEngine:
    """Main rule engine for NIDS"""
    
    def __init__(self):
        self.rules = {}
        self.rule_counter = 1
        self.packet_history = deque(maxlen=10000)  # Store last 10k packets
        self.connection_tracker = defaultdict(list)
        self.load_default_rules()
    
    def load_default_rules(self):
        """Load default detection rules"""
        default_rules = [
            {
                'name': 'Port Scan Detection',
                'description': 'Detect rapid port scanning from single source',
                'conditions': {
                    'type': 'port_scan',
                    'threshold': 10,
                    'time_window': 60
                }
            },
            {
                'name': 'SYN Flood Detection',
                'description': 'Detect SYN flood attacks',
                'conditions': {
                    'type': 'syn_flood',
                    'threshold': 50,
                    'time_window': 30
                }
            },
            {
                'name': 'Large Packet Detection',
                'description': 'Detect abnormally large packets',
                'conditions': {
                    'type': 'large_packet',
                    'min_size': 1500
                }
            },
            {
                'name': 'Suspicious IP Detection',
                'description': 'Detect traffic from known suspicious IPs',
                'conditions': {
                    'type': 'suspicious_ip',
                    'ip_list': ['192.168.1.100', '10.0.0.50']
                }
            },
            {
                'name': 'DNS Amplification Detection',
                'description': 'Detect potential DNS amplification attacks',
                'conditions': {
                    'type': 'dns_amplification',
                    'min_size': 512,
                    'port': 53
                }
            },
            {
                'name': 'ICMP Flood Detection',
                'description': 'Detect ICMP ping floods',
                'conditions': {
                    'type': 'icmp_flood',
                    'threshold': 100,
                    'time_window': 60
                }
            },
            {
                'name': 'HTTP Anomaly Detection',
                'description': 'Detect suspicious HTTP traffic patterns',
                'conditions': {
                    'type': 'http_anomaly',
                    'suspicious_patterns': [
                        'admin', 'login', 'wp-admin', 'phpmyadmin'
                    ]
                }
            }
        ]
        
        for rule_data in default_rules:
            self.add_rule(rule_data)
    
    def add_rule(self, rule_data):
        """Add a new rule to the engine"""
        rule = Rule(
            rule_id=f"rule_{self.rule_counter}",
            name=rule_data['name'],
            description=rule_data['description'],
            conditions=rule_data['conditions']
        )
        self.rules[rule.rule_id] = rule
        self.rule_counter += 1
        return rule.rule_id
    
    def remove_rule(self, rule_id):
        """Remove a rule from the engine"""
        if rule_id in self.rules:
            del self.rules[rule_id]
            return True
        return False
    
    def enable_rule(self, rule_id):
        """Enable a rule"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True
            return True
        return False
    
    def disable_rule(self, rule_id):
        """Disable a rule"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False
            return True
        return False
    
    def evaluate_packet(self, packet):
        """Evaluate a packet against all enabled rules"""
        triggered_rules = []
        
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            
            if self._evaluate_rule(rule, packet):
                rule.hit_count += 1
                rule.last_hit = datetime.now()
                triggered_rules.append(rule)
        
        return triggered_rules
    
    def _evaluate_rule(self, rule, packet):
        """Evaluate a single rule against a packet"""
        conditions = rule.conditions
        rule_type = conditions.get('type')
        
        if rule_type == 'port_scan':
            return self._check_port_scan(conditions, packet)
        elif rule_type == 'syn_flood':
            return self._check_syn_flood(conditions, packet)
        elif rule_type == 'large_packet':
            return self._check_large_packet(conditions, packet)
        elif rule_type == 'suspicious_ip':
            return self._check_suspicious_ip(conditions, packet)
        elif rule_type == 'dns_amplification':
            return self._check_dns_amplification(conditions, packet)
        elif rule_type == 'icmp_flood':
            return self._check_icmp_flood(conditions, packet)
        elif rule_type == 'http_anomaly':
            return self._check_http_anomaly(conditions, packet)
        
        return False
    
    def _check_port_scan(self, conditions, packet):
        """Check for port scanning activity"""
        from scapy.layers.inet import IP, TCP
        
        if IP not in packet or TCP not in packet:
            return False
        
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        
        # Track connection attempts
        key = f"{src_ip}_scan"
        now = datetime.now()
        
        # Add current attempt
        self.connection_tracker[key].append({
            'timestamp': now,
            'port': dst_port
        })
        
        # Clean old entries
        threshold = conditions.get('threshold', 10)
        time_window = conditions.get('time_window', 60)
        cutoff_time = now - timedelta(seconds=time_window)
        
        recent_attempts = [
            entry for entry in self.connection_tracker[key]
            if entry['timestamp'] > cutoff_time
        ]
        
        # Check if threshold exceeded
        if len(recent_attempts) >= threshold:
            return True
        
        return False
    
    def _check_syn_flood(self, conditions, packet):
        """Check for SYN flood attacks"""
        from scapy.layers.inet import IP, TCP
        
        if IP not in packet or TCP not in packet:
            return False
        
        if packet[TCP].flags != 2:  # Not a SYN packet
            return False
        
        src_ip = packet[IP].src
        key = f"{src_ip}_syn"
        now = datetime.now()
        
        # Track SYN packets
        self.connection_tracker[key].append({
            'timestamp': now
        })
        
        # Clean old entries
        threshold = conditions.get('threshold', 50)
        time_window = conditions.get('time_window', 30)
        cutoff_time = now - timedelta(seconds=time_window)
        
        recent_syns = [
            entry for entry in self.connection_tracker[key]
            if entry['timestamp'] > cutoff_time
        ]
        
        if len(recent_syns) >= threshold:
            return True
        
        return False
    
    def _check_large_packet(self, conditions, packet):
        """Check for abnormally large packets"""
        min_size = conditions.get('min_size', 1500)
        return len(packet) > min_size
    
    def _check_suspicious_ip(self, conditions, packet):
        """Check for traffic from suspicious IPs"""
        from scapy.layers.inet import IP
        
        if IP not in packet:
            return False
        
        src_ip = packet[IP].src
        suspicious_ips = conditions.get('ip_list', [])
        
        return src_ip in suspicious_ips
    
    def _check_dns_amplification(self, conditions, packet):
        """Check for DNS amplification attacks"""
        from scapy.layers.inet import IP, UDP
        
        if IP not in packet or UDP not in packet:
            return False
        
        if packet[UDP].dport != conditions.get('port', 53):
            return False
        
        min_size = conditions.get('min_size', 512)
        return len(packet) > min_size
    
    def _check_icmp_flood(self, conditions, packet):
        """Check for ICMP flood attacks"""
        from scapy.layers.inet import IP, ICMP
        
        if IP not in packet or ICMP not in packet:
            return False
        
        if packet[ICMP].type != 8:  # Not an echo request
            return False
        
        src_ip = packet[IP].src
        key = f"{src_ip}_icmp"
        now = datetime.now()
        
        # Track ICMP packets
        self.connection_tracker[key].append({
            'timestamp': now
        })
        
        # Clean old entries
        threshold = conditions.get('threshold', 100)
        time_window = conditions.get('time_window', 60)
        cutoff_time = now - timedelta(seconds=time_window)
        
        recent_icmp = [
            entry for entry in self.connection_tracker[key]
            if entry['timestamp'] > cutoff_time
        ]
        
        if len(recent_icmp) >= threshold:
            return True
        
        return False
    
    def _check_http_anomaly(self, conditions, packet):
        """Check for suspicious HTTP patterns"""
        from scapy.layers.inet import IP, TCP
        
        if IP not in packet or TCP not in packet:
            return False
        
        # Check if it's HTTP traffic (port 80 or 443)
        if packet[TCP].dport not in [80, 443]:
            return False
        
        # Extract payload for pattern matching
        payload = str(packet.payload)
        suspicious_patterns = conditions.get('suspicious_patterns', [])
        
        for pattern in suspicious_patterns:
            if pattern.lower() in payload.lower():
                return True
        
        return False
    
    def get_rules(self):
        """Get all rules"""
        return {rule_id: rule.to_dict() for rule_id, rule in self.rules.items()}
    
    def get_rule_stats(self):
        """Get rule statistics"""
        stats = {
            'total_rules': len(self.rules),
            'enabled_rules': len([r for r in self.rules.values() if r.enabled]),
            'disabled_rules': len([r for r in self.rules.values() if not r.enabled]),
            'total_hits': sum(r.hit_count for r in self.rules.values()),
            'most_triggered': None
        }
        
        if self.rules:
            most_triggered = max(self.rules.values(), key=lambda x: x.hit_count)
            stats['most_triggered'] = {
                'rule_id': most_triggered.rule_id,
                'name': most_triggered.name,
                'hits': most_triggered.hit_count
            }
        
        return stats
    
    def save_rules(self, filename):
        """Save rules to file"""
        with open(filename, 'w') as f:
            json.dump(self.get_rules(), f, indent=2)
    
    def load_rules(self, filename):
        """Load rules from file"""
        try:
            with open(filename, 'r') as f:
                rules_data = json.load(f)
            
            self.rules.clear()
            for rule_id, rule_data in rules_data.items():
                self.rules[rule_id] = Rule.from_dict(rule_data)
            
            return True
        except FileNotFoundError:
            return False

if __name__ == "__main__":
    # Example usage
    engine = RuleEngine()
    
    # Print default rules
    print("Default Rules:")
    for rule_id, rule in engine.rules.items():
        print(f"  {rule_id}: {rule.name} - {rule.description}")
    
    # Get statistics
    stats = engine.get_rule_stats()
    print(f"\nRule Statistics:")
    print(f"  Total Rules: {stats['total_rules']}")
    print(f"  Enabled Rules: {stats['enabled_rules']}")
    print(f"  Total Hits: {stats['total_hits']}") 