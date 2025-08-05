#!/usr/bin/env python3
"""
Network Intrusion Detection System - Response System
Handles automated threat response mechanisms
"""

import time
import threading
import subprocess
import platform
import logging
from datetime import datetime
from collections import defaultdict, deque
import json

class ResponseAction:
    """Represents a response action"""
    
    def __init__(self, action_id, name, description, action_type, parameters=None):
        self.action_id = action_id
        self.name = name
        self.description = description
        self.action_type = action_type
        self.parameters = parameters or {}
        self.execution_count = 0
        self.last_executed = None
    
    def to_dict(self):
        """Convert action to dictionary"""
        return {
            'action_id': self.action_id,
            'name': self.name,
            'description': self.description,
            'action_type': self.action_type,
            'parameters': self.parameters,
            'execution_count': self.execution_count,
            'last_executed': self.last_executed.isoformat() if self.last_executed else None
        }

class ResponseSystem:
    """Main response system for NIDS"""
    
    def __init__(self):
        self.actions = {}
        self.action_counter = 1
        self.response_history = deque(maxlen=1000)
        self.blocked_ips = set()
        self.rate_limits = defaultdict(list)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('response_system.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        self.load_default_actions()
    
    def load_default_actions(self):
        """Load default response actions"""
        default_actions = [
            {
                'name': 'Block IP',
                'description': 'Block suspicious IP address',
                'action_type': 'block_ip',
                'parameters': {
                    'duration': 3600  # 1 hour
                }
            },
            {
                'name': 'Log Alert',
                'description': 'Log the alert for analysis',
                'action_type': 'log_alert',
                'parameters': {}
            },
            {
                'name': 'Send Email Alert',
                'description': 'Send email notification',
                'action_type': 'email_alert',
                'parameters': {
                    'recipient': 'admin@example.com'
                }
            },
            {
                'name': 'Rate Limit',
                'description': 'Apply rate limiting to source',
                'action_type': 'rate_limit',
                'parameters': {
                    'window': 300,  # 5 minutes
                    'max_requests': 100
                }
            },
            {
                'name': 'Kill Connection',
                'description': 'Terminate suspicious connection',
                'action_type': 'kill_connection',
                'parameters': {}
            },
            {
                'name': 'Increase Monitoring',
                'description': 'Increase monitoring level for source',
                'action_type': 'increase_monitoring',
                'parameters': {
                    'duration': 1800  # 30 minutes
                }
            }
        ]
        
        for action_data in default_actions:
            self.add_action(action_data)
    
    def add_action(self, action_data):
        """Add a new response action"""
        action = ResponseAction(
            action_id=f"action_{self.action_counter}",
            name=action_data['name'],
            description=action_data['description'],
            action_type=action_data['action_type'],
            parameters=action_data.get('parameters', {})
        )
        self.actions[action.action_id] = action
        self.action_counter += 1
        return action.action_id
    
    def remove_action(self, action_id):
        """Remove a response action"""
        if action_id in self.actions:
            del self.actions[action_id]
            return True
        return False
    
    def execute_response(self, alert, action_ids=None):
        """Execute response actions for an alert"""
        if action_ids is None:
            # Use default actions based on severity
            if alert.get('severity') == 'HIGH':
                action_ids = ['action_1', 'action_2', 'action_3']  # Block, Log, Email
            else:
                action_ids = ['action_2', 'action_4']  # Log, Rate Limit
        
        executed_actions = []
        
        for action_id in action_ids:
            if action_id in self.actions:
                action = self.actions[action_id]
                success = self._execute_action(action, alert)
                
                if success:
                    action.execution_count += 1
                    action.last_executed = datetime.now()
                    executed_actions.append(action)
                    
                    # Log the response
                    self.logger.info(f"Response executed: {action.name} for alert: {alert.get('threat')}")
        
        # Record response in history
        response_record = {
            'timestamp': datetime.now(),
            'alert': alert,
            'executed_actions': [a.to_dict() for a in executed_actions]
        }
        self.response_history.append(response_record)
        
        return executed_actions
    
    def _execute_action(self, action, alert):
        """Execute a single response action"""
        try:
            if action.action_type == 'block_ip':
                return self._block_ip(action, alert)
            elif action.action_type == 'log_alert':
                return self._log_alert(action, alert)
            elif action.action_type == 'email_alert':
                return self._send_email_alert(action, alert)
            elif action.action_type == 'rate_limit':
                return self._apply_rate_limit(action, alert)
            elif action.action_type == 'kill_connection':
                return self._kill_connection(action, alert)
            elif action.action_type == 'increase_monitoring':
                return self._increase_monitoring(action, alert)
            else:
                self.logger.warning(f"Unknown action type: {action.action_type}")
                return False
        except Exception as e:
            self.logger.error(f"Error executing action {action.name}: {e}")
            return False
    
    def _block_ip(self, action, alert):
        """Block an IP address"""
        packet_info = alert.get('packet_info', {})
        src_ip = packet_info.get('src_ip')
        
        if not src_ip:
            return False
        
        # Add to blocked IPs set
        self.blocked_ips.add(src_ip)
        
        # Execute system-specific blocking command
        duration = action.parameters.get('duration', 3600)
        
        if platform.system() == 'Windows':
            # Windows firewall blocking
            cmd = f'netsh advfirewall firewall add rule name="NIDS_BLOCK_{src_ip}" dir=in action=block remoteip={src_ip}'
        else:
            # Linux iptables blocking
            cmd = f'iptables -A INPUT -s {src_ip} -j DROP'
        
        try:
            subprocess.run(cmd, shell=True, check=True, timeout=10)
            self.logger.info(f"Blocked IP: {src_ip} for {duration} seconds")
            return True
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout blocking IP: {src_ip}")
            return False
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error blocking IP {src_ip}: {e}")
            return False
    
    def _log_alert(self, action, alert):
        """Log the alert for analysis"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'alert': alert,
            'action': 'logged'
        }
        
        # Write to alert log file
        with open('alerts.log', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        self.logger.info(f"Alert logged: {alert.get('threat')}")
        return True
    
    def _send_email_alert(self, action, alert):
        """Send email alert"""
        # This is a simplified email implementation
        # In production, you'd use a proper email library like smtplib
        
        recipient = action.parameters.get('recipient', 'admin@example.com')
        subject = f"NIDS Alert: {alert.get('threat')}"
        body = f"""
        NIDS Alert Detected:
        
        Threat: {alert.get('threat')}
        Timestamp: {alert.get('timestamp')}
        Severity: {alert.get('severity')}
        Source IP: {alert.get('packet_info', {}).get('src_ip', 'Unknown')}
        
        This is an automated alert from the Network Intrusion Detection System.
        """
        
        # For demonstration, we'll just log the email
        self.logger.info(f"Email alert would be sent to {recipient}: {subject}")
        
        # In a real implementation, you would send the actual email here
        # import smtplib
        # from email.mime.text import MIMEText
        # msg = MIMEText(body)
        # msg['Subject'] = subject
        # msg['From'] = 'nids@example.com'
        # msg['To'] = recipient
        # s = smtplib.SMTP('localhost')
        # s.send_message(msg)
        # s.quit()
        
        return True
    
    def _apply_rate_limit(self, action, alert):
        """Apply rate limiting to source"""
        packet_info = alert.get('packet_info', {})
        src_ip = packet_info.get('src_ip')
        
        if not src_ip:
            return False
        
        window = action.parameters.get('window', 300)
        max_requests = action.parameters.get('max_requests', 100)
        
        now = datetime.now()
        
        # Clean old entries
        cutoff_time = now.timestamp() - window
        self.rate_limits[src_ip] = [
            timestamp for timestamp in self.rate_limits[src_ip]
            if timestamp > cutoff_time
        ]
        
        # Add current request
        self.rate_limits[src_ip].append(now.timestamp())
        
        # Check if rate limit exceeded
        if len(self.rate_limits[src_ip]) > max_requests:
            self.logger.warning(f"Rate limit exceeded for {src_ip}")
            return True
        
        return True
    
    def _kill_connection(self, action, alert):
        """Kill suspicious connection"""
        packet_info = alert.get('packet_info', {})
        src_ip = packet_info.get('src_ip')
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        
        if not src_ip:
            return False
        
        # Kill connection using system commands
        if platform.system() == 'Windows':
            # Windows: use netstat and taskkill
            cmd = f'for /f "tokens=5" %a in (\'netstat -an ^| find "{src_ip}"\') do taskkill /PID %a /F'
        else:
            # Linux: use ss and kill
            cmd = f'ss -t state established | grep "{src_ip}" | awk \'{{print $4}}\' | cut -d: -f2 | xargs -I {{}} kill {{}}'
        
        try:
            subprocess.run(cmd, shell=True, check=True, timeout=10)
            self.logger.info(f"Killed connection from {src_ip}")
            return True
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout killing connection from {src_ip}")
            return False
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error killing connection from {src_ip}: {e}")
            return False
    
    def _increase_monitoring(self, action, alert):
        """Increase monitoring level for source"""
        packet_info = alert.get('packet_info', {})
        src_ip = packet_info.get('src_ip')
        duration = action.parameters.get('duration', 1800)
        
        if not src_ip:
            return False
        
        # In a real implementation, this would modify monitoring parameters
        # For now, we'll just log the action
        self.logger.info(f"Increased monitoring for {src_ip} for {duration} seconds")
        return True
    
    def is_ip_blocked(self, ip):
        """Check if an IP is currently blocked"""
        return ip in self.blocked_ips
    
    def unblock_ip(self, ip):
        """Unblock an IP address"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            
            # Remove from system firewall
            if platform.system() == 'Windows':
                cmd = f'netsh advfirewall firewall delete rule name="NIDS_BLOCK_{ip}"'
            else:
                cmd = f'iptables -D INPUT -s {ip} -j DROP'
            
            try:
                subprocess.run(cmd, shell=True, check=True, timeout=10)
                self.logger.info(f"Unblocked IP: {ip}")
                return True
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Error unblocking IP {ip}: {e}")
                return False
        
        return False
    
    def get_response_history(self, limit=50):
        """Get recent response history"""
        return list(self.response_history)[-limit:] if self.response_history else []
    
    def get_action_stats(self):
        """Get action statistics"""
        stats = {
            'total_actions': len(self.actions),
            'total_executions': sum(a.execution_count for a in self.actions.values()),
            'blocked_ips': len(self.blocked_ips),
            'most_executed': None
        }
        
        if self.actions:
            most_executed = max(self.actions.values(), key=lambda x: x.execution_count)
            stats['most_executed'] = {
                'action_id': most_executed.action_id,
                'name': most_executed.name,
                'executions': most_executed.execution_count
            }
        
        return stats
    
    def save_actions(self, filename):
        """Save actions to file"""
        with open(filename, 'w') as f:
            json.dump({aid: action.to_dict() for aid, action in self.actions.items()}, f, indent=2)
    
    def load_actions(self, filename):
        """Load actions from file"""
        try:
            with open(filename, 'r') as f:
                actions_data = json.load(f)
            
            self.actions.clear()
            for action_id, action_data in actions_data.items():
                action = ResponseAction(
                    action_id=action_data['action_id'],
                    name=action_data['name'],
                    description=action_data['description'],
                    action_type=action_data['action_type'],
                    parameters=action_data.get('parameters', {})
                )
                action.execution_count = action_data.get('execution_count', 0)
                if action_data.get('last_executed'):
                    action.last_executed = datetime.fromisoformat(action_data['last_executed'])
                self.actions[action_id] = action
            
            return True
        except FileNotFoundError:
            return False

if __name__ == "__main__":
    # Example usage
    response_system = ResponseSystem()
    
    # Print default actions
    print("Default Response Actions:")
    for action_id, action in response_system.actions.items():
        print(f"  {action_id}: {action.name} - {action.description}")
    
    # Get statistics
    stats = response_system.get_action_stats()
    print(f"\nResponse System Statistics:")
    print(f"  Total Actions: {stats['total_actions']}")
    print(f"  Total Executions: {stats['total_executions']}")
    print(f"  Blocked IPs: {stats['blocked_ips']}") 