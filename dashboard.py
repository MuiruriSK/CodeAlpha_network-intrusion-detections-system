#!/usr/bin/env python3
"""
Network Intrusion Detection System - Dashboard
Web-based visualization and monitoring interface optimized for Windows
"""

import json
import time
import threading
import platform
import webbrowser
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import plotly.graph_objs as go
import plotly.utils
import pandas as pd
import numpy as np

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nids_dashboard_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

class DashboardData:
    """Manages dashboard data and statistics"""
    
    def __init__(self):
        self.alerts = []
        self.packet_stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'suspicious_packets': 0
        }
        self.threat_stats = {
            'port_scan': 0,
            'syn_flood': 0,
            'large_packet': 0,
            'suspicious_ip': 0,
            'dns_amplification': 0,
            'icmp_flood': 0,
            'http_anomaly': 0
        }
        self.traffic_data = []
        self.response_stats = {
            'total_responses': 0,
            'blocked_ips': 0,
            'rate_limited': 0,
            'connections_killed': 0
        }
        self.system_info = {
            'platform': platform.system(),
            'platform_version': platform.version(),
            'python_version': platform.python_version(),
            'is_windows': platform.system() == 'Windows'
        }
    
    def add_alert(self, alert):
        """Add a new alert to the dashboard"""
        self.alerts.append(alert)
        if len(self.alerts) > 1000:  # Keep only last 1000 alerts
            self.alerts.pop(0)
        
        # Update threat statistics
        threat_type = self._extract_threat_type(alert.get('threat', ''))
        if threat_type in self.threat_stats:
            self.threat_stats[threat_type] += 1
        
        # Emit real-time update
        socketio.emit('new_alert', alert)
    
    def update_packet_stats(self, stats):
        """Update packet statistics"""
        self.packet_stats.update(stats)
        socketio.emit('packet_stats_update', self.packet_stats)
    
    def update_traffic_data(self, traffic_point):
        """Update traffic data for charts"""
        # Convert datetime to string for JSON serialization
        traffic_point['timestamp'] = traffic_point['timestamp'].isoformat()
        self.traffic_data.append(traffic_point)
        if len(self.traffic_data) > 100:  # Keep only last 100 points
            self.traffic_data.pop(0)
        
        socketio.emit('traffic_update', self.traffic_data)
    
    def update_response_stats(self, stats):
        """Update response statistics"""
        self.response_stats.update(stats)
        socketio.emit('response_stats_update', self.response_stats)
    
    def _extract_threat_type(self, threat):
        """Extract threat type from threat description"""
        threat_lower = threat.lower()
        if 'port scan' in threat_lower:
            return 'port_scan'
        elif 'syn flood' in threat_lower:
            return 'syn_flood'
        elif 'large packet' in threat_lower:
            return 'large_packet'
        elif 'suspicious ip' in threat_lower:
            return 'suspicious_ip'
        elif 'dns amplification' in threat_lower:
            return 'dns_amplification'
        elif 'icmp flood' in threat_lower:
            return 'icmp_flood'
        elif 'http' in threat_lower:
            return 'http_anomaly'
        return 'unknown'
    
    def get_dashboard_data(self):
        """Get all dashboard data"""
        return {
            'alerts': self.alerts[-50:],  # Last 50 alerts
            'packet_stats': self.packet_stats,
            'threat_stats': self.threat_stats,
            'response_stats': self.response_stats,
            'system_info': self.system_info,
            'traffic_data': self.traffic_data[-50:]  # Last 50 traffic points
        }

# Global dashboard data instance
dashboard_data = DashboardData()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html', 
                         system_info=dashboard_data.system_info,
                         is_windows=dashboard_data.system_info['is_windows'])

@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts"""
    limit = request.args.get('limit', 50, type=int)
    return jsonify(dashboard_data.alerts[-limit:])

@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    return jsonify({
        'packet_stats': dashboard_data.packet_stats,
        'threat_stats': dashboard_data.threat_stats,
        'response_stats': dashboard_data.response_stats,
        'system_info': dashboard_data.system_info
    })

@app.route('/api/charts/threats')
def get_threat_chart():
    """Get threat distribution chart data"""
    threat_stats = dashboard_data.threat_stats
    
    # Create pie chart for threat distribution
    fig = go.Figure(data=[go.Pie(
        labels=list(threat_stats.keys()),
        values=list(threat_stats.values()),
        hole=0.3,
        marker_colors=['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4', '#feca57', '#ff9ff3', '#54a0ff']
    )])
    
    fig.update_layout(
        title='Threat Distribution',
        title_x=0.5,
        height=400,
        margin=dict(l=20, r=20, t=40, b=20),
        showlegend=True
    )
    
    return jsonify(json.loads(fig.to_json()))

@app.route('/api/charts/traffic')
def get_traffic_chart():
    """Get traffic chart data"""
    if not dashboard_data.traffic_data:
        # Return empty chart if no data
        fig = go.Figure()
        fig.update_layout(
            title='Network Traffic',
            xaxis_title='Time',
            yaxis_title='Packets',
            height=400,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        return jsonify(json.loads(fig.to_json()))
    
    # Convert data for plotting
    timestamps = [point['timestamp'] for point in dashboard_data.traffic_data]
    packets = [point['packets'] for point in dashboard_data.traffic_data]
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=timestamps,
        y=packets,
        mode='lines+markers',
        name='Packets',
        line=dict(color='#4ecdc4', width=2),
        marker=dict(size=4)
    ))
    
    fig.update_layout(
        title='Network Traffic Over Time',
        xaxis_title='Time',
        yaxis_title='Packets',
        height=400,
        margin=dict(l=20, r=20, t=40, b=20),
        hovermode='x unified'
    )
    
    return jsonify(json.loads(fig.to_json()))

@app.route('/api/charts/alerts_timeline')
def get_alerts_timeline():
    """Get alerts timeline chart"""
    if not dashboard_data.alerts:
        # Return empty chart if no alerts
        fig = go.Figure()
        fig.update_layout(
            title='Alerts Timeline',
            xaxis_title='Time',
            yaxis_title='Severity',
            height=400,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        return jsonify(json.loads(fig.to_json()))
    
    # Group alerts by time
    alert_times = []
    alert_severities = []
    alert_texts = []
    
    for alert in dashboard_data.alerts[-100:]:  # Last 100 alerts
        try:
            timestamp = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
            alert_times.append(timestamp)
            
            # Convert severity to numeric for plotting
            severity_map = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
            severity = severity_map.get(alert.get('severity', 'MEDIUM'), 2)
            alert_severities.append(severity)
            
            alert_texts.append(alert.get('threat', 'Unknown threat'))
        except:
            continue
    
    if not alert_times:
        # Return empty chart if no valid alerts
        fig = go.Figure()
        fig.update_layout(
            title='Alerts Timeline',
            xaxis_title='Time',
            yaxis_title='Severity',
            height=400,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        return jsonify(json.loads(fig.to_json()))
    
    # Create scatter plot
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=alert_times,
        y=alert_severities,
        mode='markers',
        name='Alerts',
        text=alert_texts,
        hovertemplate='<b>%{text}</b><br>Time: %{x}<br>Severity: %{y}<extra></extra>',
        marker=dict(
            size=8,
            color=alert_severities,
            colorscale='RdYlBu_r',
            showscale=True,
            colorbar=dict(title='Severity')
        )
    ))
    
    fig.update_layout(
        title='Alerts Timeline',
        xaxis_title='Time',
        yaxis_title='Severity',
        height=400,
        margin=dict(l=20, r=20, t=40, b=20),
        yaxis=dict(tickmode='array', tickvals=[1, 2, 3], ticktext=['Low', 'Medium', 'High'])
    )
    
    return jsonify(json.loads(fig.to_json()))

@app.route('/api/system/info')
def get_system_info():
    """Get system information"""
    return jsonify(dashboard_data.system_info)

@app.route('/api/windows/status')
def get_windows_status():
    """Get Windows-specific status information"""
    if not dashboard_data.system_info['is_windows']:
        return jsonify({'error': 'Not a Windows system'})
    
    try:
        import psutil
        import ctypes
        
        # Check administrator privileges
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        
        # Get network interfaces
        interfaces = psutil.net_if_addrs()
        active_interfaces = [name for name, addrs in interfaces.items() 
                           if any(addr.family == 2 for addr in addrs)]
        
        return jsonify({
            'is_admin': is_admin,
            'active_interfaces': active_interfaces,
            'interface_count': len(active_interfaces),
            'platform': platform.system(),
            'platform_version': platform.version()
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print(f"Client connected: {request.sid}")
    emit('connected', {'status': 'connected', 'system_info': dashboard_data.system_info})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print(f"Client disconnected: {request.sid}")

def update_dashboard_stats():
    """Update dashboard statistics periodically"""
    while True:
        try:
            # Update traffic data with current timestamp
            current_time = datetime.now()
            traffic_point = {
                'timestamp': current_time,
                'packets': dashboard_data.packet_stats['total_packets']
            }
            dashboard_data.update_traffic_data(traffic_point)
            
            time.sleep(5)  # Update every 5 seconds
        except Exception as e:
            print(f"Error updating dashboard stats: {e}")
            time.sleep(10)

def open_dashboard_browser(port=5000):
    """Open dashboard in default browser (Windows-friendly)"""
    if dashboard_data.system_info['is_windows']:
        try:
            url = f"http://localhost:{port}"
            webbrowser.open(url)
            print(f"🌐 Opening dashboard in browser: {url}")
        except Exception as e:
            print(f"❌ Could not open browser: {e}")
            print(f"   Please manually open: http://localhost:{port}")

# Start dashboard stats update thread
stats_thread = threading.Thread(target=update_dashboard_stats, daemon=True)
stats_thread.start()

if __name__ == "__main__":
    print("🚀 Starting NIDS Dashboard")
    print("=" * 50)
    print(f"Platform: {dashboard_data.system_info['platform']}")
    print(f"Windows Optimized: {dashboard_data.system_info['is_windows']}")
    print("=" * 50)
    
    # Open browser automatically on Windows
    if dashboard_data.system_info['is_windows']:
        open_dashboard_browser()
    
    # Start the dashboard
    socketio.run(app, host='0.0.0.0', port=5000, debug=False) 