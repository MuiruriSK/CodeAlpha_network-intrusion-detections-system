# Network Intrusion Detection System (NIDS) - Windows Edition

A comprehensive, real-time network intrusion detection system optimized for Windows systems. Built with Python, it monitors network traffic, detects threats, and provides automated response mechanisms with a beautiful web-based dashboard.

## 🛡️ Features

### Core Detection Capabilities
- **Real-time Packet Monitoring**: Captures and analyzes network packets in real-time with unlimited packet capture
- **Automatic Interface Detection**: Automatically detects and selects the best network interface (Wi-Fi, Ethernet, or GUID interfaces)
- **Multiple Threat Detection**:
  - Port scanning detection
  - SYN flood attacks (detection threshold: 10 packets)
  - Large packet floods
  - Suspicious IP detection
  - DNS amplification attacks
  - ICMP flood detection
  - HTTP anomaly detection

### Windows-Specific Features
- **Automatic Interface Detection**: No need to manually specify network interfaces - works with friendly names and GUID interfaces
- **Windows Firewall Integration**: Leverage Windows Firewall for threat response
- **Windows Event Log Integration**: Log security events to Windows Event Log
- **Administrator Privilege Detection**: Automatic detection and warnings
- **Windows Theme Support**: Native Windows UI styling
- **Browser Auto-Launch**: Automatically opens dashboard in default browser

### Rule Engine
- **Configurable Detection Rules**: Easy-to-configure rules for threat detection
- **Custom Rule Support**: Add your own detection patterns
- **Rule Statistics**: Track rule performance and hit counts
- **Rule Management**: Enable/disable rules dynamically

### Response System
- **Automated Responses**: Immediate threat response actions
- **IP Blocking**: Automatic blocking of suspicious IPs
- **Rate Limiting**: Apply rate limits to prevent abuse
- **Connection Termination**: Kill suspicious connections
- **Email Alerts**: Send notifications for detected threats
- **Logging**: Comprehensive alert logging

### Web Dashboard
- **Real-time Monitoring**: Live updates of network activity
- **Interactive Charts**: Visual representation of threats and traffic
- **Alert Management**: View and manage detected alerts
- **Statistics Dashboard**: Comprehensive system statistics
- **Windows System Information**: Display Windows-specific system details
- **Responsive Design**: Works on desktop and mobile devices

## 📋 Requirements

### System Requirements
- **Operating System**: Windows 10/11 (64-bit)
- **Python**: Python 3.7 or higher
- **Administrator Privileges**: Required for packet capture functionality
- **Network Interface**: Active Wi-Fi or Ethernet connection
- **Npcap/WinPcap**: For enhanced packet capture capabilities

### Windows-Specific Requirements
- **Windows Defender**: Compatible with Windows Defender (not required)
- **Windows Firewall**: Can integrate with Windows Firewall for responses
- **PowerShell**: For advanced configuration and management

## 🚀 Installation

### 1. Clone the Repository
```powershell
git clone <repository-url>
cd "Network Intrusion Detection System"
```

### 2. Create Virtual Environment (Recommended)
```powershell
python -m venv nids_env
nids_env\Scripts\Activate.ps1
```

### 3. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 4. Verify Installation
```powershell
python debug_nids.py
```

## 🎯 Usage

### Basic Usage

#### Start NIDS with Auto-Detection (Recommended)
```powershell
# Run as Administrator
python main.py
```

#### Debug System and Check Interfaces
```powershell
# Verify Windows compatibility, privileges, and interfaces
python debug_nids.py
```

#### List Available Network Interfaces
```powershell
# See all available network interfaces
python main.py --list-interfaces
```

#### Test Mode (Simulated Traffic)
```powershell
# Run with test traffic generation
python main.py --test
```

### Advanced Usage

#### Custom Dashboard Port
```powershell
# Use custom port for dashboard
python main.py -p 8080
```

#### Specify Network Interface
```powershell
# Monitor specific interface (if auto-detection fails)
python main.py -i "Wi-Fi"
```

#### Generate Test Threats
```powershell
# Test threat detection capabilities with specific interface
python test_threats.py --test syn_flood --iface "Wi-Fi"
python test_threats.py --test port_scan --iface "Wi-Fi"
python test_threats.py --test all --iface "Wi-Fi"

# Or let it auto-detect interface
python test_threats.py --test syn_flood
```

## 🖥️ Dashboard Access

### Automatic Browser Launch
The dashboard automatically opens in your default browser when you start NIDS on Windows.

### Manual Access
If the browser doesn't open automatically, manually navigate to:
```
http://localhost:5000
```

### Dashboard Features
- **Real-time Statistics**: Live packet and threat statistics
- **Interactive Charts**: Threat distribution and traffic visualization
- **Windows System Info**: Platform, version, and privilege information
- **Alert Timeline**: Visual timeline of detected threats
- **Response Actions**: Track automated response executions

## ⚙️ Configuration

### Windows-Specific Configuration
The system automatically detects and optimizes for Windows:
- **Interface Detection**: Automatically finds Wi-Fi, Ethernet, and GUID interfaces
- **Privilege Checking**: Verifies administrator privileges
- **Windows Integration**: Enables Windows Firewall and Event Log features

### Configuration Files
- `nids_config.json`: Main configuration file
- `nids_rules.json`: Detection rules configuration
- `nids_actions.json`: Response actions configuration

### Customization
```powershell
# Edit configuration files
notepad nids_config.json
notepad nids_rules.json
notepad nids_actions.json
```

## 🔧 Troubleshooting

### Common Windows Issues

#### Administrator Privileges Required
**Problem**: "Error opening adapter" or packet capture fails
**Solution**: Run PowerShell as Administrator

#### Interface Detection Issues
**Problem**: No interfaces detected or wrong interface selected
**Solution**: 
1. Run `python debug_nids.py` to check available interfaces
2. Check network adapter status in Windows
3. Manually specify interface: `python main.py -i "Wi-Fi"`

#### Threat Generator Interface Issues
**Problem**: Threats not appearing in dashboard
**Solution**:
1. Use the same interface for both NIDS and threat generator
2. Check the interface name printed by NIDS at startup
3. Use: `python test_threats.py --test syn_flood --iface "INTERFACE_NAME"`

#### Firewall Blocking
**Problem**: Dashboard not accessible
**Solution**: 
1. Allow Python through Windows Firewall
2. Check if port 5000 is available
3. Try different port: `python main.py -p 8080`

#### Missing Dependencies
**Problem**: Import errors
**Solution**: 
1. Activate virtual environment: `nids_env\Scripts\Activate.ps1`
2. Reinstall dependencies: `pip install -r requirements.txt`

### Performance Optimization

#### Windows Performance Tips
1. **Run as Administrator**: Ensures full packet capture capabilities
2. **Close Unnecessary Applications**: Free up system resources
3. **Use Wired Connection**: Ethernet provides more stable monitoring
4. **Unlimited Packet Capture**: System now captures unlimited packets (monitor memory usage)

## 📊 Monitoring and Alerts

### Real-time Monitoring
- **Packet Statistics**: Total, TCP, UDP, ICMP packet counts
- **Threat Detection**: Port scans, floods, suspicious IPs
- **Response Actions**: Blocked IPs, rate limiting, connections killed

### Alert Types
- **High Severity**: Port scans, SYN floods, DNS amplification
- **Medium Severity**: Large packets, suspicious IPs
- **Low Severity**: ICMP floods, HTTP anomalies

### Alert Response
- **Automatic Blocking**: Suspicious IPs are automatically blocked
- **Rate Limiting**: Apply temporary rate limits
- **Connection Termination**: Kill suspicious connections
- **Email Notifications**: Send alerts via email (if configured)

## 🔒 Security Considerations

### Windows Security
- **Administrator Privileges**: Required for packet capture
- **Windows Defender**: Compatible and non-conflicting
- **Firewall Integration**: Can use Windows Firewall for responses
- **Event Logging**: Security events logged to Windows Event Log

### Network Security
- **Local Monitoring**: Only monitors local network traffic
- **No Data Collection**: No personal data is collected or transmitted
- **Configurable Rules**: Customize detection sensitivity
- **Whitelist Support**: Add trusted IPs to whitelist

## 📝 Logging

### Log Files
- `nids.log`: Main application log
- `alerts.log`: Threat detection alerts
- `response_system.log`: Response action logs

### Windows Event Log
Security events are automatically logged to Windows Event Log for integration with existing security tools.

## 🤝 Contributing

### Windows-Specific Contributions
We welcome contributions, especially for Windows-specific features:
- Windows Firewall integration improvements
- Windows Event Log enhancements
- Interface detection optimizations
- Windows UI/UX improvements

### Development Setup
```powershell
# Clone repository
git clone <repository-url>
cd "Network Intrusion Detection System"

# Create virtual environment
python -m venv nids_env
nids_env\Scripts\Activate.ps1

# Install development dependencies
pip install -r requirements.txt

# Run tests
python test_nids.py
python test_threats.py --test all
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

### Windows Support
For Windows-specific issues:
1. Check the troubleshooting section above
2. Verify administrator privileges
3. Test with `python debug_nids.py`
4. Review Windows Event Log for errors

### General Support
- **Documentation**: Check this README and inline code comments
- **Issues**: Report issues on the project repository
- **Testing**: Use `python test_nids.py` to verify functionality
- **Debugging**: Use `python debug_nids.py` for system diagnostics

---

**Note**: This NIDS is optimized for Windows systems and provides enhanced Windows integration features while maintaining compatibility with other operating systems. The system now features automatic interface detection, unlimited packet capture, and improved threat detection thresholds for better testing and monitoring capabilities. 