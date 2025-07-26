# Quick Start Guide

Get up and running with RedOps in minutes! This guide will walk you through your first security assessment.

## Prerequisites

- .NET 8.0 SDK installed
- RedOps cloned and built (see [Installation Guide](INSTALLATION.md))
- Network access to target systems
- Appropriate authorization for testing

## Your First Scan

### Step 1: Launch RedOps

```bash
cd RedOps
dotnet run
```

You'll see the RedOps banner and main menu.

### Step 2: Basic Host Discovery

1. Navigate: **Reconnaissance** → **Network Discovery** → **Host Discovery**
2. Enter a target: `127.0.0.1` (localhost for safe testing)
3. Watch RedOps discover live hosts

**Example Output:**
```
[12:34:56 INF] Starting host discovery for 127.0.0.1
✓ 127.0.0.1 is alive (Response time: 1ms)
[12:34:56 INF] Host discovery completed. Found 1 live hosts.
```

### Step 3: Port Scanning

1. Navigate: **Network Discovery** → **Port Scanning**
2. Enter target: `127.0.0.1`
3. Port range: `22,80,443,3000,8080` (common ports)
4. Watch the scan progress

**Example Output:**
```
[12:35:10 INF] Starting port scan for 127.0.0.1
✓ Port 22/tcp is open
✓ Port 80/tcp is open
✗ Port 443/tcp is closed
✓ Port 8080/tcp is open
[12:35:13 INF] Port scan completed. Found 3 open ports.
```

### Step 4: Service Detection

1. Navigate: **Network Discovery** → **Service Version Detection**
2. Enter target: `127.0.0.1`
3. Ports: `22,80,8080` (the open ports from step 3)
4. See detailed service information

**Example Output:**
```
[12:35:30 INF] Starting service detection for 127.0.0.1
✓ Port 22/tcp: SSH v2.0 OpenSSH_8.9p1
✓ Port 80/tcp: HTTP Apache/2.4.52
✓ Port 8080/tcp: HTTP Nginx/1.20.1
[12:35:35 INF] Service detection completed.
```

### Step 5: Network Mapping

1. Navigate: **Network Discovery** → **Network Mapping Visualization**
2. Enter range: `127.0.0.1` (single host for this example)
3. Watch the comprehensive analysis

**Example Output:**
```
Step 1: Discovering live hosts...
✓ Found 1 live hosts

Step 2: Scanning ports and detecting services...
✓ Scanned 1 hosts, found 3 services

Step 3: Performing OS fingerprinting...
✓ OS fingerprinting completed

Network Mapping Results:
┌─────────────────────────────────────────────────────────────┐
│                     Network Statistics                      │
├─────────────────────────────────────────────────────────────┤
│ Total Hosts: 1                                              │
│ Total Services: 3                                           │
│ Scan Duration: 00:00:15                                     │
└─────────────────────────────────────────────────────────────┘

Report saved to: network_map_20250124_123545.txt
```

Congratulations! You've completed your first RedOps assessment.

## Next Steps

### Try a Real Network

**Warning: Only scan networks you own or have explicit permission to test!**

1. **Small Internal Network**
   ```
   Target: 192.168.1.0/24
   Use: Network Mapping Visualization
   ```

2. **Specific Server**
   ```
   Target: Your web server IP
   Ports: 1-1000
   Include: Service detection and OS fingerprinting
   ```

### Explore Advanced Features

1. **OS Fingerprinting**
   - Navigate: **Network Discovery** → **OS Fingerprinting**
   - Try different targets to see OS detection in action

2. **Plugin System**
   - Navigate: **Plugin Management**
   - Explore available plugins and their capabilities

3. **Custom Configurations**
   - Edit `appsettings.json` to adjust scan parameters
   - Increase concurrent scans for faster results

## Common Scenarios

### Scenario 1: Web Application Assessment

```
1. Host Discovery: example.com
2. Port Scanning: 80,443,8080,8443
3. Service Detection: Identify web servers
4. OS Fingerprinting: Determine target OS
```

### Scenario 2: Internal Network Audit

```
1. Network Mapping: 192.168.1.0/24
2. Review generated report
3. Focus on interesting services
4. Detailed analysis of critical systems
```

### Scenario 3: Single Server Analysis

```
1. Port Scanning: Full range (1-65535)
2. Service Detection: All open ports
3. OS Fingerprinting: Complete analysis
4. Document findings
```

## Understanding Output

### Color Coding

- **🟢 Green**: Success, open ports, live hosts
- **🔴 Red**: Errors, closed ports, failures
- **🟡 Yellow**: Warnings, timeouts, partial results
- **🔵 Cyan**: Information, progress updates

### Log Files

RedOps automatically creates log files:
- `redops20250124.log` - Detailed application logs
- `network_map_20250124_123545.txt` - Scan reports

### Report Structure

Network mapping reports include:
```
1. Executive Summary
2. Network Statistics
3. Host Details
4. Service Information
5. OS Distribution
6. Recommendations
```

## Tips for Success

### Performance Tips

1. **Start Small**: Begin with single hosts or small ranges
2. **Adjust Concurrency**: Modify `MaxConcurrentScans` in settings
3. **Use Appropriate Timeouts**: Increase for slow networks
4. **Monitor Resources**: Watch CPU and memory usage

### Security Tips

1. **Get Authorization**: Always obtain written permission
2. **Document Everything**: Keep detailed records
3. **Respect Scope**: Stay within authorized boundaries
4. **Be Stealthy**: Use appropriate timing and intensity

### Troubleshooting Tips

1. **Check Connectivity**: Verify network access to targets
2. **Run as Admin**: Use elevated privileges when needed
3. **Check Firewalls**: Ensure RedOps isn't blocked
4. **Review Logs**: Check log files for detailed error information

## Sample Workflows

### Quick Security Check

```bash
# 1. Launch RedOps
dotnet run

# 2. Quick network discovery
Reconnaissance → Network Discovery → Network Mapping
Target: 192.168.1.0/24

# 3. Review results
Check generated report file
```

### Detailed Server Analysis

```bash
# 1. Comprehensive port scan
Network Discovery → Port Scanning
Target: server.example.com
Ports: 1-65535

# 2. Service identification
Network Discovery → Service Version Detection
Use discovered open ports

# 3. OS fingerprinting
Network Discovery → OS Fingerprinting
Same target

# 4. Generate comprehensive report
Use Network Mapping for final analysis
```

## Getting Help

If you encounter issues:

1. **Check Prerequisites**: Ensure .NET 8.0 is installed
2. **Review Permissions**: Run with appropriate privileges
3. **Check Network**: Verify connectivity to targets
4. **Read Documentation**: 
   - [Installation Guide](INSTALLATION.md)
   - [Usage Guide](USAGE.md)
   - [Troubleshooting Guide](TROUBLESHOOTING.md)

5. **Community Support**:
   - [GitHub Issues](https://github.com/benjaminlettner/RedOps/issues)
   - [Discussions](https://github.com/benjaminlettner/RedOps/discussions)

## What's Next?

After mastering the basics:

1. **Learn Advanced Features**: Explore all reconnaissance modules
2. **Develop Plugins**: Create custom functionality
3. **Integrate with Tools**: Use RedOps in your security workflow
4. **Contribute**: Help improve RedOps for the community

## Legal Reminder

⚠️ **IMPORTANT**: RedOps is designed for authorized security testing only. Always:
- Obtain explicit written permission before scanning
- Respect scope and time limitations
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

Unauthorized access to computer systems is illegal in most jurisdictions. Use RedOps responsibly and ethically.

---

**Ready to dive deeper?** Check out the [Usage Guide](USAGE.md) for comprehensive feature documentation.
