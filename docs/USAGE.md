# Usage Guide

This comprehensive guide covers how to use RedOps effectively for penetration testing and security assessments.

## Getting Started

### Launching RedOps

```bash
cd RedOps
dotnet run
```

You'll be greeted with the RedOps banner and main menu:

```
██████╗ ███████╗██████╗  ██████╗ ██████╗ ███████╗
██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔════╝
██████╔╝█████╗  ██║  ██║██║   ██║██████╔╝███████╗
██╔══██╗██╔══╝  ██║  ██║██║   ██║██╔═══╝ ╚════██║
██║  ██║███████╗██████╔╝╚██████╔╝██║     ███████║
╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚═╝     ╚══════╝
```

### Navigation

- Use **arrow keys** to navigate menus
- Press **Enter** to select options
- Press **Escape** or **Ctrl+C** to go back or exit
- Follow the color-coded interface (red theme)

## Core Features

### 1. Reconnaissance

The reconnaissance phase is the foundation of any security assessment. RedOps provides comprehensive tools for information gathering.

#### 1.1 Network Discovery

**Host Discovery**
- Discovers live hosts on a network using ICMP ping and ARP requests
- Supports single IPs, IP ranges, and CIDR notation

```
Example inputs:
- Single IP: 192.168.1.1
- IP Range: 192.168.1.1-192.168.1.254
- CIDR: 192.168.1.0/24
- Multiple targets: 192.168.1.1,192.168.1.10,192.168.1.20
```

**Port Scanning**
- Advanced TCP and UDP port scanning
- Supports custom port ranges and common port sets
- Concurrent scanning for improved performance

```
Port range examples:
- Single port: 80
- Port range: 1-1000
- Specific ports: 22,80,443,8080
- Common ports: (uses predefined list)
```

**Service Version Detection**
- Identifies services running on open ports
- Extracts version information from service banners
- Supports 15+ common services (SSH, HTTP, FTP, SMTP, etc.)

**OS Fingerprinting**
- Multi-technique OS detection
- TTL analysis, service banner analysis, port patterns
- Confidence scoring for OS identification

**Network Mapping Visualization**
- Comprehensive network topology discovery
- Visual charts and detailed reports
- Exportable text reports with network information

#### 1.2 Web Application Reconnaissance (Coming Soon)

- Web server fingerprinting
- Directory and file enumeration
- Subdomain enumeration
- SSL/TLS certificate analysis
- API endpoint discovery

#### 1.3 OSINT & Information Gathering (Coming Soon)

- WHOIS lookups
- DNS enumeration
- Email harvesting
- Social media reconnaissance
- Document metadata analysis

### 2. Plugin System

RedOps features an extensible plugin architecture for custom functionality.

**Loading Plugins**
- Plugins are automatically loaded from the `Plugins` directory
- Select "Plugin Management" from the main menu
- View available plugins and their descriptions

**Plugin Categories**
- Reconnaissance
- Exploitation
- Post-Exploitation
- Reporting
- Utilities

## Detailed Workflows

### Basic Network Assessment

1. **Start with Host Discovery**
   ```
   Main Menu → Reconnaissance → Network Discovery → Host Discovery
   Enter target: 192.168.1.0/24
   ```

2. **Perform Port Scanning**
   ```
   Network Discovery → Port Scanning
   Enter target: 192.168.1.100
   Port range: 1-1000
   ```

3. **Service Detection**
   ```
   Network Discovery → Service Version Detection
   Enter target: 192.168.1.100
   Ports: 22,80,443
   ```

4. **OS Fingerprinting**
   ```
   Network Discovery → OS Fingerprinting
   Enter target: 192.168.1.100
   ```

5. **Network Mapping**
   ```
   Network Discovery → Network Mapping Visualization
   Enter range: 192.168.1.0/24
   ```

### Advanced Scanning Techniques

**Stealth Scanning**
- Use longer timeouts to avoid detection
- Scan smaller port ranges
- Implement delays between requests

**Large Network Scanning**
- Break large networks into smaller subnets
- Use network mapping for comprehensive coverage
- Monitor system resources during scans

**Targeted Assessment**
- Focus on specific services and ports
- Use service detection for detailed analysis
- Combine multiple techniques for comprehensive results

## Output and Reporting

### Console Output

RedOps provides real-time, color-coded output:
- **Green**: Successful operations and open ports
- **Red**: Errors and closed ports
- **Yellow**: Warnings and timeouts
- **Cyan**: Information and progress updates

### Log Files

All operations are logged to rotating log files:
- `redops{date}.log` - Application logs with timestamps
- Configurable log levels (Debug, Information, Warning, Error)

### Network Reports

Network mapping generates detailed text reports:
- `network_map_{timestamp}.txt` - Comprehensive network analysis
- Host information, services, and OS details
- Summary statistics and charts

### Report Contents

**Host Information**
- IP address and hostname
- Operating system detection
- Response times and availability

**Service Details**
- Open ports and protocols
- Service names and versions
- Banner information

**Network Statistics**
- Total hosts discovered
- Service distribution
- OS distribution charts

## Configuration

### Application Settings

Edit `appsettings.json` to customize behavior:

```json
{
  "Logging": {
    "DefaultLevel": "Information",
    "FileLogging": true,
    "ConsoleLogging": true
  },
  "Scanning": {
    "DefaultTimeout": 3000,
    "MaxConcurrentScans": 50,
    "RetryAttempts": 2
  },
  "Plugins": {
    "PluginDirectory": "Plugins",
    "AutoLoadPlugins": true
  },
  "Reporting": {
    "AutoSaveReports": true,
    "ReportDirectory": "reports"
  }
}
```

### Performance Tuning

**For Fast Networks**
```json
{
  "Scanning": {
    "DefaultTimeout": 1000,
    "MaxConcurrentScans": 100
  }
}
```

**For Slow Networks**
```json
{
  "Scanning": {
    "DefaultTimeout": 10000,
    "MaxConcurrentScans": 10
  }
}
```

**For Large Scans**
```json
{
  "Scanning": {
    "MaxConcurrentScans": 200,
    "RetryAttempts": 1
  }
}
```

## Best Practices

### Legal and Ethical Guidelines

1. **Authorization Required**
   - Only scan networks you own or have explicit permission to test
   - Obtain written authorization before conducting assessments
   - Respect scope limitations and time windows

2. **Responsible Disclosure**
   - Report vulnerabilities through proper channels
   - Allow reasonable time for remediation
   - Follow coordinated disclosure practices

3. **Documentation**
   - Keep detailed records of all activities
   - Document authorization and scope
   - Maintain evidence chain of custody

### Technical Best Practices

1. **Reconnaissance Planning**
   - Start with passive information gathering
   - Use multiple techniques for validation
   - Document findings systematically

2. **Scanning Strategy**
   - Begin with broad discovery, then focus
   - Use appropriate timing and intensity
   - Monitor for defensive responses

3. **Data Management**
   - Organize results by target and date
   - Back up important findings
   - Secure sensitive information

### Operational Security

1. **Network Considerations**
   - Be aware of network monitoring
   - Use appropriate source addresses
   - Consider traffic patterns and timing

2. **System Resources**
   - Monitor CPU and memory usage
   - Adjust concurrency for system capabilities
   - Plan for long-running operations

3. **Evidence Handling**
   - Preserve original log files
   - Use checksums for integrity
   - Follow forensic best practices

## Troubleshooting

### Common Issues

**Scans Return No Results**
- Check network connectivity
- Verify target IP ranges
- Ensure proper permissions
- Review firewall settings

**Performance Issues**
- Reduce concurrent scan limits
- Increase timeout values
- Check system resources
- Use smaller target ranges

**Permission Errors**
- Run with administrator/root privileges
- Check file system permissions
- Verify network interface access

**Service Detection Failures**
- Increase timeout values
- Check for service filtering
- Verify port accessibility
- Review banner parsing logic

### Debug Mode

Enable debug logging for detailed troubleshooting:

```json
{
  "Logging": {
    "DefaultLevel": "Debug"
  }
}
```

### Getting Help

1. Check the [Installation Guide](INSTALLATION.md) for setup issues
2. Review [Troubleshooting Guide](TROUBLESHOOTING.md) for common problems
3. Search [GitHub Issues](https://github.com/benjaminlettner/RedOps/issues)
4. Join [Community Discussions](https://github.com/benjaminlettner/RedOps/discussions)

## Advanced Usage

### Custom Plugins

Develop custom plugins for specialized functionality:

1. Reference the [Plugin Development Guide](PLUGIN_DEVELOPMENT.md)
2. Use the provided interfaces and base classes
3. Place compiled plugins in the `Plugins` directory
4. Restart RedOps to load new plugins

### Integration

**Scripting Integration**
```bash
# Automated scanning with output redirection
echo "192.168.1.0/24" | dotnet run > scan_results.txt
```

**CI/CD Integration**
- Include RedOps in security pipelines
- Parse output for automated reporting
- Integrate with vulnerability management systems

### API Usage (Future)

RedOps will support API integration for:
- Automated scanning workflows
- Integration with security platforms
- Custom dashboard development
- Reporting system integration

## Examples

### Example 1: Basic Network Discovery

```
Target: 192.168.1.0/24
Steps:
1. Host Discovery → Found 15 live hosts
2. Port Scanning → Scanned common ports
3. Service Detection → Identified web servers, SSH
4. Generate Report → Saved to network_map_20250124_143022.txt
```

### Example 2: Targeted Service Analysis

```
Target: 192.168.1.100
Steps:
1. Port Scanning → Ports 22,80,443,8080
2. Service Detection → SSH 8.2, Apache 2.4.41, Nginx 1.18
3. OS Fingerprinting → Ubuntu 20.04 (High confidence)
```

### Example 3: Large Network Assessment

```
Target: 10.0.0.0/16
Strategy:
1. Break into /24 subnets
2. Use Network Mapping for each subnet
3. Consolidate results
4. Focus on interesting services
```

This usage guide provides comprehensive coverage of RedOps functionality. For specific technical details, refer to the API documentation and source code comments.
