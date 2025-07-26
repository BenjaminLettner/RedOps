# Troubleshooting Guide

This guide helps you resolve common issues when using RedOps. If you don't find your issue here, please check our [GitHub Issues](https://github.com/benjaminlettner/RedOps/issues) or create a new one.

## Common Issues

### Installation and Setup Issues

#### Issue: "dotnet command not found"

**Symptoms:**
- Command not recognized error when running `dotnet`
- PATH environment variable issues

**Solutions:**

**Windows:**
```cmd
# Check if .NET is installed
where dotnet

# If not found, add to PATH
set PATH=%PATH%;C:\Program Files\dotnet
```

**macOS/Linux:**
```bash
# Check if .NET is installed
which dotnet

# Add to PATH if needed
export PATH=$PATH:/usr/share/dotnet
echo 'export PATH=$PATH:/usr/share/dotnet' >> ~/.bashrc
source ~/.bashrc
```

**Permanent Fix:**
- Reinstall .NET SDK from [Microsoft's official site](https://dotnet.microsoft.com/download)
- Ensure installer adds to PATH automatically

#### Issue: Build Errors

**Symptoms:**
```
error CS0234: The type or namespace name 'X' does not exist
error MSB4018: The "ResolvePackageAssets" task failed unexpectedly
```

**Solutions:**
```bash
# Clean and restore packages
dotnet clean
dotnet restore
dotnet build --configuration Release

# If still failing, delete bin/obj folders
rm -rf bin obj  # Linux/macOS
rmdir /s bin obj  # Windows

# Restore and rebuild
dotnet restore
dotnet build
```

#### Issue: Permission Denied Errors

**Symptoms:**
- Access denied when running RedOps
- Network operations fail
- File system permission errors

**Solutions:**

**Windows:**
```cmd
# Run Command Prompt as Administrator
# Right-click Command Prompt → "Run as administrator"
```

**macOS:**
```bash
# Run with sudo for network operations
sudo dotnet run

# Or grant network capabilities
sudo spctl --master-disable  # Temporary, for testing only
```

**Linux:**
```bash
# Run with sudo
sudo dotnet run

# Or set capabilities for network operations
sudo setcap cap_net_raw+ep /usr/share/dotnet/dotnet
```

### Network Scanning Issues

#### Issue: No Hosts Discovered

**Symptoms:**
- Host discovery returns no results
- Network appears empty

**Diagnosis:**
```bash
# Test basic connectivity
ping 192.168.1.1
nslookup google.com

# Check network interface
ipconfig  # Windows
ifconfig  # Linux/macOS
```

**Solutions:**
1. **Verify Target Range**
   - Ensure IP range is correct
   - Use `ipconfig`/`ifconfig` to check your network
   - Try a single known host first (e.g., your router)

2. **Check Network Connectivity**
   - Verify you're on the correct network
   - Test with known live hosts
   - Check for VPN/proxy interference

3. **Firewall Issues**
   - Temporarily disable host firewall
   - Check corporate firewall rules
   - Verify ICMP is allowed

4. **Increase Timeouts**
   ```json
   {
     "Scanning": {
       "DefaultTimeout": 10000
     }
   }
   ```

#### Issue: Port Scans Show All Ports Closed

**Symptoms:**
- All ports appear closed/filtered
- No open ports detected on known services

**Solutions:**
1. **Verify Target is Reachable**
   ```bash
   ping target-ip
   telnet target-ip 80
   ```

2. **Check for Host-based Firewalls**
   - Target may have firewall blocking scans
   - Try different ports (22, 80, 443)
   - Use longer timeouts

3. **Network Filtering**
   - Corporate firewalls may block scanning
   - Try from different network location
   - Check for IDS/IPS interference

4. **Adjust Scan Parameters**
   ```json
   {
     "Scanning": {
       "DefaultTimeout": 5000,
       "MaxConcurrentScans": 10,
       "RetryAttempts": 3
     }
   }
   ```

#### Issue: Service Detection Fails

**Symptoms:**
- Ports detected as open but no service information
- Generic "Unknown Service" results
- Banner grabbing timeouts

**Solutions:**
1. **Increase Service Timeout**
   ```json
   {
     "Scanning": {
       "ServiceTimeout": 10000
     }
   }
   ```

2. **Check Service Responsiveness**
   ```bash
   # Test manual connection
   telnet target-ip port
   nc target-ip port
   ```

3. **Service May Not Send Banners**
   - Some services don't respond to connections
   - Try different connection methods
   - Check if service requires specific protocols

### Performance Issues

#### Issue: Slow Scanning Performance

**Symptoms:**
- Scans take very long to complete
- High CPU/memory usage
- System becomes unresponsive

**Solutions:**
1. **Reduce Concurrency**
   ```json
   {
     "Scanning": {
       "MaxConcurrentScans": 25
     }
   }
   ```

2. **Optimize Target Ranges**
   - Scan smaller IP ranges
   - Focus on specific ports
   - Use host discovery first

3. **System Resources**
   - Close other applications
   - Increase available RAM
   - Use SSD for better I/O

4. **Network Optimization**
   - Use wired connection instead of WiFi
   - Reduce network latency
   - Avoid peak usage times

#### Issue: Memory Usage Issues

**Symptoms:**
- Out of memory errors
- System swap usage high
- Application crashes during large scans

**Solutions:**
1. **Reduce Scan Scope**
   ```bash
   # Instead of /16, use multiple /24 scans
   # 10.0.0.0/16 → 10.0.1.0/24, 10.0.2.0/24, etc.
   ```

2. **Adjust Configuration**
   ```json
   {
     "Scanning": {
       "MaxConcurrentScans": 20,
       "BatchSize": 100
     }
   }
   ```

3. **System Tuning**
   - Increase virtual memory
   - Close unnecessary applications
   - Monitor with task manager

### OS Fingerprinting Issues

#### Issue: Inaccurate OS Detection

**Symptoms:**
- Wrong OS identified
- Low confidence scores
- Inconsistent results

**Solutions:**
1. **Gather More Data**
   - Scan more ports for better patterns
   - Use service detection first
   - Try multiple fingerprinting runs

2. **Check Network Path**
   - NAT/proxy may modify packets
   - Firewalls can alter TTL values
   - Try from different network locations

3. **Understand Limitations**
   - Virtualized systems may show host OS
   - Load balancers can obscure real OS
   - Some systems actively fingerprint-resist

### Application Errors

#### Issue: Unhandled Exceptions

**Symptoms:**
```
Unhandled exception. System.Exception: ...
   at RedOps.Modules.NetworkDiscovery...
```

**Solutions:**
1. **Enable Debug Logging**
   ```json
   {
     "Logging": {
       "DefaultLevel": "Debug"
     }
   }
   ```

2. **Check Log Files**
   - Review `redops{date}.log`
   - Look for stack traces
   - Identify error patterns

3. **Report Issues**
   - Create GitHub issue with full error
   - Include system information
   - Provide steps to reproduce

#### Issue: Configuration Errors

**Symptoms:**
- Settings not loading
- Invalid configuration values
- Default values always used

**Solutions:**
1. **Validate JSON Syntax**
   ```bash
   # Use online JSON validator
   # Check for trailing commas, quotes
   ```

2. **Check File Location**
   ```bash
   # Ensure appsettings.json is in correct directory
   ls -la appsettings.json
   ```

3. **Reset to Defaults**
   ```json
   {
     "Logging": {
       "DefaultLevel": "Information"
     },
     "Scanning": {
       "DefaultTimeout": 3000,
       "MaxConcurrentScans": 50
     }
   }
   ```

## Platform-Specific Issues

### Windows Issues

#### Issue: Windows Defender Interference

**Symptoms:**
- Scans blocked or interrupted
- False positive detections
- Performance degradation

**Solutions:**
1. **Add Exclusions**
   - Windows Security → Virus & threat protection
   - Add RedOps directory to exclusions
   - Exclude process: `dotnet.exe`

2. **Temporary Disable**
   - Only for testing purposes
   - Re-enable after testing
   - Use caution with real-time protection

#### Issue: Windows Firewall Blocking

**Symptoms:**
- Network operations fail
- Outbound connections blocked
- No network discovery results

**Solutions:**
1. **Allow Through Firewall**
   - Windows Firewall → Allow an app
   - Add `dotnet.exe` to allowed programs
   - Enable for both private and public networks

2. **Create Firewall Rule**
   ```cmd
   # Run as Administrator
   netsh advfirewall firewall add rule name="RedOps" dir=out action=allow program="C:\Program Files\dotnet\dotnet.exe"
   ```

### macOS Issues

#### Issue: Network Permission Prompts

**Symptoms:**
- Repeated permission dialogs
- Network access denied
- Scanning operations fail

**Solutions:**
1. **Grant Permissions**
   - Allow network access when prompted
   - Check System Preferences → Security & Privacy
   - Add terminal/dotnet to allowed applications

2. **Run with Elevated Privileges**
   ```bash
   sudo dotnet run
   ```

#### Issue: Gatekeeper Blocking

**Symptoms:**
- "App cannot be opened" errors
- Developer verification required
- Unsigned binary warnings

**Solutions:**
1. **Allow in Security Settings**
   - System Preferences → Security & Privacy
   - Click "Allow Anyway" for blocked items

2. **Temporary Gatekeeper Disable**
   ```bash
   sudo spctl --master-disable  # Temporary only
   # Re-enable after testing:
   sudo spctl --master-enable
   ```

### Linux Issues

#### Issue: Network Capabilities

**Symptoms:**
- ICMP operations fail
- Raw socket errors
- Permission denied for network operations

**Solutions:**
1. **Set Capabilities**
   ```bash
   sudo setcap cap_net_raw+ep /usr/share/dotnet/dotnet
   ```

2. **Run as Root**
   ```bash
   sudo dotnet run
   ```

3. **Add to Network Group**
   ```bash
   sudo usermod -a -G netdev $USER
   # Logout and login again
   ```

#### Issue: Missing Dependencies

**Symptoms:**
- Library loading errors
- ICU/locale errors
- Runtime dependency issues

**Solutions:**

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y libicu-dev libc6-dev
```

**CentOS/RHEL:**
```bash
sudo yum install -y libicu-devel glibc-devel
```

**Arch Linux:**
```bash
sudo pacman -S icu glibc
```

## Debug Mode

Enable comprehensive debugging for troubleshooting:

```json
{
  "Logging": {
    "DefaultLevel": "Debug",
    "FileLogging": true,
    "ConsoleLogging": true
  }
}
```

This will provide detailed information about:
- Network operations
- Service detection attempts
- Error conditions
- Performance metrics

## Getting Additional Help

### Before Reporting Issues

1. **Check Prerequisites**
   - .NET 8.0 SDK installed
   - Appropriate permissions
   - Network connectivity

2. **Gather Information**
   - Operating system and version
   - .NET version (`dotnet --version`)
   - Error messages and logs
   - Steps to reproduce

3. **Try Basic Troubleshooting**
   - Restart application
   - Try different targets
   - Check network connectivity
   - Review configuration

### Reporting Issues

When creating a GitHub issue, include:

1. **Environment Details**
   ```bash
   # Include output of these commands
   dotnet --version
   uname -a  # Linux/macOS
   systeminfo  # Windows
   ```

2. **Error Information**
   - Complete error messages
   - Stack traces from logs
   - Configuration file contents

3. **Reproduction Steps**
   - Exact commands used
   - Target information (if safe to share)
   - Expected vs actual behavior

4. **Log Files**
   - Attach relevant log files
   - Remove sensitive information
   - Include timestamps

### Community Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/benjaminlettner/RedOps/issues)
- **Discussions**: [Ask questions and share tips](https://github.com/benjaminlettner/RedOps/discussions)
- **Documentation**: Check other guides in the `docs/` directory

### Professional Support

For enterprise users or complex deployments:
- Consider professional security consulting
- Engage with penetration testing professionals
- Review enterprise security tool alternatives

## Prevention Tips

### Regular Maintenance

1. **Keep Updated**
   ```bash
   # Update .NET runtime
   # Pull latest RedOps changes
   git pull origin main
   dotnet build
   ```

2. **Monitor Performance**
   - Review log files regularly
   - Monitor system resources
   - Optimize configurations

3. **Validate Configurations**
   - Test settings changes
   - Backup working configurations
   - Document custom settings

### Best Practices

1. **Start Small**
   - Test with single hosts
   - Gradually increase scope
   - Validate results

2. **Monitor Resources**
   - Watch CPU and memory usage
   - Adjust concurrency appropriately
   - Plan for long-running scans

3. **Document Issues**
   - Keep notes on problems encountered
   - Share solutions with community
   - Contribute to documentation

This troubleshooting guide covers the most common issues. For additional help, don't hesitate to reach out to the community or create detailed issue reports.
