# Installation Guide

This guide provides detailed instructions for installing and setting up RedOps on different platforms.

## System Requirements

### Minimum Requirements
- **Operating System**: Windows 10+, macOS 10.15+, or Linux (Ubuntu 18.04+, CentOS 7+)
- **.NET Runtime**: .NET 8.0 or later
- **Memory**: 2 GB RAM minimum, 4 GB recommended
- **Storage**: 500 MB free disk space
- **Network**: Internet connection for initial setup and updates

### Recommended Requirements
- **Memory**: 8 GB RAM for large network scans
- **Storage**: 2 GB free disk space for reports and logs
- **Privileges**: Administrator/root access for advanced network operations

## Installation Methods

### Method 1: Build from Source (Recommended)

1. **Install .NET 8.0 SDK**
   
   **Windows:**
   - Download from [Microsoft .NET Downloads](https://dotnet.microsoft.com/download/dotnet/8.0)
   - Run the installer and follow the setup wizard
   
   **macOS:**
   ```bash
   # Using Homebrew
   brew install dotnet
   
   # Or download from Microsoft
   # https://dotnet.microsoft.com/download/dotnet/8.0
   ```
   
   **Linux (Ubuntu/Debian):**
   ```bash
   # Add Microsoft package repository
   wget https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
   sudo dpkg -i packages-microsoft-prod.deb
   rm packages-microsoft-prod.deb
   
   # Install .NET SDK
   sudo apt-get update
   sudo apt-get install -y dotnet-sdk-8.0
   ```
   
   **Linux (CentOS/RHEL):**
   ```bash
   # Add Microsoft package repository
   sudo rpm -Uvh https://packages.microsoft.com/config/centos/7/packages-microsoft-prod.rpm
   
   # Install .NET SDK
   sudo yum install dotnet-sdk-8.0
   ```

2. **Clone the Repository**
   ```bash
   git clone https://github.com/benjaminlettner/RedOps.git
   cd RedOps
   ```

3. **Build the Project**
   ```bash
   cd RedOps
   dotnet restore
   dotnet build --configuration Release
   ```

4. **Run RedOps**
   ```bash
   dotnet run
   ```

### Method 2: Pre-built Releases (Coming Soon)

Pre-built binaries will be available on the [Releases page](https://github.com/benjaminlettner/RedOps/releases) for:
- Windows x64
- macOS x64/ARM64
- Linux x64

## Verification

After installation, verify RedOps is working correctly:

1. **Check .NET Installation**
   ```bash
   dotnet --version
   # Should show 8.0.x or later
   ```

2. **Test RedOps**
   ```bash
   cd RedOps
   dotnet run
   ```
   
   You should see the RedOps banner and main menu.

3. **Run a Basic Test**
   - Navigate to: Reconnaissance → Network Discovery → Host Discovery
   - Enter a small range like `127.0.0.1` or `localhost`
   - Verify the scan completes successfully

## Configuration

### Initial Configuration

RedOps uses `appsettings.json` for configuration. The default settings work for most users, but you can customize:

```json
{
  "Logging": {
    "DefaultLevel": "Information",
    "FileLogging": true,
    "ConsoleLogging": true
  },
  "Scanning": {
    "DefaultTimeout": 3000,
    "MaxConcurrentScans": 50
  },
  "Plugins": {
    "PluginDirectory": "Plugins",
    "AutoLoadPlugins": true
  }
}
```

### Log Configuration

Logs are stored in the application directory with rotating files:
- `redops{date}.log` - Application logs
- `network_map_{timestamp}.txt` - Network scan reports

### Plugin Directory

Create a `Plugins` directory in the application folder for custom plugins:
```bash
mkdir Plugins
```

## Platform-Specific Setup

### Windows

1. **Run as Administrator** (recommended for advanced features)
   - Right-click Command Prompt → "Run as administrator"
   - Navigate to RedOps directory and run

2. **Windows Defender**
   - Add RedOps directory to Windows Defender exclusions
   - Some network scanning features may trigger false positives

3. **Firewall Configuration**
   - Allow RedOps through Windows Firewall if prompted
   - Required for certain network discovery features

### macOS

1. **Security Permissions**
   ```bash
   # Allow network operations
   sudo spctl --master-disable  # Temporarily, re-enable after testing
   ```

2. **Network Permissions**
   - macOS may prompt for network access permissions
   - Grant access for full functionality

3. **Homebrew Dependencies** (if using Homebrew .NET)
   ```bash
   brew update
   brew upgrade dotnet
   ```

### Linux

1. **Network Capabilities**
   ```bash
   # For ICMP ping operations (optional)
   sudo setcap cap_net_raw+ep /usr/share/dotnet/dotnet
   ```

2. **User Permissions**
   ```bash
   # Add user to necessary groups
   sudo usermod -a -G netdev $USER
   ```

3. **Dependencies**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install -y libicu-dev
   
   # CentOS/RHEL
   sudo yum install -y libicu
   ```

## Troubleshooting

### Common Issues

**Issue: "dotnet command not found"**
```bash
# Verify PATH includes .NET
echo $PATH
export PATH=$PATH:/usr/share/dotnet  # Linux/macOS
```

**Issue: "Permission denied" errors**
```bash
# Run with appropriate privileges
sudo dotnet run  # Linux/macOS
# Or run Command Prompt as Administrator (Windows)
```

**Issue: Build errors**
```bash
# Clean and rebuild
dotnet clean
dotnet restore
dotnet build
```

**Issue: Network scanning fails**
- Check firewall settings
- Verify network connectivity
- Run with administrator/root privileges
- Check antivirus software interference

### Performance Optimization

1. **Increase Concurrent Scans** (for powerful systems)
   ```json
   {
     "Scanning": {
       "MaxConcurrentScans": 100
     }
   }
   ```

2. **Adjust Timeouts** (for slow networks)
   ```json
   {
     "Scanning": {
       "DefaultTimeout": 5000
     }
   }
   ```

3. **Memory Management**
   - Close other applications during large scans
   - Monitor system resources
   - Use smaller IP ranges for initial testing

## Updating

### Update from Git
```bash
cd RedOps
git pull origin main
dotnet build --configuration Release
```

### Update .NET Runtime
Follow platform-specific instructions to update .NET to the latest version.

## Uninstallation

1. **Remove Application Files**
   ```bash
   rm -rf /path/to/RedOps  # Linux/macOS
   # Or delete folder in Windows Explorer
   ```

2. **Remove .NET (optional)**
   - Follow Microsoft's uninstallation guide
   - Only if not used by other applications

3. **Clean Up Logs**
   ```bash
   # Remove any remaining log files
   rm -f redops*.log network_map_*.txt
   ```

## Next Steps

After successful installation:

1. Read the [Usage Guide](USAGE.md)
2. Try the [Quick Start Tutorial](QUICKSTART.md)
3. Explore [Plugin Development](PLUGIN_DEVELOPMENT.md)
4. Join the [Community Discussions](https://github.com/benjaminlettner/RedOps/discussions)

## Support

If you encounter issues:

1. Check the [Troubleshooting Guide](TROUBLESHOOTING.md)
2. Search [existing issues](https://github.com/benjaminlettner/RedOps/issues)
3. Create a [new issue](https://github.com/benjaminlettner/RedOps/issues/new) with:
   - Operating system and version
   - .NET version (`dotnet --version`)
   - Error messages and logs
   - Steps to reproduce
