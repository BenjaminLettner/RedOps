# RedOps - Offensive Security Tool

[![.NET](https://img.shields.io/badge/.NET-8.0-blue.svg)](https://dotnet.microsoft.com/download)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/benjaminlettner/RedOps)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.com/benjaminlettner/RedOps)

A comprehensive **offensive security tool** designed for penetration testing and security assessments, following the **cyber kill chain methodology**. Built with C# and Spectre.Console for a modern, interactive command-line experience.

![RedOps Banner](docs/images/redops-banner.png)

## 🎯 Overview

RedOps is a modular penetration testing framework that provides security professionals with a comprehensive suite of reconnaissance, exploitation, and post-exploitation tools. The project follows industry-standard methodologies and emphasizes usability, extensibility, and professional reporting.

### Key Features

- 🔍 **Comprehensive Reconnaissance**: Network discovery, service enumeration, OS fingerprinting
- 🗺️ **Network Mapping**: Visual network topology with detailed host analysis  
- 🎨 **Modern UI**: Interactive console interface with progress indicators and color coding
- 🔌 **Plugin Architecture**: Extensible framework for custom tools and modules
- 📊 **Professional Reporting**: Detailed reports with evidence and recommendations
- ⚡ **High Performance**: Async/await patterns with concurrent scanning capabilities

## 🚀 Quick Start

### Prerequisites

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or later
- Windows, Linux, or macOS
- Administrative/root privileges (for some network operations)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/benjaminlettner/RedOps.git
   cd RedOps
   ```

2. **Build the project**
   ```bash
   cd RedOps
   dotnet build
   ```

3. **Run RedOps**
   ```bash
   dotnet run
   ```

### First Scan

1. Launch RedOps and navigate to **Reconnaissance → Network Discovery**
2. Try **Host Discovery** with your local network (e.g., `192.168.1.0/24`)
3. Explore **Network Mapping Visualization** for comprehensive topology analysis

## 📋 Current Features

### ✅ Phase 1: Reconnaissance (COMPLETE)

#### 1.1 Network Discovery
- **✅ Advanced Port Scanning**: TCP/UDP scanning with service detection
- **✅ Host Discovery**: ICMP ping sweeps and ARP discovery
- **✅ Service Version Detection**: Banner grabbing and service fingerprinting
- **✅ OS Fingerprinting**: Multi-technique operating system identification
- **✅ Network Mapping**: Visual network topology with comprehensive reporting

#### 1.2 Web Application Recon (Planned)
- 🔄 Web server fingerprinting
- 🔄 Directory and file enumeration
- 🔄 Subdomain enumeration
- 🔄 SSL/TLS certificate analysis
- 🔄 API endpoint discovery

#### 1.3 OSINT & Information Gathering (Planned)
- 🔄 WHOIS lookups
- 🔄 DNS enumeration
- 🔄 Email harvesting
- 🔄 Social media reconnaissance
- 🔄 Document metadata analysis

### 🔄 Future Phases
- **Phase 2**: Weaponization & Delivery
- **Phase 3**: Exploitation
- **Phase 4**: Command & Control
- **Phase 5**: Actions on Objectives
- **Phase 6**: Reporting & Analysis

## 🛠️ Architecture

RedOps follows a modular architecture with clear separation of concerns:

```
RedOps/
├── Core/
│   └── Plugins/           # Plugin architecture and interfaces
├── Modules/
│   └── Reconnaissance/    # Reconnaissance tools and techniques
│       └── NetworkDiscovery/
├── Utils/                 # Utility classes (logging, config, UI)
├── Resources/             # Static resources (OUI database, etc.)
└── SamplePlugin/          # Example plugin implementation
```

### Key Components

- **Plugin System**: Extensible architecture for adding new capabilities
- **Network Discovery**: Comprehensive network reconnaissance suite
- **Service Detection**: Advanced service identification and version detection
- **OS Fingerprinting**: Multi-technique operating system identification
- **Network Mapping**: Visual topology discovery and analysis

## 📖 Usage Guide

### Network Discovery

#### Port Scanning
```bash
# Launch RedOps
dotnet run

# Navigate to: Reconnaissance → Network Discovery → Comprehensive Port Scan
# Enter target: google.com or 192.168.1.1
# Select port range: Common ports, All well-known, or custom range
```

#### OS Fingerprinting
```bash
# Navigate to: Reconnaissance → Network Discovery → OS Fingerprinting  
# Enter target IP: 192.168.1.1
# View detailed OS analysis with confidence scoring
```

#### Network Mapping
```bash
# Navigate to: Reconnaissance → Network Discovery → Network Mapping Visualization
# Enter network range: 192.168.1.0/24 or 192.168.1.1-254
# Get comprehensive network topology with:
#   - Live host discovery
#   - Service enumeration  
#   - OS fingerprinting
#   - Visual network maps
#   - Exportable reports
```

### Plugin Development

RedOps supports custom plugins for extending functionality:

```csharp
public class MyCustomPlugin : IPlugin
{
    public string Name => "My Custom Tool";
    public string Description => "Custom reconnaissance tool";
    public PluginCategory Category => PluginCategory.Reconnaissance;
    
    public async Task ExecuteAsync(PluginContext context)
    {
        // Your custom logic here
        context.Logger.Information("Executing custom plugin...");
    }
}
```

## 🔧 Configuration

RedOps uses `appsettings.json` for configuration:

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
  }
}
```

## 📊 Sample Output

### Network Mapping Results
```
╭─────────────────── Network Map Visualization ───────────────────╮
│ Network Range    │ 192.168.1.0/24                              │
│ Scan Duration    │ 45.2 seconds                                 │
│ Live Hosts       │ 12                                           │
│ Total Services   │ 34                                           │
│ Scan Time        │ 2024-01-15 14:30:22                         │
╰──────────────────────────────────────────────────────────────────╯

Operating System Distribution:
██████████████████████████████████████████████████████████ Windows (8)
██████████████████████████ Linux/Unix (3)
████████ Network Device (1)

Discovered Hosts:
┌─────────────────┬──────────────────┬─────────────┬─────────────────┬───────────────┐
│ IP Address      │ Hostname         │ OS          │ Services        │ Response Time │
├─────────────────┼──────────────────┼─────────────┼─────────────────┼───────────────┤
│ 192.168.1.1     │ router.local     │ Network     │ 22/TCP, 80/TCP  │ 2ms           │
│ 192.168.1.100   │ desktop-pc       │ Windows     │ 135/TCP, 445/TCP│ 15ms          │
│ 192.168.1.150   │ server.local     │ Linux       │ 22/TCP, 80/TCP  │ 8ms           │
└─────────────────┴──────────────────┴─────────────┴─────────────────┴───────────────┘
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Commit your changes: `git commit -m 'Add amazing feature'`
5. Push to the branch: `git push origin feature/amazing-feature`
6. Open a Pull Request

### Code Style

- Follow C# coding conventions
- Use meaningful variable and method names
- Add XML documentation for public APIs
- Include unit tests for new features

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Legal Disclaimer

**IMPORTANT**: RedOps is designed for authorized security testing and educational purposes only. 

- Only use this tool on systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal in most jurisdictions
- Users are responsible for complying with all applicable laws and regulations
- The developers assume no liability for misuse of this software

## 🙏 Acknowledgments

- [Spectre.Console](https://spectreconsole.net/) - For the amazing console UI framework
- [Serilog](https://serilog.net/) - For structured logging capabilities
- The cybersecurity community for inspiration and best practices

## 📞 Support

- 📖 [Documentation](docs/)
- 🐛 [Issue Tracker](https://github.com/benjaminlettner/RedOps/issues)
- 💬 [Discussions](https://github.com/benjaminlettner/RedOps/discussions)

---

**Made with ❤️ for the cybersecurity community**
