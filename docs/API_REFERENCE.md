# API Reference

This document provides comprehensive API documentation for RedOps core components, modules, and plugin interfaces.

## Core Components

### RedOps.Core.Plugins

#### IPlugin Interface

The main interface that all plugins must implement.

```csharp
namespace RedOps.Core.Plugins
{
    public interface IPlugin
    {
        string Name { get; }
        string Description { get; }
        PluginCategory Category { get; }
        Task<bool> ExecuteAsync(PluginContext context);
    }
}
```

**Properties:**
- `Name`: Unique identifier for the plugin
- `Description`: Brief description of plugin functionality
- `Category`: Cyber kill chain category (see PluginCategory enum)

**Methods:**
- `ExecuteAsync(PluginContext context)`: Main plugin execution method
  - **Parameters**: `context` - Runtime context with logger, configuration, and shared data
  - **Returns**: `Task<bool>` - True if execution successful, false otherwise

#### PluginCategory Enum

```csharp
public enum PluginCategory
{
    Reconnaissance,
    Weaponization,
    Delivery,
    Exploitation,
    Installation,
    CommandAndControl,
    ActionsOnObjectives,
    PostExploitation,
    Reporting,
    Utilities
}
```

#### PluginContext Class

```csharp
public class PluginContext
{
    public ILogger Logger { get; set; }
    public IConfiguration Configuration { get; set; }
    public Dictionary<string, object> SharedData { get; set; }
}
```

**Properties:**
- `Logger`: Serilog logger instance for structured logging
- `Configuration`: Application configuration from appsettings.json
- `SharedData`: Dictionary for sharing data between plugins

#### PluginManager Class

```csharp
public class PluginManager
{
    public List<IPlugin> LoadedPlugins { get; }
    
    public void LoadPlugins(string pluginDirectory);
    public List<IPlugin> GetPluginsByCategory(PluginCategory category);
    public IPlugin GetPluginByName(string name);
    public Task<bool> ExecutePluginAsync(string pluginName, PluginContext context);
}
```

**Methods:**
- `LoadPlugins(string pluginDirectory)`: Load plugins from specified directory
- `GetPluginsByCategory(PluginCategory category)`: Filter plugins by category
- `GetPluginByName(string name)`: Find plugin by name
- `ExecutePluginAsync(string pluginName, PluginContext context)`: Execute specific plugin

## Network Discovery Module

### RedOps.Modules.Reconnaissance.NetworkDiscovery

#### HostDiscoverer Class

```csharp
public static class HostDiscoverer
{
    public static async Task<List<string>> DiscoverHostsAsync(string networkRange, int timeout = 3000);
    public static async Task<bool> IsHostAliveAsync(string ipAddress, int timeout = 3000);
}
```

**Methods:**
- `DiscoverHostsAsync(string networkRange, int timeout)`: Discover live hosts in network range
  - **Parameters**: 
    - `networkRange`: IP range (CIDR, range, or single IP)
    - `timeout`: Timeout in milliseconds (default: 3000)
  - **Returns**: `Task<List<string>>` - List of live IP addresses

- `IsHostAliveAsync(string ipAddress, int timeout)`: Check if single host is alive
  - **Parameters**:
    - `ipAddress`: Target IP address
    - `timeout`: Timeout in milliseconds (default: 3000)
  - **Returns**: `Task<bool>` - True if host responds

#### PortScanner Class

```csharp
public class PortScanner
{
    public static async Task<List<OpenPortInfo>> ScanPortsAsync(string target, int[] ports, int timeout = 3000);
    public static async Task<List<OpenPortInfo>> ScanPortRangeAsync(string target, int startPort, int endPort, int timeout = 3000);
    public static async Task<List<OpenPortInfo>> ScanCommonPortsAsync(string target, int timeout = 3000);
}
```

**Methods:**
- `ScanPortsAsync(string target, int[] ports, int timeout)`: Scan specific ports
  - **Parameters**:
    - `target`: Target IP or hostname
    - `ports`: Array of port numbers to scan
    - `timeout`: Connection timeout in milliseconds
  - **Returns**: `Task<List<OpenPortInfo>>` - List of open ports with details

- `ScanPortRangeAsync(string target, int startPort, int endPort, int timeout)`: Scan port range
  - **Parameters**:
    - `target`: Target IP or hostname
    - `startPort`: Starting port number
    - `endPort`: Ending port number
    - `timeout`: Connection timeout in milliseconds
  - **Returns**: `Task<List<OpenPortInfo>>` - List of open ports

- `ScanCommonPortsAsync(string target, int timeout)`: Scan common ports
  - **Parameters**:
    - `target`: Target IP or hostname
    - `timeout`: Connection timeout in milliseconds
  - **Returns**: `Task<List<OpenPortInfo>>` - List of open common ports

#### ServiceDetector Class

```csharp
public class ServiceDetector
{
    public async Task<List<OpenPortInfo>> DetectServicesAsync(string target, int[] ports, int timeout = 3000);
    public async Task<OpenPortInfo> DetectServiceAsync(string target, int port, int timeout = 3000);
}
```

**Methods:**
- `DetectServicesAsync(string target, int[] ports, int timeout)`: Detect services on multiple ports
  - **Parameters**:
    - `target`: Target IP or hostname
    - `ports`: Array of port numbers
    - `timeout`: Connection timeout in milliseconds
  - **Returns**: `Task<List<OpenPortInfo>>` - List of ports with service information

- `DetectServiceAsync(string target, int port, int timeout)`: Detect service on single port
  - **Parameters**:
    - `target`: Target IP or hostname
    - `port`: Port number
    - `timeout`: Connection timeout in milliseconds
  - **Returns**: `Task<OpenPortInfo>` - Port information with service details

#### OSFingerprinter Class

```csharp
public class OSFingerprinter
{
    public async Task<OSFingerprintResult> FingerprintOSAsync(string ipAddress, List<OpenPortInfo> openPorts);
}
```

**Methods:**
- `FingerprintOSAsync(string ipAddress, List<OpenPortInfo> openPorts)`: Perform OS fingerprinting
  - **Parameters**:
    - `ipAddress`: Target IP address
    - `openPorts`: List of open ports for analysis
  - **Returns**: `Task<OSFingerprintResult>` - OS fingerprinting results

#### NetworkMapper Class

```csharp
public class NetworkMapper
{
    public async Task<NetworkMap> CreateNetworkMapAsync(string networkRange);
    public void DisplayNetworkMap(NetworkMap networkMap);
    public async Task SaveNetworkMapAsync(NetworkMap networkMap, string filename);
}
```

**Methods:**
- `CreateNetworkMapAsync(string networkRange)`: Create comprehensive network map
  - **Parameters**: `networkRange`: Network range to map
  - **Returns**: `Task<NetworkMap>` - Complete network mapping results

- `DisplayNetworkMap(NetworkMap networkMap)`: Display network map in console
  - **Parameters**: `networkMap`: Network map to display

- `SaveNetworkMapAsync(NetworkMap networkMap, string filename)`: Save network map to file
  - **Parameters**:
    - `networkMap`: Network map to save
    - `filename`: Output filename

## Data Models

### OpenPortInfo Class

```csharp
public class OpenPortInfo
{
    public int Port { get; set; }
    public string Protocol { get; set; } = "tcp";
    public string ServiceName { get; set; } = "Unknown";
    public string ServiceVersion { get; set; } = "";
    public string Banner { get; set; } = "";
    public DateTime ScanTime { get; set; }
    public TimeSpan ResponseTime { get; set; }
}
```

**Properties:**
- `Port`: Port number
- `Protocol`: Protocol type (tcp/udp)
- `ServiceName`: Identified service name
- `ServiceVersion`: Service version information
- `Banner`: Service banner text
- `ScanTime`: When the port was scanned
- `ResponseTime`: Connection response time

### OSFingerprintResult Class

```csharp
public class OSFingerprintResult
{
    public string IpAddress { get; set; } = "";
    public string OperatingSystem { get; set; } = "Unknown";
    public string Confidence { get; set; } = "Low";
    public List<string> Evidence { get; set; } = new();
    public List<string> OpenPorts { get; set; } = new();
    public Dictionary<string, string> Details { get; set; } = new();
}
```

**Properties:**
- `IpAddress`: Target IP address
- `OperatingSystem`: Detected operating system
- `Confidence`: Confidence level (Low/Medium/High)
- `Evidence`: List of evidence supporting OS detection
- `OpenPorts`: List of open ports used in analysis
- `Details`: Additional OS details and characteristics

### NetworkMap Class

```csharp
public class NetworkMap
{
    public string NetworkRange { get; set; } = "";
    public List<NetworkNode> Nodes { get; set; } = new();
    public TimeSpan ScanDuration { get; set; }
    public DateTime ScanTime { get; set; }
    public Dictionary<string, int> ServiceCounts { get; set; } = new();
    public Dictionary<string, int> OSCounts { get; set; } = new();
}
```

**Properties:**
- `NetworkRange`: Scanned network range
- `Nodes`: List of discovered network nodes
- `ScanDuration`: Total scan duration
- `ScanTime`: When scan was performed
- `ServiceCounts`: Count of each service type
- `OSCounts`: Count of each OS type

### NetworkNode Class

```csharp
public class NetworkNode
{
    public string IpAddress { get; set; } = "";
    public string Hostname { get; set; } = "";
    public bool IsAlive { get; set; }
    public List<OpenPortInfo> Services { get; set; } = new();
    public OSFingerprintResult OSInfo { get; set; } = new();
    public TimeSpan ResponseTime { get; set; }
}
```

**Properties:**
- `IpAddress`: Node IP address
- `Hostname`: Resolved hostname (if available)
- `IsAlive`: Whether node responded to discovery
- `Services`: List of services running on node
- `OSInfo`: OS fingerprinting results
- `ResponseTime`: Average response time

## Utility Classes

### RedOps.Utils

#### Logger Class

```csharp
public static class Logger
{
    public static ILogger Instance { get; }
    
    public static void Information(string message);
    public static void Warning(string message);
    public static void Error(string message);
    public static void Debug(string message);
}
```

**Methods:**
- `Information(string message)`: Log informational message
- `Warning(string message)`: Log warning message
- `Error(string message)`: Log error message
- `Debug(string message)`: Log debug message

#### ConfigHelper Class

```csharp
public static class ConfigHelper
{
    public static IConfiguration Configuration { get; }
    
    public static T GetValue<T>(string key, T defaultValue = default);
    public static IConfigurationSection GetSection(string sectionName);
}
```

**Methods:**
- `GetValue<T>(string key, T defaultValue)`: Get configuration value with default
- `GetSection(string sectionName)`: Get configuration section

#### UIHelper Class

```csharp
public static class UIHelper
{
    public static void DisplayBanner();
    public static void DisplayError(string message);
    public static void DisplaySuccess(string message);
    public static void DisplayWarning(string message);
    public static void DisplayInfo(string message);
}
```

**Methods:**
- `DisplayBanner()`: Display RedOps banner
- `DisplayError(string message)`: Display error message with red formatting
- `DisplaySuccess(string message)`: Display success message with green formatting
- `DisplayWarning(string message)`: Display warning message with yellow formatting
- `DisplayInfo(string message)`: Display info message with cyan formatting

## Configuration Schema

### appsettings.json Structure

```json
{
  "Logging": {
    "DefaultLevel": "Information",
    "FileLogging": true,
    "ConsoleLogging": true,
    "LogDirectory": "logs",
    "MaxLogFiles": 10
  },
  "Scanning": {
    "DefaultTimeout": 3000,
    "MaxConcurrentScans": 50,
    "RetryAttempts": 2,
    "CommonPorts": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
  },
  "Plugins": {
    "PluginDirectory": "Plugins",
    "AutoLoadPlugins": true,
    "EnabledCategories": ["Reconnaissance", "Utilities"]
  },
  "Reporting": {
    "AutoSaveReports": true,
    "ReportDirectory": "reports",
    "ReportFormat": "text",
    "IncludeTimestamps": true
  },
  "NetworkDiscovery": {
    "PingTimeout": 3000,
    "PortScanTimeout": 3000,
    "ServiceDetectionTimeout": 5000,
    "OSFingerprintTimeout": 10000,
    "MaxHostsPerScan": 254
  }
}
```

## Error Handling

### Exception Types

RedOps uses standard .NET exceptions with custom messages:

- `ArgumentException`: Invalid input parameters
- `TimeoutException`: Operation timeout exceeded
- `NetworkException`: Network connectivity issues
- `SecurityException`: Security-related errors
- `PluginException`: Plugin execution errors

### Error Codes

Common error scenarios and their handling:

- **Network Unreachable**: Target network not accessible
- **Host Timeout**: Target host not responding within timeout
- **Port Closed**: Target port not accepting connections
- **Service Unresponsive**: Service not providing banner/response
- **Permission Denied**: Insufficient privileges for operation
- **Plugin Load Failed**: Plugin assembly could not be loaded
- **Configuration Invalid**: Invalid configuration values

## Performance Considerations

### Concurrency Limits

Default concurrency settings:
- **MaxConcurrentScans**: 50 (adjustable based on system resources)
- **SemaphoreSlim**: Used to control concurrent operations
- **Task.WhenAll**: For parallel execution of independent operations

### Memory Management

- **Streaming**: Large datasets processed in streams
- **Disposal**: Proper disposal of network resources
- **Garbage Collection**: Minimal object allocation in hot paths

### Network Optimization

- **Connection Pooling**: Reuse connections where possible
- **Timeout Management**: Appropriate timeouts for different operations
- **Rate Limiting**: Prevent network flooding

## Security Considerations

### Input Validation

All user inputs are validated for:
- **IP Address Format**: Valid IPv4/IPv6 addresses
- **Port Ranges**: Valid port numbers (1-65535)
- **File Paths**: Path traversal prevention
- **Command Injection**: Sanitization of shell commands

### Network Safety

- **Rate Limiting**: Prevent DoS conditions
- **Timeout Enforcement**: Prevent hanging operations
- **Resource Limits**: Memory and CPU usage bounds
- **Permission Checks**: Verify required privileges

### Data Protection

- **Credential Handling**: Secure storage and transmission
- **Log Sanitization**: Remove sensitive data from logs
- **Encryption**: Encrypt sensitive configuration data
- **Access Control**: Restrict file and network access

## Integration Examples

### Custom Plugin Integration

```csharp
// Create custom plugin
public class MyPlugin : IPlugin
{
    public string Name => "My Custom Plugin";
    public string Description => "Custom functionality";
    public PluginCategory Category => PluginCategory.Reconnaissance;

    public async Task<bool> ExecuteAsync(PluginContext context)
    {
        // Use RedOps APIs
        var scanner = new PortScanner();
        var results = await scanner.ScanCommonPortsAsync("target.com");
        
        // Log results
        context.Logger.Information($"Found {results.Count} open ports");
        
        return true;
    }
}
```

### Programmatic Usage

```csharp
// Use RedOps components programmatically
var hostDiscoverer = new HostDiscoverer();
var liveHosts = await hostDiscoverer.DiscoverHostsAsync("192.168.1.0/24");

var portScanner = new PortScanner();
foreach (var host in liveHosts)
{
    var openPorts = await portScanner.ScanCommonPortsAsync(host);
    Console.WriteLine($"{host}: {openPorts.Count} open ports");
}
```

### Configuration Integration

```csharp
// Access configuration in plugins
public async Task<bool> ExecuteAsync(PluginContext context)
{
    var timeout = context.Configuration.GetValue<int>("Scanning:DefaultTimeout", 3000);
    var maxConcurrency = context.Configuration.GetValue<int>("Scanning:MaxConcurrentScans", 50);
    
    // Use configuration values
    var scanner = new PortScanner();
    // Configure scanner with values...
    
    return true;
}
```

This API reference provides comprehensive documentation for integrating with and extending RedOps functionality. For additional examples and use cases, refer to the source code and sample plugins.
