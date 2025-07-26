# Plugin Development Guide

RedOps features an extensible plugin architecture that allows developers to create custom functionality. This guide covers everything you need to know to develop, test, and distribute RedOps plugins.

## Overview

The RedOps plugin system is designed around the cyber kill chain methodology, allowing plugins to extend functionality in specific phases of a security assessment.

### Plugin Architecture

```
RedOps.Core.Plugins/
├── IPlugin.cs          # Main plugin interface
├── PluginCategory.cs   # Category enumeration
├── PluginContext.cs    # Runtime context for plugins
└── PluginManager.cs    # Plugin discovery and management
```

### Plugin Categories

Plugins are organized into categories based on the cyber kill chain:

- **Reconnaissance**: Information gathering and target discovery
- **Weaponization**: Payload and exploit development
- **Delivery**: Attack vector delivery mechanisms
- **Exploitation**: Vulnerability exploitation tools
- **Installation**: Persistence and backdoor installation
- **CommandAndControl**: C2 communication and management
- **ActionsOnObjectives**: Data exfiltration and impact operations
- **PostExploitation**: Privilege escalation and lateral movement
- **Reporting**: Report generation and analysis
- **Utilities**: General-purpose tools and helpers

## Getting Started

### Prerequisites

- .NET 8.0 SDK
- RedOps source code
- Visual Studio, VS Code, or preferred IDE
- Basic understanding of C# and async programming

### Development Environment Setup

1. **Clone RedOps Repository**
   ```bash
   git clone https://github.com/benjaminlettner/RedOps.git
   cd RedOps
   ```

2. **Create Plugin Project**
   ```bash
   # Create new class library project
   dotnet new classlib -n MyCustomPlugin
   cd MyCustomPlugin
   
   # Add reference to RedOps core
   dotnet add reference ../RedOps/RedOps.csproj
   ```

3. **Install Required Packages**
   ```bash
   dotnet add package Serilog
   dotnet add package Microsoft.Extensions.Configuration
   ```

## Plugin Interface

### IPlugin Interface

All plugins must implement the `IPlugin` interface:

```csharp
using RedOps.Core.Plugins;

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

### Plugin Properties

- **Name**: Unique identifier for your plugin
- **Description**: Brief description of plugin functionality
- **Category**: Cyber kill chain category
- **ExecuteAsync**: Main plugin execution method

## Creating Your First Plugin

### Basic Plugin Template

```csharp
using RedOps.Core.Plugins;
using Serilog;

namespace MyCustomPlugin
{
    public class ExampleReconPlugin : IPlugin
    {
        public string Name => "Example Reconnaissance Plugin";
        public string Description => "Demonstrates basic reconnaissance functionality";
        public PluginCategory Category => PluginCategory.Reconnaissance;

        public async Task<bool> ExecuteAsync(PluginContext context)
        {
            var logger = context.Logger;
            
            try
            {
                logger.Information($"Starting {Name}");
                
                // Get target from user input
                Console.Write("Enter target IP or hostname: ");
                var target = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(target))
                {
                    logger.Warning("No target specified");
                    return false;
                }
                
                // Perform reconnaissance logic
                await PerformReconnaissance(target, logger);
                
                logger.Information($"{Name} completed successfully");
                return true;
            }
            catch (Exception ex)
            {
                logger.Error($"Error in {Name}: {ex.Message}");
                return false;
            }
        }
        
        private async Task PerformReconnaissance(string target, ILogger logger)
        {
            // Your custom reconnaissance logic here
            logger.Information($"Performing reconnaissance on {target}");
            
            // Example: DNS lookup
            try
            {
                var hostEntry = await Dns.GetHostEntryAsync(target);
                logger.Information($"Resolved {target} to {hostEntry.AddressList[0]}");
            }
            catch (Exception ex)
            {
                logger.Warning($"DNS resolution failed: {ex.Message}");
            }
            
            // Add more reconnaissance techniques...
        }
    }
}
```

### Advanced Plugin Example

```csharp
using RedOps.Core.Plugins;
using RedOps.Modules.Reconnaissance.NetworkDiscovery;
using Serilog;
using Spectre.Console;
using System.Net.NetworkInformation;

namespace MyCustomPlugin
{
    public class AdvancedPortScannerPlugin : IPlugin
    {
        public string Name => "Advanced Port Scanner";
        public string Description => "Custom port scanner with advanced features";
        public PluginCategory Category => PluginCategory.Reconnaissance;

        public async Task<bool> ExecuteAsync(PluginContext context)
        {
            var logger = context.Logger;
            
            try
            {
                // Get scan parameters from user
                var config = GetScanConfiguration();
                if (config == null) return false;
                
                // Display scan information
                DisplayScanInfo(config);
                
                // Perform scan
                var results = await PerformAdvancedScan(config, logger);
                
                // Display results
                DisplayResults(results);
                
                // Save results if requested
                if (AnsiConsole.Confirm("Save results to file?"))
                {
                    await SaveResults(results, config.Target);
                }
                
                return true;
            }
            catch (Exception ex)
            {
                logger.Error($"Error in {Name}: {ex.Message}");
                AnsiConsole.MarkupLine($"[red]Error: {ex.Message}[/]");
                return false;
            }
        }
        
        private ScanConfiguration GetScanConfiguration()
        {
            var config = new ScanConfiguration();
            
            // Target input
            config.Target = AnsiConsole.Ask<string>("Enter target IP or hostname:");
            
            // Port range selection
            var portOption = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("Select port range:")
                    .AddChoices("Common ports", "Full range (1-65535)", "Custom range"));
            
            switch (portOption)
            {
                case "Common ports":
                    config.Ports = new[] { 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306 };
                    break;
                case "Full range (1-65535)":
                    config.StartPort = 1;
                    config.EndPort = 65535;
                    break;
                case "Custom range":
                    config.StartPort = AnsiConsole.Ask<int>("Start port:");
                    config.EndPort = AnsiConsole.Ask<int>("End port:");
                    break;
            }
            
            // Scan options
            config.Timeout = AnsiConsole.Ask("Timeout (ms):", 3000);
            config.MaxConcurrency = AnsiConsole.Ask("Max concurrent scans:", 50);
            config.IncludeUDP = AnsiConsole.Confirm("Include UDP scan?");
            
            return config;
        }
        
        private async Task<List<ScanResult>> PerformAdvancedScan(ScanConfiguration config, ILogger logger)
        {
            var results = new List<ScanResult>();
            var ports = config.Ports ?? Enumerable.Range(config.StartPort, config.EndPort - config.StartPort + 1);
            
            await AnsiConsole.Progress()
                .StartAsync(async ctx =>
                {
                    var task = ctx.AddTask("[green]Scanning ports...[/]");
                    task.MaxValue = ports.Count();
                    
                    var semaphore = new SemaphoreSlim(config.MaxConcurrency);
                    var tasks = ports.Select(async port =>
                    {
                        await semaphore.WaitAsync();
                        try
                        {
                            var result = await ScanPort(config.Target, port, config.Timeout, logger);
                            if (result != null)
                            {
                                lock (results)
                                {
                                    results.Add(result);
                                }
                            }
                            task.Increment(1);
                        }
                        finally
                        {
                            semaphore.Release();
                        }
                    });
                    
                    await Task.WhenAll(tasks);
                });
            
            return results.OrderBy(r => r.Port).ToList();
        }
        
        private async Task<ScanResult> ScanPort(string target, int port, int timeout, ILogger logger)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(target, port);
                
                if (await Task.WhenAny(connectTask, Task.Delay(timeout)) == connectTask)
                {
                    if (client.Connected)
                    {
                        // Try to grab banner
                        var banner = await GrabBanner(client, timeout);
                        
                        return new ScanResult
                        {
                            Port = port,
                            IsOpen = true,
                            Service = IdentifyService(port, banner),
                            Banner = banner,
                            ResponseTime = DateTime.Now
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                logger.Debug($"Port {port} scan failed: {ex.Message}");
            }
            
            return null;
        }
        
        // Additional helper methods...
    }
    
    public class ScanConfiguration
    {
        public string Target { get; set; }
        public int[]? Ports { get; set; }
        public int StartPort { get; set; }
        public int EndPort { get; set; }
        public int Timeout { get; set; }
        public int MaxConcurrency { get; set; }
        public bool IncludeUDP { get; set; }
    }
    
    public class ScanResult
    {
        public int Port { get; set; }
        public bool IsOpen { get; set; }
        public string Service { get; set; }
        public string Banner { get; set; }
        public DateTime ResponseTime { get; set; }
    }
}
```

## Plugin Context

The `PluginContext` provides access to shared services and configuration:

```csharp
public class PluginContext
{
    public ILogger Logger { get; set; }
    public IConfiguration Configuration { get; set; }
    public Dictionary<string, object> SharedData { get; set; }
    
    public PluginContext()
    {
        SharedData = new Dictionary<string, object>();
    }
}
```

### Using Plugin Context

```csharp
public async Task<bool> ExecuteAsync(PluginContext context)
{
    // Access logger
    var logger = context.Logger;
    logger.Information("Plugin started");
    
    // Access configuration
    var timeout = context.Configuration.GetValue<int>("Scanning:DefaultTimeout", 3000);
    
    // Share data between plugins
    context.SharedData["MyPluginResults"] = results;
    
    // Access shared data from other plugins
    if (context.SharedData.ContainsKey("PreviousResults"))
    {
        var previousResults = context.SharedData["PreviousResults"];
        // Use previous results...
    }
    
    return true;
}
```

## Building and Testing

### Building Your Plugin

```bash
# Build the plugin
dotnet build --configuration Release

# The output will be in bin/Release/net8.0/
```

### Testing Your Plugin

1. **Copy to Plugins Directory**
   ```bash
   # Copy built DLL to RedOps plugins directory
   cp bin/Release/net8.0/MyCustomPlugin.dll ../RedOps/bin/Release/net8.0/Plugins/
   ```

2. **Test in RedOps**
   ```bash
   cd ../RedOps
   dotnet run
   # Navigate to Plugin Management to see your plugin
   ```

3. **Debug Your Plugin**
   ```csharp
   // Add debug logging
   logger.Debug("Debug information here");
   
   // Use breakpoints in your IDE
   // Attach debugger to running RedOps process
   ```

## Best Practices

### Code Quality

1. **Error Handling**
   ```csharp
   public async Task<bool> ExecuteAsync(PluginContext context)
   {
       try
       {
           // Plugin logic
           return true;
       }
       catch (Exception ex)
       {
           context.Logger.Error($"Plugin error: {ex.Message}");
           return false;
       }
   }
   ```

2. **Async/Await Patterns**
   ```csharp
   // Use ConfigureAwait(false) for library code
   await SomeAsyncOperation().ConfigureAwait(false);
   
   // Use proper cancellation tokens
   public async Task<bool> ExecuteAsync(PluginContext context, CancellationToken cancellationToken = default)
   {
       // Check for cancellation
       cancellationToken.ThrowIfCancellationRequested();
   }
   ```

3. **Resource Management**
   ```csharp
   // Dispose resources properly
   using var client = new HttpClient();
   using var stream = new FileStream(path, FileMode.Open);
   
   // Use semaphores for concurrency control
   using var semaphore = new SemaphoreSlim(maxConcurrency);
   ```

### User Experience

1. **Clear Output**
   ```csharp
   // Use Spectre.Console for rich output
   AnsiConsole.MarkupLine("[green]Success:[/] Operation completed");
   AnsiConsole.MarkupLine("[red]Error:[/] Something went wrong");
   
   // Show progress for long operations
   await AnsiConsole.Progress().StartAsync(async ctx =>
   {
       var task = ctx.AddTask("[green]Processing...[/]");
       // Update progress: task.Increment(1);
   });
   ```

2. **Input Validation**
   ```csharp
   // Validate user input
   var target = AnsiConsole.Ask<string>("Enter target:");
   if (string.IsNullOrWhiteSpace(target))
   {
       AnsiConsole.MarkupLine("[red]Error: Target cannot be empty[/]");
       return false;
   }
   
   // Use regex for validation
   if (!Regex.IsMatch(target, @"^[\w\.-]+$"))
   {
       AnsiConsole.MarkupLine("[red]Error: Invalid target format[/]");
       return false;
   }
   ```

3. **Configuration Options**
   ```csharp
   // Allow configuration through appsettings.json
   var config = context.Configuration.GetSection("MyPlugin");
   var defaultTimeout = config.GetValue<int>("DefaultTimeout", 3000);
   ```

### Security Considerations

1. **Input Sanitization**
   ```csharp
   // Sanitize file paths
   var safePath = Path.GetFullPath(userInput);
   if (!safePath.StartsWith(allowedDirectory))
   {
       throw new SecurityException("Path traversal detected");
   }
   ```

2. **Network Safety**
   ```csharp
   // Implement rate limiting
   private readonly SemaphoreSlim _rateLimiter = new(10, 10);
   
   // Add timeouts to prevent hanging
   using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
   ```

3. **Credential Handling**
   ```csharp
   // Never log credentials
   logger.Information($"Connecting to {target}"); // Don't log password
   
   // Use SecureString for sensitive data
   // Clear sensitive data after use
   Array.Clear(passwordBytes, 0, passwordBytes.Length);
   ```

## Distribution

### Packaging Your Plugin

1. **Create NuGet Package**
   ```xml
   <!-- In your .csproj file -->
   <PropertyGroup>
     <PackageId>RedOps.Plugin.MyCustomPlugin</PackageId>
     <Version>1.0.0</Version>
     <Authors>Your Name</Authors>
     <Description>Custom plugin for RedOps</Description>
     <PackageTags>redops;plugin;security;pentest</PackageTags>
   </PropertyGroup>
   ```

2. **Build Package**
   ```bash
   dotnet pack --configuration Release
   ```

### Plugin Metadata

Include metadata in your plugin:

```csharp
[assembly: AssemblyTitle("My Custom Plugin")]
[assembly: AssemblyDescription("Advanced reconnaissance plugin for RedOps")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
```

### Documentation

Create comprehensive documentation:

```
MyCustomPlugin/
├── README.md           # Plugin overview and usage
├── CHANGELOG.md        # Version history
├── docs/
│   ├── configuration.md
│   ├── examples.md
│   └── api-reference.md
└── samples/
    └── example-usage.cs
```

## Advanced Topics

### Plugin Dependencies

```csharp
// Handle plugin dependencies
public class MyPlugin : IPlugin
{
    private readonly IRequiredService _service;
    
    public MyPlugin()
    {
        // Initialize dependencies
        _service = new RequiredService();
    }
}
```

### Plugin Communication

```csharp
// Plugins can communicate through shared context
public async Task<bool> ExecuteAsync(PluginContext context)
{
    // Store results for other plugins
    context.SharedData["NetworkScanResults"] = scanResults;
    
    // Access results from previous plugins
    if (context.SharedData.TryGetValue("HostDiscoveryResults", out var hosts))
    {
        var hostList = (List<string>)hosts;
        // Use discovered hosts
    }
    
    return true;
}
```

### Plugin Lifecycle

```csharp
public interface IAdvancedPlugin : IPlugin
{
    Task InitializeAsync(PluginContext context);
    Task CleanupAsync(PluginContext context);
}

public class MyAdvancedPlugin : IAdvancedPlugin
{
    public async Task InitializeAsync(PluginContext context)
    {
        // Plugin initialization logic
        context.Logger.Information("Plugin initialized");
    }
    
    public async Task<bool> ExecuteAsync(PluginContext context)
    {
        // Main plugin logic
        return true;
    }
    
    public async Task CleanupAsync(PluginContext context)
    {
        // Cleanup resources
        context.Logger.Information("Plugin cleanup completed");
    }
}
```

## Example Plugins

### Simple WHOIS Plugin

```csharp
public class WhoisPlugin : IPlugin
{
    public string Name => "WHOIS Lookup";
    public string Description => "Performs WHOIS lookups for domains";
    public PluginCategory Category => PluginCategory.Reconnaissance;

    public async Task<bool> ExecuteAsync(PluginContext context)
    {
        var domain = AnsiConsole.Ask<string>("Enter domain name:");
        
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync("whois.internic.net", 43);
            
            using var stream = client.GetStream();
            using var writer = new StreamWriter(stream);
            using var reader = new StreamReader(stream);
            
            await writer.WriteLineAsync(domain);
            await writer.FlushAsync();
            
            var response = await reader.ReadToEndAsync();
            
            AnsiConsole.WriteLine(response);
            return true;
        }
        catch (Exception ex)
        {
            context.Logger.Error($"WHOIS lookup failed: {ex.Message}");
            return false;
        }
    }
}
```

### HTTP Header Analysis Plugin

```csharp
public class HttpHeaderAnalysisPlugin : IPlugin
{
    public string Name => "HTTP Header Analysis";
    public string Description => "Analyzes HTTP headers for security information";
    public PluginCategory Category => PluginCategory.Reconnaissance;

    public async Task<bool> ExecuteAsync(PluginContext context)
    {
        var url = AnsiConsole.Ask<string>("Enter URL:");
        
        try
        {
            using var client = new HttpClient();
            var response = await client.GetAsync(url);
            
            var table = new Table();
            table.AddColumn("Header");
            table.AddColumn("Value");
            
            foreach (var header in response.Headers)
            {
                table.AddRow(header.Key, string.Join(", ", header.Value));
            }
            
            AnsiConsole.Write(table);
            
            // Analyze security headers
            AnalyzeSecurityHeaders(response.Headers, context.Logger);
            
            return true;
        }
        catch (Exception ex)
        {
            context.Logger.Error($"HTTP analysis failed: {ex.Message}");
            return false;
        }
    }
    
    private void AnalyzeSecurityHeaders(HttpResponseHeaders headers, ILogger logger)
    {
        var securityHeaders = new[]
        {
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection"
        };
        
        foreach (var header in securityHeaders)
        {
            if (headers.Contains(header))
            {
                AnsiConsole.MarkupLine($"[green]✓[/] {header} present");
            }
            else
            {
                AnsiConsole.MarkupLine($"[red]✗[/] {header} missing");
            }
        }
    }
}
```

## Contributing to RedOps

### Plugin Submission Process

1. **Fork the Repository**
2. **Create Plugin Branch**
3. **Develop and Test Plugin**
4. **Submit Pull Request**
5. **Code Review Process**
6. **Integration Testing**
7. **Documentation Review**
8. **Merge and Release**

### Plugin Standards

All contributed plugins must meet:
- Code quality standards
- Security requirements
- Documentation completeness
- Test coverage requirements
- Performance benchmarks

## Support and Community

### Getting Help

- **GitHub Issues**: Report bugs and request features
- **Discussions**: Ask questions and share ideas
- **Documentation**: Comprehensive guides and examples
- **Code Reviews**: Community feedback on plugins

### Contributing

- Submit bug reports and feature requests
- Contribute code improvements
- Write documentation and tutorials
- Help other developers in discussions

This plugin development guide provides everything needed to create powerful, secure, and user-friendly plugins for RedOps. Happy coding!
