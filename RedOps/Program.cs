using Spectre.Console;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using RedOps.Core.Plugins;
using RedOps.Modules.Reconnaissance.NetworkDiscovery;
using RedOps.Modules.Reconnaissance.WebApplicationRecon;
using RedOps.Utils;
using Serilog;
using System.Threading.Tasks;

public class Program
{
    public static async Task Main(string[] args)
    {
        Logger.Initialize();
        // ConfigHelper.Initialize(); // Removed: Configuration is loaded on-demand by ConfigHelper

        // Initialize and load plugins
        var pluginManager = new PluginManager(Logger.SerilogInstance);
        pluginManager.LoadPlugins(); // Uses default "Plugins" directory
        Logger.Information($"Loaded {pluginManager.GetPlugins().Count()} plugins."); // Corrected to Information

        Console.Title = "RedOps - Offensive Security Tool";
        bool showMainMenu = true;
        while (showMainMenu)
        {
            UIHelper.DisplayHeader("Main Menu");

            if (AnsiConsole.Profile.Capabilities.Interactive)
            {
                var originalChoices = new[] {
                    "📡 Reconnaissance", "🎯 Weaponization & Delivery", "💥 Exploitation",
                    "💻 Command & Control", "🏁 Actions on Objectives", "📊 Reporting & Analysis",
                    "🚪 Exit"
                };

                var selectionPrompt = new SelectionPrompt<string>()
                    .Title(string.Empty)
                    .PageSize(10)
                    .MoreChoicesText("[grey](Move up and down to reveal more options)[/]")
                    .AddChoices(originalChoices) 
                    .UseConverter(choice => {     
                        var choiceDisplayLength = Markup.Remove(choice).Length;
                        int paddingLength = (AnsiConsole.Profile.Width - choiceDisplayLength) / 2;
                        string padding = new string(' ', Math.Max(0, paddingLength));
                        return padding + choice; 
                    });

                string choice = AnsiConsole.Prompt(selectionPrompt); 

                switch (choice)
                {
                    case "📡 Reconnaissance":
                        await ShowReconnaissanceMenu(pluginManager); 
                        break;
                    case "🚪 Exit":
                        showMainMenu = false;
                        AnsiConsole.MarkupLine("[green]Exiting RedOps. Goodbye![/]");
                        break;
                    default:
                        AnsiConsole.MarkupLine($"You selected: [yellow]{choice.Replace("[", "[[").Replace("]", "]]")}[/]");
                        AnsiConsole.MarkupLine("[grey]This main menu option is not yet implemented. Press any key to return.[/]");
                        AnsiConsole.Console.Input.ReadKey(true);
                        break;
                }
            }
            else
            {
                AnsiConsole.MarkupLine("Non-interactive terminal detected. RedOps requires an interactive terminal.");
                showMainMenu = false; 
            }
        }
    }

    private static async Task ShowReconnaissanceMenu(PluginManager pluginManager)
    {
        bool showReconMenu = true;
        while (showReconMenu)
        {
            UIHelper.DisplayHeader("Reconnaissance Menu");

            var choices = new List<string> { "🌐 Network Discovery", "🌍 OSINT & Information Gathering", "🔎 Web Application Recon", "↩️ Back to Main Menu" };

            // Dynamically add plugins for Reconnaissance category
            var reconPlugins = pluginManager.GetPluginsByCategory(PluginCategory.Reconnaissance);
            foreach (var plugin in reconPlugins)
            {
                choices.Insert(choices.Count - 1, $"[yellow]🔌 {plugin.Name}[/]"); // Insert before 'Back to Main Menu'
            }

            var selectionPrompt = new SelectionPrompt<string>()
                .Title(string.Empty)
                .PageSize(10)
                .MoreChoicesText("[grey](Move up and down to reveal more options)[/]")
                .AddChoices(choices)
                .UseConverter(choiceText => {
                    var choiceDisplayLength = Markup.Remove(choiceText).Length;
                    int paddingLength = (AnsiConsole.Profile.Width - choiceDisplayLength) / 2;
                    string padding = new string(' ', Math.Max(0, paddingLength));
                    return padding + choiceText;
                });

            string selectedOption = AnsiConsole.Prompt(selectionPrompt);

            // Handle plugin selection
            var selectedPlugin = reconPlugins.FirstOrDefault(p => selectedOption.Contains(p.Name));
            if (selectedPlugin != null)
            {
                AnsiConsole.MarkupLine($"Executing plugin: [yellow]{selectedPlugin.Name}[/]...");
                var pluginContext = new PluginContext(Logger.SerilogInstance);
                try
                {
                    await selectedPlugin.ExecuteAsync(pluginContext);
                    AnsiConsole.MarkupLine($"Finished executing plugin: [green]{selectedPlugin.Name}[/]. Press any key to continue.");
                }
                catch (Exception ex)
                {
                    Logger.Error($"Error executing plugin {selectedPlugin.Name}", ex);
                    AnsiConsole.MarkupLine($"[red]Error executing plugin {selectedPlugin.Name}: {ex.Message}[/]. Press any key to continue.");
                }
                AnsiConsole.Console.Input.ReadKey(true);
            }
            else
            {
                switch (selectedOption)
                {
                    case "🌐 Network Discovery":
                        await ShowNetworkDiscoveryMenu();
                        break;
                    case "🔎 Web Application Recon":
                        await ShowWebApplicationReconMenu();
                        break;
                    case "↩️ Back to Main Menu":
                        showReconMenu = false;
                        return;
                    default:
                        AnsiConsole.MarkupLine($"You selected: [yellow]{selectedOption.Replace("[", "[[").Replace("]", "]]")}[/]");
                        AnsiConsole.MarkupLine("[grey]This reconnaissance option is not yet implemented. Press any key to return.[/]");
                        AnsiConsole.Console.Input.ReadKey(true);
                        break;
                }
            }
        }
    }

    public static async Task ShowNetworkDiscoveryMenu()
    {
        bool showNetDiscoveryMenu = true;
        while(showNetDiscoveryMenu)
        {
            UIHelper.DisplayHeader("Network Discovery Menu");

            var originalChoices = new[] {
                "🚀 Comprehensive Port Scan (TCP & UDP)", 
                "📍 Host Discovery (ICMP, ARP)", 
                "🐾 OS Fingerprinting", 
                "🗺️ Network Mapping Visualization",
                "↩️ Back to Reconnaissance Menu"
            };

            var selectionPrompt = new SelectionPrompt<string>()
                .Title(string.Empty)
                .PageSize(10)
                .MoreChoicesText("[grey](Move up and down to reveal more options)[/]")
                .AddChoices(originalChoices)
                .UseConverter(choice => {
                    var choiceDisplayLength = Markup.Remove(choice).Length;
                    int paddingLength = (AnsiConsole.Profile.Width - choiceDisplayLength) / 2;
                    string padding = new string(' ', Math.Max(0, paddingLength));
                    return padding + choice;
                });

            string choice = AnsiConsole.Prompt(selectionPrompt);

            switch (choice)
            {
                case "🚀 Comprehensive Port Scan (TCP & UDP)": 
                    await PortScanner.ExecuteComprehensiveScanAsync(); 
                    break;
                case "📍 Host Discovery (ICMP, ARP)": 
                    await HostDiscoverer.ExecuteIcmpScanAsync(); 
                    break;
                case "🐾 OS Fingerprinting":
                    await ExecuteOSFingerprintingAsync();
                    break;
                case "🗺️ Network Mapping Visualization":
                    await ExecuteNetworkMappingAsync();
                    break;
                case "↩️ Back to Reconnaissance Menu":
                    showNetDiscoveryMenu = false; 
                    return;
                default:
                    AnsiConsole.MarkupLine($"You selected: [yellow]{choice.Replace("[", "[[").Replace("]", "]]")}[/]");
                    AnsiConsole.MarkupLine("[grey]This network discovery option is not yet implemented. Press any key to return.[/]");
                    AnsiConsole.Console.Input.ReadKey(true);
                    break;
            }
        }
    }

    private static async Task ExecuteOSFingerprintingAsync()
    {
        try
        {
            UIHelper.DisplayHeader("OS Fingerprinting");
            
            // Get target IP address from user
            string targetIp = AnsiConsole.Ask<string>("[green]Enter target IP address:[/]");
            
            // Validate IP address
            if (!System.Net.IPAddress.TryParse(targetIp, out _))
            {
                AnsiConsole.MarkupLine("[red]Invalid IP address format![/]");
                AnsiConsole.MarkupLine("Press any key to continue...");
                AnsiConsole.Console.Input.ReadKey(true);
                return;
            }

            AnsiConsole.MarkupLine($"[yellow]Starting OS fingerprinting for {targetIp}...[/]");
            
            // First, perform a quick port scan to get open ports
            var commonPorts = new[] { 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3389, 5900 };
            
            AnsiConsole.MarkupLine("[cyan]Scanning common ports for service detection...[/]");
            var openPorts = new List<OpenPortInfo>();
            
            await AnsiConsole.Progress()
                .StartAsync(async ctx =>
                {
                    var task = ctx.AddTask("[green]Scanning ports...[/]");
                    task.MaxValue = commonPorts.Length;
                    
                    foreach (var port in commonPorts)
                    {
                        var portInfo = await ScanSinglePortAsync(targetIp, port);
                        if (portInfo != null)
                        {
                            openPorts.Add(portInfo);
                        }
                        task.Increment(1);
                    }
                });

            if (openPorts.Count == 0)
            {
                AnsiConsole.MarkupLine("[yellow]No open ports found on common ports. Proceeding with basic OS fingerprinting...[/]");
            }
            else
            {
                AnsiConsole.MarkupLine($"[green]Found {openPorts.Count} open ports. Performing service detection...[/]");
                
                // Perform service detection on open ports
                var serviceDetector = new ServiceDetector();
                openPorts = await serviceDetector.DetectServicesAsync(openPorts);
            }

            // Perform OS fingerprinting
            AnsiConsole.MarkupLine("[cyan]Performing OS fingerprinting...[/]");
            var osFingerprinter = new OSFingerprinter();
            var fingerprintResult = await osFingerprinter.FingerprintOSAsync(targetIp, openPorts);

            // Display results
            UIHelper.DisplayHeader("OS Fingerprinting Results");
            
            var table = new Table();
            table.AddColumn("[bold]Property[/]");
            table.AddColumn("[bold]Value[/]");
            
            table.AddRow("Target IP", fingerprintResult.IpAddress);
            table.AddRow("Operating System", $"[yellow]{fingerprintResult.OperatingSystem}[/]");
            table.AddRow("OS Version", fingerprintResult.OSVersion ?? "Unknown");
            table.AddRow("Confidence", GetConfidenceColor(fingerprintResult.Confidence));
            table.AddRow("TTL Value", fingerprintResult.TTL.ToString());
            table.AddRow("Open Ports", string.Join(", ", fingerprintResult.OpenPorts));
            
            AnsiConsole.Write(table);
            
            if (fingerprintResult.Evidence.Count > 0)
            {
                AnsiConsole.MarkupLine("\n[bold]Evidence:[/]");
                foreach (var evidence in fingerprintResult.Evidence)
                {
                    AnsiConsole.MarkupLine($"  • {evidence}");
                }
            }

            if (openPorts.Count > 0)
            {
                AnsiConsole.MarkupLine("\n[bold]Detected Services:[/]");
                var serviceTable = new Table();
                serviceTable.AddColumn("[bold]Port[/]");
                serviceTable.AddColumn("[bold]Protocol[/]");
                serviceTable.AddColumn("[bold]Service[/]");
                serviceTable.AddColumn("[bold]Version[/]");
                
                foreach (var port in openPorts)
                {
                    serviceTable.AddRow(
                        port.Port.ToString(),
                        port.Protocol,
                        port.ServiceName ?? "Unknown",
                        port.ServiceVersion ?? "Unknown"
                    );
                }
                
                AnsiConsole.Write(serviceTable);
            }
            
            Logger.Information($"OS fingerprinting completed for {targetIp}: {fingerprintResult.OperatingSystem} ({fingerprintResult.Confidence} confidence)");
        }
        catch (Exception ex)
        {
            Logger.Error($"Error during OS fingerprinting: {ex.Message}");
            AnsiConsole.MarkupLine($"[red]Error during OS fingerprinting: {ex.Message}[/]");
        }
        
        AnsiConsole.MarkupLine("\nPress any key to continue...");
        AnsiConsole.Console.Input.ReadKey(true);
    }
    
    private static string GetConfidenceColor(string confidence)
    {
        return confidence.ToLower() switch
        {
            "high" => "[green]High[/]",
            "medium" => "[yellow]Medium[/]",
            "low" => "[orange1]Low[/]",
            _ => "[red]Very Low[/]"
        };
    }
    
    private static async Task<OpenPortInfo?> ScanSinglePortAsync(string targetIp, int port)
    {
        try
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(IPAddress.Parse(targetIp), port);
            
            if (await Task.WhenAny(connectTask, Task.Delay(2000)) == connectTask && client.Connected)
            {
                // Port is open, create OpenPortInfo object
                var portInfo = new OpenPortInfo(IPAddress.Parse(targetIp), port, "TCP");
                
                // Try to grab banner if possible
                try
                {
                    using var stream = client.GetStream();
                    stream.ReadTimeout = 1000;
                    byte[] buffer = new byte[1024];
                    
                    var readTask = stream.ReadAsync(buffer, 0, buffer.Length);
                    if (await Task.WhenAny(readTask, Task.Delay(1000)) == readTask)
                    {
                        int bytesRead = await readTask;
                        if (bytesRead > 0)
                        {
                            portInfo.Banner = System.Text.Encoding.ASCII.GetString(buffer, 0, bytesRead).Trim();
                        }
                    }
                }
                catch
                {
                    // Banner grabbing failed, but port is still open
                }
                
                return portInfo;
            }
        }
        catch
        {
            // Port is closed or connection failed
        }
        
        return null;
    }
    
    private static async Task ExecuteNetworkMappingAsync()
    {
        try
        {
            UIHelper.DisplayHeader("Network Mapping Visualization");
            
            // Get target network range from user
            string networkRange = AnsiConsole.Ask<string>("[green]Enter network range (e.g., 192.168.1.0/24 or 192.168.1.1-254):[/]");
            
            // Validate network range format
            if (string.IsNullOrWhiteSpace(networkRange))
            {
                AnsiConsole.MarkupLine("[red]Invalid network range format![/]");
                AnsiConsole.MarkupLine("Press any key to continue...");
                AnsiConsole.Console.Input.ReadKey(true);
                return;
            }

            AnsiConsole.MarkupLine($"[yellow]Starting comprehensive network mapping for {networkRange}...[/]");
            AnsiConsole.MarkupLine("[grey]This process will perform host discovery, port scanning, service detection, and OS fingerprinting.[/]");
            
            // Confirm before starting intensive scan
            if (!AnsiConsole.Confirm("[yellow]This may take several minutes. Continue?[/]"))
            {
                AnsiConsole.MarkupLine("[grey]Network mapping cancelled.[/]");
                AnsiConsole.MarkupLine("Press any key to continue...");
                AnsiConsole.Console.Input.ReadKey(true);
                return;
            }
            
            // Create network mapper and perform mapping
            var networkMapper = new NetworkMapper();
            var networkMap = await networkMapper.CreateNetworkMapAsync(networkRange);
            
            // Display the network map visualization
            networkMapper.DisplayNetworkMap(networkMap);
            
            // Offer to save results
            if (AnsiConsole.Confirm("[yellow]Would you like to save the network map to a file?[/]"))
            {
                await SaveNetworkMapAsync(networkMap);
            }
            
            Logger.Information($"Network mapping completed for {networkRange}. Found {networkMap.AliveHosts} live hosts with {networkMap.TotalServices} services");
        }
        catch (Exception ex)
        {
            Logger.Error($"Error during network mapping: {ex.Message}");
            AnsiConsole.MarkupLine($"[red]Error during network mapping: {ex.Message}[/]");
        }
        
        AnsiConsole.MarkupLine("\nPress any key to continue...");
        AnsiConsole.Console.Input.ReadKey(true);
    }
    
    private static async Task SaveNetworkMapAsync(NetworkMapper.NetworkMap networkMap)
    {
        try
        {
            var fileName = $"network_map_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
            var filePath = Path.Combine(Environment.CurrentDirectory, fileName);
            
            var report = new StringBuilder();
            report.AppendLine("=== REDOPS NETWORK MAP REPORT ===");
            report.AppendLine($"Generated: {networkMap.ScanTime:yyyy-MM-dd HH:mm:ss}");
            report.AppendLine($"Network Range: {networkMap.NetworkRange}");
            report.AppendLine($"Scan Duration: {networkMap.ScanDuration.TotalSeconds:F1} seconds");
            report.AppendLine($"Live Hosts: {networkMap.AliveHosts}");
            report.AppendLine($"Total Services: {networkMap.TotalServices}");
            report.AppendLine();
            
            if (networkMap.OSDistribution.Any())
            {
                report.AppendLine("=== OPERATING SYSTEM DISTRIBUTION ===");
                foreach (var os in networkMap.OSDistribution.OrderByDescending(x => x.Value))
                {
                    report.AppendLine($"{os.Key}: {os.Value} hosts");
                }
                report.AppendLine();
            }
            
            report.AppendLine("=== DISCOVERED HOSTS ===");
            foreach (var host in networkMap.Nodes.Where(n => n.IsAlive).OrderBy(n => n.IpAddress.ToString()))
            {
                report.AppendLine($"Host: {host.IpAddress}");
                report.AppendLine($"  Hostname: {host.Hostname}");
                report.AppendLine($"  Operating System: {host.OperatingSystem} ({host.OSConfidence} confidence)");
                report.AppendLine($"  Response Time: {host.ResponseTime}ms");
                report.AppendLine($"  TTL: {host.TTL}");
                
                if (host.Services.Any())
                {
                    report.AppendLine("  Services:");
                    foreach (var service in host.Services.OrderBy(s => s.Port))
                    {
                        report.AppendLine($"    {service.Port}/{service.Protocol} - {service.ServiceName} {service.Version}");
                        if (!string.IsNullOrEmpty(service.Banner))
                        {
                            report.AppendLine($"      Banner: {service.Banner}");
                        }
                    }
                }
                else
                {
                    report.AppendLine("  Services: None detected");
                }
                report.AppendLine();
            }
            
            await File.WriteAllTextAsync(filePath, report.ToString());
            AnsiConsole.MarkupLine($"[green]Network map saved to: {fileName}[/]");
            Logger.Information($"Network map report saved to {filePath}");
        }
        catch (Exception ex)
        {
            Logger.Error($"Error saving network map: {ex.Message}");
            AnsiConsole.MarkupLine($"[red]Error saving network map: {ex.Message}[/]");
        }
    }

    private static async Task ShowWebApplicationReconMenu()
    {
        bool showWebReconMenu = true;
        while (showWebReconMenu)
        {
            UIHelper.DisplayHeader("Web Application Reconnaissance Menu");

            var originalChoices = new[] {
                "🌐 Web Server Fingerprinting",
                "📁 Directory and File Enumeration",
                "🔍 Subdomain Enumeration",
                "🔒 SSL/TLS Certificate Analysis",
                "🔗 API Endpoint Discovery",
                "↩️ Back to Reconnaissance Menu"
            };

            var selectionPrompt = new SelectionPrompt<string>()
                .Title(string.Empty)
                .PageSize(10)
                .MoreChoicesText("[grey](Move up and down to reveal more options)[/]")
                .AddChoices(originalChoices)
                .UseConverter(choice => {
                    var choiceDisplayLength = Markup.Remove(choice).Length;
                    int paddingLength = (AnsiConsole.Profile.Width - choiceDisplayLength) / 2;
                    string padding = new string(' ', Math.Max(0, paddingLength));
                    return padding + choice;
                });

            string choice = AnsiConsole.Prompt(selectionPrompt);

            switch (choice)
            {
                case "🌐 Web Server Fingerprinting":
                    await ExecuteWebServerFingerprintingAsync();
                    break;
                case "📁 Directory and File Enumeration":
                    await ExecuteDirectoryEnumerationAsync();
                    break;
                case "🔍 Subdomain Enumeration":
                    await ExecuteSubdomainEnumerationAsync();
                    break;
                case "🔒 SSL/TLS Certificate Analysis":
                    await ExecuteSslCertificateAnalysisAsync();
                    break;
                case "🔗 API Endpoint Discovery":
                    await ExecuteApiEndpointDiscoveryAsync();
                    break;
                case "↩️ Back to Reconnaissance Menu":
                    showWebReconMenu = false;
                    return;
                default:
                    var escapedChoice = choice.Replace("[", "[[").Replace("]", "]]");
                    AnsiConsole.MarkupLine($"You selected: [yellow]{escapedChoice}[/]");
                    AnsiConsole.MarkupLine("[grey]This web application reconnaissance option is not yet implemented. Press any key to return.[/]");
                    AnsiConsole.Console.Input.ReadKey(true);
                    break;
            }
        }
    }

    private static async Task ExecuteWebServerFingerprintingAsync()
    {
        try
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[red]Web Server Fingerprinting[/]").RuleStyle("grey"));
            AnsiConsole.WriteLine();

            var target = AnsiConsole.Ask<string>("Enter target URL or domain (e.g., example.com or https://example.com):");

            if (string.IsNullOrWhiteSpace(target))
            {
                AnsiConsole.MarkupLine("[red]Error: Target cannot be empty[/]");
                AnsiConsole.MarkupLine("Press any key to return...");
                AnsiConsole.Console.Input.ReadKey(true);
                return;
            }

            Logger.Information($"Starting web server fingerprinting for {target}");

            using var fingerprinter = new WebServerFingerprinter();
            
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[cyan]Analyzing web server...[/]");
            
            var webServerInfo = await fingerprinter.FingerprintWebServerAsync(target);
            
            fingerprinter.DisplayWebServerInfo(webServerInfo);

            // Ask if user wants to save results
            if (AnsiConsole.Confirm("Save results to file?"))
            {
                await SaveWebServerResults(webServerInfo);
            }

            AnsiConsole.MarkupLine("\n[grey]Press any key to return to menu...[/]");
            AnsiConsole.Console.Input.ReadKey(true);
        }
        catch (Exception ex)
        {
            Logger.Error($"Error during web server fingerprinting: {ex.Message}");
            AnsiConsole.MarkupLine($"[red]Error: {ex.Message}[/]");
            AnsiConsole.MarkupLine("Press any key to return...");
            AnsiConsole.Console.Input.ReadKey(true);
        }
    }

    private static async Task SaveWebServerResults(WebServerInfo webServerInfo)
    {
        try
        {
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var fileName = $"webserver_fingerprint_{timestamp}.txt";
            var filePath = Path.Combine(Directory.GetCurrentDirectory(), fileName);

            var report = new StringBuilder();
            report.AppendLine("=== Web Server Fingerprinting Report ===");
            report.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            report.AppendLine($"Target: {webServerInfo.Url}");
            report.AppendLine();

            report.AppendLine("=== Basic Information ===");
            report.AppendLine($"Status Code: {webServerInfo.StatusCode} {webServerInfo.StatusDescription}");
            report.AppendLine($"Accessible: {webServerInfo.IsAccessible}");
            report.AppendLine($"Server Software: {webServerInfo.ServerSoftware}");
            report.AppendLine($"Server Type: {webServerInfo.WebServerType}");
            report.AppendLine($"Server Version: {webServerInfo.ServerVersion}");
            
            if (!string.IsNullOrEmpty(webServerInfo.PoweredBy))
                report.AppendLine($"Powered By: {webServerInfo.PoweredBy}");
            
            if (!string.IsNullOrEmpty(webServerInfo.PageTitle))
                report.AppendLine($"Page Title: {webServerInfo.PageTitle}");

            report.AppendLine($"Content Length: {webServerInfo.ContentLength}");
            report.AppendLine($"Has Load Balancer: {webServerInfo.HasLoadBalancer}");
            report.AppendLine($"Has CDN: {webServerInfo.HasCDN}");
            
            if (!string.IsNullOrEmpty(webServerInfo.CDNProvider))
                report.AppendLine($"CDN Provider: {webServerInfo.CDNProvider}");
            
            report.AppendLine($"Has WAF: {webServerInfo.HasWAF}");
            report.AppendLine($"Form Count: {webServerInfo.FormCount}");
            report.AppendLine($"Input Fields: {webServerInfo.InputFieldCount}");
            report.AppendLine();

            if (webServerInfo.SecurityHeaders.Any())
            {
                report.AppendLine("=== Security Headers ===");
                foreach (var header in webServerInfo.SecurityHeaders)
                {
                    report.AppendLine($"✓ {header}");
                }
                report.AppendLine();
            }

            if (webServerInfo.DetectedTechnologies.Any())
            {
                report.AppendLine("=== Detected Technologies ===");
                foreach (var tech in webServerInfo.DetectedTechnologies)
                {
                    report.AppendLine($"• {tech}");
                }
                report.AppendLine();
            }

            if (webServerInfo.Headers.Any())
            {
                report.AppendLine("=== HTTP Headers ===");
                foreach (var kvp in webServerInfo.Headers.OrderBy(h => h.Key))
                {
                    report.AppendLine($"{kvp.Key}: {kvp.Value}");
                }
                report.AppendLine();
            }

            if (!string.IsNullOrEmpty(webServerInfo.Error))
            {
                report.AppendLine("=== Errors ===");
                report.AppendLine(webServerInfo.Error);
                report.AppendLine();
            }

            await File.WriteAllTextAsync(filePath, report.ToString());
            AnsiConsole.MarkupLine($"[green]Web server fingerprint saved to: {fileName}[/]");
            Logger.Information($"Web server fingerprint report saved to {filePath}");
        }
        catch (Exception ex)
        {
            Logger.Error($"Error saving web server fingerprint: {ex.Message}");
            AnsiConsole.MarkupLine($"[red]Error saving web server fingerprint: {ex.Message}[/]");
        }
    }

    private static async Task ExecuteDirectoryEnumerationAsync()
    {
        try
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[red]Directory and File Enumeration[/]").RuleStyle("grey"));
            AnsiConsole.WriteLine();

            var target = AnsiConsole.Ask<string>("Enter target URL or domain (e.g., example.com or https://example.com):");

            if (string.IsNullOrWhiteSpace(target))
            {
                AnsiConsole.MarkupLine("[red]Error: Target cannot be empty[/]");
                AnsiConsole.MarkupLine("Press any key to return...");
                AnsiConsole.Console.Input.ReadKey(true);
                return;
            }

            // Get enumeration options from user
            var options = GetDirectoryEnumerationOptions();

            Logger.Information($"Starting directory enumeration for {target}");

            using var enumerator = new DirectoryEnumerator(options.MaxConcurrency);
            
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[cyan]Starting directory and file enumeration...[/]");
            
            var result = await enumerator.EnumerateDirectoriesAsync(target, options);
            
            enumerator.DisplayResults(result);

            // Ask if user wants to save results
            if (result.FoundPaths.Any() && AnsiConsole.Confirm("Save results to file?"))
            {
                await SaveDirectoryEnumerationResults(result);
            }

            AnsiConsole.MarkupLine("\n[grey]Press any key to return to menu...[/]");
            AnsiConsole.Console.Input.ReadKey(true);
        }
        catch (Exception ex)
        {
            Logger.Error($"Error during directory enumeration: {ex.Message}");
            AnsiConsole.MarkupLine($"[red]Error: {ex.Message}[/]");
            AnsiConsole.MarkupLine("Press any key to return...");
            AnsiConsole.Console.Input.ReadKey(true);
        }
    }

    private static DirectoryEnumerationOptions GetDirectoryEnumerationOptions()
    {
        var options = new DirectoryEnumerationOptions();

        AnsiConsole.MarkupLine("[cyan]Configure enumeration options:[/]");
        AnsiConsole.WriteLine();

        // Wordlist selection with size indicators
        var wordlistChoices = AnsiConsole.Prompt(
            new MultiSelectionPrompt<string>()
                .Title("Select wordlists to use (larger wordlists = better coverage):")
                .Required()
                .PageSize(10)
                .MoreChoicesText("[grey](Move up and down to reveal more options)[/]")
                .InstructionsText("[grey](Press [blue]<space>[/] to toggle, [green]<enter>[/] to accept)[/]")
                .AddChoices(new[] {
                    "Common Directories (RAFT: 30k+ entries - RECOMMENDED)",
                    "Common Files (RAFT: 17k+ entries - RECOMMENDED)", 
                    "Backup Files (Custom patterns)",
                    "Configuration Files (Security-focused)"
                })
        );

        options.UseCommonDirectories = wordlistChoices.Any(choice => choice.StartsWith("Common Directories"));
        options.UseCommonFiles = wordlistChoices.Any(choice => choice.StartsWith("Common Files"));
        options.UseBackupFiles = wordlistChoices.Any(choice => choice.StartsWith("Backup Files"));
        options.UseConfigFiles = wordlistChoices.Any(choice => choice.StartsWith("Configuration Files"));

        // Additional options
        options.IncludeRedirects = AnsiConsole.Confirm("Include redirects (3xx status codes)?", true);
        options.IncludeClientErrors = AnsiConsole.Confirm("Include client errors (4xx status codes)?", true);

        // File extensions
        if (AnsiConsole.Confirm("Add specific file extensions?"))
        {
            var extensions = AnsiConsole.Ask<string>("Enter file extensions (comma-separated, e.g., php,asp,jsp):");
            if (!string.IsNullOrWhiteSpace(extensions))
            {
                options.FileExtensions = extensions.Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(ext => ext.Trim())
                    .ToList();
            }
        }

        // Concurrency
        options.MaxConcurrency = AnsiConsole.Ask("Max concurrent requests:", 20);
        if (options.MaxConcurrency > 50)
        {
            AnsiConsole.MarkupLine("[yellow]Warning: High concurrency may trigger rate limiting or blocking[/]");
        }

        return options;
    }

    private static async Task SaveDirectoryEnumerationResults(DirectoryEnumerationResult result)
    {
        try
        {
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var fileName = $"directory_enumeration_{timestamp}.txt";
            var filePath = Path.Combine(Directory.GetCurrentDirectory(), fileName);

            var report = new StringBuilder();
            report.AppendLine("=== Directory and File Enumeration Report ===");
            report.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            report.AppendLine($"Target: {result.BaseUrl}");
            report.AppendLine();

            report.AppendLine("=== Scan Configuration ===");
            report.AppendLine($"Common Directories: {result.Options.UseCommonDirectories}");
            report.AppendLine($"Common Files: {result.Options.UseCommonFiles}");
            report.AppendLine($"Backup Files: {result.Options.UseBackupFiles}");
            report.AppendLine($"Config Files: {result.Options.UseConfigFiles}");
            report.AppendLine($"Include Redirects: {result.Options.IncludeRedirects}");
            report.AppendLine($"Include Client Errors: {result.Options.IncludeClientErrors}");
            
            if (result.Options.FileExtensions?.Any() == true)
                report.AppendLine($"File Extensions: {string.Join(", ", result.Options.FileExtensions)}");
            
            report.AppendLine($"Max Concurrency: {result.Options.MaxConcurrency}");
            report.AppendLine();

            report.AppendLine("=== Summary Statistics ===");
            report.AppendLine($"Total Paths Found: {result.FoundPaths.Count}");
            report.AppendLine($"Directories: {result.FoundPaths.Count(p => p.IsDirectory)}");
            report.AppendLine($"Files: {result.FoundPaths.Count(p => !p.IsDirectory)}");
            report.AppendLine($"Interesting Paths: {result.FoundPaths.Count(p => p.IsInteresting)}");
            report.AppendLine($"Status 200 (OK): {result.FoundPaths.Count(p => p.StatusCode == 200)}");
            report.AppendLine($"Status 403 (Forbidden): {result.FoundPaths.Count(p => p.StatusCode == 403)}");
            report.AppendLine($"Redirects (3xx): {result.FoundPaths.Count(p => p.StatusCode >= 300 && p.StatusCode < 400)}");
            report.AppendLine();

            // Interesting paths section
            var interestingPaths = result.FoundPaths.Where(p => p.IsInteresting).ToList();
            if (interestingPaths.Any())
            {
                report.AppendLine("=== Interesting Paths ===");
                foreach (var path in interestingPaths)
                {
                    report.AppendLine($"[{path.StatusCode}] {path.FullUrl}");
                    report.AppendLine($"    Type: {(path.IsDirectory ? "Directory" : "File")}");
                    report.AppendLine($"    Size: {(path.ContentLength > 0 ? $"{path.ContentLength} bytes" : "Unknown")}");
                    report.AppendLine($"    Content-Type: {path.ContentType}");
                    
                    if (path.InterestingDetails?.Any() == true)
                    {
                        report.AppendLine($"    Details: {string.Join(", ", path.InterestingDetails)}");
                    }
                    report.AppendLine();
                }
            }

            // All paths section
            report.AppendLine("=== All Found Paths ===");
            foreach (var path in result.FoundPaths.OrderBy(p => p.StatusCode).ThenBy(p => p.Path))
            {
                var typeIndicator = path.IsDirectory ? "[DIR]" : "[FILE]";
                var sizeInfo = path.ContentLength > 0 ? $" ({path.ContentLength} bytes)" : "";
                report.AppendLine($"[{path.StatusCode}] {typeIndicator} {path.FullUrl}{sizeInfo}");
            }

            if (!string.IsNullOrEmpty(result.Error))
            {
                report.AppendLine();
                report.AppendLine("=== Errors ===");
                report.AppendLine(result.Error);
            }

            await File.WriteAllTextAsync(filePath, report.ToString());
            AnsiConsole.MarkupLine($"[green]Directory enumeration results saved to: {fileName}[/]");
            Logger.Information($"Directory enumeration report saved to {filePath}");
        }
        catch (Exception ex)
        {
            Logger.Error($"Error saving directory enumeration results: {ex.Message}");
            AnsiConsole.MarkupLine($"[red]Error saving directory enumeration results: {ex.Message}[/]");
        }
    }

    private static async Task ExecuteSubdomainEnumerationAsync()
    {
        try
        {
            AnsiConsole.Clear();
            AnsiConsole.Write(new Rule("[bold green]Subdomain Enumeration[/]").RuleStyle("green"));
            AnsiConsole.WriteLine();

            // Get target domain
            var domain = AnsiConsole.Ask<string>("[cyan]Enter target domain (e.g., example.com):[/]");
            if (string.IsNullOrWhiteSpace(domain))
            {
                AnsiConsole.MarkupLine("[red]Invalid domain provided.[/]");
                return;
            }

            // Get enumeration options
            var options = GetSubdomainEnumerationOptions();

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"[yellow]Starting subdomain enumeration for: {domain}[/]");
            AnsiConsole.WriteLine();

            // Perform subdomain enumeration
            using var enumerator = new SubdomainEnumerator(options.MaxConcurrency);
            var result = await enumerator.EnumerateSubdomainsAsync(domain, options);

            // Display results
            enumerator.DisplayResults(result);

            // Ask if user wants to save results
            if (result.DiscoveredSubdomains.Any() && AnsiConsole.Confirm("[cyan]Save results to file?[/]", true))
            {
                var saved = await enumerator.SaveResultsAsync(result);
                if (!saved)
                {
                    AnsiConsole.MarkupLine("[red]Failed to save results.[/]");
                }
            }
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Error during subdomain enumeration: {ex.Message}[/]");
            Logger.Error($"Error during subdomain enumeration: {ex.Message}");
        }

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[grey]Press any key to return to the menu...[/]");
        AnsiConsole.Console.Input.ReadKey(true);
    }

    private static SubdomainEnumerationOptions GetSubdomainEnumerationOptions()
    {
        var options = new SubdomainEnumerationOptions();

        AnsiConsole.MarkupLine("[cyan]Configure subdomain enumeration options:[/]");
        AnsiConsole.WriteLine();

        // Wordlist selection
        var wordlistChoices = AnsiConsole.Prompt(
            new MultiSelectionPrompt<string>()
                .Title("Select wordlists to use:")
                .Required()
                .PageSize(10)
                .MoreChoicesText("[grey](Move up and down to reveal more options)[/]")
                .InstructionsText("[grey](Press [blue]<space>[/] to toggle, [green]<enter>[/] to accept)[/]")
                .AddChoices(new[] {
                    "Common Subdomains",
                    "Comprehensive Subdomains"
                })
        );

        options.UseCommonSubdomains = wordlistChoices.Contains("Common Subdomains");
        options.UseComprehensiveSubdomains = wordlistChoices.Contains("Comprehensive Subdomains");

        // Additional options
        options.PerformDnsResolution = AnsiConsole.Confirm("Perform DNS resolution?", true);
        options.CheckHttpStatus = AnsiConsole.Confirm("Check HTTP/HTTPS status?", true);
        options.IncludeWildcardDetection = AnsiConsole.Confirm("Enable wildcard detection?", true);

        // Performance options
        options.MaxConcurrency = AnsiConsole.Ask("Max concurrent requests:", 50);
        options.TimeoutSeconds = AnsiConsole.Ask("Request timeout (seconds):", 5);

        // Custom subdomains
        if (AnsiConsole.Confirm("Add custom subdomains?"))
        {
            var customSubdomains = AnsiConsole.Ask<string>("Enter custom subdomains (comma-separated):");
            if (!string.IsNullOrWhiteSpace(customSubdomains))
            {
                options.CustomSubdomains = customSubdomains.Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(sub => sub.Trim())
                    .ToList();
            }
        }

        return options;
    }

    private static async Task ExecuteSslCertificateAnalysisAsync()
    {
        try
        {
            AnsiConsole.Clear();
            AnsiConsole.Write(new Rule("[bold green]SSL/TLS Certificate Analysis[/]").RuleStyle("green"));
            AnsiConsole.WriteLine();

            // Get target host
            var host = AnsiConsole.Ask<string>("[cyan]Enter target host (e.g., example.com):[/]");
            if (string.IsNullOrWhiteSpace(host))
            {
                AnsiConsole.MarkupLine("[red]Invalid host provided.[/]");
                return;
            }

            // Get analysis options
            var options = GetSslCertificateAnalysisOptions();

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"[yellow]Starting SSL/TLS certificate analysis for: {host}[/]");
            AnsiConsole.WriteLine();

            // Perform SSL certificate analysis
            using var analyzer = new SslCertificateAnalyzer();
            var result = await analyzer.AnalyzeSslCertificateAsync(host, options);

            // Display results
            analyzer.DisplayResults(result);

            // Ask if user wants to save results
            if (result.ConnectionResults.Any() && AnsiConsole.Confirm("[cyan]Save results to file?[/]", true))
            {
                var saved = await analyzer.SaveResultsAsync(result);
                if (!saved)
                {
                    AnsiConsole.MarkupLine("[red]Failed to save results.[/]");
                }
            }
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Error during SSL certificate analysis: {ex.Message}[/]");
            Logger.Error($"Error during SSL certificate analysis: {ex.Message}");
        }

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[grey]Press any key to return to the menu...[/]");
        AnsiConsole.Console.Input.ReadKey(true);
    }

    private static SslCertificateAnalysisOptions GetSslCertificateAnalysisOptions()
    {
        var options = new SslCertificateAnalysisOptions();

        AnsiConsole.MarkupLine("[cyan]Configure SSL/TLS certificate analysis options:[/]");
        AnsiConsole.WriteLine();

        // Analysis features
        var analysisChoices = AnsiConsole.Prompt(
            new MultiSelectionPrompt<string>()
                .Title("Select analysis features:")
                .Required()
                .PageSize(10)
                .MoreChoicesText("[grey](Move up and down to reveal more options)[/]")
                .InstructionsText("[grey](Press [blue]<space>[/] to toggle, [green]<enter>[/] to accept)[/]")
                .AddChoices(new[] {
                    "Certificate Chain Analysis",
                    "Certificate Expiry Check",
                    "Weak Cipher Detection",
                    "SSL Version Analysis",
                    "Deep Security Inspection"
                })
        );

        options.CheckCertificateChain = analysisChoices.Any(choice => choice.StartsWith("Certificate Chain"));
        options.CheckCertificateExpiry = analysisChoices.Any(choice => choice.StartsWith("Certificate Expiry"));
        options.CheckWeakCiphers = analysisChoices.Any(choice => choice.StartsWith("Weak Cipher"));
        options.CheckSslVersions = analysisChoices.Any(choice => choice.StartsWith("SSL Version"));
        options.PerformDeepInspection = analysisChoices.Any(choice => choice.StartsWith("Deep Security"));

        // Port configuration
        if (AnsiConsole.Confirm("Use custom ports?", false))
        {
            var portsInput = AnsiConsole.Ask<string>("Enter ports (comma-separated, e.g., 443,8443,9443):", "443");
            if (!string.IsNullOrWhiteSpace(portsInput))
            {
                try
                {
                    options.CustomPorts = portsInput.Split(',', StringSplitOptions.RemoveEmptyEntries)
                        .Select(p => int.Parse(p.Trim()))
                        .ToList();
                }
                catch
                {
                    AnsiConsole.MarkupLine("[yellow]Invalid port format, using default port 443[/]");
                    options.CustomPorts = new List<int> { 443 };
                }
            }
        }

        // Timeout configuration
        options.TimeoutSeconds = AnsiConsole.Ask("Connection timeout (seconds):", 10);

        return options;
    }

    private static async Task ExecuteApiEndpointDiscoveryAsync()
    {
        try
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[red]API Endpoint Discovery[/]").RuleStyle("grey"));
            AnsiConsole.WriteLine();

            var target = AnsiConsole.Ask<string>("Enter target URL or domain (e.g., example.com or https://example.com):");

            if (string.IsNullOrWhiteSpace(target))
            {
                AnsiConsole.MarkupLine("[red]Invalid target specified.[/]");
                return;
            }

            // Get API endpoint discovery options
            var options = GetApiEndpointDiscoveryOptions();

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"[green]Starting API endpoint discovery for {target}...[/]");
            AnsiConsole.WriteLine();

            using var discoverer = new ApiEndpointDiscoverer(options.MaxConcurrency);
            
            await AnsiConsole.Progress()
                .StartAsync(async ctx =>
                {
                    var task = ctx.AddTask("[green]Discovering API endpoints...[/]");
                    task.IsIndeterminate = true;
                    
                    var result = await discoverer.DiscoverApiEndpointsAsync(target, options);
                    
                    task.StopTask();
                    
                    // Display results
                    discoverer.DisplayResults(result);
                    
                    // Ask if user wants to save results
                    if (result.DiscoveredEndpoints.Any() && 
                        AnsiConsole.Confirm("Save API endpoint discovery results to file?"))
                    {
                        var fileName = AnsiConsole.Ask("Enter filename (or press Enter for default):", 
                            $"api_endpoint_discovery_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
                        
                        var saved = await discoverer.SaveResultsAsync(result, fileName);
                        if (saved)
                        {
                            AnsiConsole.MarkupLine($"[green]Results saved to {fileName}[/]");
                        }
                        else
                        {
                            AnsiConsole.MarkupLine("[red]Failed to save results.[/]");
                        }
                    }
                });
        }
        catch (Exception ex)
        {
            Logger.Error($"Error during API endpoint discovery: {ex.Message}");
            AnsiConsole.MarkupLine($"[red]Error: {ex.Message}[/]");
        }
        finally
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[grey]Press any key to continue...[/]");
            Console.ReadKey();
        }
    }

    private static ApiEndpointDiscoveryOptions GetApiEndpointDiscoveryOptions()
    {
        var options = new ApiEndpointDiscoveryOptions();

        AnsiConsole.MarkupLine("[cyan]Configure API endpoint discovery options:[/]");
        AnsiConsole.WriteLine();

        // Discovery features selection
        var discoveryFeatures = AnsiConsole.Prompt(
            new MultiSelectionPrompt<string>()
                .Title("Select discovery features:")
                .Required()
                .PageSize(10)
                .InstructionsText("[grey](Press [blue]<space>[/] to toggle, [green]<enter>[/] to accept)[/]")
                .AddChoices(new[] {
                    "REST API Endpoints",
                    "GraphQL Endpoints", 
                    "Swagger/OpenAPI Documentation",
                    "JavaScript File Analysis",
                    "Common API Paths",
                    "Authentication Testing"
                }));

        // Set default selections if none chosen
        if (!discoveryFeatures.Any())
        {
            discoveryFeatures = new List<string> { "REST API Endpoints", "Common API Paths", "Swagger/OpenAPI Documentation" };
        }

        options.DiscoverRestEndpoints = discoveryFeatures.Contains("REST API Endpoints");
        options.DiscoverGraphQlEndpoints = discoveryFeatures.Contains("GraphQL Endpoints");
        options.DiscoverSwaggerDocs = discoveryFeatures.Contains("Swagger/OpenAPI Documentation");
        options.AnalyzeJavaScriptFiles = discoveryFeatures.Contains("JavaScript File Analysis");
        options.TestCommonApiPaths = discoveryFeatures.Contains("Common API Paths");
        options.CheckAuthentication = discoveryFeatures.Contains("Authentication Testing");

        AnsiConsole.WriteLine();

        // Custom endpoints
        if (AnsiConsole.Confirm("Add custom API endpoints to test?"))
        {
            var customEndpoints = new List<string>();
            while (true)
            {
                var endpoint = AnsiConsole.Ask<string>("Enter custom endpoint (or press Enter to finish):", "");
                if (string.IsNullOrWhiteSpace(endpoint))
                    break;
                customEndpoints.Add(endpoint);
            }
            options.CustomEndpoints = customEndpoints;
        }

        // Performance settings
        options.MaxConcurrency = AnsiConsole.Ask("Max concurrent requests:", 20);
        options.TimeoutSeconds = AnsiConsole.Ask("Request timeout (seconds):", 10);

        return options;
    }
}
