using Spectre.Console;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using RedOps.Modules.Reconnaissance.NetworkDiscovery;
using RedOps.Utils;
using System.Threading.Tasks;
using RedOps.Core.Plugins;

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
}
