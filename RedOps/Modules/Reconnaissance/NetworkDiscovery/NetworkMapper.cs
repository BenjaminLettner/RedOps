using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Spectre.Console;
using RedOps.Utils;

namespace RedOps.Modules.Reconnaissance.NetworkDiscovery;

public class NetworkMapper
{
    public class NetworkNode
    {
        public IPAddress IpAddress { get; set; }
        public string Hostname { get; set; } = "Unknown";
        public string OperatingSystem { get; set; } = "Unknown";
        public string OSConfidence { get; set; } = "Low";
        public List<ServiceInfo> Services { get; set; } = new List<ServiceInfo>();
        public long ResponseTime { get; set; }
        public int TTL { get; set; }
        public string MacAddress { get; set; } = "N/A";
        public string Vendor { get; set; } = "N/A";
        public bool IsAlive { get; set; }
        
        public NetworkNode(IPAddress ipAddress)
        {
            IpAddress = ipAddress;
        }
    }

    public class ServiceInfo
    {
        public int Port { get; set; }
        public string Protocol { get; set; } = "TCP";
        public string ServiceName { get; set; } = "Unknown";
        public string Version { get; set; } = "Unknown";
        public string Banner { get; set; } = string.Empty;
        
        public ServiceInfo(int port, string protocol)
        {
            Port = port;
            Protocol = protocol;
        }
    }

    public class NetworkMap
    {
        public string NetworkRange { get; set; } = string.Empty;
        public List<NetworkNode> Nodes { get; set; } = new List<NetworkNode>();
        public DateTime ScanTime { get; set; } = DateTime.Now;
        public TimeSpan ScanDuration { get; set; }
        
        public int AliveHosts => Nodes.Count(n => n.IsAlive);
        public int TotalServices => Nodes.Sum(n => n.Services.Count);
        public Dictionary<string, int> OSDistribution => Nodes
            .Where(n => n.IsAlive && !n.OperatingSystem.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            .GroupBy(n => n.OperatingSystem)
            .ToDictionary(g => g.Key, g => g.Count());
    }

    public async Task<NetworkMap> CreateNetworkMapAsync(string networkRange)
    {
        var networkMap = new NetworkMap { NetworkRange = networkRange };
        var startTime = DateTime.Now;
        
        Logger.Information($"Starting network mapping for range: {networkRange}");
        
        try
        {
            // Step 1: Host Discovery
            AnsiConsole.MarkupLine("[cyan]Step 1: Discovering live hosts...[/]");
            var liveHosts = await DiscoverLiveHostsAsync(networkRange);
            
            // Step 2: Port Scanning and Service Detection
            AnsiConsole.MarkupLine("[cyan]Step 2: Scanning ports and detecting services...[/]");
            await ScanServicesAsync(liveHosts);
            
            // Step 3: OS Fingerprinting
            AnsiConsole.MarkupLine("[cyan]Step 3: Performing OS fingerprinting...[/]");
            await PerformOSFingerprintingAsync(liveHosts);
            
            networkMap.Nodes = liveHosts;
            networkMap.ScanDuration = DateTime.Now - startTime;
            
            Logger.Information($"Network mapping completed. Found {liveHosts.Count} live hosts with {liveHosts.Sum(h => h.Services.Count)} services");
        }
        catch (Exception ex)
        {
            Logger.Error($"Error during network mapping: {ex.Message}");
            throw;
        }
        
        return networkMap;
    }

    private async Task<List<NetworkNode>> DiscoverLiveHostsAsync(string networkRange)
    {
        var liveHosts = new List<NetworkNode>();
        
        // Parse the network range and get IP addresses
        var ipAddresses = ParseNetworkRange(networkRange);
        
        await AnsiConsole.Progress()
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask("[green]Discovering hosts...[/]");
                task.MaxValue = ipAddresses.Count;
                
                var semaphore = new System.Threading.SemaphoreSlim(20); // Limit concurrent pings
                var tasks = ipAddresses.Select(async ip =>
                {
                    await semaphore.WaitAsync();
                    try
                    {
                        var node = await PingHostAsync(ip);
                        if (node != null)
                        {
                            lock (liveHosts)
                            {
                                liveHosts.Add(node);
                            }
                        }
                    }
                    finally
                    {
                        task.Increment(1);
                        semaphore.Release();
                    }
                });
                
                await Task.WhenAll(tasks);
            });
        
        return liveHosts.OrderBy(h => h.IpAddress.ToString()).ToList();
    }

    private async Task<NetworkNode?> PingHostAsync(IPAddress ipAddress)
    {
        try
        {
            using var ping = new System.Net.NetworkInformation.Ping();
            var reply = await ping.SendPingAsync(ipAddress, 3000);
            
            if (reply.Status == System.Net.NetworkInformation.IPStatus.Success)
            {
                var node = new NetworkNode(ipAddress)
                {
                    IsAlive = true,
                    ResponseTime = reply.RoundtripTime,
                    TTL = reply.Options?.Ttl ?? 0
                };
                
                // Try to resolve hostname
                try
                {
                    var hostEntry = await Dns.GetHostEntryAsync(ipAddress);
                    node.Hostname = hostEntry.HostName;
                }
                catch
                {
                    node.Hostname = "Unknown";
                }
                
                return node;
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Ping failed for {ipAddress}: {ex.Message}");
        }
        
        return null;
    }

    private async Task ScanServicesAsync(List<NetworkNode> hosts)
    {
        var commonPorts = new[] { 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 27017 };
        
        await AnsiConsole.Progress()
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask("[green]Scanning services...[/]");
                task.MaxValue = hosts.Count * commonPorts.Length;
                
                var semaphore = new System.Threading.SemaphoreSlim(50);
                var tasks = hosts.SelectMany(host => commonPorts.Select(async port =>
                {
                    await semaphore.WaitAsync();
                    try
                    {
                        var service = await ScanPortAsync(host.IpAddress, port);
                        if (service != null)
                        {
                            lock (host.Services)
                            {
                                host.Services.Add(service);
                            }
                        }
                    }
                    finally
                    {
                        task.Increment(1);
                        semaphore.Release();
                    }
                }));
                
                await Task.WhenAll(tasks);
            });
        
        // Perform service detection on discovered services
        var serviceDetector = new ServiceDetector();
        foreach (var host in hosts.Where(h => h.Services.Any()))
        {
            var openPorts = host.Services.Select(s => new OpenPortInfo(host.IpAddress, s.Port, s.Protocol)).ToList();
            var detectedServices = await serviceDetector.DetectServicesAsync(openPorts);
            
            for (int i = 0; i < host.Services.Count; i++)
            {
                var detectedService = detectedServices.FirstOrDefault(d => d.Port == host.Services[i].Port);
                if (detectedService != null)
                {
                    host.Services[i].ServiceName = detectedService.ServiceName ?? "Unknown";
                    host.Services[i].Version = detectedService.ServiceVersion ?? "Unknown";
                    host.Services[i].Banner = detectedService.Banner ?? string.Empty;
                }
            }
        }
    }

    private async Task<ServiceInfo?> ScanPortAsync(IPAddress ipAddress, int port)
    {
        try
        {
            using var client = new System.Net.Sockets.TcpClient();
            var connectTask = client.ConnectAsync(ipAddress, port);
            
            if (await Task.WhenAny(connectTask, Task.Delay(1000)) == connectTask && client.Connected)
            {
                return new ServiceInfo(port, "TCP");
            }
        }
        catch
        {
            // Port is closed or connection failed
        }
        
        return null;
    }

    private async Task PerformOSFingerprintingAsync(List<NetworkNode> hosts)
    {
        var osFingerprinter = new OSFingerprinter();
        
        await AnsiConsole.Progress()
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask("[green]Fingerprinting OS...[/]");
                task.MaxValue = hosts.Count;
                
                var semaphore = new System.Threading.SemaphoreSlim(10);
                var tasks = hosts.Select(async host =>
                {
                    await semaphore.WaitAsync();
                    try
                    {
                        var openPorts = host.Services.Select(s => new OpenPortInfo(host.IpAddress, s.Port, s.Protocol)
                        {
                            ServiceName = s.ServiceName,
                            ServiceVersion = s.Version,
                            Banner = s.Banner
                        }).ToList();
                        
                        var result = await osFingerprinter.FingerprintOSAsync(host.IpAddress.ToString(), openPorts);
                        host.OperatingSystem = result.OperatingSystem;
                        host.OSConfidence = result.Confidence;
                    }
                    finally
                    {
                        task.Increment(1);
                        semaphore.Release();
                    }
                });
                
                await Task.WhenAll(tasks);
            });
    }

    private List<IPAddress> ParseNetworkRange(string networkRange)
    {
        var ipList = new List<IPAddress>();
        
        try
        {
            // Handle CIDR notation (e.g., 192.168.1.0/24)
            if (networkRange.Contains("/"))
            {
                var parts = networkRange.Split('/');
                if (parts.Length == 2 && IPAddress.TryParse(parts[0], out IPAddress? networkAddress) && int.TryParse(parts[1], out int cidrPrefix))
                {
                    var networkBytes = networkAddress.GetAddressBytes();
                    var hostBits = 32 - cidrPrefix;
                    var numHosts = (int)Math.Pow(2, hostBits) - 2; // Exclude network and broadcast
                    
                    for (int i = 1; i <= numHosts && i <= 254; i++) // Limit to reasonable range
                    {
                        var hostBytes = (byte[])networkBytes.Clone();
                        hostBytes[3] = (byte)((networkBytes[3] & (0xFF << hostBits)) + i);
                        ipList.Add(new IPAddress(hostBytes));
                    }
                }
            }
            // Handle range notation (e.g., 192.168.1.1-254)
            else if (networkRange.Contains("-"))
            {
                var parts = networkRange.Split('-');
                if (parts.Length == 2)
                {
                    var baseParts = parts[0].Split('.');
                    if (baseParts.Length == 4 && int.TryParse(parts[1], out int endRange))
                    {
                        var baseIp = string.Join(".", baseParts.Take(3));
                        var startRange = int.Parse(baseParts[3]);
                        
                        for (int i = startRange; i <= endRange && i <= 254; i++)
                        {
                            if (IPAddress.TryParse($"{baseIp}.{i}", out IPAddress? ip))
                            {
                                ipList.Add(ip);
                            }
                        }
                    }
                }
            }
            // Single IP
            else if (IPAddress.TryParse(networkRange, out IPAddress? singleIp))
            {
                ipList.Add(singleIp);
            }
        }
        catch (Exception ex)
        {
            Logger.Error($"Error parsing network range {networkRange}: {ex.Message}");
        }
        
        return ipList;
    }

    public void DisplayNetworkMap(NetworkMap networkMap)
    {
        UIHelper.DisplayHeader("Network Map Visualization");
        
        // Summary statistics
        var summaryTable = new Table();
        summaryTable.AddColumn("[bold]Metric[/]");
        summaryTable.AddColumn("[bold]Value[/]");
        
        summaryTable.AddRow("Network Range", networkMap.NetworkRange);
        summaryTable.AddRow("Scan Duration", $"{networkMap.ScanDuration.TotalSeconds:F1} seconds");
        summaryTable.AddRow("Live Hosts", $"[green]{networkMap.AliveHosts}[/]");
        summaryTable.AddRow("Total Services", $"[yellow]{networkMap.TotalServices}[/]");
        summaryTable.AddRow("Scan Time", networkMap.ScanTime.ToString("yyyy-MM-dd HH:mm:ss"));
        
        AnsiConsole.Write(summaryTable);
        
        // OS Distribution
        if (networkMap.OSDistribution.Any())
        {
            AnsiConsole.MarkupLine("\n[bold]Operating System Distribution:[/]");
            var osChart = new BreakdownChart()
                .Width(60)
                .ShowPercentage();
                
            foreach (var os in networkMap.OSDistribution)
            {
                osChart.AddItem(os.Key, os.Value, GetOSColor(os.Key));
            }
            
            AnsiConsole.Write(osChart);
        }
        
        // Detailed host information
        AnsiConsole.MarkupLine("\n[bold]Discovered Hosts:[/]");
        
        var hostTable = new Table();
        hostTable.AddColumn("[bold]IP Address[/]");
        hostTable.AddColumn("[bold]Hostname[/]");
        hostTable.AddColumn("[bold]OS[/]");
        hostTable.AddColumn("[bold]Services[/]");
        hostTable.AddColumn("[bold]Response Time[/]");
        
        foreach (var host in networkMap.Nodes.Where(n => n.IsAlive).OrderBy(n => n.IpAddress.ToString()))
        {
            var servicesText = host.Services.Any() 
                ? string.Join(", ", host.Services.Select(s => $"{s.Port}/{s.Protocol}"))
                : "None";
            
            if (servicesText.Length > 40)
            {
                servicesText = servicesText.Substring(0, 37) + "...";
            }
            
            var osText = host.OperatingSystem == "Unknown" 
                ? "[grey]Unknown[/]" 
                : $"[{GetOSColor(host.OperatingSystem)}]{host.OperatingSystem}[/]";
            
            hostTable.AddRow(
                host.IpAddress.ToString(),
                host.Hostname == "Unknown" ? "[grey]Unknown[/]" : host.Hostname,
                osText,
                servicesText,
                $"{host.ResponseTime}ms"
            );
        }
        
        AnsiConsole.Write(hostTable);
        
        // Service summary
        if (networkMap.TotalServices > 0)
        {
            AnsiConsole.MarkupLine("\n[bold]Service Summary:[/]");
            var serviceSummary = networkMap.Nodes
                .SelectMany(n => n.Services)
                .GroupBy(s => $"{s.ServiceName}:{s.Port}")
                .OrderByDescending(g => g.Count())
                .Take(10)
                .ToDictionary(g => g.Key, g => g.Count());
            
            var serviceTable = new Table();
            serviceTable.AddColumn("[bold]Service[/]");
            serviceTable.AddColumn("[bold]Count[/]");
            serviceTable.AddColumn("[bold]Hosts[/]");
            
            foreach (var service in serviceSummary)
            {
                var hosts = networkMap.Nodes
                    .Where(n => n.Services.Any(s => $"{s.ServiceName}:{s.Port}" == service.Key))
                    .Select(n => n.IpAddress.ToString())
                    .Take(3);
                
                var hostsText = string.Join(", ", hosts);
                if (service.Value > 3)
                {
                    hostsText += $" (+{service.Value - 3} more)";
                }
                
                serviceTable.AddRow(
                    service.Key,
                    service.Value.ToString(),
                    hostsText
                );
            }
            
            AnsiConsole.Write(serviceTable);
        }
    }
    
    private static Color GetOSColor(string os)
    {
        return os.ToLower() switch
        {
            var x when x.Contains("windows") => Color.Blue,
            var x when x.Contains("linux") => Color.Green,
            var x when x.Contains("unix") => Color.Green,
            var x when x.Contains("macos") => Color.Purple,
            var x when x.Contains("network") => Color.Orange1,
            _ => Color.Grey
        };
    }
}
