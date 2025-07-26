using Spectre.Console;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics; // Added to use Process and ProcessStartInfo
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets; // Added for AddressFamily
using System.Text.RegularExpressions; // Added for Regex
using System.Threading;
using System.Threading.Tasks;
using RedOps.Utils; // For Logger
using System.Reflection; // Added for Assembly
using System.IO; // Added for StreamReader

namespace RedOps.Modules.Reconnaissance.NetworkDiscovery
{
    public static class HostDiscoverer
    {
        private static readonly Dictionary<string, string> OuiVendorMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        static HostDiscoverer() // Static constructor to load OUI data
        {
            LoadOuiData();
        }

        private static void LoadOuiData()
        {
            var assembly = Assembly.GetExecutingAssembly();
            string resourceName = "RedOps.Resources.oui.txt";
            // Regex to capture OUI in formats like "00-00-00 (hex) VENDOR" or "000000 (base 16) VENDOR"
            // It captures the OUI prefix (group 1) and the vendor name (group 2)
            var ouiRegex = new Regex(@"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}|[0-9A-Fa-f]{6})\s+\((?:hex|base 16)\)\s+(.+)$", RegexOptions.IgnoreCase);

            OuiVendorMap.Clear(); // Clear any existing entries, including fallbacks

            try
            {
                using (Stream? stream = assembly.GetManifestResourceStream(resourceName))
                {
                    if (stream == null)
                    {
                        Logger.Error($"OUI data file ({resourceName}) not found as embedded resource. Populating with fallbacks.");
                        PopulateFallbackOuiMap();
                        return;
                    }
                    using (StreamReader reader = new StreamReader(stream))
                    {
                        string? line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#")) // Skip comments and empty lines
                                continue;

                            Match match = ouiRegex.Match(line.Trim());
                            if (match.Success)
                            {
                                string ouiRaw = match.Groups[1].Value;
                                string vendor = match.Groups[2].Value.Trim();

                                // Normalize OUI to XX:XX:XX format
                                string ouiNormalized;
                                if (ouiRaw.Contains("-"))
                                {
                                    ouiNormalized = ouiRaw.Replace("-", ":").ToUpperInvariant();
                                }
                                else // Assumes XXXXXX format
                                {
                                    // Ensure ouiRaw is exactly 6 characters for Substring
                                    if (ouiRaw.Length == 6) {
                                        ouiNormalized = string.Format("{0}:{1}:{2}", 
                                            ouiRaw.Substring(0, 2), 
                                            ouiRaw.Substring(2, 2), 
                                            ouiRaw.Substring(4, 2)).ToUpperInvariant();
                                    } else {
                                        // Logger.Debug($"OUI in XXXXXX format has unexpected length: {ouiRaw}. Line: {line}");
                                        continue; // Skip this malformed entry
                                    }
                                }

                                if (!OuiVendorMap.ContainsKey(ouiNormalized))
                                {
                                    OuiVendorMap.Add(ouiNormalized, vendor);
                                }
                                else
                                {
                                    // Optionally log if a duplicate OUI definition is found, though IEEE list should be unique
                                    // Logger.Debug($"Duplicate OUI found (will not overwrite): {ouiNormalized} for vendor {vendor}. Existing: {OuiVendorMap[ouiNormalized]}");
                                }
                            }
                            else
                            {
                                // Logger.Debug($"Skipping line in OUI file (does not match expected format): {line}");
                            }
                        }
                        Logger.Info($"Successfully loaded {OuiVendorMap.Count} OUI entries from {resourceName}.");
                        if (OuiVendorMap.Count == 0)
                        {
                            Logger.Warning($"No OUI entries loaded from {resourceName}. Populating with fallbacks.");
                            PopulateFallbackOuiMap();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Error loading OUI data from {resourceName}: {ex.Message}. Populating with fallbacks.");
                PopulateFallbackOuiMap(); // Fallback in case of any error during processing
            }
        }

        private static void PopulateFallbackOuiMap()
        {
            Logger.Warning("Populating OUI map with minimal fallback entries.");
            // Add a few very common ones here as a last resort
            OuiVendorMap["00:50:56"] = "VMware, Inc.";
            OuiVendorMap["00:0C:29"] = "VMware, Inc.";
            OuiVendorMap["08:00:27"] = "Oracle Corporation (VirtualBox)";
            OuiVendorMap["B8:27:EB"] = "Raspberry Pi Foundation";
            OuiVendorMap["DC:A9:04"] = "Apple, Inc.";
        }

        public static async Task ExecuteIcmpScanAsync()
        {
            AnsiConsole.MarkupLine("[yellow]ICMP Host Discovery (Ping Sweep)[/]");
            var targetRangeInput = AnsiConsole.Ask<string>("Enter target IP range (e.g., 192.168.1.1-254 or 192.168.1.0/24):");

            Logger.Information($"ICMP scan initiated for range: {targetRangeInput}");
            
            List<IPAddress> ipsToScan = ParseIpRangeOrCidr(targetRangeInput);

            if (!ipsToScan.Any())
            {
                AnsiConsole.MarkupLine("[red]Error: No valid IP addresses to scan, or input format was incorrect.[/]");
                Logger.Warning($"No valid IP addresses parsed for ICMP scan from input: {targetRangeInput}");
                AnsiConsole.MarkupLine("[grey]Press any key to return.[/]");
                Console.ReadKey(true);
                return;
            }

            AnsiConsole.MarkupLine($"[grey]Preparing to scan {ipsToScan.Count} IP addresses...[/]");

            var liveHosts = new ConcurrentBag<HostInfo>();
            int timeoutMs = 1500; // Ping timeout in milliseconds
            int maxConcurrentPings = 100;
            var semaphore = new SemaphoreSlim(maxConcurrentPings);
            var pingTasks = new List<Task>();

            await AnsiConsole.Progress()
                .AutoClear(false)
                .Columns(new ProgressColumn[]
                {                    
                    new TaskDescriptionColumn(),
                    new ProgressBarColumn(),
                    new PercentageColumn(),
                    new RemainingTimeColumn(),
                    new SpinnerColumn(Spinner.Known.Dots)
                })
                .StartAsync(async ctx =>
                {
                    var scanTask = ctx.AddTask("[green]Scanning IPs[/]", new ProgressTaskSettings
                    {
                        MaxValue = ipsToScan.Count
                    });

                    foreach (var ipAddress in ipsToScan)
                    {
                        await semaphore.WaitAsync(); // Wait for a slot

                        pingTasks.Add(Task.Run(async () =>
                        {
                            try
                            {
                                using (var pinger = new Ping())
                                {
                                    // Logger.Debug($"Pinging {ipAddress}...");
                                    PingReply reply = await pinger.SendPingAsync(ipAddress, timeoutMs);
                                    if (reply.Status == IPStatus.Success)
                                    {
                                        string hostname = "N/A";
                                        try
                                        {
                                            // Attempt to resolve hostname
                                            IPHostEntry hostEntry = await Dns.GetHostEntryAsync(ipAddress);
                                            hostname = hostEntry.HostName;
                                            // Check if the resolved hostname is just the IP address (common for non-resolvable local IPs or reverse DNS not set up)
                                            if (hostname == ipAddress.ToString()) hostname = "N/A"; 
                                        }
                                        catch (SocketException ex) // Handles host not found, etc.
                                        {
                                            Logger.Debug($"DNS resolution failed for {ipAddress}: {ex.Message}");
                                            hostname = "N/A (Resolution failed)";
                                        }
                                        catch (Exception ex)
                                        {
                                            Logger.Warning($"Unexpected error during DNS resolution for {ipAddress}: {ex.Message}");
                                            hostname = "N/A (Error)";
                                        }

                                        // Get TTL using native ping as .NET Ping.Options.Ttl might be 0 on macOS
                                        int ttl = await GetTtlFromNativePingAsync(ipAddress);

                                        // Get MAC Address and Vendor
                                        string macAddress = await GetMacAddressAsync(ipAddress);
                                        string vendor = "N/A";
                                        if (!string.IsNullOrWhiteSpace(macAddress) && macAddress != "(incomplete)" && !macAddress.StartsWith("N/A") && !macAddress.StartsWith("(error)"))
                                        {
                                            vendor = GetVendorFromMac(macAddress); // No longer awaited
                                        }
                                        else
                                        {
                                            macAddress = "N/A"; // Ensure consistent "N/A" if not found
                                        }

                                        liveHosts.Add(new HostInfo { 
                                            IpAddress = ipAddress, 
                                            Hostname = hostname, 
                                            RoundtripTime = reply.RoundtripTime,
                                            Ttl = ttl,
                                            MacAddress = macAddress,
                                            Vendor = vendor
                                        });
                                        // Logger.Info($"Host {ipAddress} ({hostname}) is live (Roundtrip: {reply.RoundtripTime}ms, TTL: {ttl}, MAC: {macAddress}, Vendor: {vendor}).");
                                    }
                                    else
                                    {
                                        // Logger.Debug($"Host {ipAddress} did not respond or status: {reply.Status}");
                                    }
                                }
                            }
                            catch (PingException pex)
                            {
                                Logger.Warning($"PingException for {ipAddress}: {pex.Message}");
                            }
                            catch (Exception ex)
                            {
                                Logger.Error($"Error pinging {ipAddress}", ex);
                            }
                            finally
                            {
                                scanTask.Increment(1);
                                ctx.Refresh();
                                semaphore.Release();
                            }
                        }));
                    }
                    await Task.WhenAll(pingTasks);
                    scanTask.StopTask(); // Mark as complete
                });

            AnsiConsole.MarkupLine("\n[bold green]ICMP Scan Complete.[/]");
            if (liveHosts.Any())
            {
                AnsiConsole.MarkupLine("[bold yellow]Live Hosts Found:[/]");
                // Sort by IP address for consistent display
                foreach (var liveHost in liveHosts.OrderBy(h => h.IpAddress.GetAddressBytes(), new ByteArrayComparer()))
                {
                    AnsiConsole.MarkupLine($"  [green]{liveHost.IpAddress,-18}[/] [cyan]{liveHost.Hostname,-25}[/] [blue](RTT: {liveHost.RoundtripTime}ms)[/] [magenta](TTL: {liveHost.Ttl,-3})[/] [yellow](MAC: {liveHost.MacAddress,-18})[/] [white](Vendor: {liveHost.Vendor})[/]");
                }
            }
            else
            {
                AnsiConsole.MarkupLine("[yellow]No live hosts found in the specified range.[/]");
            }

            AnsiConsole.MarkupLine("\n[grey]Press any key to return to the Network Discovery Menu.[/]");
            Console.ReadKey(true);
        }

        private static List<IPAddress> ParseIpRangeOrCidr(string rangeInput)
        {
            var ipList = new List<IPAddress>();
            if (string.IsNullOrWhiteSpace(rangeInput))
            {
                Logger.Error("IP range input was null or empty.");
                return ipList;
            }

            try
            {
                // Try CIDR notation first (e.g., 192.168.1.0/24)
                if (rangeInput.Contains("/"))
                {
                    var parts = rangeInput.Split('/');
                    if (parts.Length == 2 && IPAddress.TryParse(parts[0], out IPAddress? networkAddress) && int.TryParse(parts[1], out int cidrPrefix))
                    {
                        if (cidrPrefix < 0 || cidrPrefix > 32)
                        {
                            Logger.Error($"Invalid CIDR prefix: {cidrPrefix}. Must be between 0 and 32.");
                            return ipList;
                        }
                        if (networkAddress == null) { Logger.Error("Failed to parse network address for CIDR."); return ipList; } // Explicit null check

                        var networkAddressBytes = networkAddress.GetAddressBytes();
                        if (networkAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || networkAddressBytes.Length != 4)
                        {
                            Logger.Error("CIDR notation is currently only supported for IPv4.");
                            return ipList;
                        }

                        uint ipAsUint = (uint)networkAddressBytes[0] << 24 | (uint)networkAddressBytes[1] << 16 | (uint)networkAddressBytes[2] << 8 | (uint)networkAddressBytes[3];
                        uint mask = uint.MaxValue << (32 - cidrPrefix);
                        uint firstIpUint = ipAsUint & mask;
                        long numberOfAddresses = (cidrPrefix == 32) ? 1 : (cidrPrefix == 31) ? 2 : 1L << (32 - cidrPrefix);
                        
                        long maxAddressesToScan = 1L << 16; 
                        if (numberOfAddresses > maxAddressesToScan)
                        {
                            Logger.Warning($"CIDR range /{cidrPrefix} is too large ({numberOfAddresses} addresses). Limiting to {maxAddressesToScan} addresses for safety.");
                            numberOfAddresses = maxAddressesToScan;
                        }
                        if (cidrPrefix == 32) 
                        {
                             // For /32, BitConverter.GetBytes handles endianness based on system.
                             // IPAddress constructor expects network order (big-endian).
                             byte[] addressBytes = BitConverter.GetBytes(firstIpUint);
                             if (BitConverter.IsLittleEndian) Array.Reverse(addressBytes); // Ensure Big Endian for IPAddress constructor
                             ipList.Add(new IPAddress(addressBytes));
                        }
                        else
                        {
                            for (uint i = 0; i < numberOfAddresses; i++)
                            {
                                byte[] addressBytes = BitConverter.GetBytes(firstIpUint + i);
                                if (BitConverter.IsLittleEndian) Array.Reverse(addressBytes);
                                ipList.Add(new IPAddress(addressBytes));
                            }
                        }
                    }
                    else
                    {
                        Logger.Error($"Invalid CIDR format: {rangeInput}");
                    }
                }
                // Try IP range (e.g., 192.168.1.1-192.168.1.254 or 192.168.1.10-20)
                else if (rangeInput.Contains("-"))
                {
                    var parts = rangeInput.Split('-');
                    if (parts.Length == 2 && IPAddress.TryParse(parts[0], out IPAddress? startIp))
                    {
                        if (startIp == null) { Logger.Error("Failed to parse start IP for range."); return ipList; }

                        IPAddress? endIp;
                        if (IPAddress.TryParse(parts[1], out IPAddress? parsedEndIp))
                        {
                            endIp = parsedEndIp;
                        }
                        else if (byte.TryParse(parts[1], out byte endOctet) && startIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            var startBytes = startIp.GetAddressBytes();
                            if (startBytes.Length == 4) 
                            {
                                endIp = new IPAddress(new byte[] { startBytes[0], startBytes[1], startBytes[2], endOctet });
                            }
                            else
                            {
                                Logger.Error($"Short-form IP range (e.g., 192.168.1.1-20) is only supported for IPv4: {rangeInput}");
                                return ipList;
                            }
                        }
                        else
                        {
                            Logger.Error($"Invalid end IP in range: {rangeInput}");
                            return ipList;
                        }

                        if (endIp == null) { Logger.Error("Failed to parse end IP for range."); return ipList; }

                        if (startIp.AddressFamily != endIp.AddressFamily)
                        {
                            Logger.Error("Start and end IP addresses in range must be of the same address family.");
                            return ipList;
                        }

                        if (startIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) 
                        {
                            var startIpBytes = startIp.GetAddressBytes();
                            var endIpBytes = endIp.GetAddressBytes();
                            uint currentIpUint = (uint)startIpBytes[0] << 24 | (uint)startIpBytes[1] << 16 | (uint)startIpBytes[2] << 8 | (uint)startIpBytes[3];
                            uint endIpUint = (uint)endIpBytes[0] << 24 | (uint)endIpBytes[1] << 16 | (uint)endIpBytes[2] << 8 | (uint)endIpBytes[3];

                            if (currentIpUint > endIpUint)
                            {
                                Logger.Error($"Start IP {startIp} cannot be greater than End IP {endIp}.");
                                return ipList;
                            }
                            
                            long count = 0;
                            long maxAddressesToScan = 1L << 16; 

                            for (uint i = currentIpUint; i <= endIpUint; i++)
                            {
                                if (count++ >= maxAddressesToScan)
                                {
                                    Logger.Warning($"IP range is too large. Limiting to {maxAddressesToScan} addresses for safety.");
                                    break;
                                }
                                byte[] addressBytes = BitConverter.GetBytes(i);
                                if (BitConverter.IsLittleEndian) Array.Reverse(addressBytes);
                                ipList.Add(new IPAddress(addressBytes));
                                if (i == uint.MaxValue) break; 
                            }
                        }
                        else 
                        {
                            Logger.Warning("Iterating IPv6 ranges is not supported. Only start and end IPs will be added if they are single addresses.");
                            if (startIp.Equals(endIp)) ipList.Add(startIp);
                            else { ipList.Add(startIp); ipList.Add(endIp); }
                        }
                    }
                    else
                    {
                        Logger.Error($"Invalid IP range format: {rangeInput}");
                    }
                }
                // Try single IP
                else if (IPAddress.TryParse(rangeInput, out IPAddress? singleIp))
                {
                    if (singleIp != null) ipList.Add(singleIp);
                    else { Logger.Error($"Failed to parse single IP: {rangeInput}"); }
                }
                else
                {
                    Logger.Error($"Invalid IP address or range format: {rangeInput}");
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Error parsing IP range input '{rangeInput}'", ex);
                return new List<IPAddress>(); // Return empty list on any unexpected error during parsing
            }
            return ipList.Distinct().ToList(); // Ensure uniqueness and return
        }

        private static async Task<int> GetTtlFromNativePingAsync(IPAddress ipAddress)
        {
            if (!OperatingSystem.IsMacOS()) // Only use this workaround on macOS
            {
                // For other OS, we might rely on PingReply.Options.Ttl if it works there,
                // or implement similar native ping parsing if needed.
                // For now, returning 0 if not macOS and .NET Ping didn't provide it.
                // This part might need refinement if we want accurate TTL on other OS where .NET Ping fails for TTL.
                return 0; // Or some other indicator that it's not from native ping
            }

            var processStartInfo = new ProcessStartInfo
            {
                FileName = "ping",
                Arguments = $"-c 1 -W 500 {ipAddress}", // -c 1 (count 1), -W 500 (timeout 500ms for reply)
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            try
            {
                using var process = Process.Start(processStartInfo);
                if (process == null)
                {
                    Logger.Warning($"Failed to start native ping process for {ipAddress}.");
                    return 0;
                }

                string output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync(); // Ensure process has exited before trying to get TTL

                // Regex to find ttl=XX. Example: PING 8.8.8.8 (8.8.8.8): 56 data bytes
                // 64 bytes from 8.8.8.8: icmp_seq=0 ttl=116 time=10.511 ms
                Match match = Regex.Match(output, @"ttl=(\d+)", RegexOptions.IgnoreCase);
                if (match.Success && int.TryParse(match.Groups[1].Value, out int ttlValue))
                {
                    return ttlValue;
                }
                else
                {
                    Logger.Debug($"Could not parse TTL from native ping output for {ipAddress}:\n{output}");
                }
            }
            catch (Exception ex)
            {
                Logger.Warning($"Error executing or parsing native ping for {ipAddress}: {ex.Message}");
            }
            return 0; // Default to 0 if TTL cannot be determined
        }

        private static string GetVendorFromMac(string macAddress) 
        {
            if (string.IsNullOrWhiteSpace(macAddress) || macAddress.Equals("N/A", StringComparison.OrdinalIgnoreCase) || macAddress.Equals("(incomplete)", StringComparison.OrdinalIgnoreCase))
            {
                return "N/A";
            }

            string oui = macAddress.Replace(":", "").Replace("-", "").Substring(0, 6).ToUpperInvariant();
            string formattedOui = string.Join(":", Enumerable.Range(0, oui.Length / 2).Select(i => oui.Substring(i * 2, 2)));

            if (OuiVendorMap.TryGetValue(formattedOui, out string? localVendor))
            {
                return localVendor;
            }
            
            // Online API call removed

            return "Unknown"; // Default if local lookup fails
        }

        private static async Task<string> GetMacAddressAsync(IPAddress ipAddress)
        {
            if (!OperatingSystem.IsMacOS()) // ARP parsing is OS-specific
            {
                // Placeholder for other OS or if direct ARP not feasible
                return "N/A (OS not macOS)"; 
            }

            var processStartInfo = new ProcessStartInfo
            {
                FileName = "arp",
                Arguments = $"-n {ipAddress}", // -n prevents DNS resolution for the IP itself
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            try
            {
                using var process = Process.Start(processStartInfo);
                if (process == null)
                {
                    Logger.Warning($"Failed to start arp process for {ipAddress}.");
                    return "(error)";
                }

                string output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();

                // Regex for MAC address: xx:xx:xx:xx:xx:xx or x:x:x:x:x:x (some arp outputs might be single digit for first octet)
                // Example output: ? (192.168.1.1) at 0:c:29:aa:bb:cc on en0 ifscope [ethernet]
                // Or: ? (192.168.1.100) at (incomplete) on en0 ifscope [ethernet]
                Match match = Regex.Match(output, @"at\s+(([0-9A-Fa-f]{1,2}[:-]){5}([0-9A-Fa-f]{1,2}))", RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    return match.Groups[1].Value; // The full MAC address
                }
                else if (output.Contains("(incomplete)"))
                {
                    return "(incomplete)";
                }
                Logger.Debug($"Could not parse MAC address from arp output for {ipAddress}:\n{output}");
            }
            catch (Exception ex)
            {
                Logger.Warning($"Error executing or parsing arp for {ipAddress}: {ex.Message}");
                return "(error)";
            }
            return "N/A"; // Default if not found
        }
    }

    public class HostInfo
    {
        public required IPAddress IpAddress { get; set; }
        public string Hostname { get; set; } = "N/A";
        public long RoundtripTime { get; set; }
        public int Ttl { get; set; }
        public string MacAddress { get; set; } = "N/A";
        public string Vendor { get; set; } = "N/A";
    }

    // Helper class for sorting IPAddress objects
    public class ByteArrayComparer : IComparer<byte[]>
    {
        public int Compare(byte[]? a, byte[]? b)
        {
            if (a == null && b == null) return 0;
            if (a == null) return -1;
            if (b == null) return 1;
            for (int i = 0; i < a.Length && i < b.Length; i++)
            {
                if (a[i] < b[i]) return -1;
                if (a[i] > b[i]) return 1;
            }
            return a.Length.CompareTo(b.Length);
        }
    }
}
