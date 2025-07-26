using Spectre.Console;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using RedOps.Utils;

namespace RedOps.Modules.Reconnaissance.NetworkDiscovery
{
    public class PortScanner
    {
        private static readonly List<int> TopCommonPorts = new List<int>
        {
            20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 137, 138, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
        };
        private const int MaxConcurrentScans = 50; // Define the constant

        // NEW Public Orchestrator Method
        public static async Task ExecuteComprehensiveScanAsync()
        {
            var targetHost = AnsiConsole.Ask<string>("Enter target host (e.g., google.com or IP address):");
            IPAddress? targetIp = await ResolveHostAsync(targetHost);
            if (targetIp == null)
            {
                AnsiConsole.MarkupLine("[grey]Press any key to return.[/]");
                Console.ReadKey(true);
                return;
            }

            string portsInput;
            var portSelectionMode = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("Select port scanning mode:")
                    .PageSize(5)
                    .AddChoices(new[] {
                        "Enter ports manually",
                        "Scan Top ~20 Common Ports",
                        "Scan All Well-Known Ports (1-1023)"
                    }));

            switch (portSelectionMode)
            {
                case "Scan Top ~20 Common Ports":
                    portsInput = string.Join(",", TopCommonPorts);
                    AnsiConsole.MarkupLine($"[grey]Using common ports: {portsInput}[/]");
                    break;
                case "Scan All Well-Known Ports (1-1023)":
                    portsInput = "1-1023";
                    AnsiConsole.MarkupLine($"[grey]Using well-known ports (1-1023)[/]");
                    break;
                case "Enter ports manually":
                default:
                    portsInput = AnsiConsole.Ask<string>("Enter ports to scan (e.g., 80, 443, 22-25, 1-1024):");
                    break;
            }

            List<int> portsToScan = ParsePortsInput(portsInput);
            if (!portsToScan.Any())
            {
                AnsiConsole.MarkupLine("[red]No valid ports to scan.[/]");
                AnsiConsole.MarkupLine("[grey]Press any key to return.[/]");
                Console.ReadKey(true);
                return;
            }

            AnsiConsole.MarkupLine($"Starting Comprehensive Scan for [yellow]{targetHost}[/] ([yellow]{targetIp}[/]) on ports: [cyan]{string.Join(", ", portsToScan)}[/]");
            Logger.Info($"Comprehensive Scan initiated for host: {targetHost}, IP: {targetIp}, ports: {string.Join(", ", portsToScan)}");

            var openTcpPorts = new ConcurrentBag<int>();
            var closedTcpPorts = new ConcurrentBag<int>(); // For TCP, typically means filtered/no response
            var serviceDetectionResults = new ConcurrentDictionary<int, string>();

            await ScanTcpPortsInternalAsync(targetIp, portsToScan, targetHost, openTcpPorts, closedTcpPorts, serviceDetectionResults);

            // UDP Scan Phase
            var openUdpPorts = new ConcurrentBag<int>();
            var closedUdpPorts = new ConcurrentBag<int>();
            var openOrFilteredUdpPorts = new ConcurrentBag<int>();
            var erroredUdpPorts = new ConcurrentBag<int>();

            await ScanUdpPortsInternalAsync(targetIp, portsToScan, targetHost, openUdpPorts, closedUdpPorts, openOrFilteredUdpPorts, erroredUdpPorts);

            AnsiConsole.MarkupLine("[bold green]Comprehensive Scan Complete.[/]");
            AnsiConsole.MarkupLine("[grey]Press any key to return to the Network Discovery Menu.[/]");
            Console.ReadKey(true);
        }

        // REFACTORED ExecuteTcpScan to be an internal method
        private static async Task ScanTcpPortsInternalAsync(IPAddress targetIp, List<int> ports, string targetHostForDisplay, ConcurrentBag<int> openPortsBag, ConcurrentBag<int> closedPortsBag, ConcurrentDictionary<int, string> serviceDetectionResults)
        {
            AnsiConsole.MarkupLine("--- [blue]TCP Scan Phase (including Service Detection)[/] ---");
            Logger.Info($"TCP Scan phase started for host: {targetHostForDisplay} ({targetIp}), ports: {string.Join(", ", ports)}");

            var progress = AnsiConsole.Progress()
                .AutoClear(false)
                .Columns(new ProgressColumn[]
                {
                    new TaskDescriptionColumn(),
                    new ProgressBarColumn(),
                    new PercentageColumn(),
                    new RemainingTimeColumn(),
                    new SpinnerColumn(Spinner.Known.Dots),
                });

            await progress.StartAsync(async ctx =>
            {
                var progressTask = ctx.AddTask("[green]Scanning TCP ports[/]", new ProgressTaskSettings
                {
                    MaxValue = ports.Count
                });

                var semaphore = new SemaphoreSlim(MaxConcurrentScans);

                var scanTasks = ports.Select(async port =>
                {
                    await semaphore.WaitAsync();
                    try
                    {
                        using (var tcpClient = new TcpClient())
                        {
                            var connectTask = tcpClient.ConnectAsync(targetIp, port);
                            if (await Task.WhenAny(connectTask, Task.Delay(2000)) == connectTask && connectTask.IsCompletedSuccessfully)
                            {
                                openPortsBag.Add(port);
                                Logger.Debug($"TCP Port {targetIp}:{port} is Open");
                                // Attempt service detection
                                try
                                {
                                    using (var stream = tcpClient.GetStream())
                                    {
                                        stream.ReadTimeout = 1000; // Short timeout for banner read
                                        stream.WriteTimeout = 1000;
                                        // Try sending a simple HTTP GET request for common web ports
                                        if (port == 80 || port == 8080)
                                        {
                                            byte[] request = System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: " + targetHostForDisplay + "\r\nConnection: close\r\n\r\n");
                                            await stream.WriteAsync(request, 0, request.Length);
                                        }
                                        else if (port == 443) // Basic SSL/TLS handshake start might reveal something
                                        {
                                            // For HTTPS, a proper SSL handshake is complex. This is a placeholder.
                                            // A more robust approach would use SslStream.
                                        }

                                        byte[] buffer = new byte[1024];
                                        int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                                        if (bytesRead > 0)
                                        {
                                            string banner = System.Text.Encoding.ASCII.GetString(buffer, 0, bytesRead).Trim();
                                            serviceDetectionResults[port] = banner;
                                            Logger.Debug($"Service on {targetIp}:{port} - Banner: {banner}");
                                        }
                                        else
                                        {
                                            serviceDetectionResults[port] = "(No banner)";
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    serviceDetectionResults[port] = "(Banner grab failed: " + ex.GetType().Name + ")";
                                    Logger.Debug($"Failed to get banner for {targetIp}:{port}: {ex.Message}");
                                }
                                tcpClient.Close();
                            }
                            else
                            {
                                closedPortsBag.Add(port); // Timeout or other connection failure
                                Logger.Debug($"TCP Port {targetIp}:{port} is Closed/Filtered (Connection failed or timed out)");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        closedPortsBag.Add(port);
                        Logger.Error($"Error scanning TCP port {targetIp}:{port}: {ex.Message}", ex);
                    }
                    finally
                    {
                        progressTask.Increment(1);
                        semaphore.Release();
                    }
                });
                await Task.WhenAll(scanTasks);
                progressTask.StopTask();
            });

            AnsiConsole.MarkupLine($"TCP Scan Results for [yellow]{targetHostForDisplay} ({targetIp})[/]:");
            AnsiConsole.MarkupLine("Attempting service detection for open TCP ports...");
            var openTcpList = openPortsBag.OrderBy(p => p).ToList();
            if (openTcpList.Any())
            {
                AnsiConsole.MarkupLine("[bold green]Open TCP ports and detected services:[/] ");
                foreach (var port in openTcpList)
                {
                    string serviceInfo = serviceDetectionResults.TryGetValue(port, out var banner) ? banner : "(No banner detected)";
                    AnsiConsole.MarkupLine($"  Port {port}/TCP: [green]Open[/] - {serviceInfo}");
                    Logger.Info($"Host: {targetIp}, Port: {port}/TCP, State: Open, Service: {(serviceDetectionResults.ContainsKey(port) ? "(Banner available)" : "")} , Version: , Banner: {serviceInfo}");
                }
            }
            LogAndDisplayResults("Filtered TCP ports (timeout/no response)", closedPortsBag.OrderBy(p => p).ToList(), targetIp, s => Logger.Info(s), port => $"  Port {port}/TCP: [yellow]Filtered[/]");
        }

        // REFACTORED ExecuteUdpScan to be an internal method
        private static async Task ScanUdpPortsInternalAsync(IPAddress targetIp, List<int> portsToScan, string targetHostForDisplay, 
                                                        ConcurrentBag<int> openUdpPorts, 
                                                        ConcurrentBag<int> closedUdpPorts, 
                                                        ConcurrentBag<int> openOrFilteredUdpPorts,
                                                        ConcurrentBag<int> erroredUdpPorts)
        {
            AnsiConsole.MarkupLine("--- [blue]UDP Scan Phase[/] ---");
            Logger.Info($"UDP Scan phase started for host: {targetHostForDisplay} ({targetIp}), ports: {string.Join(", ", portsToScan)}");
            await PerformUdpPortScanTasksAsync(targetIp, portsToScan, openUdpPorts, closedUdpPorts, openOrFilteredUdpPorts, erroredUdpPorts);

            AnsiConsole.MarkupLine($"UDP Scan Results for [yellow]{targetHostForDisplay} ({targetIp})[/]:");
            LogAndDisplayResults("Open UDP ports", openUdpPorts.OrderBy(p => p).ToList(), targetIp, s => Logger.Info(s), port => $"  Port {port}/UDP: [green]Open[/]");
            LogAndDisplayResults("Open|Filtered UDP ports", openOrFilteredUdpPorts.OrderBy(p => p).ToList(), targetIp, s => Logger.Info(s), port => $"  Port {port}/UDP: [yellow]Open|Filtered[/]");
            LogAndDisplayResults("Closed UDP ports", closedUdpPorts.OrderBy(p => p).ToList(), targetIp, s => Logger.Info(s), port => $"  Port {port}/UDP: [red]Closed[/]");
            LogAndDisplayResults("Errored UDP ports", erroredUdpPorts.OrderBy(p => p).ToList(), targetIp, s => Logger.Warning(s), port => $"  Port {port}/UDP: [orange1]Errored[/]");
        }

        // Internal UDP Scanner (called by ExecuteComprehensiveScanAsync)
        private static async Task PerformUdpPortScanTasksAsync(IPAddress targetIp, List<int> ports, 
                                                              ConcurrentBag<int> openUdpPorts, 
                                                              ConcurrentBag<int> closedUdpPorts, 
                                                              ConcurrentBag<int> openOrFilteredUdpPorts, 
                                                              ConcurrentBag<int> erroredUdpPorts)
        {
            byte[] payload = Array.Empty<byte>();
            const int receiveTimeoutMilliseconds = 2000;

            var progress = AnsiConsole.Progress()
                .AutoClear(false)
                .Columns(new ProgressColumn[]
                {
                    new TaskDescriptionColumn(), new ProgressBarColumn(), new PercentageColumn(), new RemainingTimeColumn(), new SpinnerColumn(Spinner.Known.Dots),
                });

            await progress.StartAsync(async ctx =>
            {
                var progressTask = ctx.AddTask("[green]Scanning UDP ports[/]", new ProgressTaskSettings { MaxValue = ports.Count });
                var semaphore = new SemaphoreSlim(MaxConcurrentScans);

                var scanTasks = ports.Select(async port =>
                {
                    await semaphore.WaitAsync();
                    try
                    {
                        using (var udpClient = new UdpClient())
                        {
                            // Set socket-level timeouts as a fallback, primary control is CancellationTokenSource
                            udpClient.Client.ReceiveTimeout = receiveTimeoutMilliseconds + 500; // Slightly longer than CTS
                            udpClient.Client.SendTimeout = receiveTimeoutMilliseconds;

                            try
                            {
                                using (var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(receiveTimeoutMilliseconds)))
                                {
                                    // SendAsync does not directly accept a CancellationToken for the send operation itself in all .NET versions/scenarios
                                    // The timeout for send is primarily managed by udpClient.Client.SendTimeout.
                                    await udpClient.SendAsync(payload, payload.Length, new IPEndPoint(targetIp, port));
                                    Logger.Debug($"Sent UDP probe to {targetIp}:{port}");

                                    UdpReceiveResult result = await udpClient.ReceiveAsync(cts.Token); // Token primarily for ReceiveAsync
                                    openUdpPorts.Add(port);
                                    Logger.Debug($"UDP Port {targetIp}:{port} is Open (received response of {result.Buffer.Length} bytes)");
                                }
                            }
                            catch (OperationCanceledException) // Timeout from cts.Token on ReceiveAsync
                            {
                                openOrFilteredUdpPorts.Add(port);
                                Logger.Debug($"UDP Port {targetIp}:{port} is Open|Filtered (Receive Timeout)");
                            }
                            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset || ex.SocketErrorCode == SocketError.ConnectionRefused)
                            {
                                closedUdpPorts.Add(port);
                                Logger.Debug($"UDP Port {targetIp}:{port} is Closed (ICMP Port Unreachable: {ex.SocketErrorCode})");
                            }
                            catch (SocketException ex) // Other socket exceptions
                            {
                                if (ex.SocketErrorCode == SocketError.TimedOut) // This might catch SendTimeout or ReceiveTimeout if CTS didn't cancel first
                                {
                                    openOrFilteredUdpPorts.Add(port);
                                    Logger.Debug($"UDP Port {targetIp}:{port} is Open|Filtered (Socket Level Timeout: {ex.SocketErrorCode})");
                                }
                                else
                                {
                                    erroredUdpPorts.Add(port);
                                    Logger.Error($"SocketException scanning UDP port {targetIp}:{port}. Error: {ex.SocketErrorCode}, Message: {ex.Message}", ex);
                                }
                            }
                            catch (Exception ex) // Non-socket related exceptions
                            {
                                erroredUdpPorts.Add(port);
                                Logger.Error($"Generic error scanning UDP port {targetIp}:{port}. Exception: {ex.ToString()}", ex);
                            }
                        }
                    }
                    catch (Exception ex) // Catch exceptions from UdpClient creation or semaphore handling
                    {
                        erroredUdpPorts.Add(port);
                        Logger.Error($"Outer error processing UDP port {targetIp}:{port}. Exception: {ex.ToString()}", ex);
                    }
                    finally
                    {
                        progressTask.Increment(1);
                        semaphore.Release();
                    }
                });
                await Task.WhenAll(scanTasks);
                progressTask.StopTask();
            });
        }

        // Helper method to resolve host and handle errors
        private static async Task<IPAddress?> ResolveHostAsync(string targetHost, bool interactiveConsole = true)
        {
            if (string.IsNullOrWhiteSpace(targetHost))
            {
                if (interactiveConsole) AnsiConsole.MarkupLine("[red]Target host cannot be empty.[/]");
                Logger.Error("ResolveHostAsync: Target host is null or whitespace.");
                return null;
            }
            try
            {
                IPHostEntry hostEntry = await Dns.GetHostEntryAsync(targetHost);
                IPAddress? primaryIp = hostEntry.AddressList.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork || ip.AddressFamily == AddressFamily.InterNetworkV6);
                
                if (primaryIp == null)
                {
                    if (interactiveConsole) AnsiConsole.MarkupLine($"[red]Could not resolve host: {targetHost}[/]");
                    Logger.Error($"ResolveHostAsync: No suitable IP address found for {targetHost}.");
                    return null;
                }

                string allIps = string.Join(", ", hostEntry.AddressList.Select(ip => ip.ToString()));
                if (interactiveConsole) AnsiConsole.MarkupLine($"Resolved [yellow]{targetHost}[/] to: [green]{primaryIp}[/] (Primary used for scan)");
                Logger.Info($"ResolveHostAsync: Resolved {targetHost} to: {allIps}. Using {primaryIp} for scan.");
                return primaryIp;
            }
            catch (SocketException ex)
            {
                if (interactiveConsole) AnsiConsole.MarkupLine($"[red]Error resolving host {targetHost}: {ex.Message}[/]");
                Logger.Error($"ResolveHostAsync: SocketException for {targetHost}", ex);
                return null;
            }
            catch (Exception ex)
            {
                if (interactiveConsole) AnsiConsole.MarkupLine($"[red]An unexpected error occurred while resolving host {targetHost}: {ex.Message}[/]");
                Logger.Error($"ResolveHostAsync: Unexpected error for {targetHost}", ex);
                return null;
            }
        }

        // Helper method to parse ports input
        private static List<int> ParsePortsInput(string portsInput, bool interactiveConsole = true)
        {
            var portsToScan = new List<int>();
            if (string.IsNullOrWhiteSpace(portsInput))
            {
                if (interactiveConsole) AnsiConsole.MarkupLine("[red]Ports input cannot be empty.[/]");
                Logger.Error("ParsePortsInput: Ports input is null or whitespace.");
                return portsToScan;
            }
            try
            {
                var parts = portsInput.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var part in parts)
                {
                    if (part.Contains('-'))
                    {
                        var range = part.Split('-');
                        if (range.Length == 2 && int.TryParse(range[0].Trim(), out int startPort) && int.TryParse(range[1].Trim(), out int endPort))
                        {
                            if (startPort <= endPort && startPort > 0 && endPort <= 65535)
                            {
                                for (int i = startPort; i <= endPort; i++)
                                {
                                    portsToScan.Add(i);
                                }
                            }
                            else
                            {
                                if (interactiveConsole) AnsiConsole.MarkupLine($"[red]Invalid port range: {part}. Ports must be between 1 and 65535 and start <= end.[/]");
                                Logger.Warning($"ParsePortsInput: Invalid port range {part}.");
                            }
                        }
                        else
                        {
                            if (interactiveConsole) AnsiConsole.MarkupLine($"[red]Invalid port range format: {part}[/]");
                            Logger.Warning($"ParsePortsInput: Invalid port range format {part}.");
                        }
                    }
                    else if (int.TryParse(part.Trim(), out int portNumber))
                    {
                        if (portNumber > 0 && portNumber <= 65535)
                        {
                            portsToScan.Add(portNumber);
                        }
                        else
                        {
                            if (interactiveConsole) AnsiConsole.MarkupLine($"[red]Invalid port number: {portNumber}. Port must be between 1 and 65535.[/]");
                            Logger.Warning($"ParsePortsInput: Invalid port number {portNumber}.");
                        }
                    }
                    else
                    {
                        if (interactiveConsole) AnsiConsole.MarkupLine($"[red]Invalid port entry: {part}[/]");
                        Logger.Warning($"ParsePortsInput: Invalid port entry {part}.");
                    }
                }
                return portsToScan.Distinct().OrderBy(p => p).ToList();
            }
            catch (Exception ex)
            {
                if (interactiveConsole) AnsiConsole.MarkupLine($"[red]Error parsing ports input: {ex.Message}[/]");
                Logger.Error("ParsePortsInput: Exception while parsing.", ex);
                return new List<int>();
            }
        }

        // Helper method to log and display results
        private static void LogAndDisplayResults(string title, List<int> ports, IPAddress targetIp, Action<string> logMethod, Func<int, string> displayPortFormat)
        {
            if (ports.Any())
            {
                // AnsiConsole.MarkupLine($"[bold]{title.Replace(" ports", "")}:[/] {string.Join(", ", ports)}"); // Simpler console output for list
                logMethod($"{title} on {targetIp}: {string.Join(", ", ports)}");
                AnsiConsole.MarkupLine($"[bold]{title}:[/]");
                foreach (var port in ports)
                {
                    AnsiConsole.MarkupLine(displayPortFormat(port));
                }
            }
        }
    }
}
