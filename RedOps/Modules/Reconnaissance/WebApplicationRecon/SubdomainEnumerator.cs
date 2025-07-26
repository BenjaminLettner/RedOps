using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using Serilog;
using Spectre.Console;
using RedOps.Utils;

namespace RedOps.Modules.Reconnaissance.WebApplicationRecon
{
    public class SubdomainEnumerationOptions
    {
        public bool UseCommonSubdomains { get; set; } = true;
        public bool UseComprehensiveSubdomains { get; set; } = false;
        public bool PerformDnsResolution { get; set; } = true;
        public bool CheckHttpStatus { get; set; } = true;
        public bool IncludeWildcardDetection { get; set; } = true;
        public int MaxConcurrency { get; set; } = 50;
        public int TimeoutSeconds { get; set; } = 5;
        public List<string> CustomSubdomains { get; set; } = new();
        public List<string> CustomDnsServers { get; set; } = new();
    }

    public class SubdomainInfo
    {
        public string Subdomain { get; set; } = string.Empty;
        public string FullDomain { get; set; } = string.Empty;
        public List<IPAddress> IpAddresses { get; set; } = new();
        public bool IsResolvable { get; set; }
        public bool IsReachable { get; set; }
        public int? HttpStatusCode { get; set; }
        public string? HttpRedirectLocation { get; set; }
        public long ResponseTimeMs { get; set; }
        public List<string> CnameRecords { get; set; } = new();
        public List<string> TxtRecords { get; set; } = new();
        public bool IsWildcard { get; set; }
        public DateTime DiscoveryTime { get; set; } = DateTime.Now;
    }

    public class SubdomainEnumerationResult
    {
        public string Domain { get; set; } = string.Empty;
        public DateTime ScanTime { get; set; } = DateTime.Now;
        public SubdomainEnumerationOptions Options { get; set; } = new();
        public List<SubdomainInfo> DiscoveredSubdomains { get; set; } = new();
        public List<SubdomainInfo> ReachableSubdomains { get; set; } = new();
        public int TotalSubdomainsChecked { get; set; }
        public int ResolvedSubdomains { get; set; }
        public int ReachableSubdomainsCount { get; set; }
        public bool WildcardDetected { get; set; }
        public string? WildcardIp { get; set; }
        public TimeSpan ScanDuration { get; set; }
        public string? Error { get; set; }
    }

    public class SubdomainEnumerator : IDisposable
    {
        private static readonly ILogger Logger = Serilog.Log.ForContext<SubdomainEnumerator>();
        private readonly SemaphoreSlim _semaphore;
        private readonly WordlistManager _wordlistManager;
        private readonly System.Net.Http.HttpClient _httpClient;

        public SubdomainEnumerator(int maxConcurrency = 50)
        {
            _semaphore = new SemaphoreSlim(maxConcurrency, maxConcurrency);
            _wordlistManager = new WordlistManager();
            _httpClient = new System.Net.Http.HttpClient()
            {
                Timeout = TimeSpan.FromSeconds(10)
            };
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "RedOps/1.0 (Security Scanner)");
        }

        public async Task<SubdomainEnumerationResult> EnumerateSubdomainsAsync(string domain, SubdomainEnumerationOptions options)
        {
            var startTime = DateTime.Now;
            var result = new SubdomainEnumerationResult
            {
                Domain = domain,
                ScanTime = startTime,
                Options = options
            };

            try
            {
                Logger.Information($"Starting subdomain enumeration for {domain}");

                // Clean domain name
                domain = CleanDomainName(domain);
                result.Domain = domain;

                // Detect wildcard DNS
                if (options.IncludeWildcardDetection)
                {
                    await DetectWildcardDns(domain, result);
                }

                // Get subdomain wordlists
                var subdomains = await GetSubdomainWordlistsAsync(options);
                result.TotalSubdomainsChecked = subdomains.Count;

                Logger.Information($"Testing {subdomains.Count} potential subdomains for {domain}");

                // Perform subdomain enumeration with progress tracking
                await EnumerateWithProgress(domain, subdomains, result, options);

                // Filter and categorize results
                result.DiscoveredSubdomains = result.DiscoveredSubdomains
                    .Where(s => s.IsResolvable && !s.IsWildcard)
                    .OrderBy(s => s.Subdomain)
                    .ToList();

                result.ReachableSubdomains = result.DiscoveredSubdomains
                    .Where(s => s.IsReachable)
                    .ToList();

                result.ResolvedSubdomains = result.DiscoveredSubdomains.Count;
                result.ReachableSubdomainsCount = result.ReachableSubdomains.Count;
                result.ScanDuration = DateTime.Now - startTime;

                Logger.Information($"Subdomain enumeration completed for {domain}. Found {result.ResolvedSubdomains} subdomains ({result.ReachableSubdomainsCount} reachable)");
            }
            catch (Exception ex)
            {
                Logger.Error($"Error during subdomain enumeration for {domain}: {ex.Message}");
                result.Error = ex.Message;
                result.ScanDuration = DateTime.Now - startTime;
            }

            return result;
        }

        private string CleanDomainName(string domain)
        {
            // Remove protocol if present
            if (domain.StartsWith("http://") || domain.StartsWith("https://"))
            {
                var uri = new Uri(domain);
                domain = uri.Host;
            }

            // Remove www prefix if present
            if (domain.StartsWith("www."))
            {
                domain = domain.Substring(4);
            }

            return domain.ToLower().Trim();
        }

        private async Task DetectWildcardDns(string domain, SubdomainEnumerationResult result)
        {
            try
            {
                Logger.Information($"Detecting wildcard DNS for {domain}");

                // Generate random subdomain that shouldn't exist
                var randomSubdomain = $"{Guid.NewGuid().ToString("N")[..8]}.{domain}";
                
                var addresses = await ResolveHostnameAsync(randomSubdomain);
                if (addresses.Any())
                {
                    result.WildcardDetected = true;
                    result.WildcardIp = addresses.First().ToString();
                    Logger.Warning($"Wildcard DNS detected for {domain} - resolves to {result.WildcardIp}");
                }
                else
                {
                    Logger.Information($"No wildcard DNS detected for {domain}");
                }
            }
            catch (Exception ex)
            {
                Logger.Warning($"Error detecting wildcard DNS for {domain}: {ex.Message}");
            }
        }

        private async Task<List<string>> GetSubdomainWordlistsAsync(SubdomainEnumerationOptions options)
        {
            var allSubdomains = new List<string>();

            if (options.UseComprehensiveSubdomains)
            {
                var comprehensive = await _wordlistManager.GetWordlistAsync(WordlistType.ComprehensiveSubdomains);
                allSubdomains.AddRange(comprehensive);
                Logger.Information($"Loaded {comprehensive.Count} comprehensive subdomains");
            }

            if (options.UseCommonSubdomains)
            {
                var common = await _wordlistManager.GetWordlistAsync(WordlistType.Subdomains);
                allSubdomains.AddRange(common);
                Logger.Information($"Loaded {common.Count} common subdomains");
            }

            // Add custom subdomains
            if (options.CustomSubdomains?.Any() == true)
            {
                allSubdomains.AddRange(options.CustomSubdomains);
                Logger.Information($"Added {options.CustomSubdomains.Count} custom subdomains");
            }

            // If no wordlists selected, use common as default
            if (!allSubdomains.Any())
            {
                var fallback = await _wordlistManager.GetWordlistAsync(WordlistType.Subdomains);
                allSubdomains.AddRange(fallback);
                Logger.Information($"Using fallback common subdomains: {fallback.Count} entries");
            }

            return allSubdomains.Distinct().ToList();
        }

        private async Task EnumerateWithProgress(string domain, List<string> subdomains, SubdomainEnumerationResult result, SubdomainEnumerationOptions options)
        {
            var progress = AnsiConsole.Progress()
                .Columns(new ProgressColumn[]
                {
                    new TaskDescriptionColumn(),
                    new ProgressBarColumn(),
                    new PercentageColumn(),
                    new RemainingTimeColumn(),
                    new SpinnerColumn()
                });

            await progress.StartAsync(async ctx =>
            {
                var task = ctx.AddTask($"[green]Enumerating subdomains for {domain}[/]", maxValue: subdomains.Count);

                var semaphore = new SemaphoreSlim(options.MaxConcurrency, options.MaxConcurrency);
                var tasks = subdomains.Select(async subdomain =>
                {
                    await semaphore.WaitAsync();
                    try
                    {
                        var subdomainInfo = await CheckSubdomainAsync(subdomain, domain, options);
                        if (subdomainInfo != null)
                        {
                            lock (result.DiscoveredSubdomains)
                            {
                                result.DiscoveredSubdomains.Add(subdomainInfo);
                            }
                        }
                    }
                    finally
                    {
                        semaphore.Release();
                        task.Increment(1);
                    }
                });

                await Task.WhenAll(tasks);
            });
        }

        private async Task<SubdomainInfo?> CheckSubdomainAsync(string subdomain, string domain, SubdomainEnumerationOptions options)
        {
            try
            {
                var fullDomain = $"{subdomain}.{domain}";
                var subdomainInfo = new SubdomainInfo
                {
                    Subdomain = subdomain,
                    FullDomain = fullDomain
                };

                var startTime = DateTime.Now;

                // Perform DNS resolution
                if (options.PerformDnsResolution)
                {
                    var addresses = await ResolveHostnameAsync(fullDomain);
                    if (addresses.Any())
                    {
                        subdomainInfo.IsResolvable = true;
                        subdomainInfo.IpAddresses = addresses.ToList();

                        // Additional DNS record lookups
                        await GetAdditionalDnsRecords(fullDomain, subdomainInfo);
                    }
                }

                subdomainInfo.ResponseTimeMs = (long)(DateTime.Now - startTime).TotalMilliseconds;

                // Check HTTP status if resolvable
                if (subdomainInfo.IsResolvable && options.CheckHttpStatus)
                {
                    await CheckHttpStatus(subdomainInfo, options);
                }

                // Only return if resolvable (unless it's a custom subdomain)
                if (subdomainInfo.IsResolvable || options.CustomSubdomains.Contains(subdomain))
                {
                    Logger.Debug($"Found subdomain: {fullDomain} -> {string.Join(", ", subdomainInfo.IpAddresses)}");
                    return subdomainInfo;
                }

                return null;
            }
            catch (Exception ex)
            {
                Logger.Debug($"Error checking subdomain {subdomain}.{domain}: {ex.Message}");
                return null;
            }
        }

        private async Task<IPAddress[]> ResolveHostnameAsync(string hostname)
        {
            try
            {
                var hostEntry = await Dns.GetHostEntryAsync(hostname);
                return hostEntry.AddressList;
            }
            catch
            {
                return Array.Empty<IPAddress>();
            }
        }

        private async Task GetAdditionalDnsRecords(string hostname, SubdomainInfo subdomainInfo)
        {
            try
            {
                // This is a simplified version - in a full implementation,
                // you might use a DNS library like DnsClient.NET for more detailed queries
                var hostEntry = await Dns.GetHostEntryAsync(hostname);
                
                // Check for CNAME by comparing hostname with aliases
                if (hostEntry.Aliases?.Any() == true)
                {
                    subdomainInfo.CnameRecords.AddRange(hostEntry.Aliases);
                }
            }
            catch (Exception ex)
            {
                Logger.Debug($"Error getting additional DNS records for {hostname}: {ex.Message}");
            }
        }

        private async Task CheckHttpStatus(SubdomainInfo subdomainInfo, SubdomainEnumerationOptions options)
        {
            var protocols = new[] { "https", "http" };
            
            foreach (var protocol in protocols)
            {
                try
                {
                    var url = $"{protocol}://{subdomainInfo.FullDomain}";
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(options.TimeoutSeconds));
                    
                    var response = await _httpClient.GetAsync(url, cts.Token);
                    subdomainInfo.IsReachable = true;
                    subdomainInfo.HttpStatusCode = (int)response.StatusCode;

                    // Check for redirects
                    if (response.Headers.Location != null)
                    {
                        subdomainInfo.HttpRedirectLocation = response.Headers.Location.ToString();
                    }

                    Logger.Debug($"HTTP {protocol.ToUpper()} check for {subdomainInfo.FullDomain}: {response.StatusCode}");
                    break; // If HTTPS works, don't try HTTP
                }
                catch (TaskCanceledException)
                {
                    Logger.Debug($"HTTP {protocol.ToUpper()} timeout for {subdomainInfo.FullDomain}");
                }
                catch (Exception ex)
                {
                    Logger.Debug($"HTTP {protocol.ToUpper()} error for {subdomainInfo.FullDomain}: {ex.Message}");
                }
            }
        }

        public void DisplayResults(SubdomainEnumerationResult result)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule($"[bold green]Subdomain Enumeration Results for {result.Domain}[/]").RuleStyle("green"));
            AnsiConsole.WriteLine();

            // Summary
            var summaryTable = new Table()
                .Border(TableBorder.Rounded)
                .BorderColor(Color.Green);

            summaryTable.AddColumn("[bold]Metric[/]");
            summaryTable.AddColumn("[bold]Value[/]");

            summaryTable.AddRow("Domain", result.Domain);
            summaryTable.AddRow("Scan Time", result.ScanTime.ToString("yyyy-MM-dd HH:mm:ss"));
            summaryTable.AddRow("Duration", $"{result.ScanDuration.TotalSeconds:F1} seconds");
            summaryTable.AddRow("Subdomains Checked", result.TotalSubdomainsChecked.ToString());
            summaryTable.AddRow("Resolved Subdomains", $"[green]{result.ResolvedSubdomains}[/]");
            summaryTable.AddRow("Reachable Subdomains", $"[yellow]{result.ReachableSubdomainsCount}[/]");
            summaryTable.AddRow("Wildcard Detected", result.WildcardDetected ? $"[red]Yes ({result.WildcardIp})[/]" : "[green]No[/]");

            AnsiConsole.Write(summaryTable);
            AnsiConsole.WriteLine();

            if (result.DiscoveredSubdomains.Any())
            {
                // Discovered subdomains table
                var subdomainsTable = new Table()
                    .Border(TableBorder.Rounded)
                    .BorderColor(Color.Blue);

                subdomainsTable.AddColumn("[bold]Subdomain[/]");
                subdomainsTable.AddColumn("[bold]IP Address(es)[/]");
                subdomainsTable.AddColumn("[bold]HTTP Status[/]");
                subdomainsTable.AddColumn("[bold]Response Time[/]");
                subdomainsTable.AddColumn("[bold]Notes[/]");

                foreach (var subdomain in result.DiscoveredSubdomains.Take(50)) // Limit display
                {
                    var ipAddresses = string.Join(", ", subdomain.IpAddresses.Take(3));
                    if (subdomain.IpAddresses.Count > 3)
                        ipAddresses += $" (+{subdomain.IpAddresses.Count - 3} more)";

                    var httpStatus = subdomain.HttpStatusCode?.ToString() ?? "N/A";
                    var statusColor = subdomain.IsReachable ? "green" : "gray";
                    
                    var notes = new List<string>();
                    if (subdomain.CnameRecords.Any())
                        notes.Add($"CNAME: {string.Join(", ", subdomain.CnameRecords.Take(2))}");
                    if (!string.IsNullOrEmpty(subdomain.HttpRedirectLocation))
                        notes.Add($"Redirects to: {subdomain.HttpRedirectLocation}");

                    subdomainsTable.AddRow(
                        $"[cyan]{subdomain.FullDomain}[/]",
                        ipAddresses,
                        $"[{statusColor}]{httpStatus}[/]",
                        $"{subdomain.ResponseTimeMs}ms",
                        string.Join("; ", notes)
                    );
                }

                if (result.DiscoveredSubdomains.Count > 50)
                {
                    subdomainsTable.AddRow($"[dim]... and {result.DiscoveredSubdomains.Count - 50} more subdomains[/]", "", "", "", "");
                }

                AnsiConsole.Write(subdomainsTable);
            }
            else
            {
                AnsiConsole.MarkupLine("[yellow]No subdomains discovered.[/]");
            }

            AnsiConsole.WriteLine();
        }

        public async Task<bool> SaveResultsAsync(SubdomainEnumerationResult result, string? filePath = null)
        {
            try
            {
                filePath ??= $"subdomain_enumeration_{result.Domain}_{DateTime.Now:yyyyMMdd_HHmmss}.txt";

                var content = new System.Text.StringBuilder();
                content.AppendLine($"Subdomain Enumeration Report");
                content.AppendLine($"Domain: {result.Domain}");
                content.AppendLine($"Scan Time: {result.ScanTime:yyyy-MM-dd HH:mm:ss}");
                content.AppendLine($"Duration: {result.ScanDuration.TotalSeconds:F1} seconds");
                content.AppendLine($"Subdomains Checked: {result.TotalSubdomainsChecked}");
                content.AppendLine($"Resolved Subdomains: {result.ResolvedSubdomains}");
                content.AppendLine($"Reachable Subdomains: {result.ReachableSubdomainsCount}");
                content.AppendLine($"Wildcard Detected: {(result.WildcardDetected ? $"Yes ({result.WildcardIp})" : "No")}");
                content.AppendLine();

                if (result.DiscoveredSubdomains.Any())
                {
                    content.AppendLine("Discovered Subdomains:");
                    content.AppendLine("======================");
                    
                    foreach (var subdomain in result.DiscoveredSubdomains)
                    {
                        content.AppendLine($"[{subdomain.HttpStatusCode ?? 0}] {subdomain.FullDomain}");
                        content.AppendLine($"    IP Addresses: {string.Join(", ", subdomain.IpAddresses)}");
                        content.AppendLine($"    Response Time: {subdomain.ResponseTimeMs}ms");
                        content.AppendLine($"    Reachable: {(subdomain.IsReachable ? "Yes" : "No")}");
                        
                        if (subdomain.CnameRecords.Any())
                            content.AppendLine($"    CNAME: {string.Join(", ", subdomain.CnameRecords)}");
                        
                        if (!string.IsNullOrEmpty(subdomain.HttpRedirectLocation))
                            content.AppendLine($"    Redirects to: {subdomain.HttpRedirectLocation}");
                        
                        content.AppendLine();
                    }
                }

                await System.IO.File.WriteAllTextAsync(filePath, content.ToString());
                Logger.Information($"Subdomain enumeration results saved to {filePath}");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Error saving subdomain enumeration results: {ex.Message}");
                return false;
            }
        }

        public void Dispose()
        {
            _semaphore?.Dispose();
            _httpClient?.Dispose();
        }
    }
}
