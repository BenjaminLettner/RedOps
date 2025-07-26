using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using RedOps.Utils;

namespace RedOps.Modules.Reconnaissance.NetworkDiscovery;

public class OSFingerprinter
{
    private const int DefaultTimeoutMilliseconds = 3000;

    public class OSFingerprintResult
    {
        public string IpAddress { get; set; } = string.Empty;
        public string OperatingSystem { get; set; } = "Unknown";
        public string OSVersion { get; set; } = string.Empty;
        public string Confidence { get; set; } = "Low";
        public List<string> Evidence { get; set; } = new List<string>();
        public int TTL { get; set; }
        public string TCPWindowSize { get; set; } = string.Empty;
        public List<string> OpenPorts { get; set; } = new List<string>();
    }

    public async Task<OSFingerprintResult> FingerprintOSAsync(string ipAddress, List<OpenPortInfo> openPorts)
    {
        var result = new OSFingerprintResult
        {
            IpAddress = ipAddress,
            OpenPorts = openPorts.Select(p => $"{p.Port}/{p.Protocol}").ToList()
        };

        try
        {
            Logger.Information($"Starting OS fingerprinting for {ipAddress}");

            // Perform multiple fingerprinting techniques
            await PerformTTLAnalysis(result);
            await AnalyzeServiceBanners(result, openPorts);
            AnalyzePortPatterns(result, openPorts);
            await PerformTCPFingerprinting(result);

            // Determine final OS based on collected evidence
            DetermineOperatingSystem(result);

            Logger.Information($"OS fingerprinting completed for {ipAddress}: {result.OperatingSystem} ({result.Confidence} confidence)");
        }
        catch (Exception ex)
        {
            Logger.Error($"Error during OS fingerprinting for {ipAddress}: {ex.Message}");
            result.OperatingSystem = "Error";
            result.Evidence.Add($"Fingerprinting failed: {ex.Message}");
        }

        return result;
    }

    private async Task PerformTTLAnalysis(OSFingerprintResult result)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(IPAddress.Parse(result.IpAddress), DefaultTimeoutMilliseconds);
            
            if (reply.Status == IPStatus.Success)
            {
                result.TTL = reply.Options?.Ttl ?? 0;
                
                // Common TTL values for different operating systems
                var ttlSignatures = new Dictionary<int, (string os, string evidence)>
                {
                    { 64, ("Linux/Unix", "TTL=64 (typical Linux/Unix)") },
                    { 128, ("Windows", "TTL=128 (typical Windows)") },
                    { 255, ("Cisco/Network Device", "TTL=255 (typical Cisco/Network equipment)") },
                    { 60, ("macOS", "TTL=60 (typical macOS)") },
                    { 32, ("Windows 95/98", "TTL=32 (Windows 95/98)") }
                };

                // Check for exact matches first
                if (ttlSignatures.ContainsKey(result.TTL))
                {
                    var (os, evidence) = ttlSignatures[result.TTL];
                    result.Evidence.Add(evidence);
                }
                else
                {
                    // Check for TTL ranges (accounting for hops)
                    if (result.TTL > 240) // Likely started at 255
                    {
                        result.Evidence.Add($"TTL={result.TTL} (likely Cisco/Network device, started at 255)");
                    }
                    else if (result.TTL > 120) // Likely started at 128
                    {
                        result.Evidence.Add($"TTL={result.TTL} (likely Windows, started at 128)");
                    }
                    else if (result.TTL > 56) // Likely started at 64
                    {
                        result.Evidence.Add($"TTL={result.TTL} (likely Linux/Unix, started at 64)");
                    }
                    else if (result.TTL > 28) // Likely started at 32
                    {
                        result.Evidence.Add($"TTL={result.TTL} (likely older Windows, started at 32)");
                    }
                    else
                    {
                        result.Evidence.Add($"TTL={result.TTL} (unusual TTL value)");
                    }
                }

                Logger.Debug($"TTL analysis for {result.IpAddress}: TTL={result.TTL}");
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"TTL analysis failed for {result.IpAddress}: {ex.Message}");
        }
    }

    private async Task AnalyzeServiceBanners(OSFingerprintResult result, List<OpenPortInfo> openPorts)
    {
        foreach (var port in openPorts.Where(p => !string.IsNullOrEmpty(p.Banner)))
        {
            var banner = port.Banner.ToLower();
            
            // SSH banner analysis
            if (banner.Contains("openssh"))
            {
                if (banner.Contains("ubuntu"))
                {
                    result.Evidence.Add($"SSH banner indicates Ubuntu: {port.Banner}");
                }
                else if (banner.Contains("debian"))
                {
                    result.Evidence.Add($"SSH banner indicates Debian: {port.Banner}");
                }
                else if (banner.Contains("centos") || banner.Contains("rhel"))
                {
                    result.Evidence.Add($"SSH banner indicates CentOS/RHEL: {port.Banner}");
                }
                else if (banner.Contains("freebsd"))
                {
                    result.Evidence.Add($"SSH banner indicates FreeBSD: {port.Banner}");
                }
                else
                {
                    result.Evidence.Add($"SSH banner indicates Linux/Unix: {port.Banner}");
                }
            }

            // HTTP Server header analysis
            if (banner.Contains("server:"))
            {
                if (banner.Contains("iis"))
                {
                    result.Evidence.Add($"IIS server indicates Windows: {port.Banner}");
                }
                else if (banner.Contains("apache"))
                {
                    if (banner.Contains("ubuntu"))
                    {
                        result.Evidence.Add($"Apache on Ubuntu: {port.Banner}");
                    }
                    else if (banner.Contains("debian"))
                    {
                        result.Evidence.Add($"Apache on Debian: {port.Banner}");
                    }
                    else if (banner.Contains("centos") || banner.Contains("rhel"))
                    {
                        result.Evidence.Add($"Apache on CentOS/RHEL: {port.Banner}");
                    }
                    else
                    {
                        result.Evidence.Add($"Apache server indicates Linux/Unix: {port.Banner}");
                    }
                }
                else if (banner.Contains("nginx"))
                {
                    result.Evidence.Add($"Nginx server indicates Linux/Unix: {port.Banner}");
                }
                else if (banner.Contains("microsoft"))
                {
                    result.Evidence.Add($"Microsoft server indicates Windows: {port.Banner}");
                }
            }

            // FTP banner analysis
            if (banner.Contains("microsoft ftp"))
            {
                result.Evidence.Add($"Microsoft FTP indicates Windows: {port.Banner}");
            }
            else if (banner.Contains("vsftpd"))
            {
                result.Evidence.Add($"vsftpd indicates Linux: {port.Banner}");
            }
            else if (banner.Contains("proftpd"))
            {
                result.Evidence.Add($"ProFTPD indicates Linux/Unix: {port.Banner}");
            }

            // SMTP banner analysis
            if (banner.Contains("microsoft smtp") || banner.Contains("exchange"))
            {
                result.Evidence.Add($"Microsoft SMTP/Exchange indicates Windows: {port.Banner}");
            }
            else if (banner.Contains("postfix"))
            {
                result.Evidence.Add($"Postfix indicates Linux/Unix: {port.Banner}");
            }
            else if (banner.Contains("sendmail"))
            {
                result.Evidence.Add($"Sendmail indicates Linux/Unix: {port.Banner}");
            }
        }
    }

    private void AnalyzePortPatterns(OSFingerprintResult result, List<OpenPortInfo> openPorts)
    {
        var tcpPorts = openPorts.Where(p => p.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase))
                                .Select(p => p.Port).ToHashSet();

        // Windows-specific port patterns
        if (tcpPorts.Contains(135) && tcpPorts.Contains(139) && tcpPorts.Contains(445))
        {
            result.Evidence.Add("Windows RPC/SMB ports (135, 139, 445) detected");
        }
        else if (tcpPorts.Contains(445))
        {
            result.Evidence.Add("SMB port (445) detected - likely Windows or Samba");
        }

        if (tcpPorts.Contains(3389))
        {
            result.Evidence.Add("RDP port (3389) detected - likely Windows");
        }

        if (tcpPorts.Contains(1433))
        {
            result.Evidence.Add("MSSQL port (1433) detected - likely Windows");
        }

        // Linux/Unix-specific patterns
        if (tcpPorts.Contains(22))
        {
            result.Evidence.Add("SSH port (22) detected - likely Linux/Unix");
        }

        if (tcpPorts.Contains(111))
        {
            result.Evidence.Add("RPC portmapper (111) detected - likely Linux/Unix");
        }

        // Network device patterns
        if (tcpPorts.Contains(161) || tcpPorts.Contains(162))
        {
            result.Evidence.Add("SNMP ports detected - likely network device");
        }

        if (tcpPorts.Contains(23) && tcpPorts.Count < 5)
        {
            result.Evidence.Add("Telnet with few open ports - likely network device");
        }
    }

    private async Task PerformTCPFingerprinting(OSFingerprintResult result)
    {
        try
        {
            // Attempt to connect to a common port to analyze TCP characteristics
            var testPorts = new[] { 80, 443, 22, 23, 21 };
            
            foreach (var port in testPorts)
            {
                try
                {
                    using var client = new TcpClient();
                    var connectTask = client.ConnectAsync(IPAddress.Parse(result.IpAddress), port);
                    
                    if (await Task.WhenAny(connectTask, Task.Delay(1000)) == connectTask && client.Connected)
                    {
                        // Connection successful - we could analyze TCP window size here
                        // This is a simplified implementation
                        result.TCPWindowSize = "Connected successfully";
                        Logger.Debug($"TCP connection successful to {result.IpAddress}:{port}");
                        break;
                    }
                }
                catch (Exception ex)
                {
                    Logger.Debug($"TCP connection failed to {result.IpAddress}:{port}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"TCP fingerprinting failed for {result.IpAddress}: {ex.Message}");
        }
    }

    private void DetermineOperatingSystem(OSFingerprintResult result)
    {
        var evidenceText = string.Join(" ", result.Evidence).ToLower();
        var windowsScore = 0;
        var linuxScore = 0;
        var networkDeviceScore = 0;
        var macosScore = 0;

        // Score based on evidence
        if (evidenceText.Contains("windows") || evidenceText.Contains("iis") || 
            evidenceText.Contains("microsoft") || evidenceText.Contains("exchange") ||
            evidenceText.Contains("rdp") || evidenceText.Contains("mssql"))
        {
            windowsScore += 3;
        }

        if (evidenceText.Contains("ttl=128") || evidenceText.Contains("started at 128"))
        {
            windowsScore += 2;
        }

        if (evidenceText.Contains("smb") && evidenceText.Contains("rpc"))
        {
            windowsScore += 2;
        }

        if (evidenceText.Contains("linux") || evidenceText.Contains("ubuntu") || 
            evidenceText.Contains("debian") || evidenceText.Contains("centos") ||
            evidenceText.Contains("rhel") || evidenceText.Contains("apache") ||
            evidenceText.Contains("nginx") || evidenceText.Contains("openssh") ||
            evidenceText.Contains("postfix") || evidenceText.Contains("sendmail"))
        {
            linuxScore += 3;
        }

        if (evidenceText.Contains("ttl=64") || evidenceText.Contains("started at 64"))
        {
            linuxScore += 2;
        }

        if (evidenceText.Contains("ssh"))
        {
            linuxScore += 1;
        }

        if (evidenceText.Contains("cisco") || evidenceText.Contains("network device") ||
            evidenceText.Contains("snmp") || evidenceText.Contains("ttl=255"))
        {
            networkDeviceScore += 3;
        }

        if (evidenceText.Contains("macos") || evidenceText.Contains("ttl=60"))
        {
            macosScore += 2;
        }

        // Determine OS based on highest score
        var maxScore = Math.Max(Math.Max(windowsScore, linuxScore), Math.Max(networkDeviceScore, macosScore));
        
        if (maxScore == 0)
        {
            result.OperatingSystem = "Unknown";
            result.Confidence = "Very Low";
        }
        else if (maxScore == windowsScore)
        {
            result.OperatingSystem = "Windows";
            result.Confidence = maxScore >= 4 ? "High" : maxScore >= 2 ? "Medium" : "Low";
        }
        else if (maxScore == linuxScore)
        {
            result.OperatingSystem = "Linux/Unix";
            result.Confidence = maxScore >= 4 ? "High" : maxScore >= 2 ? "Medium" : "Low";
        }
        else if (maxScore == networkDeviceScore)
        {
            result.OperatingSystem = "Network Device";
            result.Confidence = maxScore >= 3 ? "High" : "Medium";
        }
        else if (maxScore == macosScore)
        {
            result.OperatingSystem = "macOS";
            result.Confidence = maxScore >= 2 ? "Medium" : "Low";
        }

        // Extract version information if available
        ExtractOSVersion(result);
    }

    private void ExtractOSVersion(OSFingerprintResult result)
    {
        foreach (var evidence in result.Evidence)
        {
            var evidenceLower = evidence.ToLower();
            
            // Ubuntu version extraction
            if (evidenceLower.Contains("ubuntu"))
            {
                var ubuntuMatch = System.Text.RegularExpressions.Regex.Match(evidence, @"ubuntu[^\d]*(\d+\.\d+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (ubuntuMatch.Success)
                {
                    result.OSVersion = $"Ubuntu {ubuntuMatch.Groups[1].Value}";
                    return;
                }
            }
            
            // Debian version extraction
            if (evidenceLower.Contains("debian"))
            {
                var debianMatch = System.Text.RegularExpressions.Regex.Match(evidence, @"debian[^\d]*(\d+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (debianMatch.Success)
                {
                    result.OSVersion = $"Debian {debianMatch.Groups[1].Value}";
                    return;
                }
            }
            
            // CentOS/RHEL version extraction
            if (evidenceLower.Contains("centos") || evidenceLower.Contains("rhel"))
            {
                var centosMatch = System.Text.RegularExpressions.Regex.Match(evidence, @"(?:centos|rhel)[^\d]*(\d+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (centosMatch.Success)
                {
                    var osName = evidenceLower.Contains("centos") ? "CentOS" : "RHEL";
                    result.OSVersion = $"{osName} {centosMatch.Groups[1].Value}";
                    return;
                }
            }
        }
    }
}
