using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using RedOps.Utils; // For Logger

namespace RedOps.Modules.Reconnaissance.NetworkDiscovery;

public class ServiceDetector
{
    private const int DefaultTimeoutMilliseconds = 2000; // 2 seconds timeout for connection and read

    public async Task<List<OpenPortInfo>> DetectServicesAsync(List<OpenPortInfo> openPorts)
    {
        var updatedPortInfoList = new List<OpenPortInfo>();

        foreach (var portInfo in openPorts)
        {
            if (portInfo.Protocol.Equals("TCP", System.StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    using (var client = new TcpClient())
                    {
                        var connectTask = client.ConnectAsync(portInfo.IpAddress, portInfo.Port);
                        if (await Task.WhenAny(connectTask, Task.Delay(DefaultTimeoutMilliseconds)) == connectTask && client.Connected)
                        {
                            // Connected successfully
                            using (var stream = client.GetStream())
                            {
                                // Set a read timeout
                                stream.ReadTimeout = DefaultTimeoutMilliseconds;
                                byte[] buffer = new byte[1024]; // Buffer to store the banner
                                int bytesRead = 0;

                                try
                                {
                                    // Attempt to read some data (banner)
                                    var readTask = stream.ReadAsync(buffer, 0, buffer.Length);
                                    if (await Task.WhenAny(readTask, Task.Delay(DefaultTimeoutMilliseconds)) == readTask)
                                    {
                                        bytesRead = await readTask;
                                    }
                                }
                                catch (System.IO.IOException ex) when (ex.InnerException is SocketException se && se.SocketErrorCode == SocketError.TimedOut)
                                {
                                    // Read timed out, which is common if the service doesn't send an immediate banner
                                    Logger.Debug($"Read timeout for {portInfo.IpAddress}:{portInfo.Port}. No banner received.");
                                }
                                catch (Exception ex)
                                {
                                    Logger.Debug($"Error reading banner from {portInfo.IpAddress}:{portInfo.Port}: {ex.Message}");
                                }

                                if (bytesRead > 0)
                                {
                                    portInfo.Banner = Encoding.ASCII.GetString(buffer, 0, bytesRead).Trim();
                                    // Basic parsing (can be greatly expanded)
                                    ParseBanner(portInfo);
                                    Logger.Verbose($"Banner from {portInfo.IpAddress}:{portInfo.Port}: {portInfo.Banner}");
                                }
                                else
                                {
                                    Logger.Verbose($"No banner received from {portInfo.IpAddress}:{portInfo.Port}.");
                                }
                            }
                        }
                        else
                        {
                            Logger.Debug($"Connection timed out or failed for {portInfo.IpAddress}:{portInfo.Port}.");
                        }
                    }
                }
                catch (SocketException ex)
                {
                    // Handle specific socket errors, e.g., connection refused
                    Logger.Debug($"SocketException connecting to {portInfo.IpAddress}:{portInfo.Port}: {ex.Message}");
                }
                catch (Exception ex)
                {
                    Logger.Error($"Error detecting service on {portInfo.IpAddress}:{portInfo.Port}: {ex.Message}");
                }
            }
            else if (portInfo.Protocol.Equals("UDP", System.StringComparison.OrdinalIgnoreCase))
            {
                // UDP service detection is more complex and often requires service-specific probes.
                // For now, we'll skip detailed UDP service detection.
                portInfo.ServiceName = "Unknown UDP Service";
                Logger.Debug($"UDP service detection for {portInfo.IpAddress}:{portInfo.Port} not yet implemented.");
            }
            updatedPortInfoList.Add(portInfo);
        }
        return updatedPortInfoList;
    }

    private void ParseBanner(OpenPortInfo portInfo)
    {
        if (string.IsNullOrWhiteSpace(portInfo.Banner))
        {
            // Try to identify service by port number if no banner
            IdentifyServiceByPort(portInfo);
            return;
        }

        // Enhanced service detection with more comprehensive parsing
        // Order matters, more specific patterns should come first
        
        // SSH Detection
        if (portInfo.Banner.Contains("SSH-"))
        {
            portInfo.ServiceName = "SSH";
            // Example: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
            var sshMatch = System.Text.RegularExpressions.Regex.Match(portInfo.Banner, @"SSH-(\d+\.\d+)-([^\s\r\n]+)");
            if (sshMatch.Success)
            {
                portInfo.ServiceVersion = $"v{sshMatch.Groups[1].Value} {sshMatch.Groups[2].Value}";
            }
        }
        // HTTP/HTTPS Detection
        else if (portInfo.Banner.StartsWith("HTTP/") || portInfo.Banner.Contains("Server: "))
        {
            portInfo.ServiceName = portInfo.Port == 443 ? "HTTPS" : "HTTP";
            var serverMatch = System.Text.RegularExpressions.Regex.Match(portInfo.Banner, @"Server: ([^\r\n]+)");
            if (serverMatch.Success)
            {
                portInfo.ServiceVersion = serverMatch.Groups[1].Value.Trim();
            }
            else
            {
                var httpMatch = System.Text.RegularExpressions.Regex.Match(portInfo.Banner, @"HTTP/([\d\.]+)");
                if (httpMatch.Success)
                {
                    portInfo.ServiceVersion = $"HTTP/{httpMatch.Groups[1].Value}";
                }
            }
        }
        // FTP Detection
        else if (portInfo.Banner.Contains("FTP") || portInfo.Banner.StartsWith("220"))
        {
            portInfo.ServiceName = "FTP";
            // Examples: 220 (vsFTPd 3.0.3), 220 Microsoft FTP Service, 220 ProFTPD Server
            var ftpPatterns = new[]
            {
                @"220[\s-]+([^\r\n\(]+)\(([^\)]+)\)", // 220 (vsFTPd 3.0.3)
                @"220[\s-]+([^\r\n]+?)(?:\s+ready|\s*$)", // 220 Microsoft FTP Service
                @"\(([^\)]+)\)" // Generic parentheses content
            };
            
            foreach (var pattern in ftpPatterns)
            {
                var match = System.Text.RegularExpressions.Regex.Match(portInfo.Banner, pattern);
                if (match.Success)
                {
                    portInfo.ServiceVersion = match.Groups[match.Groups.Count - 1].Value.Trim();
                    break;
                }
            }
        }
        // SMTP Detection
        else if (portInfo.Banner.StartsWith("220") && (portInfo.Port == 25 || portInfo.Port == 587 || portInfo.Port == 465))
        {
            portInfo.ServiceName = "SMTP";
            var smtpMatch = System.Text.RegularExpressions.Regex.Match(portInfo.Banner, @"220[\s-]+([^\r\n]+)");
            if (smtpMatch.Success)
            {
                portInfo.ServiceVersion = smtpMatch.Groups[1].Value.Trim();
            }
        }
        // POP3 Detection
        else if (portInfo.Banner.StartsWith("+OK") && (portInfo.Port == 110 || portInfo.Port == 995))
        {
            portInfo.ServiceName = "POP3";
            var pop3Match = System.Text.RegularExpressions.Regex.Match(portInfo.Banner, @"\+OK\s+([^\r\n]+)");
            if (pop3Match.Success)
            {
                portInfo.ServiceVersion = pop3Match.Groups[1].Value.Trim();
            }
        }
        // IMAP Detection
        else if (portInfo.Banner.StartsWith("* OK") && (portInfo.Port == 143 || portInfo.Port == 993))
        {
            portInfo.ServiceName = "IMAP";
            var imapMatch = System.Text.RegularExpressions.Regex.Match(portInfo.Banner, @"\* OK\s+([^\r\n]+)");
            if (imapMatch.Success)
            {
                portInfo.ServiceVersion = imapMatch.Groups[1].Value.Trim();
            }
        }
        // Telnet Detection
        else if (portInfo.Port == 23 || portInfo.Banner.ToLower().Contains("telnet"))
        {
            portInfo.ServiceName = "Telnet";
            portInfo.ServiceVersion = portInfo.Banner.Length > 50 ? portInfo.Banner.Substring(0, 50) + "..." : portInfo.Banner;
        }
        // DNS Detection
        else if (portInfo.Port == 53)
        {
            portInfo.ServiceName = "DNS";
            portInfo.ServiceVersion = "DNS Server";
        }
        // MySQL Detection
        else if (portInfo.Port == 3306 || portInfo.Banner.Contains("mysql"))
        {
            portInfo.ServiceName = "MySQL";
            var mysqlMatch = System.Text.RegularExpressions.Regex.Match(portInfo.Banner, @"([\d\.]+)-([^\s\r\n]+)");
            if (mysqlMatch.Success)
            {
                portInfo.ServiceVersion = $"v{mysqlMatch.Groups[1].Value} {mysqlMatch.Groups[2].Value}";
            }
        }
        // PostgreSQL Detection
        else if (portInfo.Port == 5432 || portInfo.Banner.ToLower().Contains("postgresql"))
        {
            portInfo.ServiceName = "PostgreSQL";
            portInfo.ServiceVersion = "PostgreSQL Database";
        }
        // Redis Detection
        else if (portInfo.Port == 6379 || portInfo.Banner.StartsWith("+PONG") || portInfo.Banner.Contains("redis"))
        {
            portInfo.ServiceName = "Redis";
            portInfo.ServiceVersion = "Redis Server";
        }
        // MongoDB Detection
        else if (portInfo.Port == 27017 || portInfo.Banner.Contains("mongodb"))
        {
            portInfo.ServiceName = "MongoDB";
            portInfo.ServiceVersion = "MongoDB Database";
        }
        // RDP Detection
        else if (portInfo.Port == 3389)
        {
            portInfo.ServiceName = "RDP";
            portInfo.ServiceVersion = "Remote Desktop Protocol";
        }
        // VNC Detection
        else if (portInfo.Banner.StartsWith("RFB") || portInfo.Port == 5900)
        {
            portInfo.ServiceName = "VNC";
            var vncMatch = System.Text.RegularExpressions.Regex.Match(portInfo.Banner, @"RFB\s+([\d\.]+)");
            if (vncMatch.Success)
            {
                portInfo.ServiceVersion = $"RFB v{vncMatch.Groups[1].Value}";
            }
            else
            {
                portInfo.ServiceVersion = "VNC Server";
            }
        }
        // SNMP Detection
        else if (portInfo.Port == 161 || portInfo.Port == 162)
        {
            portInfo.ServiceName = "SNMP";
            portInfo.ServiceVersion = "SNMP Agent";
        }
        // Default fallback
        else
        {
            IdentifyServiceByPort(portInfo);
            // Use a snippet of the banner if no specific service is identified
            if (string.IsNullOrEmpty(portInfo.ServiceVersion))
            {
                portInfo.ServiceVersion = portInfo.Banner.Length > 50 ? portInfo.Banner.Substring(0, 50) + "..." : portInfo.Banner;
            }
        }
    }

    private void IdentifyServiceByPort(OpenPortInfo portInfo)
    {
        // Common port to service mappings when no banner is available
        var commonPorts = new Dictionary<int, (string service, string description)>
        {
            { 21, ("FTP", "File Transfer Protocol") },
            { 22, ("SSH", "Secure Shell") },
            { 23, ("Telnet", "Telnet Protocol") },
            { 25, ("SMTP", "Simple Mail Transfer Protocol") },
            { 53, ("DNS", "Domain Name System") },
            { 80, ("HTTP", "Hypertext Transfer Protocol") },
            { 110, ("POP3", "Post Office Protocol v3") },
            { 143, ("IMAP", "Internet Message Access Protocol") },
            { 443, ("HTTPS", "HTTP Secure") },
            { 465, ("SMTPS", "SMTP Secure") },
            { 587, ("SMTP", "SMTP (Submission)") },
            { 993, ("IMAPS", "IMAP Secure") },
            { 995, ("POP3S", "POP3 Secure") },
            { 1433, ("MSSQL", "Microsoft SQL Server") },
            { 3306, ("MySQL", "MySQL Database") },
            { 3389, ("RDP", "Remote Desktop Protocol") },
            { 5432, ("PostgreSQL", "PostgreSQL Database") },
            { 5900, ("VNC", "Virtual Network Computing") },
            { 6379, ("Redis", "Redis Database") },
            { 27017, ("MongoDB", "MongoDB Database") }
        };

        if (commonPorts.TryGetValue(portInfo.Port, out var serviceInfo))
        {
            portInfo.ServiceName = serviceInfo.service;
            if (string.IsNullOrEmpty(portInfo.ServiceVersion))
            {
                portInfo.ServiceVersion = serviceInfo.description;
            }
        }
        else
        {
            portInfo.ServiceName = "Unknown";
            if (string.IsNullOrEmpty(portInfo.ServiceVersion))
            {
                portInfo.ServiceVersion = "Unknown Service";
            }
        }
    }
}
