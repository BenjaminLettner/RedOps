using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Serilog;
using Spectre.Console;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.IO;

namespace RedOps.Modules.Reconnaissance.WebApplicationRecon
{
    public class SslCertificateAnalysisOptions
    {
        public bool CheckCertificateChain { get; set; } = true;
        public bool CheckCertificateExpiry { get; set; } = true;
        public bool CheckWeakCiphers { get; set; } = true;
        public bool CheckSslVersions { get; set; } = true;
        public bool CheckCertificateTransparency { get; set; } = true;
        public bool CheckRevocationStatus { get; set; } = true;
        public bool PerformDeepInspection { get; set; } = true;
        public int TimeoutSeconds { get; set; } = 10;
        public List<int> CustomPorts { get; set; } = new() { 443, 8443, 9443 };
    }

    public class CertificateInfo
    {
        public string Subject { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public string SerialNumber { get; set; } = string.Empty;
        public string Thumbprint { get; set; } = string.Empty;
        public string SignatureAlgorithm { get; set; } = string.Empty;
        public string PublicKeyAlgorithm { get; set; } = string.Empty;
        public int KeySize { get; set; }
        public List<string> SubjectAlternativeNames { get; set; } = new();
        public List<string> Extensions { get; set; } = new();
        public bool IsSelfSigned { get; set; }
        public bool IsExpired { get; set; }
        public bool IsExpiringSoon { get; set; }
        public int DaysUntilExpiry { get; set; }
        public string Version { get; set; } = string.Empty;
    }

    public class SslConnectionInfo
    {
        public string Host { get; set; } = string.Empty;
        public int Port { get; set; }
        public bool IsConnectable { get; set; }
        public string SslProtocol { get; set; } = string.Empty;
        public string CipherSuite { get; set; } = string.Empty;
        public string KeyExchange { get; set; } = string.Empty;
        public string HashAlgorithm { get; set; } = string.Empty;
        public List<string> SupportedProtocols { get; set; } = new();
        public List<string> SupportedCiphers { get; set; } = new();
        public List<string> WeakProtocols { get; set; } = new();
        public List<string> WeakCiphers { get; set; } = new();
        public CertificateInfo? Certificate { get; set; }
        public List<CertificateInfo> CertificateChain { get; set; } = new();
        public List<string> SecurityIssues { get; set; } = new();
        public List<string> SecurityRecommendations { get; set; } = new();
        public long HandshakeTimeMs { get; set; }
    }

    public class SslCertificateAnalysisResult
    {
        public string TargetHost { get; set; } = string.Empty;
        public DateTime ScanTime { get; set; } = DateTime.Now;
        public SslCertificateAnalysisOptions Options { get; set; } = new();
        public List<SslConnectionInfo> ConnectionResults { get; set; } = new();
        public List<string> OverallSecurityIssues { get; set; } = new();
        public List<string> OverallRecommendations { get; set; } = new();
        public string SecurityGrade { get; set; } = "Unknown";
        public TimeSpan ScanDuration { get; set; }
        public string? Error { get; set; }
    }

    public class SslCertificateAnalyzer : IDisposable
    {
        private static readonly ILogger Logger = Serilog.Log.ForContext<SslCertificateAnalyzer>();
        private readonly HttpClient _httpClient;

        public SslCertificateAnalyzer()
        {
            var handler = new HttpClientHandler()
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true
            };

            _httpClient = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "RedOps/1.0 (SSL Certificate Analyzer)");
        }

        public async Task<SslCertificateAnalysisResult> AnalyzeSslCertificateAsync(string host, SslCertificateAnalysisOptions options)
        {
            var startTime = DateTime.Now;
            var result = new SslCertificateAnalysisResult
            {
                TargetHost = host,
                ScanTime = startTime,
                Options = options
            };

            try
            {
                Logger.Information($"Starting SSL/TLS certificate analysis for {host}");

                // Clean host name
                host = CleanHostName(host);
                result.TargetHost = host;

                // Analyze SSL connections on different ports
                await AnalyzeMultiplePorts(host, options, result);

                // Perform overall security assessment
                PerformOverallSecurityAssessment(result);

                // Calculate security grade
                result.SecurityGrade = CalculateSecurityGrade(result);

                result.ScanDuration = DateTime.Now - startTime;
                Logger.Information($"SSL/TLS certificate analysis completed for {host}. Grade: {result.SecurityGrade}");
            }
            catch (Exception ex)
            {
                Logger.Error($"Error during SSL/TLS certificate analysis for {host}: {ex.Message}");
                result.Error = ex.Message;
                result.ScanDuration = DateTime.Now - startTime;
            }

            return result;
        }

        private string CleanHostName(string host)
        {
            // Remove protocol if present
            if (host.StartsWith("http://") || host.StartsWith("https://"))
            {
                var uri = new Uri(host);
                host = uri.Host;
            }

            return host.ToLower().Trim();
        }

        private async Task AnalyzeMultiplePorts(string host, SslCertificateAnalysisOptions options, SslCertificateAnalysisResult result)
        {
            var ports = options.CustomPorts.Any() ? options.CustomPorts : new List<int> { 443 };

            var tasks = ports.Select(port => AnalyzeSslConnectionAsync(host, port, options));
            var connectionResults = await Task.WhenAll(tasks);

            result.ConnectionResults = connectionResults.Where(r => r != null).ToList()!;
        }

        private async Task<SslConnectionInfo?> AnalyzeSslConnectionAsync(string host, int port, SslCertificateAnalysisOptions options)
        {
            try
            {
                var connectionInfo = new SslConnectionInfo
                {
                    Host = host,
                    Port = port
                };

                var startTime = DateTime.Now;

                // Test SSL connection
                using var tcpClient = new TcpClient();
                await tcpClient.ConnectAsync(host, port);

                using var sslStream = new SslStream(tcpClient.GetStream(), false, ValidateServerCertificate);
                
                try
                {
                    await sslStream.AuthenticateAsClientAsync(host);
                    connectionInfo.IsConnectable = true;
                    connectionInfo.HandshakeTimeMs = (long)(DateTime.Now - startTime).TotalMilliseconds;

                    // Extract SSL/TLS information
                    ExtractSslInformation(sslStream, connectionInfo);

                    // Extract certificate information
                    if (sslStream.RemoteCertificate != null)
                    {
                        var cert = new X509Certificate2(sslStream.RemoteCertificate);
                        connectionInfo.Certificate = ExtractCertificateInfo(cert);

                        // Extract certificate chain if available
                        if (options.CheckCertificateChain)
                        {
                            ExtractCertificateChain(cert, connectionInfo);
                        }
                    }

                    // Perform security analysis
                    AnalyzeSslSecurity(connectionInfo, options);

                    Logger.Debug($"SSL analysis completed for {host}:{port} - Protocol: {connectionInfo.SslProtocol}");
                }
                catch (Exception ex)
                {
                    Logger.Debug($"SSL handshake failed for {host}:{port}: {ex.Message}");
                    connectionInfo.SecurityIssues.Add($"SSL handshake failed: {ex.Message}");
                }

                return connectionInfo;
            }
            catch (Exception ex)
            {
                Logger.Debug($"Connection failed for {host}:{port}: {ex.Message}");
                return new SslConnectionInfo
                {
                    Host = host,
                    Port = port,
                    IsConnectable = false,
                    SecurityIssues = new List<string> { $"Connection failed: {ex.Message}" }
                };
            }
        }

        private bool ValidateServerCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
        {
            // Accept all certificates for analysis purposes
            return true;
        }

        private void ExtractSslInformation(SslStream sslStream, SslConnectionInfo connectionInfo)
        {
            connectionInfo.SslProtocol = sslStream.SslProtocol.ToString();
            connectionInfo.CipherSuite = sslStream.CipherAlgorithm.ToString();
            connectionInfo.KeyExchange = sslStream.KeyExchangeAlgorithm.ToString();
            connectionInfo.HashAlgorithm = sslStream.HashAlgorithm.ToString();

            // Check for weak protocols
            var weakProtocols = new[] { "Ssl2", "Ssl3", "Tls", "Tls11" };
            if (weakProtocols.Contains(sslStream.SslProtocol.ToString()))
            {
                connectionInfo.WeakProtocols.Add(sslStream.SslProtocol.ToString());
            }

            // Check for weak ciphers (simplified check)
            var cipherName = sslStream.CipherAlgorithm.ToString().ToLower();
            var weakCiphers = new[] { "des", "rc4", "md5", "null" };
            if (weakCiphers.Any(weak => cipherName.Contains(weak)))
            {
                connectionInfo.WeakCiphers.Add(sslStream.CipherAlgorithm.ToString());
            }
        }

        private CertificateInfo ExtractCertificateInfo(X509Certificate2 certificate)
        {
            var certInfo = new CertificateInfo
            {
                Subject = certificate.Subject,
                Issuer = certificate.Issuer,
                NotBefore = certificate.NotBefore,
                NotAfter = certificate.NotAfter,
                SerialNumber = certificate.SerialNumber,
                Thumbprint = certificate.Thumbprint,
                SignatureAlgorithm = certificate.SignatureAlgorithm.FriendlyName ?? "Unknown",
                PublicKeyAlgorithm = certificate.PublicKey.Oid.FriendlyName ?? "Unknown",
                KeySize = GetPublicKeySize(certificate),
                Version = $"V{certificate.Version}",
                IsSelfSigned = certificate.Subject == certificate.Issuer
            };

            // Calculate expiry information
            var now = DateTime.Now;
            certInfo.IsExpired = now > certificate.NotAfter;
            certInfo.DaysUntilExpiry = (int)(certificate.NotAfter - now).TotalDays;
            certInfo.IsExpiringSoon = certInfo.DaysUntilExpiry <= 30 && certInfo.DaysUntilExpiry > 0;

            // Extract Subject Alternative Names
            foreach (var extension in certificate.Extensions)
            {
                if (extension.Oid?.Value == "2.5.29.17") // Subject Alternative Name
                {
                    var sanExtension = extension as X509SubjectAlternativeNameExtension;
                    if (sanExtension != null)
                    {
                        var sans = sanExtension.Format(false).Split(',');
                        certInfo.SubjectAlternativeNames.AddRange(sans.Select(san => san.Trim()));
                    }
                }

                certInfo.Extensions.Add($"{extension.Oid?.FriendlyName ?? extension.Oid?.Value}: {extension.Format(false)}");
            }

            return certInfo;
        }

        private int GetPublicKeySize(X509Certificate2 certificate)
        {
            try
            {
                // Try to get RSA key size
                using var rsa = certificate.GetRSAPublicKey();
                if (rsa != null)
                {
                    return rsa.KeySize;
                }

                // Try to get ECDSA key size
                using var ecdsa = certificate.GetECDsaPublicKey();
                if (ecdsa != null)
                {
                    return ecdsa.KeySize;
                }

                // Try to get DSA key size
                using var dsa = certificate.GetDSAPublicKey();
                if (dsa != null)
                {
                    return dsa.KeySize;
                }

                // Fallback: try to parse from algorithm parameters
                return certificate.PublicKey.EncodedKeyValue.RawData.Length * 8;
            }
            catch
            {
                // If all else fails, return 0 to indicate unknown
                return 0;
            }
        }

        private void ExtractCertificateChain(X509Certificate2 certificate, SslConnectionInfo connectionInfo)
        {
            try
            {
                using var chain = new X509Chain();
                chain.Build(certificate);

                foreach (var element in chain.ChainElements)
                {
                    var certInfo = ExtractCertificateInfo(element.Certificate);
                    connectionInfo.CertificateChain.Add(certInfo);
                }
            }
            catch (Exception ex)
            {
                Logger.Debug($"Error extracting certificate chain: {ex.Message}");
                connectionInfo.SecurityIssues.Add($"Certificate chain extraction failed: {ex.Message}");
            }
        }

        private void AnalyzeSslSecurity(SslConnectionInfo connectionInfo, SslCertificateAnalysisOptions options)
        {
            var issues = connectionInfo.SecurityIssues;
            var recommendations = connectionInfo.SecurityRecommendations;

            // Check SSL/TLS protocol version
            if (connectionInfo.WeakProtocols.Any())
            {
                issues.Add($"Weak SSL/TLS protocols detected: {string.Join(", ", connectionInfo.WeakProtocols)}");
                recommendations.Add("Disable weak SSL/TLS protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1)");
            }

            // Check cipher suites
            if (connectionInfo.WeakCiphers.Any())
            {
                issues.Add($"Weak cipher suites detected: {string.Join(", ", connectionInfo.WeakCiphers)}");
                recommendations.Add("Disable weak cipher suites and use strong encryption");
            }

            // Check certificate
            if (connectionInfo.Certificate != null)
            {
                var cert = connectionInfo.Certificate;

                if (cert.IsExpired)
                {
                    issues.Add("Certificate has expired");
                    recommendations.Add("Renew the SSL certificate immediately");
                }
                else if (cert.IsExpiringSoon)
                {
                    issues.Add($"Certificate expires soon ({cert.DaysUntilExpiry} days)");
                    recommendations.Add("Plan certificate renewal");
                }

                if (cert.IsSelfSigned)
                {
                    issues.Add("Certificate is self-signed");
                    recommendations.Add("Use a certificate from a trusted Certificate Authority");
                }

                if (cert.KeySize < 2048)
                {
                    issues.Add($"Weak key size: {cert.KeySize} bits");
                    recommendations.Add("Use at least 2048-bit RSA keys or 256-bit ECC keys");
                }

                if (cert.SignatureAlgorithm.Contains("SHA1"))
                {
                    issues.Add("Certificate uses weak SHA-1 signature algorithm");
                    recommendations.Add("Use certificates with SHA-256 or stronger signature algorithms");
                }
            }

            // Check handshake time
            if (connectionInfo.HandshakeTimeMs > 5000)
            {
                issues.Add($"Slow SSL handshake: {connectionInfo.HandshakeTimeMs}ms");
                recommendations.Add("Optimize SSL configuration for better performance");
            }
        }

        private void PerformOverallSecurityAssessment(SslCertificateAnalysisResult result)
        {
            var allIssues = result.ConnectionResults.SelectMany(c => c.SecurityIssues).Distinct().ToList();
            var allRecommendations = result.ConnectionResults.SelectMany(c => c.SecurityRecommendations).Distinct().ToList();

            result.OverallSecurityIssues = allIssues;
            result.OverallRecommendations = allRecommendations;

            // Add overall assessments
            if (!result.ConnectionResults.Any(c => c.IsConnectable))
            {
                result.OverallSecurityIssues.Add("No SSL/TLS connections could be established");
            }

            var expiredCerts = result.ConnectionResults.Count(c => c.Certificate?.IsExpired == true);
            if (expiredCerts > 0)
            {
                result.OverallSecurityIssues.Add($"{expiredCerts} expired certificate(s) detected");
            }

            var selfSignedCerts = result.ConnectionResults.Count(c => c.Certificate?.IsSelfSigned == true);
            if (selfSignedCerts > 0)
            {
                result.OverallSecurityIssues.Add($"{selfSignedCerts} self-signed certificate(s) detected");
            }
        }

        private string CalculateSecurityGrade(SslCertificateAnalysisResult result)
        {
            var score = 100;

            // Deduct points for issues
            foreach (var connection in result.ConnectionResults)
            {
                if (!connection.IsConnectable) score -= 20;
                if (connection.WeakProtocols.Any()) score -= 15;
                if (connection.WeakCiphers.Any()) score -= 15;
                if (connection.Certificate?.IsExpired == true) score -= 25;
                if (connection.Certificate?.IsSelfSigned == true) score -= 10;
                if (connection.Certificate?.KeySize < 2048) score -= 10;
                if (connection.Certificate?.SignatureAlgorithm.Contains("SHA1") == true) score -= 10;
            }

            return score switch
            {
                >= 90 => "A+",
                >= 80 => "A",
                >= 70 => "B",
                >= 60 => "C",
                >= 50 => "D",
                _ => "F"
            };
        }

        public void DisplayResults(SslCertificateAnalysisResult result)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule($"[bold green]SSL/TLS Certificate Analysis Results for {result.TargetHost}[/]").RuleStyle("green"));
            AnsiConsole.WriteLine();

            // Summary
            var summaryTable = new Table()
                .Border(TableBorder.Rounded)
                .BorderColor(Color.Green);

            summaryTable.AddColumn("[bold]Metric[/]");
            summaryTable.AddColumn("[bold]Value[/]");

            summaryTable.AddRow("Target Host", result.TargetHost);
            summaryTable.AddRow("Scan Time", result.ScanTime.ToString("yyyy-MM-dd HH:mm:ss"));
            summaryTable.AddRow("Duration", $"{result.ScanDuration.TotalSeconds:F1} seconds");
            summaryTable.AddRow("Ports Analyzed", result.ConnectionResults.Count.ToString());
            summaryTable.AddRow("Successful Connections", result.ConnectionResults.Count(c => c.IsConnectable).ToString());
            
            var gradeColor = result.SecurityGrade switch
            {
                "A+" or "A" => "green",
                "B" or "C" => "yellow",
                _ => "red"
            };
            summaryTable.AddRow("Security Grade", $"[{gradeColor}]{result.SecurityGrade}[/]");

            AnsiConsole.Write(summaryTable);
            AnsiConsole.WriteLine();

            // Connection details
            if (result.ConnectionResults.Any(c => c.IsConnectable))
            {
                var connectionsTable = new Table()
                    .Border(TableBorder.Rounded)
                    .BorderColor(Color.Blue);

                connectionsTable.AddColumn("[bold]Port[/]");
                connectionsTable.AddColumn("[bold]Protocol[/]");
                connectionsTable.AddColumn("[bold]Cipher[/]");
                connectionsTable.AddColumn("[bold]Certificate[/]");
                connectionsTable.AddColumn("[bold]Expiry[/]");
                connectionsTable.AddColumn("[bold]Issues[/]");

                foreach (var connection in result.ConnectionResults.Where(c => c.IsConnectable))
                {
                    var cert = connection.Certificate;
                    var certInfo = cert != null ? 
                        $"{cert.Subject.Split(',')[0].Replace("CN=", "")}" : "N/A";
                    
                    var expiryInfo = cert != null ?
                        (cert.IsExpired ? "[red]Expired[/]" :
                         cert.IsExpiringSoon ? $"[yellow]{cert.DaysUntilExpiry} days[/]" :
                         $"[green]{cert.DaysUntilExpiry} days[/]") : "N/A";

                    var issuesCount = connection.SecurityIssues.Count;
                    var issuesColor = issuesCount == 0 ? "green" : issuesCount <= 2 ? "yellow" : "red";

                    connectionsTable.AddRow(
                        connection.Port.ToString(),
                        connection.SslProtocol,
                        connection.CipherSuite,
                        certInfo,
                        expiryInfo,
                        $"[{issuesColor}]{issuesCount} issue(s)[/]"
                    );
                }

                AnsiConsole.Write(connectionsTable);
                AnsiConsole.WriteLine();
            }

            // Security issues
            if (result.OverallSecurityIssues.Any())
            {
                AnsiConsole.Write(new Rule("[bold red]Security Issues[/]").RuleStyle("red"));
                foreach (var issue in result.OverallSecurityIssues)
                {
                    AnsiConsole.MarkupLine($"[red]• {issue}[/]");
                }
                AnsiConsole.WriteLine();
            }

            // Recommendations
            if (result.OverallRecommendations.Any())
            {
                AnsiConsole.Write(new Rule("[bold yellow]Security Recommendations[/]").RuleStyle("yellow"));
                foreach (var recommendation in result.OverallRecommendations)
                {
                    AnsiConsole.MarkupLine($"[yellow]• {recommendation}[/]");
                }
                AnsiConsole.WriteLine();
            }

            if (!result.OverallSecurityIssues.Any())
            {
                AnsiConsole.MarkupLine("[green]✓ No significant security issues detected![/]");
            }
        }

        public async Task<bool> SaveResultsAsync(SslCertificateAnalysisResult result, string? filePath = null)
        {
            try
            {
                filePath ??= $"ssl_certificate_analysis_{result.TargetHost}_{DateTime.Now:yyyyMMdd_HHmmss}.txt";

                var content = new StringBuilder();
                content.AppendLine($"SSL/TLS Certificate Analysis Report");
                content.AppendLine($"Target Host: {result.TargetHost}");
                content.AppendLine($"Scan Time: {result.ScanTime:yyyy-MM-dd HH:mm:ss}");
                content.AppendLine($"Duration: {result.ScanDuration.TotalSeconds:F1} seconds");
                content.AppendLine($"Security Grade: {result.SecurityGrade}");
                content.AppendLine();

                content.AppendLine("Connection Results:");
                content.AppendLine("==================");
                foreach (var connection in result.ConnectionResults)
                {
                    content.AppendLine($"Port {connection.Port}: {(connection.IsConnectable ? "Connected" : "Failed")}");
                    if (connection.IsConnectable)
                    {
                        content.AppendLine($"  Protocol: {connection.SslProtocol}");
                        content.AppendLine($"  Cipher: {connection.CipherSuite}");
                        content.AppendLine($"  Handshake Time: {connection.HandshakeTimeMs}ms");
                        
                        if (connection.Certificate != null)
                        {
                            var cert = connection.Certificate;
                            content.AppendLine($"  Certificate Subject: {cert.Subject}");
                            content.AppendLine($"  Certificate Issuer: {cert.Issuer}");
                            content.AppendLine($"  Valid From: {cert.NotBefore:yyyy-MM-dd}");
                            content.AppendLine($"  Valid To: {cert.NotAfter:yyyy-MM-dd}");
                            content.AppendLine($"  Days Until Expiry: {cert.DaysUntilExpiry}");
                            content.AppendLine($"  Key Size: {cert.KeySize} bits");
                            content.AppendLine($"  Signature Algorithm: {cert.SignatureAlgorithm}");
                            content.AppendLine($"  Self-Signed: {cert.IsSelfSigned}");
                        }
                    }
                    
                    if (connection.SecurityIssues.Any())
                    {
                        content.AppendLine($"  Security Issues:");
                        foreach (var issue in connection.SecurityIssues)
                        {
                            content.AppendLine($"    - {issue}");
                        }
                    }
                    content.AppendLine();
                }

                if (result.OverallSecurityIssues.Any())
                {
                    content.AppendLine("Overall Security Issues:");
                    content.AppendLine("=======================");
                    foreach (var issue in result.OverallSecurityIssues)
                    {
                        content.AppendLine($"- {issue}");
                    }
                    content.AppendLine();
                }

                if (result.OverallRecommendations.Any())
                {
                    content.AppendLine("Security Recommendations:");
                    content.AppendLine("=========================");
                    foreach (var recommendation in result.OverallRecommendations)
                    {
                        content.AppendLine($"- {recommendation}");
                    }
                }

                await File.WriteAllTextAsync(filePath, content.ToString());
                Logger.Information($"SSL certificate analysis results saved to {filePath}");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Error saving SSL certificate analysis results: {ex.Message}");
                return false;
            }
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}
