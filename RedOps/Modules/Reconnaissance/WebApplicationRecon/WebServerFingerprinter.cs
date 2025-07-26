using System.Net.Http;
using System.Text.RegularExpressions;
using Serilog;
using Spectre.Console;

namespace RedOps.Modules.Reconnaissance.WebApplicationRecon
{
    public class WebServerFingerprinter : IDisposable
    {
        private static readonly ILogger Logger = Log.ForContext<WebServerFingerprinter>();
        private readonly HttpClient _httpClient;

        public WebServerFingerprinter()
        {
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Add("User-Agent", 
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
            _httpClient.Timeout = TimeSpan.FromSeconds(10);
        }

        public async Task<WebServerInfo> FingerprintWebServerAsync(string url)
        {
            var webServerInfo = new WebServerInfo
            {
                Url = url,
                ScanTime = DateTime.Now
            };

            try
            {
                Logger.Information($"Starting web server fingerprinting for {url}");

                // Ensure URL has protocol
                if (!url.StartsWith("http://") && !url.StartsWith("https://"))
                {
                    url = "http://" + url;
                }

                // Perform HTTP HEAD request first
                await PerformHeadRequest(url, webServerInfo);

                // Perform HTTP GET request for additional analysis
                await PerformGetRequest(url, webServerInfo);

                // Analyze server headers and response
                AnalyzeServerFingerprint(webServerInfo);

                Logger.Information($"Web server fingerprinting completed for {webServerInfo.Url}");
            }
            catch (Exception ex)
            {
                Logger.Error($"Error during web server fingerprinting for {url}: {ex.Message}");
                webServerInfo.Error = ex.Message;
            }

            return webServerInfo;
        }

        private async Task PerformHeadRequest(string url, WebServerInfo webServerInfo)
        {
            try
            {
                var response = await _httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                
                webServerInfo.StatusCode = (int)response.StatusCode;
                webServerInfo.StatusDescription = response.ReasonPhrase ?? "";
                webServerInfo.IsAccessible = response.IsSuccessStatusCode;

                // Extract headers
                foreach (var header in response.Headers)
                {
                    webServerInfo.Headers[header.Key] = string.Join(", ", header.Value);
                }

                foreach (var header in response.Content.Headers)
                {
                    webServerInfo.Headers[header.Key] = string.Join(", ", header.Value);
                }

                Logger.Debug($"HEAD request completed for {url} - Status: {response.StatusCode}");
            }
            catch (Exception ex)
            {
                Logger.Warning($"HEAD request failed for {url}: {ex.Message}");
            }
        }

        private async Task PerformGetRequest(string url, WebServerInfo webServerInfo)
        {
            try
            {
                var response = await _httpClient.GetAsync(url);
                var content = await response.Content.ReadAsStringAsync();

                webServerInfo.ContentLength = content.Length;
                webServerInfo.ResponseBody = content.Length > 1000 ? content.Substring(0, 1000) + "..." : content;

                // Update headers from GET request (might have additional headers)
                foreach (var header in response.Headers)
                {
                    webServerInfo.Headers[header.Key] = string.Join(", ", header.Value);
                }

                foreach (var header in response.Content.Headers)
                {
                    webServerInfo.Headers[header.Key] = string.Join(", ", header.Value);
                }

                // Analyze response body for additional fingerprinting
                AnalyzeResponseBody(content, webServerInfo);

                Logger.Debug($"GET request completed for {url} - Content length: {content.Length}");
            }
            catch (Exception ex)
            {
                Logger.Warning($"GET request failed for {url}: {ex.Message}");
            }
        }

        private void AnalyzeServerFingerprint(WebServerInfo webServerInfo)
        {
            // Analyze Server header
            if (webServerInfo.Headers.TryGetValue("Server", out var serverHeader))
            {
                webServerInfo.ServerSoftware = serverHeader;
                webServerInfo.WebServerType = ExtractServerType(serverHeader);
                webServerInfo.ServerVersion = ExtractServerVersion(serverHeader);
            }

            // Analyze X-Powered-By header
            if (webServerInfo.Headers.TryGetValue("X-Powered-By", out var poweredBy))
            {
                webServerInfo.PoweredBy = poweredBy;
                if (string.IsNullOrEmpty(webServerInfo.WebServerType))
                {
                    webServerInfo.WebServerType = ExtractServerType(poweredBy);
                }
            }

            // Analyze other identifying headers
            AnalyzeAdditionalHeaders(webServerInfo);

            // Security headers analysis
            AnalyzeSecurityHeaders(webServerInfo);

            // Technology stack detection
            DetectTechnologyStack(webServerInfo);
        }

        private string ExtractServerType(string serverHeader)
        {
            var serverTypes = new Dictionary<string, string>
            {
                { "apache", "Apache HTTP Server" },
                { "nginx", "Nginx" },
                { "iis", "Microsoft IIS" },
                { "lighttpd", "Lighttpd" },
                { "tomcat", "Apache Tomcat" },
                { "jetty", "Eclipse Jetty" },
                { "cloudflare", "Cloudflare" },
                { "cloudfront", "Amazon CloudFront" },
                { "gunicorn", "Gunicorn" },
                { "uwsgi", "uWSGI" },
                { "kestrel", "ASP.NET Core Kestrel" },
                { "caddy", "Caddy" },
                { "traefik", "Traefik" }
            };

            var lowerHeader = serverHeader.ToLower();
            foreach (var kvp in serverTypes)
            {
                if (lowerHeader.Contains(kvp.Key))
                {
                    return kvp.Value;
                }
            }

            return "Unknown";
        }

        private string ExtractServerVersion(string serverHeader)
        {
            // Extract version using regex patterns
            var versionPatterns = new[]
            {
                @"Apache/(\d+\.\d+\.\d+)",
                @"nginx/(\d+\.\d+\.\d+)",
                @"Microsoft-IIS/(\d+\.\d+)",
                @"lighttpd/(\d+\.\d+\.\d+)",
                @"Tomcat/(\d+\.\d+\.\d+)",
                @"Jetty\((\d+\.\d+\.\d+)\)",
                @"Kestrel/(\d+\.\d+\.\d+)",
                @"Caddy/(\d+\.\d+\.\d+)",
                @"/(\d+\.\d+\.\d+)" // Generic version pattern
            };

            foreach (var pattern in versionPatterns)
            {
                var match = Regex.Match(serverHeader, pattern, RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    return match.Groups[1].Value;
                }
            }

            return "Unknown";
        }

        private void AnalyzeAdditionalHeaders(WebServerInfo webServerInfo)
        {
            // Check for load balancer headers
            var loadBalancerHeaders = new[] { "X-Load-Balancer", "X-Forwarded-Server", "X-Real-IP", "X-Forwarded-For" };
            foreach (var header in loadBalancerHeaders)
            {
                if (webServerInfo.Headers.ContainsKey(header))
                {
                    webServerInfo.HasLoadBalancer = true;
                    break;
                }
            }

            // Check for CDN headers
            var cdnHeaders = new[] { "CF-RAY", "X-Cache", "X-Served-By", "X-Timer", "X-Varnish" };
            foreach (var header in cdnHeaders)
            {
                if (webServerInfo.Headers.ContainsKey(header))
                {
                    webServerInfo.HasCDN = true;
                    if (webServerInfo.Headers.ContainsKey("CF-RAY"))
                        webServerInfo.CDNProvider = "Cloudflare";
                    else if (webServerInfo.Headers.ContainsKey("X-Served-By"))
                        webServerInfo.CDNProvider = "Fastly";
                    else if (webServerInfo.Headers.ContainsKey("X-Varnish"))
                        webServerInfo.CDNProvider = "Varnish";
                    break;
                }
            }

            // Check for WAF headers
            var wafHeaders = new[] { "X-Sucuri-ID", "X-Mod-Security", "X-WAF-Event-Info", "X-Blocked-By" };
            foreach (var header in wafHeaders)
            {
                if (webServerInfo.Headers.ContainsKey(header))
                {
                    webServerInfo.HasWAF = true;
                    break;
                }
            }
        }

        private void AnalyzeSecurityHeaders(WebServerInfo webServerInfo)
        {
            var securityHeaders = new Dictionary<string, string>
            {
                { "Strict-Transport-Security", "HSTS" },
                { "Content-Security-Policy", "CSP" },
                { "X-Frame-Options", "X-Frame-Options" },
                { "X-Content-Type-Options", "X-Content-Type-Options" },
                { "X-XSS-Protection", "X-XSS-Protection" },
                { "Referrer-Policy", "Referrer-Policy" },
                { "Permissions-Policy", "Permissions-Policy" }
            };

            foreach (var kvp in securityHeaders)
            {
                if (webServerInfo.Headers.ContainsKey(kvp.Key))
                {
                    webServerInfo.SecurityHeaders.Add(kvp.Value);
                }
            }
        }

        private void DetectTechnologyStack(WebServerInfo webServerInfo)
        {
            var technologies = new List<string>();

            // Analyze headers for technology indicators
            if (webServerInfo.Headers.TryGetValue("X-Powered-By", out var poweredBy))
            {
                if (poweredBy.Contains("ASP.NET")) technologies.Add("ASP.NET");
                if (poweredBy.Contains("PHP")) technologies.Add("PHP");
                if (poweredBy.Contains("Express")) technologies.Add("Node.js/Express");
            }

            // Analyze response body patterns (if available)
            if (!string.IsNullOrEmpty(webServerInfo.ResponseBody))
            {
                var bodyLower = webServerInfo.ResponseBody.ToLower();
                
                if (bodyLower.Contains("wordpress")) technologies.Add("WordPress");
                if (bodyLower.Contains("drupal")) technologies.Add("Drupal");
                if (bodyLower.Contains("joomla")) technologies.Add("Joomla");
                if (bodyLower.Contains("django")) technologies.Add("Django");
                if (bodyLower.Contains("laravel")) technologies.Add("Laravel");
                if (bodyLower.Contains("react")) technologies.Add("React");
                if (bodyLower.Contains("angular")) technologies.Add("Angular");
                if (bodyLower.Contains("vue")) technologies.Add("Vue.js");
            }

            webServerInfo.DetectedTechnologies = technologies;
        }

        private void AnalyzeResponseBody(string responseBody, WebServerInfo webServerInfo)
        {
            if (string.IsNullOrEmpty(responseBody)) return;

            // Extract title
            var titleMatch = Regex.Match(responseBody, @"<title[^>]*>([^<]+)</title>", RegexOptions.IgnoreCase);
            if (titleMatch.Success)
            {
                webServerInfo.PageTitle = titleMatch.Groups[1].Value.Trim();
            }

            // Count forms (potential attack vectors)
            var formMatches = Regex.Matches(responseBody, @"<form[^>]*>", RegexOptions.IgnoreCase);
            webServerInfo.FormCount = formMatches.Count;

            // Count input fields
            var inputMatches = Regex.Matches(responseBody, @"<input[^>]*>", RegexOptions.IgnoreCase);
            webServerInfo.InputFieldCount = inputMatches.Count;

            // Check for common CMS indicators
            DetectCMSFromBody(responseBody, webServerInfo);
        }

        private void DetectCMSFromBody(string responseBody, WebServerInfo webServerInfo)
        {
            var cmsIndicators = new Dictionary<string, string>
            {
                { "wp-content", "WordPress" },
                { "wp-includes", "WordPress" },
                { "/sites/default/files", "Drupal" },
                { "/modules/", "Drupal" },
                { "/media/jui/", "Joomla" },
                { "/administrator/", "Joomla" },
                { "Powered by Shopify", "Shopify" },
                { "cdn.shopify.com", "Shopify" }
            };

            var bodyLower = responseBody.ToLower();
            foreach (var kvp in cmsIndicators)
            {
                if (bodyLower.Contains(kvp.Key.ToLower()))
                {
                    if (!webServerInfo.DetectedTechnologies.Contains(kvp.Value))
                    {
                        webServerInfo.DetectedTechnologies.Add(kvp.Value);
                    }
                }
            }
        }

        public void DisplayWebServerInfo(WebServerInfo webServerInfo)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule($"[red]Web Server Fingerprint: {webServerInfo.Url}[/]").RuleStyle("grey"));
            AnsiConsole.WriteLine();

            if (!string.IsNullOrEmpty(webServerInfo.Error))
            {
                AnsiConsole.MarkupLine($"[red]Error: {webServerInfo.Error}[/]");
                return;
            }

            // Basic Information
            var basicTable = new Table();
            basicTable.AddColumn("Property");
            basicTable.AddColumn("Value");
            basicTable.Border(TableBorder.Rounded);

            basicTable.AddRow("URL", webServerInfo.Url);
            basicTable.AddRow("Status", $"{webServerInfo.StatusCode} {webServerInfo.StatusDescription}");
            basicTable.AddRow("Accessible", webServerInfo.IsAccessible ? "[green]Yes[/]" : "[red]No[/]");
            basicTable.AddRow("Server Software", webServerInfo.ServerSoftware ?? "Unknown");
            basicTable.AddRow("Server Type", webServerInfo.WebServerType ?? "Unknown");
            basicTable.AddRow("Server Version", webServerInfo.ServerVersion ?? "Unknown");
            
            if (!string.IsNullOrEmpty(webServerInfo.PoweredBy))
                basicTable.AddRow("Powered By", webServerInfo.PoweredBy);
            
            if (!string.IsNullOrEmpty(webServerInfo.PageTitle))
                basicTable.AddRow("Page Title", webServerInfo.PageTitle);

            basicTable.AddRow("Content Length", webServerInfo.ContentLength.ToString());
            basicTable.AddRow("Has Load Balancer", webServerInfo.HasLoadBalancer ? "[yellow]Yes[/]" : "No");
            basicTable.AddRow("Has CDN", webServerInfo.HasCDN ? "[yellow]Yes[/]" : "No");
            
            if (!string.IsNullOrEmpty(webServerInfo.CDNProvider))
                basicTable.AddRow("CDN Provider", webServerInfo.CDNProvider);
            
            basicTable.AddRow("Has WAF", webServerInfo.HasWAF ? "[yellow]Yes[/]" : "No");
            basicTable.AddRow("Form Count", webServerInfo.FormCount.ToString());
            basicTable.AddRow("Input Fields", webServerInfo.InputFieldCount.ToString());

            AnsiConsole.Write(basicTable);

            // Security Headers
            if (webServerInfo.SecurityHeaders.Any())
            {
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("[green]Security Headers Present:[/]");
                foreach (var header in webServerInfo.SecurityHeaders)
                {
                    AnsiConsole.MarkupLine($"  [green]✓[/] {header}");
                }
            }
            else
            {
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("[red]⚠ No security headers detected[/]");
            }

            // Detected Technologies
            if (webServerInfo.DetectedTechnologies.Any())
            {
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("[cyan]Detected Technologies:[/]");
                foreach (var tech in webServerInfo.DetectedTechnologies)
                {
                    AnsiConsole.MarkupLine($"  [cyan]•[/] {tech}");
                }
            }

            // HTTP Headers
            if (webServerInfo.Headers.Any())
            {
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("[yellow]HTTP Headers:[/]");
                
                var headerTable = new Table();
                headerTable.AddColumn("Header");
                headerTable.AddColumn("Value");
                headerTable.Border(TableBorder.Simple);

                foreach (var kvp in webServerInfo.Headers.OrderBy(h => h.Key))
                {
                    var value = kvp.Value.Length > 80 ? kvp.Value.Substring(0, 80) + "..." : kvp.Value;
                    headerTable.AddRow(kvp.Key, value);
                }

                AnsiConsole.Write(headerTable);
            }

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"[grey]Scan completed at: {webServerInfo.ScanTime:yyyy-MM-dd HH:mm:ss}[/]");
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }

    public class WebServerInfo
    {
        public string Url { get; set; } = "";
        public DateTime ScanTime { get; set; }
        public int StatusCode { get; set; }
        public string StatusDescription { get; set; } = "";
        public bool IsAccessible { get; set; }
        public string ServerSoftware { get; set; } = "";
        public string WebServerType { get; set; } = "";
        public string ServerVersion { get; set; } = "";
        public string PoweredBy { get; set; } = "";
        public string PageTitle { get; set; } = "";
        public int ContentLength { get; set; }
        public bool HasLoadBalancer { get; set; }
        public bool HasCDN { get; set; }
        public string CDNProvider { get; set; } = "";
        public bool HasWAF { get; set; }
        public int FormCount { get; set; }
        public int InputFieldCount { get; set; }
        public Dictionary<string, string> Headers { get; set; } = new();
        public List<string> SecurityHeaders { get; set; } = new();
        public List<string> DetectedTechnologies { get; set; } = new();
        public string ResponseBody { get; set; } = "";
        public string Error { get; set; } = "";
    }
}
