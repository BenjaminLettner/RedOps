using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Serilog;
using Spectre.Console;
using System.Text;
using System.IO;

namespace RedOps.Modules.Reconnaissance.WebApplicationRecon
{
    public class ApiEndpointDiscoveryOptions
    {
        public bool DiscoverRestEndpoints { get; set; } = true;
        public bool DiscoverGraphQlEndpoints { get; set; } = true;
        public bool DiscoverSwaggerDocs { get; set; } = true;
        public bool AnalyzeJavaScriptFiles { get; set; } = true;
        public bool TestCommonApiPaths { get; set; } = true;
        public bool CheckAuthentication { get; set; } = true;
        public int MaxConcurrency { get; set; } = 20;
        public int TimeoutSeconds { get; set; } = 10;
        public List<string> CustomEndpoints { get; set; } = new();
    }

    public class ApiEndpoint
    {
        public string Url { get; set; } = string.Empty;
        public string Method { get; set; } = string.Empty;
        public int StatusCode { get; set; }
        public string ResponseContentType { get; set; } = string.Empty;
        public long ResponseSizeBytes { get; set; }
        public long ResponseTimeMs { get; set; }
        public string ApiType { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public List<string> Parameters { get; set; } = new();
        public List<string> Headers { get; set; } = new();
        public string? SampleResponse { get; set; }
        public bool RequiresAuthentication { get; set; }
        public List<string> SecurityIssues { get; set; } = new();
        public DateTime DiscoveryTime { get; set; } = DateTime.Now;
    }

    public class ApiDocumentation
    {
        public string Url { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public List<ApiEndpoint> DocumentedEndpoints { get; set; } = new();
        public bool IsPubliclyAccessible { get; set; }
    }

    public class ApiEndpointDiscoveryResult
    {
        public string BaseUrl { get; set; } = string.Empty;
        public DateTime ScanTime { get; set; } = DateTime.Now;
        public ApiEndpointDiscoveryOptions Options { get; set; } = new();
        public List<ApiEndpoint> DiscoveredEndpoints { get; set; } = new();
        public List<ApiDocumentation> ApiDocumentations { get; set; } = new();
        public List<string> SecurityFindings { get; set; } = new();
        public List<string> Recommendations { get; set; } = new();
        public int TotalEndpointsTested { get; set; }
        public int AccessibleEndpoints { get; set; }
        public int AuthenticatedEndpoints { get; set; }
        public TimeSpan ScanDuration { get; set; }
        public string? Error { get; set; }
    }

    public class ApiEndpointDiscoverer : IDisposable
    {
        private static readonly ILogger Logger = Serilog.Log.ForContext<ApiEndpointDiscoverer>();
        private readonly HttpClient _httpClient;
        private readonly SemaphoreSlim _semaphore;

        public ApiEndpointDiscoverer(int maxConcurrency = 20)
        {
            _httpClient = new HttpClient()
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "RedOps/1.0 (API Discovery Scanner)");
            _semaphore = new SemaphoreSlim(maxConcurrency, maxConcurrency);
        }

        public async Task<ApiEndpointDiscoveryResult> DiscoverApiEndpointsAsync(string baseUrl, ApiEndpointDiscoveryOptions options)
        {
            var startTime = DateTime.Now;
            var result = new ApiEndpointDiscoveryResult
            {
                BaseUrl = baseUrl,
                ScanTime = startTime,
                Options = options
            };

            try
            {
                Logger.Information($"Starting API endpoint discovery for {baseUrl}");

                baseUrl = CleanBaseUrl(baseUrl);
                result.BaseUrl = baseUrl;

                if (options.DiscoverSwaggerDocs)
                    await DiscoverApiDocumentationAsync(baseUrl, result);

                if (options.TestCommonApiPaths)
                    await DiscoverCommonApiEndpointsAsync(baseUrl, result, options);

                if (options.AnalyzeJavaScriptFiles)
                    await AnalyzeJavaScriptForEndpointsAsync(baseUrl, result);

                if (options.DiscoverGraphQlEndpoints)
                    await DiscoverGraphQlEndpointsAsync(baseUrl, result);

                if (options.CustomEndpoints.Any())
                    await TestCustomEndpointsAsync(baseUrl, result, options);

                PerformSecurityAnalysis(result);

                result.TotalEndpointsTested = result.DiscoveredEndpoints.Count;
                result.AccessibleEndpoints = result.DiscoveredEndpoints.Count(e => e.StatusCode >= 200 && e.StatusCode < 400);
                result.AuthenticatedEndpoints = result.DiscoveredEndpoints.Count(e => e.RequiresAuthentication);
                result.ScanDuration = DateTime.Now - startTime;

                Logger.Information($"API endpoint discovery completed for {baseUrl}. Found {result.AccessibleEndpoints} accessible endpoints");
            }
            catch (Exception ex)
            {
                Logger.Error($"Error during API endpoint discovery for {baseUrl}: {ex.Message}");
                result.Error = ex.Message;
                result.ScanDuration = DateTime.Now - startTime;
            }

            return result;
        }

        private string CleanBaseUrl(string baseUrl)
        {
            if (!baseUrl.StartsWith("http://") && !baseUrl.StartsWith("https://"))
                baseUrl = "https://" + baseUrl;
            return baseUrl.TrimEnd('/');
        }

        private async Task DiscoverApiDocumentationAsync(string baseUrl, ApiEndpointDiscoveryResult result)
        {
            var documentationPaths = new[]
            {
                "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
                "/api-docs", "/api-docs.json", "/docs", "/docs.json",
                "/openapi.json", "/openapi.yaml", "/v1/swagger.json",
                "/api/swagger.json", "/api/docs", "/redoc", "/swagger-ui"
            };

            var tasks = documentationPaths.Select(path => DiscoverDocumentationAtPathAsync(baseUrl + path, result));
            await Task.WhenAll(tasks);
        }

        private async Task DiscoverDocumentationAtPathAsync(string url, ApiEndpointDiscoveryResult result)
        {
            try
            {
                await _semaphore.WaitAsync();
                
                var response = await _httpClient.GetAsync(url);
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var documentation = new ApiDocumentation
                    {
                        Url = url,
                        IsPubliclyAccessible = true,
                        Type = url.Contains("swagger") ? "Swagger" : "OpenAPI"
                    };

                    await ParseApiDocumentationAsync(content, documentation);

                    if (documentation.DocumentedEndpoints.Any() || !string.IsNullOrEmpty(documentation.Title))
                    {
                        result.ApiDocumentations.Add(documentation);
                        result.DiscoveredEndpoints.AddRange(documentation.DocumentedEndpoints);
                        Logger.Information($"Found API documentation at {url}: {documentation.Title}");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug($"Error checking API documentation at {url}: {ex.Message}");
            }
            finally
            {
                _semaphore.Release();
            }
        }

        private Task ParseApiDocumentationAsync(string content, ApiDocumentation documentation)
        {
            try
            {
                using var jsonDoc = JsonDocument.Parse(content);
                var root = jsonDoc.RootElement;

                if (root.TryGetProperty("info", out var info))
                {
                    if (info.TryGetProperty("title", out var title))
                        documentation.Title = title.GetString() ?? "";
                    if (info.TryGetProperty("version", out var version))
                        documentation.Version = version.GetString() ?? "";
                }

                if (root.TryGetProperty("paths", out var paths))
                {
                    foreach (var path in paths.EnumerateObject())
                    {
                        foreach (var method in path.Value.EnumerateObject())
                        {
                            var endpoint = new ApiEndpoint
                            {
                                Url = documentation.Url.Replace("/swagger.json", "").Replace("/openapi.json", "") + path.Name,
                                Method = method.Name.ToUpper(),
                                ApiType = "REST"
                            };

                            if (method.Value.TryGetProperty("summary", out var summary))
                                endpoint.Description = summary.GetString() ?? "";

                            documentation.DocumentedEndpoints.Add(endpoint);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug($"Error parsing API documentation: {ex.Message}");
            }
            
            return Task.CompletedTask;
        }

        private async Task DiscoverCommonApiEndpointsAsync(string baseUrl, ApiEndpointDiscoveryResult result, ApiEndpointDiscoveryOptions options)
        {
            var commonApiPaths = new[]
            {
                "/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/graphql",
                "/api/users", "/api/auth", "/api/login", "/api/health", "/api/status",
                "/api/config", "/api/data", "/api/search", "/v1/api", "/api/admin"
            };

            var tasks = commonApiPaths.Select(path => TestApiEndpointAsync(baseUrl + path, "GET", result));
            await Task.WhenAll(tasks);
        }

        private async Task TestApiEndpointAsync(string url, string method, ApiEndpointDiscoveryResult result)
        {
            try
            {
                await _semaphore.WaitAsync();
                
                var startTime = DateTime.Now;
                var request = new HttpRequestMessage(new HttpMethod(method), url);
                var response = await _httpClient.SendAsync(request);
                var responseTime = (long)(DateTime.Now - startTime).TotalMilliseconds;
                
                var endpoint = new ApiEndpoint
                {
                    Url = url,
                    Method = method,
                    StatusCode = (int)response.StatusCode,
                    ResponseTimeMs = responseTime,
                    ResponseContentType = response.Content.Headers.ContentType?.MediaType ?? ""
                };

                if (response.IsSuccessStatusCode || response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    endpoint.ResponseSizeBytes = content.Length;
                    
                    AnalyzeApiResponse(endpoint, content, response);
                    
                    if (endpoint.StatusCode == 401)
                        endpoint.RequiresAuthentication = true;

                    result.DiscoveredEndpoints.Add(endpoint);
                    Logger.Debug($"Found API endpoint: {method} {url} -> {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                Logger.Debug($"Error testing API endpoint {method} {url}: {ex.Message}");
            }
            finally
            {
                _semaphore.Release();
            }
        }

        private void AnalyzeApiResponse(ApiEndpoint endpoint, string content, HttpResponseMessage response)
        {
            var contentType = endpoint.ResponseContentType.ToLower();
            
            if (contentType.Contains("json"))
            {
                endpoint.ApiType = "REST";
                if (content.Length < 1000)
                    endpoint.SampleResponse = content;
                
                if (content.Contains("\"data\"") && content.Contains("\"query\""))
                    endpoint.ApiType = "GraphQL";
            }
            else if (contentType.Contains("xml"))
            {
                endpoint.ApiType = "SOAP/XML";
            }

            if (response.Headers.WwwAuthenticate?.Any() == true)
                endpoint.RequiresAuthentication = true;

            CheckForSecurityIssues(endpoint, response);
        }

        private void CheckForSecurityIssues(ApiEndpoint endpoint, HttpResponseMessage response)
        {
            if (!response.Headers.Contains("X-Content-Type-Options"))
                endpoint.SecurityIssues.Add("Missing X-Content-Type-Options header");

            if (endpoint.SampleResponse?.Contains("stack trace") == true)
                endpoint.SecurityIssues.Add("Verbose error messages may leak information");

            if (endpoint.StatusCode == 200 && endpoint.ResponseSizeBytes > 10000)
                endpoint.SecurityIssues.Add("Large response size may indicate information disclosure");
        }

        private async Task AnalyzeJavaScriptForEndpointsAsync(string baseUrl, ApiEndpointDiscoveryResult result)
        {
            var jsFiles = new[] { "/app.js", "/main.js", "/bundle.js", "/js/app.js" };

            foreach (var jsFile in jsFiles)
            {
                try
                {
                    var response = await _httpClient.GetAsync(baseUrl + jsFile);
                    if (response.IsSuccessStatusCode)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        ExtractApiEndpointsFromJavaScript(content, baseUrl, result);
                    }
                }
                catch (Exception ex)
                {
                    Logger.Debug($"Error analyzing JavaScript file {jsFile}: {ex.Message}");
                }
            }
        }

        private void ExtractApiEndpointsFromJavaScript(string jsContent, string baseUrl, ApiEndpointDiscoveryResult result)
        {
            var patterns = new[]
            {
                @"['""](/api/[^'""]+)['""]",
                @"['""](/rest/[^'""]+)['""]",
                @"fetch\s*\(\s*['""]([^'""]+)['""]"
            };

            foreach (var pattern in patterns)
            {
                var matches = Regex.Matches(jsContent, pattern, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    var endpoint = match.Groups[1].Value;
                    if (endpoint.StartsWith("/") && !result.DiscoveredEndpoints.Any(e => e.Url.EndsWith(endpoint)))
                    {
                        result.DiscoveredEndpoints.Add(new ApiEndpoint
                        {
                            Url = baseUrl + endpoint,
                            Method = "GET",
                            ApiType = "REST",
                            Description = "Discovered from JavaScript analysis"
                        });
                    }
                }
            }
        }

        private async Task DiscoverGraphQlEndpointsAsync(string baseUrl, ApiEndpointDiscoveryResult result)
        {
            var graphqlPaths = new[] { "/graphql", "/graphiql", "/api/graphql" };

            foreach (var path in graphqlPaths)
            {
                try
                {
                    var introspectionQuery = @"{""query"":""{ __schema { types { name } } }""}";
                    var content = new StringContent(introspectionQuery, Encoding.UTF8, "application/json");
                    
                    var response = await _httpClient.PostAsync(baseUrl + path, content);
                    if (response.IsSuccessStatusCode)
                    {
                        var responseContent = await response.Content.ReadAsStringAsync();
                        
                        var endpoint = new ApiEndpoint
                        {
                            Url = baseUrl + path,
                            Method = "POST",
                            StatusCode = (int)response.StatusCode,
                            ApiType = "GraphQL",
                            Description = "GraphQL endpoint"
                        };

                        if (responseContent.Contains("__schema"))
                            endpoint.SecurityIssues.Add("GraphQL introspection enabled - may expose schema");

                        result.DiscoveredEndpoints.Add(endpoint);
                        Logger.Information($"Found GraphQL endpoint at {baseUrl + path}");
                    }
                }
                catch (Exception ex)
                {
                    Logger.Debug($"Error testing GraphQL endpoint {path}: {ex.Message}");
                }
            }
        }

        private async Task TestCustomEndpointsAsync(string baseUrl, ApiEndpointDiscoveryResult result, ApiEndpointDiscoveryOptions options)
        {
            var tasks = options.CustomEndpoints.Select(endpoint => 
                TestApiEndpointAsync(baseUrl + (endpoint.StartsWith("/") ? endpoint : "/" + endpoint), "GET", result));
            await Task.WhenAll(tasks);
        }

        private void PerformSecurityAnalysis(ApiEndpointDiscoveryResult result)
        {
            var securityFindings = new List<string>();
            var recommendations = new List<string>();

            var publicEndpoints = result.DiscoveredEndpoints.Where(e => e.StatusCode >= 200 && e.StatusCode < 300 && !e.RequiresAuthentication).ToList();
            if (publicEndpoints.Count > 5)
            {
                securityFindings.Add($"{publicEndpoints.Count} publicly accessible API endpoints found");
                recommendations.Add("Review public API endpoints and implement authentication where appropriate");
            }

            var endpointsWithIssues = result.DiscoveredEndpoints.Where(e => e.SecurityIssues.Any()).ToList();
            if (endpointsWithIssues.Any())
            {
                securityFindings.Add($"{endpointsWithIssues.Count} endpoints have security issues");
                recommendations.Add("Address security issues in API endpoints");
            }

            if (result.ApiDocumentations.Any(d => d.IsPubliclyAccessible))
            {
                securityFindings.Add("API documentation is publicly accessible");
                recommendations.Add("Consider restricting access to API documentation");
            }

            result.SecurityFindings = securityFindings;
            result.Recommendations = recommendations;
        }

        public void DisplayResults(ApiEndpointDiscoveryResult result)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule($"[bold green]API Endpoint Discovery Results for {result.BaseUrl}[/]").RuleStyle("green"));
            AnsiConsole.WriteLine();

            // Summary
            var summaryTable = new Table().Border(TableBorder.Rounded).BorderColor(Color.Green);
            summaryTable.AddColumn("[bold]Metric[/]");
            summaryTable.AddColumn("[bold]Value[/]");

            summaryTable.AddRow("Base URL", result.BaseUrl);
            summaryTable.AddRow("Scan Time", result.ScanTime.ToString("yyyy-MM-dd HH:mm:ss"));
            summaryTable.AddRow("Duration", $"{result.ScanDuration.TotalSeconds:F1} seconds");
            summaryTable.AddRow("Total Endpoints Tested", result.TotalEndpointsTested.ToString());
            summaryTable.AddRow("Accessible Endpoints", $"[green]{result.AccessibleEndpoints}[/]");
            summaryTable.AddRow("Authenticated Endpoints", $"[yellow]{result.AuthenticatedEndpoints}[/]");
            summaryTable.AddRow("API Documentation Found", result.ApiDocumentations.Count.ToString());

            AnsiConsole.Write(summaryTable);
            AnsiConsole.WriteLine();

            // API Endpoints
            if (result.DiscoveredEndpoints.Any())
            {
                var endpointsTable = new Table().Border(TableBorder.Rounded).BorderColor(Color.Blue);
                endpointsTable.AddColumn("[bold]Method[/]");
                endpointsTable.AddColumn("[bold]Endpoint[/]");
                endpointsTable.AddColumn("[bold]Status[/]");
                endpointsTable.AddColumn("[bold]Type[/]");
                endpointsTable.AddColumn("[bold]Auth[/]");
                endpointsTable.AddColumn("[bold]Issues[/]");

                foreach (var endpoint in result.DiscoveredEndpoints.Take(15))
                {
                    var statusColor = endpoint.StatusCode >= 200 && endpoint.StatusCode < 300 ? "green" :
                                     endpoint.StatusCode == 401 ? "yellow" : "red";
                    
                    var authStatus = endpoint.RequiresAuthentication ? "[yellow]Yes[/]" : "[green]No[/]";
                    var issuesCount = endpoint.SecurityIssues.Count;
                    var issuesColor = issuesCount == 0 ? "green" : "red";

                    endpointsTable.AddRow(
                        $"[cyan]{endpoint.Method}[/]",
                        endpoint.Url.Length > 40 ? endpoint.Url.Substring(0, 37) + "..." : endpoint.Url,
                        $"[{statusColor}]{endpoint.StatusCode}[/]",
                        endpoint.ApiType,
                        authStatus,
                        $"[{issuesColor}]{issuesCount}[/]"
                    );
                }

                if (result.DiscoveredEndpoints.Count > 15)
                    endpointsTable.AddRow($"[dim]... and {result.DiscoveredEndpoints.Count - 15} more endpoints[/]", "", "", "", "", "");

                AnsiConsole.Write(endpointsTable);
                AnsiConsole.WriteLine();
            }

            // Security Findings
            if (result.SecurityFindings.Any())
            {
                AnsiConsole.Write(new Rule("[bold red]Security Findings[/]").RuleStyle("red"));
                foreach (var finding in result.SecurityFindings)
                    AnsiConsole.MarkupLine($"[red]• {finding}[/]");
                AnsiConsole.WriteLine();
            }

            // Recommendations
            if (result.Recommendations.Any())
            {
                AnsiConsole.Write(new Rule("[bold yellow]Recommendations[/]").RuleStyle("yellow"));
                foreach (var recommendation in result.Recommendations)
                    AnsiConsole.MarkupLine($"[yellow]• {recommendation}[/]");
                AnsiConsole.WriteLine();
            }

            if (!result.DiscoveredEndpoints.Any())
                AnsiConsole.MarkupLine("[yellow]No API endpoints discovered.[/]");
        }

        public async Task<bool> SaveResultsAsync(ApiEndpointDiscoveryResult result, string? filePath = null)
        {
            try
            {
                filePath ??= $"api_endpoint_discovery_{DateTime.Now:yyyyMMdd_HHmmss}.txt";

                var content = new StringBuilder();
                content.AppendLine($"API Endpoint Discovery Report");
                content.AppendLine($"Base URL: {result.BaseUrl}");
                content.AppendLine($"Scan Time: {result.ScanTime:yyyy-MM-dd HH:mm:ss}");
                content.AppendLine($"Duration: {result.ScanDuration.TotalSeconds:F1} seconds");
                content.AppendLine();

                if (result.DiscoveredEndpoints.Any())
                {
                    content.AppendLine("Discovered API Endpoints:");
                    content.AppendLine("========================");
                    foreach (var endpoint in result.DiscoveredEndpoints)
                    {
                        content.AppendLine($"[{endpoint.StatusCode}] {endpoint.Method} {endpoint.Url}");
                        content.AppendLine($"    Type: {endpoint.ApiType}");
                        content.AppendLine($"    Response Time: {endpoint.ResponseTimeMs}ms");
                        if (endpoint.SecurityIssues.Any())
                        {
                            content.AppendLine($"    Security Issues:");
                            foreach (var issue in endpoint.SecurityIssues)
                                content.AppendLine($"      - {issue}");
                        }
                        content.AppendLine();
                    }
                }

                if (result.SecurityFindings.Any())
                {
                    content.AppendLine("Security Findings:");
                    content.AppendLine("==================");
                    foreach (var finding in result.SecurityFindings)
                        content.AppendLine($"- {finding}");
                    content.AppendLine();
                }

                if (result.Recommendations.Any())
                {
                    content.AppendLine("Recommendations:");
                    content.AppendLine("================");
                    foreach (var recommendation in result.Recommendations)
                        content.AppendLine($"- {recommendation}");
                }

                await File.WriteAllTextAsync(filePath, content.ToString());
                Logger.Information($"API endpoint discovery results saved to {filePath}");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Error saving API endpoint discovery results: {ex.Message}");
                return false;
            }
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
            _semaphore?.Dispose();
        }
    }
}
