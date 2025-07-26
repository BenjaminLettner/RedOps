using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using Serilog;
using Spectre.Console;
using RedOps.Utils;

namespace RedOps.Modules.Reconnaissance.WebApplicationRecon
{
    public class DirectoryEnumerator : IDisposable
    {
        private static readonly ILogger Logger = Serilog.Log.ForContext<DirectoryEnumerator>();
        private readonly HttpClient _httpClient;
        private readonly SemaphoreSlim _semaphore;
        private readonly WordlistManager _wordlistManager;

        public DirectoryEnumerator(int maxConcurrency = 20)
        {
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Add("User-Agent", 
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
            _httpClient.Timeout = TimeSpan.FromSeconds(10);
            _semaphore = new SemaphoreSlim(maxConcurrency, maxConcurrency);
            _wordlistManager = new WordlistManager();
        }

        public async Task<DirectoryEnumerationResult> EnumerateDirectoriesAsync(string baseUrl, DirectoryEnumerationOptions options)
        {
            var result = new DirectoryEnumerationResult
            {
                BaseUrl = baseUrl,
                ScanTime = DateTime.Now,
                Options = options
            };

            try
            {
                Logger.Information($"Starting directory enumeration for {baseUrl}");

                // Ensure URL has protocol and ends with /
                if (!baseUrl.StartsWith("http://") && !baseUrl.StartsWith("https://"))
                {
                    baseUrl = "http://" + baseUrl;
                }

                if (!baseUrl.EndsWith("/"))
                {
                    baseUrl += "/";
                }

                result.BaseUrl = baseUrl;

                // Get wordlists based on options
                var wordlists = await GetWordlistsAsync(options);
                var totalPaths = wordlists.Sum(w => w.Count);

                Logger.Information($"Starting enumeration with {totalPaths} paths from {wordlists.Count} wordlists");

                // Perform enumeration with progress tracking
                await EnumerateWithProgress(baseUrl, wordlists, result, options);

                // Sort results by status code and path
                result.FoundPaths = result.FoundPaths
                    .OrderBy(p => p.StatusCode)
                    .ThenBy(p => p.Path)
                    .ToList();

                Logger.Information($"Directory enumeration completed for {baseUrl}. Found {result.FoundPaths.Count} accessible paths");
            }
            catch (Exception ex)
            {
                Logger.Error($"Error during directory enumeration for {baseUrl}: {ex.Message}");
                result.Error = ex.Message;
            }

            return result;
        }

        private async Task EnumerateWithProgress(string baseUrl, List<List<string>> wordlists, DirectoryEnumerationResult result, DirectoryEnumerationOptions options)
        {
            var allPaths = new List<string>();
            
            // Combine all wordlists
            foreach (var wordlist in wordlists)
            {
                allPaths.AddRange(wordlist);
            }

            // Add file extensions if specified
            if (options.FileExtensions?.Any() == true)
            {
                var pathsWithExtensions = new List<string>();
                foreach (var path in allPaths.ToList())
                {
                    pathsWithExtensions.Add(path); // Original path
                    foreach (var ext in options.FileExtensions)
                    {
                        pathsWithExtensions.Add($"{path}.{ext.TrimStart('.')}");
                    }
                }
                allPaths = pathsWithExtensions;
            }

            // Remove duplicates
            allPaths = allPaths.Distinct().ToList();

            await AnsiConsole.Progress()
                .StartAsync(async ctx =>
                {
                    var task = ctx.AddTask("[green]Enumerating directories and files...[/]");
                    task.MaxValue = allPaths.Count;

                    var tasks = allPaths.Select(async path =>
                    {
                        await _semaphore.WaitAsync();
                        try
                        {
                            var foundPath = await CheckPath(baseUrl, path, options);
                            if (foundPath != null)
                            {
                                lock (result.FoundPaths)
                                {
                                    result.FoundPaths.Add(foundPath);
                                }
                            }
                            task.Increment(1);
                        }
                        finally
                        {
                            _semaphore.Release();
                        }
                    });

                    await Task.WhenAll(tasks);
                });
        }

        private async Task<FoundPath?> CheckPath(string baseUrl, string path, DirectoryEnumerationOptions options)
        {
            try
            {
                var fullUrl = baseUrl + path.TrimStart('/');
                var response = await _httpClient.GetAsync(fullUrl);
                
                var statusCode = (int)response.StatusCode;
                
                // Check if we should include this status code
                if (!ShouldIncludeStatusCode(statusCode, options))
                {
                    return null;
                }

                var contentLength = response.Content.Headers.ContentLength ?? 0;
                var contentType = response.Content.Headers.ContentType?.MediaType ?? "";
                
                // Read a sample of the content for analysis
                var content = "";
                if (contentLength < 10000) // Only read small responses fully
                {
                    content = await response.Content.ReadAsStringAsync();
                }

                var foundPath = new FoundPath
                {
                    Path = path,
                    FullUrl = fullUrl,
                    StatusCode = statusCode,
                    StatusDescription = response.ReasonPhrase ?? "",
                    ContentLength = contentLength,
                    ContentType = contentType,
                    ResponseTime = DateTime.Now,
                    IsDirectory = IsDirectory(path, response, content),
                    IsInteresting = IsInterestingPath(path, statusCode, contentType, content)
                };

                // Extract additional information for interesting paths
                if (foundPath.IsInteresting)
                {
                    AnalyzeInterestingPath(foundPath, content, response);
                }

                Logger.Debug($"Found path: {path} - Status: {statusCode} - Length: {contentLength}");
                return foundPath;
            }
            catch (HttpRequestException)
            {
                // Connection issues, skip
                return null;
            }
            catch (TaskCanceledException)
            {
                // Timeout, skip
                return null;
            }
            catch (Exception ex)
            {
                Logger.Debug($"Error checking path {path}: {ex.Message}");
                return null;
            }
        }

        private bool ShouldIncludeStatusCode(int statusCode, DirectoryEnumerationOptions options)
        {
            // Always include successful responses
            if (statusCode >= 200 && statusCode < 300) return true;
            
            // Include redirects if specified
            if (options.IncludeRedirects && statusCode >= 300 && statusCode < 400) return true;
            
            // Include client errors if specified (403 Forbidden is often interesting)
            if (options.IncludeClientErrors && statusCode >= 400 && statusCode < 500) return true;
            
            // Include specific interesting status codes
            var interestingCodes = new[] { 401, 403, 405, 500, 501, 502, 503 };
            if (interestingCodes.Contains(statusCode)) return true;

            return false;
        }

        private bool IsDirectory(string path, HttpResponseMessage response, string content)
        {
            // Check if path ends with /
            if (path.EndsWith("/")) return true;
            
            // Check content type
            var contentType = response.Content.Headers.ContentType?.MediaType ?? "";
            if (contentType.Contains("text/html"))
            {
                // Look for directory listing indicators
                if (content.Contains("Index of") || 
                    content.Contains("Directory listing") ||
                    content.Contains("Parent Directory") ||
                    content.Contains("[DIR]"))
                {
                    return true;
                }
            }

            return false;
        }

        private bool IsInterestingPath(string path, int statusCode, string contentType, string content)
        {
            // Interesting file extensions
            var interestingExtensions = new[] { 
                ".config", ".xml", ".json", ".yml", ".yaml", ".env", ".log", 
                ".bak", ".backup", ".old", ".tmp", ".sql", ".db", ".sqlite",
                ".git", ".svn", ".htaccess", ".htpasswd", ".php", ".asp", ".aspx"
            };

            if (interestingExtensions.Any(ext => path.EndsWith(ext, StringComparison.OrdinalIgnoreCase)))
                return true;

            // Interesting directories
            var interestingDirs = new[] {
                "admin", "administrator", "backup", "config", "database", "db",
                "logs", "log", "temp", "tmp", "test", "dev", "development",
                "staging", "api", "private", "internal", "secret"
            };

            if (interestingDirs.Any(dir => path.Contains(dir, StringComparison.OrdinalIgnoreCase)))
                return true;

            // Status code based
            if (statusCode == 403) return true; // Forbidden - might indicate protected content
            if (statusCode == 401) return true; // Unauthorized - authentication required

            // Content based
            if (!string.IsNullOrEmpty(content))
            {
                var contentLower = content.ToLower();
                if (contentLower.Contains("password") || 
                    contentLower.Contains("username") ||
                    contentLower.Contains("login") ||
                    contentLower.Contains("database") ||
                    contentLower.Contains("connection string") ||
                    contentLower.Contains("api key"))
                {
                    return true;
                }
            }

            return false;
        }

        private void AnalyzeInterestingPath(FoundPath foundPath, string content, HttpResponseMessage response)
        {
            var details = new List<string>();

            // Analyze headers
            if (response.Headers.WwwAuthenticate?.Any() == true)
            {
                details.Add("Requires authentication");
            }

            if (response.Headers.Contains("X-Powered-By"))
            {
                var poweredBy = string.Join(", ", response.Headers.GetValues("X-Powered-By"));
                details.Add($"Powered by: {poweredBy}");
            }

            // Analyze content
            if (!string.IsNullOrEmpty(content) && content.Length < 5000)
            {
                // Look for sensitive information patterns
                var patterns = new Dictionary<string, string>
                {
                    { @"password\s*[=:]\s*['""]?([^'"">\s]+)", "Password found" },
                    { @"api[_-]?key\s*[=:]\s*['""]?([^'"">\s]+)", "API key found" },
                    { @"secret\s*[=:]\s*['""]?([^'"">\s]+)", "Secret found" },
                    { @"token\s*[=:]\s*['""]?([^'"">\s]+)", "Token found" },
                    { @"database\s*[=:]\s*['""]?([^'"">\s]+)", "Database reference found" }
                };

                foreach (var pattern in patterns)
                {
                    if (Regex.IsMatch(content, pattern.Key, RegexOptions.IgnoreCase))
                    {
                        details.Add(pattern.Value);
                    }
                }

                // Check for directory listings
                if (content.Contains("Index of") || content.Contains("[DIR]"))
                {
                    details.Add("Directory listing enabled");
                }

                // Check for error pages with information disclosure
                if (content.Contains("stack trace", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("exception", StringComparison.OrdinalIgnoreCase))
                {
                    details.Add("Error page with potential information disclosure");
                }
            }

            foundPath.InterestingDetails = details;
        }

        private async Task<List<List<string>>> GetWordlistsAsync(DirectoryEnumerationOptions options)
        {
            var wordlists = new List<List<string>>();
            var wordlistTypes = new List<WordlistType>();

            // Map options to wordlist types, prioritizing largest/most comprehensive wordlists
            if (options.UseCommonDirectories)
            {
                // Priority order: RAFT (30k) > Big (20k) > Comprehensive (560) > Common (4.6k) > Built-in fallback
                var raftInfo = _wordlistManager.GetWordlistInfo(WordlistType.RaftDirectories);
                var bigInfo = _wordlistManager.GetWordlistInfo(WordlistType.BigDirectories);
                var comprehensiveInfo = _wordlistManager.GetWordlistInfo(WordlistType.ComprehensiveDirectories);
                var commonInfo = _wordlistManager.GetWordlistInfo(WordlistType.CommonDirectories);
                
                if (raftInfo?.IsAvailable == true)
                {
                    wordlistTypes.Add(WordlistType.RaftDirectories);
                    Logger.Information($"Using RAFT directories wordlist ({raftInfo.EntryCount} entries)");
                }
                else if (bigInfo?.IsAvailable == true)
                {
                    wordlistTypes.Add(WordlistType.BigDirectories);
                    Logger.Information($"Using Big directories wordlist ({bigInfo.EntryCount} entries)");
                }
                else if (comprehensiveInfo?.IsAvailable == true)
                {
                    wordlistTypes.Add(WordlistType.ComprehensiveDirectories);
                    Logger.Information($"Using Comprehensive directories wordlist ({comprehensiveInfo.EntryCount} entries)");
                }
                else if (commonInfo?.IsAvailable == true)
                {
                    wordlistTypes.Add(WordlistType.CommonDirectories);
                    Logger.Information($"Using Common directories wordlist ({commonInfo.EntryCount} entries)");
                }
                else
                {
                    // Final fallback to built-in
                    wordlistTypes.Add(WordlistType.CommonDirectories);
                    Logger.Warning("Using built-in directories wordlist as fallback");
                }
            }

            if (options.UseCommonFiles)
            {
                // Priority order: RAFT (17k) > Comprehensive (557) > Common (built-in) > Built-in fallback
                var raftInfo = _wordlistManager.GetWordlistInfo(WordlistType.RaftFiles);
                var comprehensiveInfo = _wordlistManager.GetWordlistInfo(WordlistType.ComprehensiveFiles);
                var commonInfo = _wordlistManager.GetWordlistInfo(WordlistType.CommonFiles);
                
                if (raftInfo?.IsAvailable == true)
                {
                    wordlistTypes.Add(WordlistType.RaftFiles);
                    Logger.Information($"Using RAFT files wordlist ({raftInfo.EntryCount} entries)");
                }
                else if (comprehensiveInfo?.IsAvailable == true)
                {
                    wordlistTypes.Add(WordlistType.ComprehensiveFiles);
                    Logger.Information($"Using Comprehensive files wordlist ({comprehensiveInfo.EntryCount} entries)");
                }
                else if (commonInfo?.IsAvailable == true)
                {
                    wordlistTypes.Add(WordlistType.CommonFiles);
                    Logger.Information($"Using Common files wordlist ({commonInfo.EntryCount} entries)");
                }
                else
                {
                    // Final fallback to built-in
                    wordlistTypes.Add(WordlistType.CommonFiles);
                    Logger.Warning("Using built-in files wordlist as fallback");
                }
            }

            if (options.UseBackupFiles)
            {
                wordlistTypes.Add(WordlistType.BackupFiles);
            }

            if (options.UseConfigFiles)
            {
                wordlistTypes.Add(WordlistType.ConfigFiles);
            }

            // Load all selected wordlists
            foreach (var type in wordlistTypes)
            {
                try
                {
                    var wordlist = await _wordlistManager.GetWordlistAsync(type);
                    if (wordlist.Any())
                    {
                        wordlists.Add(wordlist);
                        var info = _wordlistManager.GetWordlistInfo(type);
                        Logger.Information($"Loaded {wordlist.Count} entries from {info?.Name ?? type.ToString()}");
                    }
                }
                catch (Exception ex)
                {
                    Logger.Warning($"Failed to load wordlist {type}: {ex.Message}");
                }
            }

            // Add custom wordlist if provided
            if (options.CustomWordlist?.Any() == true)
            {
                wordlists.Add(options.CustomWordlist.ToList());
                Logger.Information($"Added custom wordlist with {options.CustomWordlist.Count} entries");
            }

            // If no wordlists loaded, use built-in common directories as fallback
            if (!wordlists.Any())
            {
                Logger.Warning("No wordlists loaded, using built-in common directories as fallback");
                var fallback = await _wordlistManager.GetWordlistAsync(WordlistType.CommonDirectories);
                wordlists.Add(fallback);
            }

            return wordlists;
        }

        private List<string> GetCommonDirectories()
        {
            return new List<string>
            {
                "admin", "administrator", "admin.php", "admin.html", "admin/",
                "login", "login.php", "login.html", "login/",
                "backup", "backups", "backup/", "backups/",
                "config", "configuration", "config/", "configs/",
                "database", "db", "data", "database/", "db/", "data/",
                "logs", "log", "logs/", "log/",
                "temp", "tmp", "temporary", "temp/", "tmp/",
                "test", "testing", "tests", "test/", "tests/",
                "dev", "development", "staging", "dev/", "development/",
                "api", "api/", "v1", "v2", "api/v1", "api/v2",
                "private", "internal", "secret", "private/", "internal/",
                "upload", "uploads", "files", "upload/", "uploads/", "files/",
                "images", "img", "assets", "static", "images/", "img/", "assets/", "static/",
                "js", "css", "scripts", "style", "js/", "css/", "scripts/",
                "includes", "inc", "lib", "library", "includes/", "inc/", "lib/",
                "old", "new", "beta", "alpha", "old/", "new/",
                "mobile", "m", "www", "web", "site",
                "cms", "wp", "wordpress", "drupal", "joomla",
                "phpmyadmin", "pma", "mysql", "sql",
                "ftp", "sftp", "ssh", "telnet",
                "mail", "email", "webmail", "roundcube",
                "forum", "forums", "blog", "news",
                "shop", "store", "cart", "checkout", "payment",
                "user", "users", "profile", "account", "accounts",
                "search", "help", "support", "contact", "about"
            };
        }

        private List<string> GetCommonFiles()
        {
            return new List<string>
            {
                "index.html", "index.php", "index.asp", "index.aspx", "index.jsp",
                "default.html", "default.php", "default.asp", "default.aspx",
                "home.html", "home.php", "main.html", "main.php",
                "robots.txt", "sitemap.xml", "sitemap.txt",
                "favicon.ico", "apple-touch-icon.png",
                "crossdomain.xml", "clientaccesspolicy.xml",
                "web.config", "app.config", "global.asax",
                ".htaccess", ".htpasswd", ".htgroup",
                "readme.txt", "readme.html", "README.md", "CHANGELOG.md",
                "license.txt", "LICENSE", "COPYING",
                "phpinfo.php", "info.php", "test.php",
                "login.html", "login.php", "signin.php", "auth.php",
                "logout.php", "signout.php", "exit.php",
                "register.php", "signup.php", "join.php",
                "contact.php", "contact.html", "feedback.php",
                "search.php", "search.html", "find.php",
                "error.html", "404.html", "500.html", "403.html",
                "style.css", "main.css", "bootstrap.css", "theme.css",
                "jquery.js", "main.js", "app.js", "script.js",
                "upload.php", "file.php", "download.php",
                "rss.xml", "feed.xml", "atom.xml"
            };
        }

        private List<string> GetBackupFiles()
        {
            return new List<string>
            {
                "backup.zip", "backup.tar", "backup.tar.gz", "backup.rar",
                "site.zip", "website.zip", "web.zip", "www.zip",
                "database.sql", "db.sql", "dump.sql", "backup.sql",
                "config.bak", "web.config.bak", ".htaccess.bak",
                "index.php.bak", "index.html.bak", "main.php.bak",
                "backup.txt", "backup.log", "old.txt",
                "copy.php", "copy.html", "original.php",
                "temp.php", "tmp.php", "test.php.old",
                "site.old", "website.old", "backup.old",
                "archive.zip", "files.zip", "data.zip",
                "export.sql", "import.sql", "migrate.sql",
                "backup_" + DateTime.Now.Year,
                "backup_" + DateTime.Now.ToString("yyyy-MM"),
                "backup_" + DateTime.Now.ToString("yyyy-MM-dd")
            };
        }

        private List<string> GetConfigFiles()
        {
            return new List<string>
            {
                "config.php", "config.inc", "config.xml", "config.json",
                "configuration.php", "settings.php", "app.config",
                "web.config", "global.asax", "appsettings.json",
                "database.php", "db.php", "connection.php", "connect.php",
                ".env", ".env.local", ".env.production", ".env.development",
                "wp-config.php", "local_settings.py", "settings.py",
                "config.yml", "config.yaml", "_config.yml",
                "package.json", "composer.json", "bower.json",
                "Gemfile", "requirements.txt", "pom.xml",
                "server.xml", "context.xml", "hibernate.cfg.xml",
                "spring.xml", "applicationContext.xml",
                "log4j.properties", "log4j.xml", "logback.xml",
                "nginx.conf", "apache.conf", "httpd.conf",
                ".gitignore", ".gitconfig", ".svnignore",
                "Dockerfile", "docker-compose.yml", "Vagrantfile"
            };
        }

        public void DisplayResults(DirectoryEnumerationResult result)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule($"[red]Directory Enumeration Results: {result.BaseUrl}[/]").RuleStyle("grey"));
            AnsiConsole.WriteLine();

            if (!string.IsNullOrEmpty(result.Error))
            {
                AnsiConsole.MarkupLine($"[red]Error: {result.Error}[/]");
                return;
            }

            if (!result.FoundPaths.Any())
            {
                AnsiConsole.MarkupLine("[yellow]No accessible paths found.[/]");
                return;
            }

            // Summary statistics
            var summary = new Table();
            summary.AddColumn("Statistic");
            summary.AddColumn("Count");
            summary.Border(TableBorder.Rounded);

            summary.AddRow("Total Paths Found", result.FoundPaths.Count.ToString());
            summary.AddRow("Directories", result.FoundPaths.Count(p => p.IsDirectory).ToString());
            summary.AddRow("Files", result.FoundPaths.Count(p => !p.IsDirectory).ToString());
            summary.AddRow("Interesting Paths", result.FoundPaths.Count(p => p.IsInteresting).ToString());
            summary.AddRow("Status 200 (OK)", result.FoundPaths.Count(p => p.StatusCode == 200).ToString());
            summary.AddRow("Status 403 (Forbidden)", result.FoundPaths.Count(p => p.StatusCode == 403).ToString());
            summary.AddRow("Redirects (3xx)", result.FoundPaths.Count(p => p.StatusCode >= 300 && p.StatusCode < 400).ToString());

            AnsiConsole.Write(summary);
            AnsiConsole.WriteLine();

            // Interesting paths first
            var interestingPaths = result.FoundPaths.Where(p => p.IsInteresting).ToList();
            if (interestingPaths.Any())
            {
                AnsiConsole.MarkupLine("[red]🔥 Interesting Paths Found:[/]");
                DisplayPathTable(interestingPaths, showDetails: true);
                AnsiConsole.WriteLine();
            }

            // All accessible paths
            AnsiConsole.MarkupLine("[green]📁 All Accessible Paths:[/]");
            DisplayPathTable(result.FoundPaths, showDetails: false);

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"[grey]Scan completed at: {result.ScanTime:yyyy-MM-dd HH:mm:ss}[/]");
        }

        private void DisplayPathTable(List<FoundPath> paths, bool showDetails)
        {
            var table = new Table();
            table.AddColumn("Status");
            table.AddColumn("Type");
            table.AddColumn("Path");
            table.AddColumn("Size");
            
            if (showDetails)
            {
                table.AddColumn("Details");
            }

            table.Border(TableBorder.Simple);

            foreach (var path in paths.Take(50)) // Limit display to avoid overwhelming output
            {
                var statusColor = GetStatusColor(path.StatusCode);
                var typeIcon = path.IsDirectory ? "📁" : "📄";
                var sizeText = path.ContentLength > 0 ? FormatFileSize(path.ContentLength) : "-";
                
                if (showDetails && path.InterestingDetails?.Any() == true)
                {
                    var details = string.Join(", ", path.InterestingDetails);
                    table.AddRow(
                        $"[{statusColor}]{path.StatusCode}[/]",
                        typeIcon,
                        path.Path,
                        sizeText,
                        $"[yellow]{details}[/]"
                    );
                }
                else if (!showDetails)
                {
                    table.AddRow(
                        $"[{statusColor}]{path.StatusCode}[/]",
                        typeIcon,
                        path.Path,
                        sizeText
                    );
                }
            }

            if (paths.Count > 50)
            {
                table.AddRow("...", "...", $"[grey]({paths.Count - 50} more paths)[/]", "...");
            }

            AnsiConsole.Write(table);
        }

        private string GetStatusColor(int statusCode)
        {
            return statusCode switch
            {
                >= 200 and < 300 => "green",
                >= 300 and < 400 => "yellow",
                >= 400 and < 500 => "red",
                >= 500 => "red",
                _ => "grey"
            };
        }

        private string FormatFileSize(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB" };
            int counter = 0;
            decimal number = bytes;
            while (Math.Round(number / 1024) >= 1)
            {
                number /= 1024;
                counter++;
            }
            return $"{number:n1} {suffixes[counter]}";
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
            _semaphore?.Dispose();
        }
    }

    public class DirectoryEnumerationResult
    {
        public string BaseUrl { get; set; } = "";
        public DateTime ScanTime { get; set; }
        public DirectoryEnumerationOptions Options { get; set; } = new();
        public List<FoundPath> FoundPaths { get; set; } = new();
        public string Error { get; set; } = "";
    }

    public class DirectoryEnumerationOptions
    {
        public bool UseCommonDirectories { get; set; } = true;
        public bool UseCommonFiles { get; set; } = true;
        public bool UseBackupFiles { get; set; } = false;
        public bool UseConfigFiles { get; set; } = false;
        public bool IncludeRedirects { get; set; } = true;
        public bool IncludeClientErrors { get; set; } = true;
        public List<string>? FileExtensions { get; set; }
        public List<string>? CustomWordlist { get; set; }
        public int MaxConcurrency { get; set; } = 20;
    }

    public class FoundPath
    {
        public string Path { get; set; } = "";
        public string FullUrl { get; set; } = "";
        public int StatusCode { get; set; }
        public string StatusDescription { get; set; } = "";
        public long ContentLength { get; set; }
        public string ContentType { get; set; } = "";
        public DateTime ResponseTime { get; set; }
        public bool IsDirectory { get; set; }
        public bool IsInteresting { get; set; }
        public List<string>? InterestingDetails { get; set; }
    }
}
