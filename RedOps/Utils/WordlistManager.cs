using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Serilog;

namespace RedOps.Utils
{
    public enum WordlistType
    {
        CommonDirectories,
        CommonFiles,
        BackupFiles,
        ConfigFiles,
        Subdomains,
        BigDirectories,
        RaftDirectories,
        RaftFiles,
        ComprehensiveDirectories,
        ComprehensiveFiles,
        ComprehensiveSubdomains,
        WebExtensions
    }

    public class WordlistInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public WordlistType Type { get; set; }
        public int EntryCount { get; set; }
        public bool IsAvailable { get; set; }
        public DateTime LastModified { get; set; }
        public long FileSizeBytes { get; set; }
    }

    public class WordlistManager
    {
        private static readonly ILogger Logger = Serilog.Log.ForContext<WordlistManager>();
        private readonly string _wordlistsDirectory;
        private readonly Dictionary<WordlistType, WordlistInfo> _wordlistInfos;
        private readonly Dictionary<WordlistType, List<string>> _cachedWordlists;

        public WordlistManager()
        {
            var assemblyLocation = Assembly.GetExecutingAssembly().Location;
            var assemblyDirectory = Path.GetDirectoryName(assemblyLocation) ?? Directory.GetCurrentDirectory();
            _wordlistsDirectory = Path.Combine(assemblyDirectory, "wordlists");
            
            _wordlistInfos = new Dictionary<WordlistType, WordlistInfo>();
            _cachedWordlists = new Dictionary<WordlistType, List<string>>();
            
            InitializeWordlistInfos();
        }

        private void InitializeWordlistInfos()
        {
            var wordlistDefinitions = new Dictionary<WordlistType, (string fileName, string name, string description)>
            {
                { WordlistType.CommonDirectories, ("common.txt", "Common Directories", "Common directory names from DirB") },
                { WordlistType.BigDirectories, ("big.txt", "Big Directory List", "Large directory wordlist from DirB") },
                { WordlistType.RaftDirectories, ("raft-medium-directories.txt", "RAFT Medium Directories", "RAFT research medium directory list") },
                { WordlistType.RaftFiles, ("raft-medium-files.txt", "RAFT Medium Files", "RAFT research medium file list") },
                { WordlistType.ComprehensiveDirectories, ("comprehensive-directories.txt", "Comprehensive Directories", "Custom comprehensive directory wordlist") },
                { WordlistType.ComprehensiveFiles, ("comprehensive-files.txt", "Comprehensive Files", "Custom comprehensive file wordlist") },
                { WordlistType.ComprehensiveSubdomains, ("subdomains-comprehensive.txt", "Comprehensive Subdomains", "Custom comprehensive subdomain wordlist") },
                { WordlistType.Subdomains, ("subdomains-top1million-5000.txt", "Top Subdomains", "Top subdomain list") },
                { WordlistType.WebExtensions, ("backup-files.txt", "Web Extensions", "Common web file extensions") }
            };

            foreach (var (type, (fileName, name, description)) in wordlistDefinitions)
            {
                var filePath = Path.Combine(_wordlistsDirectory, fileName);
                var info = new WordlistInfo
                {
                    Name = name,
                    Description = description,
                    FilePath = filePath,
                    Type = type,
                    IsAvailable = File.Exists(filePath)
                };

                if (info.IsAvailable)
                {
                    try
                    {
                        var fileInfo = new FileInfo(filePath);
                        info.LastModified = fileInfo.LastWriteTime;
                        info.FileSizeBytes = fileInfo.Length;
                        info.EntryCount = File.ReadAllLines(filePath).Where(line => !string.IsNullOrWhiteSpace(line) && !line.StartsWith("#")).Count();
                    }
                    catch (Exception ex)
                    {
                        Logger.Warning($"Error reading wordlist info for {fileName}: {ex.Message}");
                        info.IsAvailable = false;
                    }
                }

                _wordlistInfos[type] = info;
            }

            // Add built-in wordlists for backward compatibility
            AddBuiltInWordlists();
        }

        private void AddBuiltInWordlists()
        {
            // Common directories (built-in fallback)
            _wordlistInfos[WordlistType.CommonDirectories] = _wordlistInfos.GetValueOrDefault(WordlistType.CommonDirectories) ?? new WordlistInfo
            {
                Name = "Built-in Common Directories",
                Description = "Built-in common directory names",
                Type = WordlistType.CommonDirectories,
                IsAvailable = true,
                EntryCount = GetBuiltInCommonDirectories().Count
            };

            // Common files (built-in fallback)
            _wordlistInfos[WordlistType.CommonFiles] = _wordlistInfos.GetValueOrDefault(WordlistType.CommonFiles) ?? new WordlistInfo
            {
                Name = "Built-in Common Files",
                Description = "Built-in common file names",
                Type = WordlistType.CommonFiles,
                IsAvailable = true,
                EntryCount = GetBuiltInCommonFiles().Count
            };

            // Backup files (built-in fallback)
            _wordlistInfos[WordlistType.BackupFiles] = _wordlistInfos.GetValueOrDefault(WordlistType.BackupFiles) ?? new WordlistInfo
            {
                Name = "Built-in Backup Files",
                Description = "Built-in backup file patterns",
                Type = WordlistType.BackupFiles,
                IsAvailable = true,
                EntryCount = GetBuiltInBackupFiles().Count
            };

            // Config files (built-in fallback)
            _wordlistInfos[WordlistType.ConfigFiles] = _wordlistInfos.GetValueOrDefault(WordlistType.ConfigFiles) ?? new WordlistInfo
            {
                Name = "Built-in Config Files",
                Description = "Built-in configuration file names",
                Type = WordlistType.ConfigFiles,
                IsAvailable = true,
                EntryCount = GetBuiltInConfigFiles().Count
            };
        }

        public async Task<List<string>> GetWordlistAsync(WordlistType type)
        {
            if (_cachedWordlists.TryGetValue(type, out var cachedList))
            {
                return cachedList;
            }

            var wordlist = new List<string>();

            if (_wordlistInfos.TryGetValue(type, out var info) && info.IsAvailable)
            {
                if (!string.IsNullOrEmpty(info.FilePath) && File.Exists(info.FilePath))
                {
                    try
                    {
                        var lines = await File.ReadAllLinesAsync(info.FilePath);
                        wordlist = lines
                            .Where(line => !string.IsNullOrWhiteSpace(line) && !line.StartsWith("#"))
                            .Select(line => line.Trim())
                            .Distinct()
                            .ToList();

                        Logger.Information($"Loaded {wordlist.Count} entries from {info.Name}");
                    }
                    catch (Exception ex)
                    {
                        Logger.Error($"Error loading wordlist from {info.FilePath}: {ex.Message}");
                        wordlist = GetBuiltInWordlist(type);
                    }
                }
                else
                {
                    wordlist = GetBuiltInWordlist(type);
                }
            }
            else
            {
                wordlist = GetBuiltInWordlist(type);
            }

            _cachedWordlists[type] = wordlist;
            return wordlist;
        }

        private List<string> GetBuiltInWordlist(WordlistType type)
        {
            return type switch
            {
                WordlistType.CommonDirectories => GetBuiltInCommonDirectories(),
                WordlistType.CommonFiles => GetBuiltInCommonFiles(),
                WordlistType.BackupFiles => GetBuiltInBackupFiles(),
                WordlistType.ConfigFiles => GetBuiltInConfigFiles(),
                WordlistType.Subdomains => GetBuiltInSubdomains(),
                _ => new List<string>()
            };
        }

        private List<string> GetBuiltInCommonDirectories()
        {
            return new List<string>
            {
                "admin", "administrator", "login", "signin", "auth", "backup", "backups",
                "config", "configuration", "database", "db", "logs", "log", "upload", "uploads",
                "files", "download", "downloads", "images", "img", "css", "js", "scripts",
                "includes", "inc", "lib", "api", "v1", "v2", "rest", "private", "public",
                "www", "web", "site", "portal", "dashboard", "panel", "control", "cp",
                "cpanel", "phpmyadmin", "pma", "mysql", "cms", "wp", "wordpress", "wp-admin",
                "wp-content", "wp-includes", "drupal", "joomla", "forum", "blog", "news",
                "help", "support", "contact", "about", "faq", "search", "mobile", "m",
                "mail", "email", "webmail", "calendar", "chat", "social", "media", "gallery",
                "video", "audio", "temp", "tmp", "test", "dev", "development", "staging",
                "prod", "production", "old", "new", "backup", "archive", "cache", "session"
            };
        }

        private List<string> GetBuiltInCommonFiles()
        {
            return new List<string>
            {
                "index.html", "index.htm", "index.php", "index.asp", "index.aspx", "index.jsp",
                "default.html", "default.htm", "default.php", "home.html", "main.html",
                "robots.txt", "sitemap.xml", "favicon.ico", "web.config", ".htaccess",
                "config.php", "database.php", "connection.php", "auth.php", "login.php",
                "admin.php", "upload.php", "file.php", "search.php", "api.php", "test.php",
                "phpinfo.php", "info.php", "readme.txt", "changelog.txt", "license.txt",
                "install.txt", "setup.php", "installer.php", "backup.php", "export.php",
                "import.php", "update.php", "version.php", "status.php", "health.php"
            };
        }

        private List<string> GetBuiltInBackupFiles()
        {
            return new List<string>
            {
                "backup.zip", "backup.tar.gz", "backup.sql", "database.sql", "db.sql",
                "site.zip", "website.zip", "www.zip", "backup.bak", "config.bak",
                "index.php.bak", "admin.php.bak", "login.php.bak", "database.php.bak",
                "backup.old", "site.old", "www.old", "config.old", "database.old",
                "backup.tmp", "temp.zip", "tmp.zip", "backup.7z", "backup.rar"
            };
        }

        private List<string> GetBuiltInConfigFiles()
        {
            return new List<string>
            {
                ".env", ".env.local", ".env.production", "config.json", "config.xml",
                "config.yml", "config.yaml", "settings.json", "settings.xml", "app.config",
                "web.config", "database.json", "db.json", "connection.json", "auth.json",
                "api.json", "server.json", "application.json", "environment.json"
            };
        }

        private List<string> GetBuiltInSubdomains()
        {
            return new List<string>
            {
                "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "mx",
                "admin", "api", "app", "blog", "cdn", "dev", "forum", "help", "mobile",
                "shop", "ssl", "support", "test", "vpn", "wiki", "portal", "secure",
                "login", "auth", "dashboard", "panel", "control", "manage", "cpanel"
            };
        }

        public List<WordlistInfo> GetAvailableWordlists()
        {
            return _wordlistInfos.Values.Where(info => info.IsAvailable).ToList();
        }

        public WordlistInfo? GetWordlistInfo(WordlistType type)
        {
            return _wordlistInfos.TryGetValue(type, out var info) ? info : null;
        }

        public void ClearCache()
        {
            _cachedWordlists.Clear();
            Logger.Information("Wordlist cache cleared");
        }

        public async Task RefreshWordlistInfoAsync()
        {
            await Task.Run(() =>
            {
                _cachedWordlists.Clear();
                InitializeWordlistInfos();
            });
            Logger.Information("Wordlist information refreshed");
        }

        public async Task<Dictionary<WordlistType, List<string>>> GetMultipleWordlistsAsync(params WordlistType[] types)
        {
            var result = new Dictionary<WordlistType, List<string>>();
            
            foreach (var type in types)
            {
                result[type] = await GetWordlistAsync(type);
            }
            
            return result;
        }

        public async Task<List<string>> GetCombinedWordlistAsync(params WordlistType[] types)
        {
            var combinedList = new List<string>();
            
            foreach (var type in types)
            {
                var wordlist = await GetWordlistAsync(type);
                combinedList.AddRange(wordlist);
            }
            
            return combinedList.Distinct().ToList();
        }
    }
}
