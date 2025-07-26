using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;
using System;
using System.IO;

namespace RedOps.Utils
{
    public static class ConfigHelper
    {
        private static IConfigurationRoot? _configuration;

        public static IConfigurationRoot Configuration
        {
            get
            {
                if (_configuration == null)
                {
                    _configuration = new ConfigurationBuilder()
                        .SetBasePath(AppContext.BaseDirectory)
                        .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                        .Build();
                }
                return _configuration;
            }
        }

        public static string? GetSetting(string key)
        {
            return Configuration[key];
        }

        public static string? GetSampleSetting()
        {
            return Configuration["SampleSetting"];
        }
        
        public static string? GetDefaultLogLevel()
        {
            return Configuration["Logging:LogLevel:Default"];
        }
    }
}
