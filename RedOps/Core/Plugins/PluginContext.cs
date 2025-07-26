using Serilog;
using System;

namespace RedOps.Core.Plugins
{
    public class PluginContext
    {
        public Serilog.ILogger Logger { get; }

        public PluginContext(Serilog.ILogger logger)
        {
            Logger = logger ?? throw new System.ArgumentNullException(nameof(logger));
        }

        // Potentially add other shared services or context information here later
        // For example:
        // public IConfiguration AppConfiguration { get; }
        // public HttpClient HttpClient { get; }
    }
}
