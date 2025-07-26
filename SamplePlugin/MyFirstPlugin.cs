using System;
using System.Threading.Tasks;
using RedOps.Core.Plugins; // For IPlugin, PluginCategory, PluginContext
// using Serilog;             // Fully qualifying Serilog.ILogger below

namespace RedOps.Plugins.Sample // This namespace is fine, doesn't have to match file path
{
    public class MyFirstPlugin : IPlugin
    {
        public string Name => "My First Sample Plugin";
        public string Description => "A simple plugin that demonstrates the plugin architecture.";
        public PluginCategory Category => PluginCategory.Reconnaissance; // Example category

        public async System.Threading.Tasks.Task ExecuteAsync(PluginContext context)
        {
            Serilog.ILogger logger = context.Logger; // Fully qualified
            
            logger.Information("[{PluginName}] >>> Hello from MyFirstPlugin! Executing now...", Name);

            // Simulate some plugin work
            await System.Threading.Tasks.Task.Delay(1500); // Wait for 1.5 seconds

            logger.Information("[{PluginName}] >>> Finished execution of MyFirstPlugin.", Name);
        }
    }
}
