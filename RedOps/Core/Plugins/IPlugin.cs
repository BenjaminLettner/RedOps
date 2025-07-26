using System;
using System.Threading.Tasks;
using RedOps.Core.Plugins;

namespace RedOps.Core.Plugins
{
    public interface IPlugin
    {
        string Name { get; }
        string Description { get; }
        PluginCategory Category { get; }
        Task ExecuteAsync(PluginContext context);
    }
}
