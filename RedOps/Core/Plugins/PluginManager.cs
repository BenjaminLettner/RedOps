using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
// using Serilog; // Fully qualifying Serilog.ILogger below
// using Serilog.Events; // Not directly used if ILogger is fully qualified and no other Event types are used.

namespace RedOps.Core.Plugins
{
    public class PluginManager
    {
        private readonly List<IPlugin> _plugins = new();
        private readonly Serilog.ILogger _logger; // Fully qualified

        public PluginManager(Serilog.ILogger logger) // Fully qualified
        {
            _logger = logger ?? throw new System.ArgumentNullException(nameof(logger)); // Fully qualified
        }

        public void LoadPlugins(string pluginDirectory = "Plugins")
        {
            string absolutePluginDir = System.IO.Path.Combine(System.AppContext.BaseDirectory, pluginDirectory);
            _logger.Information("Looking for plugins in: {PluginDirectory}", absolutePluginDir);

            if (!System.IO.Directory.Exists(absolutePluginDir))
            {
                _logger.Warning("Plugin directory '{PluginDirectory}' not found. Creating it.", absolutePluginDir);
                try
                {
                    System.IO.Directory.CreateDirectory(absolutePluginDir);
                    _logger.Information("Successfully created plugin directory: {PluginDirectory}", absolutePluginDir);
                }
                catch (System.Exception ex)
                {
                    _logger.Error(ex, "Failed to create plugin directory: {PluginDirectory}", absolutePluginDir);
                    return; // Cannot proceed if directory cannot be created
                }
            }

            try
            {
                string[] pluginFiles = System.IO.Directory.GetFiles(absolutePluginDir, "*.dll");
                _logger.Information("Found {PluginCount} DLL(s) in plugin directory '{PluginDirectory}'.", pluginFiles.Length, absolutePluginDir);

                foreach (string pluginFile in pluginFiles)
                {
                    try
                    {
                        System.Reflection.Assembly pluginAssembly = System.Reflection.Assembly.LoadFrom(pluginFile);
                        foreach (System.Type type in pluginAssembly.GetTypes())
                        {
                            if (typeof(IPlugin).IsAssignableFrom(type) && !type.IsInterface && !type.IsAbstract)
                            {
                                IPlugin? pluginInstance = System.Activator.CreateInstance(type) as IPlugin;
                                if (pluginInstance != null)
                                {
                                    _plugins.Add(pluginInstance);
                                    _logger.Information("Successfully loaded plugin: {PluginName} from {FileName}", pluginInstance.Name, System.IO.Path.GetFileName(pluginFile));
                                }
                                else
                                {
                                    _logger.Warning("Could not create instance of plugin type '{TypeName}' from {FileName}.", type.FullName, System.IO.Path.GetFileName(pluginFile));
                                }
                            }
                        }
                    }
                    catch (System.Reflection.ReflectionTypeLoadException ex)
                    {
                        _logger.Error(ex, "Error loading types from assembly {FileName}. Loader exceptions:", System.IO.Path.GetFileName(pluginFile));
                        if (ex.LoaderExceptions != null)
                        {
                            foreach (var loaderEx in ex.LoaderExceptions)
                            {
                                _logger.Error(loaderEx, "LoaderException: {LoaderExceptionMessage}", loaderEx?.Message);
                            }
                        }
                    }
                    catch (System.Exception ex)
                    {
                        _logger.Error(ex, "Error loading plugin assembly: {FileName}", System.IO.Path.GetFileName(pluginFile));
                    }
                }
            }
            catch (System.Exception ex)
            {
                _logger.Error(ex, "Error accessing plugin directory or files: {PluginDirectory}", absolutePluginDir);
            }
            _logger.Information("Finished loading plugins. Total plugins loaded: {PluginCount}", _plugins.Count);
        }

        public System.Collections.Generic.IEnumerable<IPlugin> GetPlugins()
        {
            return _plugins;
        }

        public System.Collections.Generic.IEnumerable<IPlugin> GetPluginsByCategory(PluginCategory category)
        {
            return _plugins.Where(p => p.Category == category);
        }
    }
}
