using System;
using System.IO;
using Serilog;
using Serilog.Events; // For LogEventLevel
using Serilog.Configuration; // For LoggerSinkConfiguration
// Serilog.Sinks.File is not directly used for types, but WriteTo.File() extension method comes from Serilog.Sinks.File package.

namespace RedOps.Utils
{
    public static class Logger
    {
        private static ILogger? _serilogInstance;

        public static ILogger SerilogInstance
        {
            get
            {
                if (_serilogInstance == null)
                {
                    Initialize();
                }
                return _serilogInstance!;
            }
        }

        public static void Initialize()
        {
            if (_serilogInstance != null) return;

            string defaultLogLevelStr = ConfigHelper.GetDefaultLogLevel() ?? "Information";
            LogEventLevel minimumLevel = Enum.TryParse(defaultLogLevelStr, true, out LogEventLevel parsedLevel) 
                                         ? parsedLevel 
                                         : LogEventLevel.Information;

            _serilogInstance = new LoggerConfiguration() // Uses Serilog.LoggerConfiguration
                .MinimumLevel.Is(minimumLevel)
                .WriteTo.Console(
                    outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}",
                    restrictedToMinimumLevel: minimumLevel) // Apply minimum level to console
                .WriteTo.File("redops.log",
                    rollingInterval: RollingInterval.Day, // Uses Serilog.RollingInterval
                    outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} {Level:u3}] {Message:lj}{NewLine}{Exception}",
                    restrictedToMinimumLevel: LogEventLevel.Verbose) // Log everything to file
                .CreateLogger();

            SerilogInstance.Information("--- RedOps Logger Initialized (Serilog) ---");
        }

        // Wrapper methods (optional, but can be convenient)
        public static void Verbose(string messageTemplate, params object?[]? propertyValues) => SerilogInstance.Verbose(messageTemplate, propertyValues);
        public static void Debug(string messageTemplate, params object?[]? propertyValues) => SerilogInstance.Debug(messageTemplate, propertyValues);
        public static void Information(string messageTemplate, params object?[]? propertyValues) => SerilogInstance.Information(messageTemplate, propertyValues);
        public static void Warning(string messageTemplate, params object?[]? propertyValues) => SerilogInstance.Warning(messageTemplate, propertyValues);
        public static void Error(string messageTemplate, params object?[]? propertyValues) => SerilogInstance.Error(messageTemplate, propertyValues);
        public static void Error(Exception ex, string messageTemplate, params object?[]? propertyValues) => SerilogInstance.Error(ex, messageTemplate, propertyValues);
        public static void Fatal(string messageTemplate, params object?[]? propertyValues) => SerilogInstance.Fatal(messageTemplate, propertyValues);
        public static void Fatal(Exception ex, string messageTemplate, params object?[]? propertyValues) => SerilogInstance.Fatal(ex, messageTemplate, propertyValues);

        public static void Info(string message, Exception? ex = null)
        {
            if (ex != null)
            {
                SerilogInstance.Information(ex, message);
            }
            else
            {
                SerilogInstance.Information(message);
            }
        }
    }
}
