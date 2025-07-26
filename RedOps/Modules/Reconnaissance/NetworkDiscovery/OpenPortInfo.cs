using System.Net;

namespace RedOps.Modules.Reconnaissance.NetworkDiscovery;

public class OpenPortInfo
{
    public IPAddress IpAddress { get; }
    public int Port { get; }
    public string Protocol { get; } // "TCP" or "UDP"
    public string? ServiceName { get; set; }
    public string? ServiceVersion { get; set; }
    public string? Banner { get; set; }

    public OpenPortInfo(IPAddress ipAddress, int port, string protocol)
    {
        IpAddress = ipAddress;
        Port = port;
        Protocol = protocol;
    }

    public override string ToString()
    {
        string serviceInfo = string.IsNullOrWhiteSpace(ServiceName) ? "Unknown Service" : $"{ServiceName} {ServiceVersion}".Trim();
        return $"{IpAddress}:{Port} ({Protocol}) - {serviceInfo}";
    }
}
