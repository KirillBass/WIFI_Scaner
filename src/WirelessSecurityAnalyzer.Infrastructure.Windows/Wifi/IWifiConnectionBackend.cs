using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Wifi;

/// <summary>Native boundary; a fake implementation can drive connection/session tests without hardware.</summary>
public interface IWifiConnectionBackend : IDisposable
{
    Task<WifiConnectionInfo> ConnectAsync(Guid interfaceId, string profileXml, byte[] ssid,
        TimeSpan timeout, IProgress<WifiConnectionState> progress, CancellationToken cancellationToken);
    Task DisconnectAsync(Guid interfaceId, TimeSpan timeout, CancellationToken cancellationToken);
    Task<WifiConnectionInfo?> GetCurrentAsync(Guid? interfaceId, CancellationToken cancellationToken);
}
