using Serilog;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Wifi;

public sealed class NativeWifiConnectionBackend(ILogger logger, MacVendorResolver vendors) : IWifiConnectionBackend
{
    private readonly Lazy<NativeWifiClient> _client = new(() => new NativeWifiClient(logger, vendors));
    public Task<WifiConnectionInfo> ConnectAsync(Guid interfaceId, string profileXml, byte[] ssid,
        TimeSpan timeout, IProgress<WifiConnectionState> progress, CancellationToken cancellationToken) => Task.Run(() =>
        {
            try { return _client.Value.ConnectAsync(interfaceId, profileXml, ssid, timeout, progress, cancellationToken); }
            finally { profileXml = null!; }
        }, cancellationToken);
    public Task DisconnectAsync(Guid interfaceId, TimeSpan timeout, CancellationToken cancellationToken) =>
        Task.Run(() => _client.Value.DisconnectAsync(interfaceId, timeout, cancellationToken), cancellationToken);
    public Task<WifiConnectionInfo?> GetCurrentAsync(Guid? interfaceId, CancellationToken cancellationToken) =>
        Task.Run(() => _client.Value.GetCurrentConnection(interfaceId), cancellationToken);
    public void Dispose() { if (_client.IsValueCreated) _client.Value.Dispose(); }
}
