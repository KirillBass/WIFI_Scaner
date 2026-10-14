using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Interfaces;

public interface IWifiConnectionService
{
    Task InitializeAsync(CancellationToken cancellationToken = default);
    Task<WifiConnectionResult> ConnectAsync(WifiConnectionRequest request, CancellationToken cancellationToken = default);
    Task<WifiConnectionResult> DisconnectAsync(CancellationToken cancellationToken = default);
    Task StopAsync();
}
