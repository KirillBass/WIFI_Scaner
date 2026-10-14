using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Core.Interfaces;

public interface IDeviceMonitorService
{
    DeviceMonitorSnapshot Current { get; }
    event EventHandler<DeviceMonitorSnapshot>? Updated;
    Task DiscoverOnceAsync(LocalNetworkInfo network, DeviceDiscoveryOptions options, CancellationToken cancellationToken = default);
    Task StartAsync(LocalNetworkInfo network, DeviceDiscoveryOptions options, TimeSpan? interval = null,
        CancellationToken cancellationToken = default);
    Task RefreshIdentitiesAsync(LocalNetworkInfo network, CancellationToken cancellationToken = default) => Task.CompletedTask;
    Task StopAsync();
    Task ResetAsync() => StopAsync();
}
