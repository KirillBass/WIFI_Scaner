namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Wifi;

public sealed record WifiConnectionOptions
{
    public TimeSpan ConnectionTimeout { get; init; } = TimeSpan.FromSeconds(25);
    public TimeSpan AddressTimeout { get; init; } = TimeSpan.FromSeconds(18);
    public TimeSpan DisconnectTimeout { get; init; } = TimeSpan.FromSeconds(8);
    public TimeSpan AddressPollInterval { get; init; } = TimeSpan.FromMilliseconds(500);
    public TimeSpan SessionRefreshInterval { get; init; } = TimeSpan.FromSeconds(2);
    public void Validate()
    {
        if (ConnectionTimeout <= TimeSpan.Zero || AddressTimeout <= TimeSpan.Zero || DisconnectTimeout <= TimeSpan.Zero ||
            AddressPollInterval <= TimeSpan.Zero || SessionRefreshInterval <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(WifiConnectionOptions));
    }
}

/// <summary>Shared by the existing scanner and connector; prevents WLAN operations overlapping.</summary>
public sealed class WifiOperationCoordinator
{
    internal SemaphoreSlim Gate { get; } = new(1, 1);
}
