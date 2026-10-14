namespace WirelessSecurityAnalyzer.Core.Models;

public enum WifiConnectionState { Disconnected, Connecting, Authenticating, Connected, ObtainingAddress, Ready, Failed, Disconnecting }
public enum WifiConnectionFailure { None, UnsupportedSecurity, InvalidPassword, InvalidSsid, NoAdapter, RadioOff,
    ServiceUnavailable, AccessDenied, AuthenticationFailed, NetworkUnavailable, Timeout, AddressTimeout, Cancelled, Busy, Unexpected }

// Deliberately not a record: its generated ToString must never expose credentials.
public sealed class WifiConnectionRequest
{
    public required string Ssid { get; init; }
    public string? Bssid { get; init; }
    public IReadOnlyList<byte>? SsidBytes { get; init; }
    public required WifiSecurityInfo SecurityInfo { get; init; }
    public string? Password { get; set; }
    public required Guid InterfaceId { get; init; }
    public void ClearCredentials() => Password = null;
    public override string ToString() => $"Wi-Fi connection request ({InterfaceId}); credentials omitted";
}

public sealed record WifiConnectionInfo(Guid InterfaceId, string InterfaceName, string Ssid, string Bssid,
    WifiSecurityInfo Security, IReadOnlyList<byte>? SsidBytes = null);

public sealed record WifiConnectionResult(bool Success, WifiConnectionState State, WifiConnectionFailure Failure,
    string FailureReason, string Ssid, string? Bssid, Guid InterfaceId, DateTimeOffset? ConnectedAt);
