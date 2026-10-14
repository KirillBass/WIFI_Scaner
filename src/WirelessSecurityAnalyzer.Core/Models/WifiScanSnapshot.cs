using WirelessSecurityAnalyzer.Core.Common;

namespace WirelessSecurityAnalyzer.Core.Models;

public sealed record WifiScanSnapshot(long Version, DateTimeOffset CompletedAt,
    IReadOnlyList<WifiAccessPoint> AccessPoints);

/// <summary>A failed attempt, ordered with successful snapshots; successful BSS data is preserved.</summary>
public sealed record WifiScanFailure(long Version, WifiException Error);
