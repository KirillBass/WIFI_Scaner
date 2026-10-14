using System.Net.NetworkInformation;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

/// <summary>Bounded per-interface cache. Positive remote names may seed another interface only
/// after the subnet, gateway IP, freshly observed gateway MAC and target MAC agree.</summary>
public sealed class DeviceIdentityCache(DeviceIdentityOptions options, TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _entries = [];
    public void Clear() { lock (_gate) _entries.Clear(); }

    public void ResetSession()
    {
        lock (_gate)
            foreach (var pair in _entries.ToArray())
                if (pair.Value.LanKey is not null && !pair.Value.IsLocal &&
                    pair.Value.Identity.NameSource != DeviceNameSource.None &&
                    pair.Value.Identity.NameObservedAt + options.CacheTtl > _clock.GetUtcNow())
                    _entries[pair.Key] = pair.Value with { Expires = DateTimeOffset.MinValue, RequireGatewayProof = true };
                else _entries.Remove(pair.Key);
    }

    public bool TryGet(LocalNetworkInfo network, NetworkDevice device, out DeviceIdentity identity,
        bool allowExpired = false, PhysicalAddress? gatewayMac = null)
    {
        lock (_gate)
        {
            var lan = LanKey(network, gatewayMac);
            if (_entries.TryGetValue(Key(network, device), out var entry) &&
                (!entry.RequireGatewayProof || lan is not null && lan == entry.LanKey) &&
                (lan is null || entry.LanKey is null || lan == entry.LanKey) &&
                (allowExpired || _clock.GetUtcNow() < entry.Expires))
            { identity = entry.Identity; return true; }
        }
        identity = new DeviceIdentity(); return false;
    }

    public bool TryGetSameLan(LocalNetworkInfo network, NetworkDevice device, PhysicalAddress? gatewayMac, out DeviceIdentity identity)
    {
        var lan = LanKey(network, gatewayMac);
        lock (_gate)
        {
            if (lan is not null && !device.IsLocalMachine && DeviceStateTracker.ValidMac(device.MacAddress))
            {
                var entry = _entries.Values.Where(e => !e.IsLocal && e.LanKey == lan && e.Mac == device.MacAddress!.ToString() &&
                    e.Identity.NameSource != DeviceNameSource.None && e.Identity.NameObservedAt + options.CacheTtl > _clock.GetUtcNow())
                    .OrderByDescending(e => e.Identity.NameObservedAt).FirstOrDefault();
                if (entry is not null) { identity = entry.Identity; return true; }
            }
        }
        identity = new DeviceIdentity(); return false;
    }

    public void Store(LocalNetworkInfo network, NetworkDevice device, DeviceIdentity identity, PhysicalAddress? gatewayMac = null)
    {
        lock (_gate)
        {
            if (_entries.Count >= 4096)
                foreach (var expiredKey in _entries.OrderBy(p => p.Value.Expires).Take(512).Select(p => p.Key).ToArray()) _entries.Remove(expiredKey);
            var key = Key(network, device); var lan = LanKey(network, gatewayMac);
            var previous = _entries.GetValueOrDefault(key);
            if (lan is not null && previous?.LanKey is not null && lan != previous.LanKey) previous = null;
            if (identity.NameSource != DeviceNameSource.None && identity.NameObservedAt is null)
                identity = identity with { NameObservedAt = _clock.GetUtcNow(), NameObservedVia = network.Name };
            var merged = DeviceIdentityMerger.Merge(previous?.Identity, identity);
            var ttl = merged.NameSource == DeviceNameSource.None ? options.UnresolvedCacheTtl : options.CacheTtl;
            _entries[key] = new(merged, _clock.GetUtcNow() + ttl, lan, device.MacAddress?.ToString(), device.IsLocalMachine);
        }
    }

    public void Invalidate(LocalNetworkInfo network, IReadOnlyList<NetworkDevice> devices)
    {
        lock (_gate)
            foreach (var device in devices)
            {
                var key = Key(network, device);
                if (_entries.TryGetValue(key, out var entry)) _entries[key] = entry with { Expires = DateTimeOffset.MinValue };
            }
    }
    private static string? LanKey(LocalNetworkInfo network, PhysicalAddress? gatewayMac) =>
        network.Gateway is { } gateway && network.Subnet.ContainsHost(gateway) && DeviceStateTracker.ValidMac(gatewayMac)
            ? $"{network.NetworkAddress}/{network.PrefixLength}|{gateway}|{gatewayMac}" : null;
    private static string Key(LocalNetworkInfo network, NetworkDevice device) =>
        $"{network.InterfaceId.ToUpperInvariant()}|{network.InterfaceIndex}|{network.NetworkAddress}/{network.PrefixLength}|{network.Gateway}|" +
        (DeviceStateTracker.ValidMac(device.MacAddress) ? $"MAC:{device.MacAddress}" : $"IP:{device.IpAddress}");
    private sealed record Entry(DeviceIdentity Identity, DateTimeOffset Expires, string? LanKey, string? Mac, bool IsLocal)
    { public bool RequireGatewayProof { get; init; } }
}
