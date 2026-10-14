using System.Net;
using Serilog;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

/// <summary>One-shot legacy-unicast mDNS queries (RFC 6762 5.1/6.7), batched per network.</summary>
public sealed class MdnsNameResolver(IIdentityDatagramClient datagrams, DeviceIdentityOptions options, ILogger logger) : INetworkIdentityResolver
{
    public DeviceNameSource Source => DeviceNameSource.Mdns;
    private const string Enumeration = "_services._dns-sd._udp.local";
    private static readonly string[] Services = [Enumeration, "_workstation._tcp.local", "_device-info._tcp.local",
        "_airplay._tcp.local", "_googlecast._tcp.local", "_ipp._tcp.local", "_http._tcp.local"];

    public async Task ResolveAsync(LocalNetworkInfo network, IReadOnlyList<NetworkDevice> devices,
        Action<DeviceIdentityUpdate> publish, CancellationToken cancellationToken)
    {
        var remote = devices.Where(d => !d.IsLocalMachine).ToArray();
        if (remote.Length == 0) return;
        var id = DnsPacket.NewId();
        var records = new Dictionary<(string Name, ushort Type, string Value), DnsRecord>();
        var questions = Services.Select(s => new DnsQuestion(s, 12))
            .Concat(remote.Select(d => new DnsQuestion(DnsPacket.Reverse(d.IpAddress), 12))).ToArray();
        var queries = questions.Chunk(16).Select(q => DnsPacket.Query(id, q)).ToArray();
        void Receive(IdentityDatagram packet)
        {
            try
            {
                var message = DnsPacket.Parse(packet.Data);
                if (message.Id != id || !message.IsAnswer) return;
                foreach (var record in message.Records.Where(r => r.Class == 1))
                {
                    var key = (record.Name.ToLowerInvariant(), record.Type, record.Target ?? record.Address?.ToString() ?? "");
                    if (record.Ttl == 0) records.Remove(key);
                    else if (records.Count < 4096 || records.ContainsKey(key)) records[key] = record;
                }
                foreach (var update in Match(records.Values.ToArray(), remote)) publish(update);
            }
            catch (FormatException exception) { logger.Debug(exception, "Malformed mDNS response"); }
        }
        var endpoint = new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353);
        await datagrams.QueryAsync(network, endpoint, queries, options.MulticastWindow, Receive, cancellationToken).ConfigureAwait(false);
        // RFC 6763: type PTR -> instance PTR -> SRV/TXT -> host A. These facts
        // may arrive in separate packets; a single follow-up misses the last step.
        var asked = questions.Select(q => (q.Name.ToLowerInvariant(), q.Type)).ToHashSet();
        var remaining = 64;
        for (var round = 0; round < 3 && remaining > 0; round++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var follow = MissingQuestions(records.Values.ToArray())
                .Where(q => !records.Values.Any(r => r.Type == q.Type && r.Name.Equals(q.Name, StringComparison.OrdinalIgnoreCase)))
                .Where(q => asked.Add((q.Name.ToLowerInvariant(), q.Type))).Take(remaining).ToArray();
            if (follow.Length == 0) break;
            remaining -= follow.Length;
            await datagrams.QueryAsync(network, endpoint, follow.Chunk(16).Select(q => DnsPacket.Query(id, q)).ToArray(),
                options.QueryTimeout, Receive, cancellationToken).ConfigureAwait(false);
        }
    }

    private static IEnumerable<DnsQuestion> MissingQuestions(IReadOnlyList<DnsRecord> records)
    {
        // Prioritize host addresses so a large service catalogue cannot starve matching.
        foreach (var record in records.Where(r => r.Type == 33 && r.Target?.EndsWith(".local", StringComparison.OrdinalIgnoreCase) == true))
            yield return new(record.Target!, 1);
        foreach (var record in records.Where(r => r.Type == 12 && r.Target is not null))
        {
            var labels = record.Target!.Split('.');
            var service = labels.Length >= 3 && labels[^3].StartsWith('_') &&
                (labels[^2].Equals("_tcp", StringComparison.OrdinalIgnoreCase) || labels[^2].Equals("_udp", StringComparison.OrdinalIgnoreCase)) &&
                labels[^1].Equals("local", StringComparison.OrdinalIgnoreCase);
            if (!service) continue;
            if (record.Name.Equals(Enumeration, StringComparison.OrdinalIgnoreCase) && labels.Length == 3)
                yield return new(record.Target, 12);
            else if (labels.Length >= 4)
            {
                yield return new(record.Target, 33);
                yield return new(record.Target, 16);
            }
        }
    }

    internal static IReadOnlyList<DeviceIdentityUpdate> Match(IReadOnlyList<DnsRecord> records, IReadOnlyList<NetworkDevice> devices)
    {
        var updates = new List<DeviceIdentityUpdate>();
        var addresses = records.Where(r => r.Type == 1 && r.Address is not null && r.Name.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
            .GroupBy(r => r.Address!).ToDictionary(g => g.Key, g => g.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).First().Name);
        var pointers = records.Where(r => r.Type == 12 && r.Target?.EndsWith(".local", StringComparison.OrdinalIgnoreCase) == true)
            .GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First().Target, StringComparer.OrdinalIgnoreCase);
        var services = records.Where(r => r.Type == 33 && r.Target is not null).GroupBy(r => r.Target!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).First(), StringComparer.OrdinalIgnoreCase);
        var texts = records.Where(r => r.Type == 16).GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        foreach (var device in devices)
        {
            var reverse = DnsPacket.Reverse(device.IpAddress);
            var hostname = addresses.GetValueOrDefault(device.IpAddress) ?? pointers.GetValueOrDefault(reverse);
            if (hostname is null) continue;
            var srv = services.GetValueOrDefault(hostname);
            var txt = srv is null ? null : texts.GetValueOrDefault(srv.Name);
            string? Value(params string[] keys) => keys.Select(k => txt?.Text.GetValueOrDefault(k)).Select(DeviceIdentityMerger.Clean).FirstOrDefault(v => v is not null);
            // DNS-SD instance labels are published names, not a guess from a manufacturer.
            var instance = srv?.Name.IndexOf("._", StringComparison.Ordinal) is >= 1 and var separator ? srv.Name[..separator] : null;
            var friendly = Value("fn", "ty", "friendlyName") ?? DeviceIdentityMerger.Clean(instance);
            updates.Add(new(device, new()
            {
                Hostname = hostname, HostnameSource = DeviceNameSource.Mdns,
                FriendlyName = friendly, FriendlyNameSource = friendly is null ? DeviceNameSource.None : DeviceNameSource.Mdns,
                ModelName = Value("md", "model", "modelName"), DeviceType = Value("deviceType"), MetadataSource = DeviceNameSource.Mdns
            }));
        }
        return updates;
    }
}

/// <summary>RFC 6762 5.5/6.7: a direct, read-only PTR query to an already discovered host.
/// Complements multicast discovery when the access point does not deliver multicast.</summary>
public sealed class MdnsUnicastNameResolver(IIdentityDatagramClient datagrams, DeviceIdentityOptions options, ILogger logger) : IDeviceNameResolver
{
    public DeviceNameSource Source => DeviceNameSource.Mdns;
    public async Task<DeviceIdentity?> ResolveAsync(LocalNetworkInfo network, NetworkDevice device, CancellationToken cancellationToken)
    {
        if (device.IsLocalMachine || !network.Subnet.ContainsHost(device.IpAddress)) return null;
        var id = DnsPacket.NewId(); var reverse = DnsPacket.Reverse(device.IpAddress); DeviceIdentity? identity = null;
        await datagrams.QueryAsync(network, new(device.IpAddress, 5353), [DnsPacket.Query(id, [new(reverse, 12)])],
            options.QueryTimeout, packet =>
            {
                if (!packet.Sender.Address.Equals(device.IpAddress) || packet.Sender.Port != 5353) return;
                try
                {
                    var response = DnsPacket.Parse(packet.Data);
                    if (response.Id != id || !response.IsAnswer || !response.Questions.Any(q => q.Type == 12 && q.Name.Equals(reverse, StringComparison.OrdinalIgnoreCase))) return;
                    var valid = response.Records.Where(r => r.Class == 1 && r.Ttl > 0).ToArray();
                    var update = MdnsNameResolver.Match(valid, [device]).FirstOrDefault();
                    if (update is not null) identity = DeviceIdentityMerger.Merge(identity, update.Identity);
                }
                catch (FormatException exception) { logger.Debug(exception, "Malformed direct mDNS response"); }
            }, cancellationToken, isComplete: () => identity is { NameSource: not DeviceNameSource.None }).ConfigureAwait(false);
        return identity;
    }
}
