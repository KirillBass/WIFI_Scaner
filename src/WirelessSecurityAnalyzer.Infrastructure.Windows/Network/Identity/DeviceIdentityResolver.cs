using Serilog;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

public sealed class DeviceIdentityResolver(IEnumerable<IDeviceNameResolver> nameResolvers,
    IEnumerable<INetworkIdentityResolver> networkResolvers, MacVendorResolver vendors,
    DeviceIdentityCache cache, DeviceIdentityOptions options, ILogger logger, TimeProvider? timeProvider = null) : IDeviceIdentityResolver
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    // Shared across all devices and all per-host methods, including manually requested cycles.
    private readonly SemaphoreSlim _hostGate = new(options.MaxConcurrency, options.MaxConcurrency);
    private readonly SemaphoreSlim _cycleGate = new(1, 1);

    public void InvalidateCache(LocalNetworkInfo network, IReadOnlyList<NetworkDevice> devices) => cache.Invalidate(network, devices);

    public async Task EnrichAsync(LocalNetworkInfo network, IReadOnlyList<NetworkDevice> devices,
        Action<DeviceIdentityUpdate> publish, CancellationToken cancellationToken = default)
    {
        options.Validate();
        await _cycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var pending = new List<NetworkDevice>(); var retries = new List<NetworkDevice>(); var identities = new Dictionary<NetworkDevice, DeviceIdentity>(); var gate = new object();
            var completedNames = new HashSet<NetworkDevice>(); var networkCompleted = false;
            // An IP can be reassigned while the previous MAC remains in Unknown history.
            // Query only the most recently confirmed occupant; keep older names as history.
            var occupants = devices.Where(d => d.State != DeviceState.Offline).GroupBy(d => d.IpAddress)
                .ToDictionary(g => g.Key, g => g.OrderByDescending(d => d.State == DeviceState.Online)
                    .ThenByDescending(d => d.LastSeen).ThenByDescending(d => d.FirstSeen).First());
            var gatewayMac = devices.FirstOrDefault(d => Equals(d.IpAddress, network.Gateway) && d.State == DeviceState.Online &&
                (d.Evidence & DeviceEvidence.NeighborEntry) != 0)?.MacAddress;
            foreach (var device in devices.Where(d => d.State != DeviceState.Offline && network.Subnet.ContainsHost(d.IpAddress)))
            {
                if (cache.TryGet(network, device, out var cached, gatewayMac: gatewayMac)) { publish(new(device, cached, IsComplete: true)); continue; }
                var initial = device.Identity ?? new DeviceIdentity
                { Hostname = device.Hostname, HostnameSource = device.IsLocalMachine ? DeviceNameSource.LocalComputer : DeviceNameSource.ReverseDns };
                var retry = cache.TryGet(network, device, out var previous, allowExpired: true, gatewayMac: gatewayMac);
                if (retry) initial = DeviceIdentityMerger.Merge(previous, initial);
                else if (cache.TryGetSameLan(network, device, gatewayMac, out var shared)) initial = DeviceIdentityMerger.Merge(shared, initial);
                var identity = DeviceIdentityMerger.Merge(initial, vendors.Resolve(device) with { LastUpdated = _clock.GetUtcNow() });
                if (!ReferenceEquals(occupants[device.IpAddress], device) ||
                    device.State == DeviceState.Unknown && _clock.GetUtcNow() - device.LastSeen > options.RecentDeviceWindow)
                { publish(new(device, identity, IsComplete: true)); continue; }
                identities[device] = identity;
                (retry ? retries : pending).Add(device); publish(new(device, identity));
            }
            pending.AddRange(retries);
            if (pending.Count == 0) return;
            logger.Information("Resolving local device identities: {Count} cache misses", pending.Count);
            void Accept(DeviceIdentityUpdate update)
            {
                cancellationToken.ThrowIfCancellationRequested();
                lock (gate)
                {
                    if (!identities.TryGetValue(update.Device, out var old)) return;
                    var merged = DeviceIdentityMerger.Merge(old, update.Identity with { LastUpdated = _clock.GetUtcNow(),
                        NameObservedAt = update.Identity.NameSource != DeviceNameSource.None ? _clock.GetUtcNow() : null,
                        NameObservedVia = update.Identity.NameSource != DeviceNameSource.None ? network.Name : null });
                    if (merged == old) return;
                    identities[update.Device] = merged;
                    logger.Debug("Device identity updated from {Source}", update.Identity.NameSource);
                    publish(new(update.Device, merged));
                }
            }
            async Task Names()
            {
                await Parallel.ForEachAsync(pending, new ParallelOptions
                { MaxDegreeOfParallelism = options.MaxConcurrency, CancellationToken = cancellationToken }, async (device, token) =>
                {
                    foreach (var resolver in nameResolvers)
                    {
                        await _hostGate.WaitAsync(token).ConfigureAwait(false);
                        try
                        {
                            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
                            deadline.CancelAfter(options.QueryTimeout);
                            var identity = await resolver.ResolveAsync(network, device, deadline.Token).ConfigureAwait(false);
                            if (identity is not null) Accept(new(device, identity));
                        }
                        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                        catch (Exception exception) { logger.Debug(exception, "Optional device name resolver {Source} unavailable", resolver.Source); }
                        finally { _hostGate.Release(); }
                    }
                    // Preserve completed work even if a later scan cancels a large batch.
                    lock (gate)
                    {
                        completedNames.Add(device);
                        if (networkCompleted)
                        {
                            cache.Store(network, device, identities[device], gatewayMac);
                            publish(new(device, identities[device], IsComplete: true));
                        }
                    }
                }).ConfigureAwait(false);
            }
            async Task Network(INetworkIdentityResolver resolver)
            {
                try { await resolver.ResolveAsync(network, pending.AsReadOnly(), Accept, cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch (Exception exception) { logger.Debug(exception, "Optional network identity resolver {Source} unavailable", resolver.Source); }
            }
            async Task Networks()
            {
                await Task.WhenAll(networkResolvers.Select(Network)).ConfigureAwait(false);
                lock (gate)
                {
                    networkCompleted = true;
                    foreach (var device in completedNames)
                    {
                        cache.Store(network, device, identities[device], gatewayMac);
                        publish(new(device, identities[device], IsComplete: true));
                    }
                }
            }
            await Task.WhenAll(Networks(), Names()).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var device in pending) cache.Store(network, device, identities[device], gatewayMac);
        }
        finally { _cycleGate.Release(); }
    }
}
