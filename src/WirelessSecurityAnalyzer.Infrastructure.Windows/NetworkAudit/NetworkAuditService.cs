using System.Diagnostics;
using Serilog;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.NetworkAudit;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NetworkAudit;

/// <summary>Owns a single immutable target snapshot and a bounded, lazy work queue.</summary>
public sealed class NetworkAuditService : INetworkAuditService, IDisposable
{
    private readonly INetworkSessionService _sessions;
    private readonly IDeviceMonitorService _devices;
    private readonly ILocalNetworkService _networks;
    private readonly IPortScanner _scanner;
    private readonly IServiceDetectionEngine _engine;
    private readonly NetworkAuditOptions _options;
    private readonly ILogger _logger;
    private readonly object _gate = new();
    private readonly Dictionary<(System.Net.IPAddress, int), AuditRow> _rows = [];
    private AuditSnapshot _current = AuditSnapshot.Empty;
    private CancellationTokenSource? _cancellation;
    private Task _run = Task.CompletedTask;
    private LocalNetworkInfo? _network;
    private AuditStage _stopStage = AuditStage.Cancelled;
    private bool _disposed;
    private long _version;
    private long _checked, _open, _closed, _timedOut, _unavailable, _errors, _identified, _total;
    private int _hostsCompleted, _hostsTotal;
    private readonly Stopwatch _watch = new();
    private long _lastPublishMs;
    public NetworkAuditService(INetworkSessionService sessions, IDeviceMonitorService devices, ILocalNetworkService networks,
        IPortScanner scanner, IServiceDetectionEngine engine, NetworkAuditOptions options, ILogger logger)
    {
        _sessions = sessions; _devices = devices; _networks = networks; _scanner = scanner; _engine = engine;
        _options = options; _logger = logger; _sessions.Updated += SessionChanged;
    }
    public AuditSnapshot Current { get { lock (_gate) return _current; } }
    public event EventHandler<AuditSnapshot>? Updated;
    public Task RunAsync(AuditRequest request, CancellationToken cancellationToken = default)
    {
        AuditSnapshot started; Task run;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_run.IsCompleted) throw new InvalidOperationException("Аудит уже выполняется.");
            _options.Validate(request);
            var ports = PortScanProfiles.GetPorts(request.Profile, request.CustomPorts);
            var session = _sessions.Current;
            var targets = AuditTargets.Create(session, _devices.Current, request.IncludeLocal);
            _network = session.Network!;
            _cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _stopStage = AuditStage.Cancelled; _rows.Clear();
            _checked = _open = _closed = _timedOut = _unavailable = _errors = _identified = 0;
            _hostsCompleted = 0; _hostsTotal = targets.Count; _total = (long)targets.Count * ports.Count;
            _watch.Restart(); _lastPublishMs = 0;
            _current = _current with { AuditId = Guid.NewGuid(), SessionId = session.SessionId, Stage = AuditStage.Preparing, IsRunning = true };
            started = SnapshotLocked("Подготовка аудита текущей сети.");
            run = _run = RunCoreAsync(session, targets, ports, request, _cancellation);
        }
        Notify(started); return run;
    }
    private async Task RunCoreAsync(NetworkSession session, IReadOnlyList<AuditTarget> targets, IReadOnlyList<int> ports,
        AuditRequest request, CancellationTokenSource cancellation)
    {
        await Task.Yield();
        var token = cancellation.Token; Task? watcher = null;
        _logger.Information("Network audit {AuditId} start: subnet {Subnet}, targets {Targets}, profile {Profile}, ports {Ports}, timeout {TimeoutMs}ms, concurrency {Concurrency}",
            Current.AuditId, session.Subnet, targets.Count, request.Profile, ports.Count, request.ConnectTimeoutMs, request.Concurrency);
        try
        {
            if (!await _networks.IsCurrentAsync(session.Network!, token).ConfigureAwait(false))
            { MarkNetworkChanged(); token.ThrowIfCancellationRequested(); }
            CheckSession(session);
            lock (_gate) _current = _current with { Stage = AuditStage.Scanning };
            Publish(force: true);
            watcher = WatchNetworkAsync(session, token);
            var remaining = targets.ToDictionary(t => t.Address, _ => ports.Count);
            IEnumerable<(AuditTarget Target, int Port)> Work()
            {
                foreach (var port in ports)
                    foreach (var target in targets)
                    { token.ThrowIfCancellationRequested(); yield return (target, port); }
            }
            await Parallel.ForEachAsync(Work(), new ParallelOptions { MaxDegreeOfParallelism = request.Concurrency, CancellationToken = token },
                async (work, ct) =>
                {
                    CheckSession(session); ct.ThrowIfCancellationRequested();
                    await using var connection = await _scanner.ConnectAsync(session.Network!, work.Target.Address, work.Port,
                        TimeSpan.FromMilliseconds(request.ConnectTimeoutMs), ct).ConfigureAwait(false);
                    ct.ThrowIfCancellationRequested();
                    if (connection.Result.State == PortState.Error)
                        _logger.Debug("TCP connect {Address}:{Port}: {Error}", work.Target.Address, work.Port, connection.Result.Error);
                    lock (_gate)
                    {
                        _checked++;
                        if (_checked == _total) _current = _current with { Stage = AuditStage.Detecting };
                        switch (connection.Result.State)
                        {
                            case PortState.Open:
                                _open++;
                                _rows[(work.Target.Address, work.Port)] = new(session.SessionId, work.Target, work.Port,
                                    ServiceIdentity.Unknown, DateTimeOffset.Now, request.Profile); break;
                            case PortState.Closed: _closed++; break;
                            case PortState.Timeout: _timedOut++; break;
                            case PortState.Unavailable: _unavailable++; break;
                            default: _errors++; break;
                        }
                    }
                    Publish(force: connection.Result.State == PortState.Open && Current.Progress.Open == 0);
                    if (connection.Result.State == PortState.Open)
                    {
                        ServiceIdentity identity;
                        try { identity = await _engine.DetectAsync(session.Network!, connection, ct).ConfigureAwait(false); }
                        catch (OperationCanceledException) { throw; }
                        catch (Exception ex)
                        {
                            _logger.Debug("Service detection {Address}:{Port}: {ErrorType}", work.Target.Address, work.Port, ex.GetType().Name);
                            identity = ServiceIdentity.Unknown;
                            lock (_gate) _errors++;
                        }
                        ct.ThrowIfCancellationRequested(); CheckSession(session);
                        lock (_gate)
                        {
                            if (identity.Confidence != ServiceConfidence.Unknown) _identified++;
                            _rows[(work.Target.Address, work.Port)] = new(session.SessionId, work.Target, work.Port,
                                identity, DateTimeOffset.Now, request.Profile);
                        }
                        Publish();
                    }
                    lock (_gate) if (--remaining[work.Target.Address] == 0) _hostsCompleted++;
                    Publish();
                }).ConfigureAwait(false);
            token.ThrowIfCancellationRequested(); CheckSession(session);
            lock (_gate) _current = _current with { Stage = AuditStage.Completed };
        }
        catch (OperationCanceledException)
        { lock (_gate) _current = _current with { Stage = _stopStage }; }
        catch (Exception ex)
        {
            _logger.Warning("Network audit failed: {ErrorType}", ex.GetType().Name);
            lock (_gate) _current = _current with { Stage = AuditStage.Failed, Message = "Не удалось выполнить аудит. Обновите устройства и повторите." };
        }
        finally
        {
            await cancellation.CancelAsync().ConfigureAwait(false);
            if (watcher is not null) await watcher.ConfigureAwait(false);
            AuditSnapshot finished;
            lock (_gate)
            {
                _watch.Stop();
                if (_stopStage == AuditStage.NetworkChanged || !Matches(session, _sessions.Current))
                { _rows.Clear(); _current = _current with { Stage = AuditStage.NetworkChanged }; }
                _current = _current with { IsRunning = false };
                finished = SnapshotLocked(StageMessage());
                _cancellation = null; cancellation.Dispose();
            }
            Notify(finished);
            _logger.Information("Network audit {AuditId} end: {Stage}, checked {Checked}/{Total}, open {Open}, identified {Identified}, elapsed {Elapsed}",
                finished.AuditId, finished.Stage, finished.Progress.Checked, finished.Progress.Total, finished.Progress.Open,
                finished.Progress.Identified, finished.Progress.Elapsed);
        }
    }
    private async Task WatchNetworkAsync(NetworkSession session, CancellationToken token)
    {
        try
        {
            while (true)
            {
                await Task.Delay(1000, token).ConfigureAwait(false);
                if (!Matches(session, _sessions.Current) || !await _networks.IsCurrentAsync(session.Network!, token).ConfigureAwait(false))
                { MarkNetworkChanged(); return; }
                Publish();
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _logger.Debug("Audit context check: {ErrorType}", ex.GetType().Name); MarkNetworkChanged(); }
    }
    private static bool Matches(NetworkSession expected, NetworkSession current) => current.IsReadyForAudit &&
        expected.SessionId == current.SessionId && current.Network?.HasSameContext(expected.Network!) == true;
    private void CheckSession(NetworkSession expected)
    { if (!Matches(expected, _sessions.Current)) { MarkNetworkChanged(); throw new OperationCanceledException(); } }
    private void SessionChanged(object? sender, NetworkSession session)
    {
        bool changed;
        lock (_gate) changed = _current.SessionId != Guid.Empty &&
            (!session.IsReadyForAudit || session.SessionId != _current.SessionId || _network?.HasSameContext(session.Network!) != true);
        if (changed) MarkNetworkChanged();
    }
    private void MarkNetworkChanged()
    {
        AuditSnapshot snapshot;
        lock (_gate)
        {
            _stopStage = AuditStage.NetworkChanged; _rows.Clear();
            _current = _current with { Stage = AuditStage.NetworkChanged };
            _cancellation?.Cancel();
            snapshot = SnapshotLocked("Аудит остановлен: сеть изменилась. Обновите устройства новой сессии.");
        }
        Notify(snapshot);
    }
    private string StageMessage() => _current.Stage switch
    {
        AuditStage.Scanning => "Проверка TCP-портов и определение служб.",
        AuditStage.Detecting => "Определение служб на найденных открытых портах.",
        AuditStage.Completed => _open == 0 ? "Аудит завершён: открытых TCP-портов не найдено." : "Аудит завершён.",
        AuditStage.NetworkChanged => "Аудит остановлен: сеть изменилась. Обновите устройства новой сессии.",
        AuditStage.Cancelled => "Аудит остановлен пользователем. Частичные результаты сохранены.",
        AuditStage.Failed => _current.Message,
        _ => _current.Message
    };
    private AuditSnapshot SnapshotLocked(string message)
    {
        _lastPublishMs = _watch.ElapsedMilliseconds;
        return _current = _current with { Version = ++_version, Rows = Array.AsReadOnly(_rows.Values.ToArray()), Message = message,
            Progress = new(_hostsCompleted, _hostsTotal, _checked, _total, _open, _closed, _timedOut, _unavailable, _errors, _identified, _watch.Elapsed) };
    }
    private void Publish(bool force = false)
    {
        AuditSnapshot snapshot;
        lock (_gate)
        {
            if (_stopStage == AuditStage.NetworkChanged || (!force && _watch.ElapsedMilliseconds - _lastPublishMs < 150)) return;
            snapshot = SnapshotLocked(StageMessage());
        }
        Notify(snapshot);
    }
    private void Notify(AuditSnapshot snapshot)
    {
        foreach (EventHandler<AuditSnapshot> handler in Updated?.GetInvocationList() ?? [])
            try { handler(this, snapshot); } catch (Exception ex) { _logger.Debug("Audit subscriber failed: {ErrorType}", ex.GetType().Name); }
    }
    public Task StopAsync()
    { lock (_gate) { _cancellation?.Cancel(); return _run; } }
    public void Dispose()
    {
        lock (_gate) { if (_disposed) return; _disposed = true; _cancellation?.Cancel(); }
        _sessions.Updated -= SessionChanged;
    }
}
