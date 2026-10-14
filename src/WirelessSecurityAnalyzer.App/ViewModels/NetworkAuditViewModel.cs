using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.NetworkAudit;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed partial class NetworkAuditViewModel : ViewModelBase, IDisposable
{
    private readonly IWifiConnectionService _connections;
    private readonly INetworkAuditService? _audit;
    private IReadOnlyList<AuditRow> _allRows = [];
    private long _version = -1;
    private bool _disposed;
    public NetworkAuditViewModel(NetworkSessionViewModel session, DevicesViewModel devices, IWifiConnectionService connections,
        INetworkAuditService? audit = null)
    {
        Session = session; Devices = devices; _connections = connections; _audit = audit;
        Session.PropertyChanged += OnStateChanged; Devices.PropertyChanged += OnStateChanged;
        if (_audit is not null) { _audit.Updated += OnAuditUpdated; Apply(_audit.Current); }
    }
    public NetworkSessionViewModel Session { get; }
    public DevicesViewModel Devices { get; }
    public int DeviceCount => Session.Current.Network is { } network && Devices.SelectedNetwork?.HasSameContext(network) == true ? Devices.KnownCount : 0;
    public IReadOnlyList<string> Profiles { get; } = ["Быстрый", "Стандартный (1–1024 + основные)", "Полный (1–65535)", "Пользовательский"];
    public IReadOnlyList<string> ServiceFilters { get; } = ["Все службы", "HTTP", "HTTPS", "SSH", "FTP", "RDP", "SMB", "SMTP", "TLS", "Unknown"];
    public ObservableCollection<AuditRow> Rows { get; } = [];
    public bool CanConfigure => !IsAuditing && !IsBusy;
    public bool HasError => ErrorMessage.Length > 0;
    public bool HasFilterError => FilterError.Length > 0;
    public bool IsCustomProfile => SelectedProfileIndex == 3;
    public bool IsFullProfile => SelectedProfileIndex == 2;
    public string SelectionDetails => SelectedRow?.Details ?? "Выберите строку, чтобы увидеть ответ протокола и сведения об определении службы.";
    public string ResultCount => $"Показано: {Rows.Count} из {_allRows.Count}";
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(RefreshDevicesCommand), nameof(DisconnectCommand), nameof(StartAuditCommand)), NotifyPropertyChangedFor(nameof(CanConfigure))]
    private bool _isBusy;
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(RefreshDevicesCommand), nameof(StartAuditCommand), nameof(StopAuditCommand)), NotifyPropertyChangedFor(nameof(CanConfigure))]
    private bool _isAuditing;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(HasError))] private string _errorMessage = string.Empty;
    [ObservableProperty] private string _statusText = "Аудит ещё не запускался.";
    [ObservableProperty] private string _progressText = string.Empty;
    [ObservableProperty] private double _progressPercent;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(IsCustomProfile), nameof(IsFullProfile))] private int _selectedProfileIndex;
    [ObservableProperty] private string _customPorts = "22,80,443,8000-8010";
    [ObservableProperty] private bool _includeLocal = true;
    [ObservableProperty] private int _concurrency = 64;
    [ObservableProperty] private int _connectTimeoutMs = 650;
    [ObservableProperty] private string _searchText = string.Empty;
    [ObservableProperty] private string _portFilter = string.Empty;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(HasFilterError))] private string _filterError = string.Empty;
    [ObservableProperty] private int _selectedServiceIndex;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(SelectionDetails))] private AuditRow? _selectedRow;
    partial void OnSearchTextChanged(string value) => FilterRows();
    partial void OnPortFilterChanged(string value) => FilterRows();
    partial void OnSelectedServiceIndexChanged(int value) => FilterRows();
    private bool CanRefreshDevices() => Session.IsReady && !IsBusy && !IsAuditing && !Devices.IsBusy && !Devices.IsMonitoring;
    private bool CanDisconnect() => Session.IsConnected && !Session.IsConnecting && !IsBusy;
    private bool CanStartAudit() => _audit is not null && Session.IsReady && !IsBusy && !IsAuditing && !Devices.IsBusy;
    private bool CanStopAudit() => IsAuditing;
    [RelayCommand(CanExecute = nameof(CanRefreshDevices))]
    private async Task RefreshDevicesAsync()
    {
        if (!CanRefreshDevices() || Session.Current.Network is not { } network) return;
        IsBusy = true; ErrorMessage = string.Empty;
        try { Devices.UseSessionNetwork(network); if (Devices.ScanCommand.CanExecute(null)) await Devices.ScanCommand.ExecuteAsync(null); }
        finally { IsBusy = false; }
    }
    [RelayCommand(CanExecute = nameof(CanDisconnect))]
    private async Task DisconnectAsync()
    {
        if (!CanDisconnect()) return;
        IsBusy = true; ErrorMessage = string.Empty;
        try { ErrorMessage = (await _connections.DisconnectAsync()).FailureReason; }
        finally { IsBusy = false; }
    }
    [RelayCommand(CanExecute = nameof(CanStartAudit))]
    private async Task StartAuditAsync()
    {
        if (!CanStartAudit() || _audit is null) return;
        ErrorMessage = string.Empty;
        try { await _audit.RunAsync(new((PortProfile)SelectedProfileIndex, CustomPorts, IncludeLocal, Concurrency, ConnectTimeoutMs)); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException) { ErrorMessage = ex.Message; }
        catch (OperationCanceledException) { }
    }
    [RelayCommand(CanExecute = nameof(CanStopAudit))]
    private Task StopAuditAsync() => StopAsync();
    private void OnAuditUpdated(object? sender, AuditSnapshot snapshot)
    {
        if (Dispatcher.UIThread.CheckAccess()) Apply(snapshot);
        else Dispatcher.UIThread.Post(() => Apply(snapshot));
    }
    private void Apply(AuditSnapshot snapshot, bool force = false)
    {
        if (_disposed || !force && snapshot.Version <= _version) return;
        _version = Math.Max(_version, snapshot.Version);
        IsAuditing = snapshot.IsRunning; StatusText = snapshot.Message;
        var p = snapshot.Progress;
        ProgressPercent = p.Total == 0 ? 0 : 100d * p.Checked / p.Total;
        ProgressText = $"Устройства: {p.HostsCompleted}/{p.HostsTotal} · TCP-порты: {p.Checked}/{p.Total} · Открыто: {p.Open} · Служб подтверждено: {p.Identified}\nЗакрыто: {p.Closed} · Таймаут: {p.TimedOut} · Недоступно: {p.Unavailable} · Ошибки: {p.Errors} · Время: {p.Elapsed:hh\\:mm\\:ss}";
        // A queued update from the previous session must not put old rows back into the UI.
        _allRows = snapshot.SessionId == Session.Current.SessionId && Session.IsReady ? snapshot.Rows : [];
        FilterRows();
    }
    private void FilterRows()
    {
        var selected = SelectedRow;
        var portText = PortFilter.Trim(); int port = 0;
        var valid = portText.Length == 0 || int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is >= 1 and <= 65535;
        FilterError = valid ? "" : "Фильтр порта: число от 1 до 65535.";
        var service = SelectedServiceIndex > 0 && SelectedServiceIndex < ServiceFilters.Count ? ServiceFilters[SelectedServiceIndex] : "";
        var search = SearchText.Trim();
        var rows = _allRows.Where(r => valid && (port == 0 || r.Port == port) &&
            (service.Length == 0 || (service == "SMB" ? r.Protocol.StartsWith("SMB", StringComparison.Ordinal) : r.Protocol == service)) &&
            (search.Length == 0 || $"{r.Address} {r.Name} {r.Protocol} {r.Product} {r.Version}".Contains(search, StringComparison.OrdinalIgnoreCase)))
            .OrderBy(r => Convert.ToHexString(r.Target.Address.GetAddressBytes()), StringComparer.Ordinal).ThenBy(r => r.Port).ToArray();
        SynchronizeRows(Rows, rows);
        SelectedRow = selected is null ? null : rows.FirstOrDefault(r => r.Target.Address.Equals(selected.Target.Address) && r.Port == selected.Port);
        OnPropertyChanged(nameof(ResultCount));
    }
    private void OnStateChanged(object? sender, PropertyChangedEventArgs e)
    {
        OnPropertyChanged(nameof(DeviceCount));
        if (ReferenceEquals(sender, Session) && _audit is not null) Apply(_audit.Current, force: true);
        RefreshDevicesCommand.NotifyCanExecuteChanged(); DisconnectCommand.NotifyCanExecuteChanged(); StartAuditCommand.NotifyCanExecuteChanged();
    }
    public Task StopAsync() => _audit?.StopAsync() ?? Task.CompletedTask;
    public void Dispose()
    {
        if (_disposed) return; _disposed = true;
        Session.PropertyChanged -= OnStateChanged; Devices.PropertyChanged -= OnStateChanged;
        if (_audit is not null) { _audit.Updated -= OnAuditUpdated; _ = _audit.StopAsync(); }
    }
}
