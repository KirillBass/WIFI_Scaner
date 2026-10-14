using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WirelessSecurityAnalyzer.Core.Interfaces;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed record NavigationItem(string Title, ViewModelBase Page);

public sealed partial class MainWindowViewModel : ViewModelBase
{
    private readonly AccessPointsViewModel _accessPoints;
    private readonly SignalViewModel _signal;
    private readonly ChannelsViewModel _channels;
    private readonly DevicesViewModel _devices;
    private readonly IWifiConnectionService? _connections;
    private readonly NetworkAuditViewModel? _audit;
    public AccessPointsViewModel AccessPoints => _accessPoints;
    public NetworkSessionViewModel? Session { get; }
    public MainWindowViewModel(DashboardViewModel dashboard, AccessPointsViewModel accessPoints,
        ChannelsViewModel channels, SignalViewModel signal, DevicesViewModel devices, SettingsViewModel settings,
        NetworkAuditViewModel? audit = null, NetworkSessionViewModel? session = null, IWifiConnectionService? connections = null)
    {
        _accessPoints = accessPoints;
        _signal = signal;
        _channels = channels;
        _devices = devices;
        _audit = audit; Session = session; _connections = connections;
        var navigation = new List<NavigationItem> { new("Обзор", dashboard), new("Эфир", accessPoints), new("Каналы", channels),
            new("Сигнал", signal), new("Устройства", devices) };
        if (audit is not null) navigation.Add(new("Сетевой аудит", audit));
        navigation.Add(new("Настройки", settings));
        Navigation = navigation.AsReadOnly();
        _selectedNavigation = Navigation[1];
    }

    public IReadOnlyList<NavigationItem> Navigation { get; }
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CurrentPage))]
    private NavigationItem? _selectedNavigation;
    public ViewModelBase CurrentPage => (SelectedNavigation ?? Navigation[1]).Page;
    public void OpenNetworkAudit()
    {
        Session?.Refresh();
        if (_audit is not null && Session?.IsReady == true) SelectedNavigation = Navigation.First(n => ReferenceEquals(n.Page, _audit));
    }

    partial void OnSelectedNavigationChanged(NavigationItem? value)
    {
        // Keep the default page selected when the tab strip receives an empty selection.
        if (value is null) SelectedNavigation = Navigation[1];
    }

    [RelayCommand]
    private Task InitializeAsync() => Task.WhenAll(_accessPoints.InitializeAsync(), _devices.InitializeAsync(),
        _connections?.InitializeAsync() ?? Task.CompletedTask);
    public void Stop()
    {
        _accessPoints.Stop();
        _signal.Stop();
        _channels.Stop();
        _devices.Stop();
        _audit?.Dispose();
    }

    public async Task StopAsync()
    {
        Stop();
        await Task.WhenAll(_accessPoints.StopAsync(), _signal.StopAsync(), _channels.StopAsync(), _devices.StopAsync(),
            _connections?.StopAsync() ?? Task.CompletedTask,
            InitializeCommand.ExecutionTask ?? Task.CompletedTask);
    }
}
