using System.ComponentModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WirelessSecurityAnalyzer.Core.Interfaces;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed partial class NetworkAuditViewModel : ViewModelBase, IDisposable
{
    private readonly IWifiConnectionService _connections;
    public NetworkAuditViewModel(NetworkSessionViewModel session, DevicesViewModel devices, IWifiConnectionService connections)
    {
        Session = session; Devices = devices; _connections = connections;
        Session.PropertyChanged += OnStateChanged; Devices.PropertyChanged += OnStateChanged;
    }
    public NetworkSessionViewModel Session { get; }
    public DevicesViewModel Devices { get; }
    public int DeviceCount => Session.Current.Network is { } network && Devices.SelectedNetwork?.HasSameContext(network) == true
        ? Devices.KnownCount : 0;
    private bool CanRefreshDevices() => Session.IsReady && !IsBusy && !Devices.IsBusy && !Devices.IsMonitoring;
    private bool CanDisconnect() => Session.IsConnected && !Session.IsConnecting && !IsBusy;
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(RefreshDevicesCommand), nameof(DisconnectCommand))] private bool _isBusy;
    [ObservableProperty] private string _errorMessage = string.Empty;
    [RelayCommand(CanExecute = nameof(CanRefreshDevices))]
    private async Task RefreshDevicesAsync()
    {
        if (!Session.IsReady || Session.Current.Network is not { } network || IsBusy) return;
        IsBusy = true; ErrorMessage = string.Empty;
        try
        {
            Devices.UseSessionNetwork(network);
            if (Devices.ScanCommand.CanExecute(null)) await Devices.ScanCommand.ExecuteAsync(null);
        }
        finally { IsBusy = false; }
    }
    [RelayCommand(CanExecute = nameof(CanDisconnect))]
    private async Task DisconnectAsync()
    {
        if (!Session.IsConnected || IsBusy) return;
        IsBusy = true; ErrorMessage = string.Empty;
        try { ErrorMessage = (await _connections.DisconnectAsync()).FailureReason; }
        finally { IsBusy = false; }
    }
    private void OnStateChanged(object? sender, PropertyChangedEventArgs e)
    {
        OnPropertyChanged(nameof(DeviceCount));
        RefreshDevicesCommand.NotifyCanExecuteChanged(); DisconnectCommand.NotifyCanExecuteChanged();
    }
    public void Dispose() { Session.PropertyChanged -= OnStateChanged; Devices.PropertyChanged -= OnStateChanged; }
}
