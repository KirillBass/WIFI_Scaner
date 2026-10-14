using System.Collections.ObjectModel;
using System.ComponentModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;
using WirelessSecurityAnalyzer.Core.Common;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed partial class WifiConnectionDialogViewModel : ViewModelBase
{
    private readonly WifiAccessPoint _accessPoint;
    private readonly IWifiAdapterService _adapters;
    private readonly IWifiConnectionService _connections;
    private readonly CancellationTokenSource _lifetime = new();
    public WifiConnectionDialogViewModel(WifiAccessPoint accessPoint, IWifiAdapterService adapters,
        IWifiConnectionService connections, NetworkSessionViewModel session)
    {
        _accessPoint = accessPoint; _adapters = adapters; _connections = connections;
        Session = session;
        Session.PropertyChanged += OnSessionChanged;
    }
    public NetworkSessionViewModel Session { get; }
    public string Ssid => new AccessPointRowViewModel(_accessPoint).Ssid;
    public string Bssid => _accessPoint.Bssid;
    public string Security => WifiDisplayFormatter.Security(_accessPoint.Security);
    public bool RequiresPassword => _accessPoint.Security.Protocol != WifiSecurityProtocol.Open;
    public bool CanEdit => !IsBusy && !IsLoading;
    public bool HasError => ErrorMessage.Length > 0;
    public ObservableCollection<WifiAdapter> Adapters { get; } = [];
    public WifiConnectionResult? Result { get; private set; }
    public event Action<WifiConnectionResult?>? CloseRequested;
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(ConnectCommand))] private WifiAdapter? _selectedAdapter;
    [ObservableProperty] private string _password = string.Empty;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(CanEdit)), NotifyCanExecuteChangedFor(nameof(ConnectCommand))] private bool _isBusy;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(CanEdit)), NotifyCanExecuteChangedFor(nameof(ConnectCommand))] private bool _isLoading;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(HasError))] private string _errorMessage = string.Empty;

    public async Task InitializeAsync()
    {
        IsLoading = true;
        try
        {
            var adapters = await _adapters.GetAdaptersAsync(_lifetime.Token);
            foreach (var adapter in adapters.Where(a => a.State != WifiAdapterState.NotReady)) Adapters.Add(adapter);
            SelectedAdapter = Adapters.FirstOrDefault(a => a.Id == Session.Current.InterfaceId) ?? Adapters.FirstOrDefault();
            if (SelectedAdapter is null) ErrorMessage = WifiConnectionPolicy.Message(WifiConnectionFailure.NoAdapter);
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (WifiException exception) { ErrorMessage = WifiErrorPresenter.GetMessage(exception); }
        catch { ErrorMessage = WifiConnectionPolicy.Message(WifiConnectionFailure.NoAdapter); }
        finally { IsLoading = false; }
    }
    private bool CanConnect() => CanEdit && SelectedAdapter is not null && WifiConnectionPolicy.IsSupported(_accessPoint.Security);
    [RelayCommand(CanExecute = nameof(CanConnect), IncludeCancelCommand = true)]
    private async Task ConnectAsync(CancellationToken cancellationToken)
    {
        if (SelectedAdapter is not { } adapter) return;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        var request = new WifiConnectionRequest { Ssid = _accessPoint.Ssid, Bssid = _accessPoint.Bssid,
            SsidBytes = _accessPoint.SsidBytes, SecurityInfo = _accessPoint.Security, Password = RequiresPassword ? Password : null,
            InterfaceId = adapter.Id };
        Password = string.Empty;
        IsBusy = true; ErrorMessage = string.Empty; Result = null;
        try
        {
            Result = await _connections.ConnectAsync(request, linked.Token);
            ErrorMessage = Result.FailureReason;
        }
        catch (OperationCanceledException) { ErrorMessage = WifiConnectionPolicy.Message(WifiConnectionFailure.Cancelled); }
        catch { ErrorMessage = WifiConnectionPolicy.Message(WifiConnectionFailure.Unexpected); }
        finally { request.ClearCredentials(); Password = string.Empty; IsBusy = false; }
        TryCompletePendingAddress();
        if (Result is { Success: true, State: WifiConnectionState.Ready }) CloseRequested?.Invoke(Result);
    }
    private void OnSessionChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(NetworkSessionViewModel.Current)) return;
        if (TryCompletePendingAddress()) CloseRequested?.Invoke(Result);
    }
    private bool TryCompletePendingAddress()
    {
        if (Result?.Failure != WifiConnectionFailure.AddressTimeout) return false;
        var current = Session.Current;
        if (current.IsReadyForAudit && current.InterfaceId == SelectedAdapter?.Id && current.Ssid == _accessPoint.Ssid)
        {
            Result = new(true, WifiConnectionState.Ready, WifiConnectionFailure.None, string.Empty, current.Ssid,
                current.Bssid, current.InterfaceId!.Value, current.ConnectedAt);
            return true;
        }
        return false;
    }
    public async Task StopAsync()
    {
        Password = string.Empty;
        _lifetime.Cancel(); ConnectCommand.Cancel();
        Session.PropertyChanged -= OnSessionChanged;
        if (ConnectCommand.ExecutionTask is { } task) await task;
    }
}
