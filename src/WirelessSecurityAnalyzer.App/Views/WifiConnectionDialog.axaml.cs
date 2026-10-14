using Avalonia.Controls;
using WirelessSecurityAnalyzer.App.ViewModels;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.App.Views;

public partial class WifiConnectionDialog : Window
{
    private bool _closing;
    private bool _closed;
    private Task _initialization = Task.CompletedTask;
    public WifiConnectionDialog()
    {
        InitializeComponent();
        Opened += (_, _) =>
        {
            if (DataContext is not WifiConnectionDialogViewModel vm) return;
            vm.CloseRequested += OnCloseRequested;
            _initialization = vm.InitializeAsync();
        };
        CancelButton.Click += async (_, _) =>
        {
            if (DataContext is WifiConnectionDialogViewModel { IsBusy: true } vm)
            { vm.ConnectCommand.Cancel(); await (vm.ConnectCommand.ExecutionTask ?? Task.CompletedTask); }
            else Close();
        };
        Closing += async (_, e) =>
        {
            if (_closed || DataContext is not WifiConnectionDialogViewModel vm) return;
            e.Cancel = true;
            if (_closing) return;
            _closing = true;
            vm.CloseRequested -= OnCloseRequested;
            try { await vm.StopAsync(); await _initialization; }
            finally { _closed = true; Close(vm.Result); }
        };
    }
    private void OnCloseRequested(WifiConnectionResult? result) => Close(result);
}
