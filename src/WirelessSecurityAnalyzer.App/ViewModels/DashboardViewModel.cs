namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed class DashboardViewModel(AccessPointsViewModel accessPoints, SignalViewModel signal,
    NetworkSessionViewModel? session = null) : ViewModelBase
{
    public AccessPointsViewModel AccessPoints { get; } = accessPoints;
    public SignalViewModel Signal { get; } = signal;
    public NetworkSessionViewModel? Session { get; } = session;
}
