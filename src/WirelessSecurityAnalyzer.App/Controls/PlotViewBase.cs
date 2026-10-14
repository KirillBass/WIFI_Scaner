using System.ComponentModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;
using ScottPlot.Avalonia;

namespace WirelessSecurityAnalyzer.App.Controls;

/// <summary>Shared plot theme, subscriptions and coalesced updates while a view is attached.</summary>
public abstract class PlotViewBase : UserControl
{
    private INotifyPropertyChanged? _viewModel;
    private bool _updateQueued;
    protected bool IsAttached { get; private set; }
    protected abstract AvaPlot Chart { get; }
    protected abstract string DataProperty { get; }
    protected abstract void ConfigureAxes();
    protected abstract void UpdatePlot();

    protected PlotViewBase() => DataContextChanged += (_, _) => { if (IsAttached) BindViewModel(); };

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        IsAttached = true;
        // ConfigureAxes may replace an axis, so apply the common theme afterwards.
        ConfigureAxes();
        var plot = Chart.Plot;
        plot.FigureBackground.Color = ThemeColor("CardBrush");
        plot.DataBackground.Color = ThemeColor("WindowBrush");
        plot.Axes.Color(ThemeColor("TextBrush"));
        plot.Grid.MajorLineColor = ThemeColor("BorderBrush");
        plot.YLabel("RSSI, dBm");
        BindViewModel();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        IsAttached = false;
        if (_viewModel is not null) _viewModel.PropertyChanged -= OnViewModelChanged;
        _viewModel = null;
        base.OnDetachedFromVisualTree(e);
    }

    private void BindViewModel()
    {
        if (_viewModel is not null) _viewModel.PropertyChanged -= OnViewModelChanged;
        _viewModel = DataContext as INotifyPropertyChanged;
        if (_viewModel is not null) _viewModel.PropertyChanged += OnViewModelChanged;
        QueuePlotUpdate();
    }

    private void OnViewModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (string.IsNullOrEmpty(e.PropertyName) || e.PropertyName == DataProperty) QueuePlotUpdate();
    }

    private void QueuePlotUpdate()
    {
        if (_updateQueued || !IsAttached) return;
        _updateQueued = true;
        Dispatcher.UIThread.Post(() =>
        {
            _updateQueued = false;
            if (IsAttached) UpdatePlot();
        }, DispatcherPriority.Background);
    }

    protected ScottPlot.Color ThemeColor(string key)
    {
        var brush = this.FindResource(key) as SolidColorBrush
            ?? throw new InvalidOperationException($"Missing theme brush: {key}");
        return ScottPlot.Color.FromHex($"#{brush.Color.R:X2}{brush.Color.G:X2}{brush.Color.B:X2}");
    }
}
