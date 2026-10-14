using WirelessSecurityAnalyzer.App.Controls;
using WirelessSecurityAnalyzer.App.ViewModels;

namespace WirelessSecurityAnalyzer.App.Views;

public partial class SignalView : PlotViewBase
{
    public SignalView()
    {
        InitializeComponent();
    }

    protected override ScottPlot.Avalonia.AvaPlot Chart => SignalPlot;
    protected override string DataProperty => nameof(SignalViewModel.Samples);

    protected override void ConfigureAxes()
    {
        var plot = SignalPlot.Plot;
        plot.Axes.DateTimeTicksBottom();
        plot.XLabel("Время");
        ((ScottPlot.TickGenerators.DateTimeAutomatic)plot.Axes.Bottom.TickGenerator).LabelFormatter =
            utc => DateTime.SpecifyKind(utc, DateTimeKind.Utc).ToLocalTime().ToString("HH:mm:ss");
    }

    protected override void UpdatePlot()
    {
        var samples = (DataContext as SignalViewModel)?.Samples;
        var plot = SignalPlot.Plot;
        plot.Clear();
        var now = DateTime.UtcNow.ToOADate();
        var left = now - TimeSpan.FromSeconds(15).TotalDays;
        var right = now + TimeSpan.FromSeconds(15).TotalDays;
        double minimum = -100, maximum = -20;
        if (samples is { Count: > 0 })
        {
            var xs = samples.Select(sample => sample.Timestamp.UtcDateTime.ToOADate()).ToArray();
            var ys = samples.Select(sample => (double)sample.RssiDbm).ToArray();
            var series = plot.Add.Scatter(xs, ys);
            series.Color = ThemeColor("SignalBrush");
            series.LineWidth = 2;
            series.MarkerSize = 4;
            var padding = xs[^1] == xs[0] ? TimeSpan.FromSeconds(15).TotalDays :
                Math.Max(TimeSpan.FromSeconds(2).TotalDays, (xs[^1] - xs[0]) * .03);
            left = xs[0] - padding;
            right = xs[^1] + padding;
            minimum = Math.Min(minimum, ys.Min() - 5);
            maximum = Math.Max(maximum, ys.Max() + 5);
        }
        plot.Axes.SetLimitsX(left, right);
        plot.Axes.SetLimitsY(minimum, maximum);
        SignalPlot.Refresh();
    }
}
