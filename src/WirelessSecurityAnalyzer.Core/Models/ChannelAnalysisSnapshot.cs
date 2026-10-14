namespace WirelessSecurityAnalyzer.Core.Models;

public enum ChannelLoadLevel { Free, Low, Medium, High, Critical }

public sealed record ChannelAnalysisResult(WifiBand Band, int Channel, double CenterFrequencyMhz,
    int DirectBssCount, int InfluencingBssCount, double RawScore, double LoadScorePercent,
    ChannelLoadLevel Level, bool IsRecommended, bool UsesEstimatedWidth);

/// <summary>Immutable analysis and display geometry; no measured airtime or spectral mask.</summary>
public sealed record ChannelAnalysisSnapshot(WifiBand Band, IReadOnlyList<ChannelAnalysisResult> Channels,
    int? RecommendedChannel, DateTimeOffset AnalyzedAt, string ModelDescription, bool IsApproximate,
    IReadOnlyList<ChannelSpectrumCurve> Spectrum, int IgnoredBssCount, int DuplicateBssCount,
    int InvalidCandidateCount);

/// <summary>A visual estimated-width contour, with its peak at the actual BSS frequency/RSSI.</summary>
public sealed record ChannelSpectrumCurve(WifiAccessPoint AccessPoint, double WidthMhz,
    bool UsesEstimatedWidth, IReadOnlyList<double> FrequenciesMhz, IReadOnlyList<double> RssiDbm);
