using System.Text.RegularExpressions;
using WirelessSecurityAnalyzer.Core.NetworkAudit;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NetworkAudit;

public sealed partial class SshServiceDetector : IServiceDetector
{
    public string Name => "SSH";
    public bool IsPassive => true;
    public bool IsPreferred(int port) => port == 22;
    public Task<ServiceIdentity?> DetectAsync(ServiceProbe probe, CancellationToken cancellationToken)
    {
        foreach (var line in ProbeIo.BannerText(probe.Banner).Split('\n'))
        {
            var banner = line.TrimEnd('\r');
            if (banner.Length > 253 || banner.Contains('\0')) continue;
            var match = SshBanner().Match(banner);
            if (!match.Success) continue;
            var software = match.Groups[1].Value; string? product = null, version = null;
            foreach (var name in new[] { "OpenSSH", "dropbear", "libssh" })
                if (software.StartsWith(name + "_", StringComparison.OrdinalIgnoreCase))
                { product = name == "dropbear" ? "Dropbear" : name; version = software[(name.Length + 1)..]; break; }
            return Task.FromResult<ServiceIdentity?>(new("SSH", product, version, ServiceConfidence.High, ProbeIo.Clean(banner, 255)));
        }
        return Task.FromResult<ServiceIdentity?>(null);
    }
    [GeneratedRegex(@"^SSH-(?:2\.0|1\.99)-([!-~]+)(?: .*)?$", RegexOptions.CultureInvariant)]
    private static partial Regex SshBanner();
}
public sealed partial class FtpServiceDetector : IServiceDetector
{
    public string Name => "FTP";
    public bool IsPassive => true;
    public bool IsPreferred(int port) => port == 21;
    public Task<ServiceIdentity?> DetectAsync(ServiceProbe probe, CancellationToken cancellationToken)
    {
        var text = ProbeIo.BannerText(probe.Banner);
        var line = text.Split('\n').Select(l => l.TrimEnd('\r')).FirstOrDefault(l => l.StartsWith("220 ", StringComparison.Ordinal));
        if (line is null || text.Contains("SMTP", StringComparison.OrdinalIgnoreCase)) return Task.FromResult<ServiceIdentity?>(null);
        var known = FtpProduct().Match(line);
        // A generic 220 greeting can belong to SMTP. Require FTP evidence or its standard port.
        if (!known.Success && !text.Contains("FTP", StringComparison.OrdinalIgnoreCase) && probe.Port != 21)
            return Task.FromResult<ServiceIdentity?>(null);
        return Task.FromResult<ServiceIdentity?>(new("FTP", known.Success ? known.Groups[1].Value : null,
            known.Groups[2].Success ? known.Groups[2].Value : null,
            known.Success || text.Contains("FTP", StringComparison.OrdinalIgnoreCase) ? ServiceConfidence.High : ServiceConfidence.Medium,
            ProbeIo.Clean(line, 512), "Получено приветствие 220. Вход не выполнялся."));
    }
    [GeneratedRegex(@"\b(vsFTPd|ProFTPD|FileZilla|Pure-FTPd|Microsoft FTP Service)(?:[ /]+([0-9][0-9A-Za-z.\-_]*))?", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex FtpProduct();
}
public sealed class GenericBannerServiceDetector : IServiceDetector
{
    public string Name => "Banner";
    public bool IsPassive => true;
    public bool IsPreferred(int port) => false;
    public Task<ServiceIdentity?> DetectAsync(ServiceProbe probe, CancellationToken cancellationToken)
    {
        var line = ProbeIo.BannerText(probe.Banner).Split('\n').Select(l => l.TrimEnd('\r'))
            .FirstOrDefault(l => l.StartsWith("220 ", StringComparison.Ordinal) && l.Contains("SMTP", StringComparison.OrdinalIgnoreCase));
        return Task.FromResult<ServiceIdentity?>(line is null ? null :
            new("SMTP", null, null, ServiceConfidence.High, ProbeIo.Clean(line, 512), "Пассивное приветствие; команды SMTP не отправлялись."));
    }
}
