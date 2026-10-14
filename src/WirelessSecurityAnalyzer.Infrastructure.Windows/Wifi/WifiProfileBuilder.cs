using System.Text;
using System.Xml;
using System.Xml.Linq;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Wifi;

public sealed class WifiConnectionException(WifiConnectionFailure failure, uint? nativeCode = null)
    : Exception(WifiConnectionPolicy.Message(failure))
{
    public WifiConnectionFailure Failure { get; } = failure;
    public uint? NativeCode { get; } = nativeCode;
}

public sealed class WifiProfileBuilder
{
    public byte[] GetSsidBytes(WifiConnectionRequest request)
    {
        var bytes = request.SsidBytes?.ToArray() ?? Encoding.UTF8.GetBytes(request.Ssid);
        if (string.IsNullOrEmpty(request.Ssid) || bytes.Length is < 1 or > 32 || bytes.All(b => b == 0))
            throw new WifiConnectionException(WifiConnectionFailure.InvalidSsid);
        return bytes;
    }

    public void Validate(WifiConnectionRequest request)
    {
        _ = GetSsidBytes(request);
        if (!WifiConnectionPolicy.IsSupported(request.SecurityInfo))
            throw new WifiConnectionException(WifiConnectionFailure.UnsupportedSecurity);
        if (request.SecurityInfo.Protocol == WifiSecurityProtocol.Open) return;
        var password = request.Password;
        var psk = password is { Length: 64 } && password.All(Uri.IsHexDigit);
        if (!psk && !(password is { Length: >= 8 and <= 63 } && password.All(c => c is >= ' ' and <= '~')))
            throw new WifiConnectionException(WifiConnectionFailure.InvalidPassword);
    }

    public string Build(WifiConnectionRequest request)
    {
        Validate(request);
        XNamespace ns = "http://www.microsoft.com/networking/WLAN/profile/v1";
        XElement Element(string name, object content) => new(ns + name, content);
        var ssid = Element("SSID", Element("hex", Convert.ToHexString(GetSsidBytes(request))));
        // Hex is authoritative and also supports byte SSIDs that are not valid XML text.
        try { XmlConvert.VerifyXmlChars(request.Ssid); ssid.Add(Element("name", request.Ssid)); }
        catch (XmlException) { }
        var open = request.SecurityInfo.Protocol == WifiSecurityProtocol.Open;
        var security = Element("security", Element("authEncryption", new[]
        {
            Element("authentication", open ? "open" : "WPA2PSK"),
            Element("encryption", open ? "none" : "AES"), Element("useOneX", "false")
        }));
        if (!open)
            security.Add(Element("sharedKey", new[]
            {
                Element("keyType", request.Password!.Length == 64 ? "networkKey" : "passPhrase"),
                Element("protected", "false"), Element("keyMaterial", request.Password)
            }));
        return new XElement(ns + "WLANProfile", Element("name", "WSA-" + Guid.NewGuid().ToString("N")),
            Element("SSIDConfig", ssid), Element("connectionType", "ESS"), Element("connectionMode", "manual"),
            Element("MSM", security)).ToString(SaveOptions.DisableFormatting);
    }
}
