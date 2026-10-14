using System.Runtime.InteropServices;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;

[StructLayout(LayoutKind.Sequential)]
internal struct WlanConnectionParameters
{
    public uint Mode;
    public IntPtr Profile;
    public IntPtr Ssid;
    public IntPtr DesiredBssidList;
    public Dot11BssType BssType;
    public uint Flags;
}

// Only the fixed notification header is copied. The trailing profile XML is never read.
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct WlanConnectionNotification
{
    public uint Mode;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string ProfileName;
    public Dot11Ssid Ssid;
    public Dot11BssType BssType;
    public int SecurityEnabled;
    public uint Reason;
    public uint Flags;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WlanAssociationAttributes
{
    public Dot11Ssid Ssid;
    public Dot11BssType BssType;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] public byte[] Bssid;
    public uint PhyType;
    public uint PhyIndex;
    public uint SignalQuality;
    public uint RxRate;
    public uint TxRate;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WlanSecurityAttributes
{
    public int SecurityEnabled;
    public int OneXEnabled;
    public uint Authentication;
    public uint Cipher;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct WlanConnectionAttributes
{
    public WifiAdapterState State;
    public uint Mode;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string ProfileName;
    public WlanAssociationAttributes Association;
    public WlanSecurityAttributes Security;
}
