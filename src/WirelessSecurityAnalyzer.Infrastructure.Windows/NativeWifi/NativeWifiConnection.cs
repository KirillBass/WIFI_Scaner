using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.Linq;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Wifi;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;

internal sealed partial class NativeWifiClient
{
    private readonly ConcurrentDictionary<Guid, ConnectionCompletion> _connections = new();
    private readonly ConcurrentDictionary<Guid, TaskCompletionSource> _disconnects = new();

    internal Task<WifiConnectionInfo> ConnectAsync(Guid interfaceId, string profileXml, byte[] ssid,
        TimeSpan timeout, IProgress<WifiConnectionState> progress, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var adapter = GetAdapters().FirstOrDefault(a => a.Id == interfaceId)
            ?? throw new WifiConnectionException(WifiConnectionFailure.NoAdapter);
        if (adapter.State == WifiAdapterState.NotReady) throw new WifiConnectionException(WifiConnectionFailure.RadioOff);
        RegisterNotifications();
        // Only the generated nonsecret profile name is retained during the asynchronous wait.
        XNamespace ns = "http://www.microsoft.com/networking/WLAN/profile/v1";
        var profileName = XElement.Parse(profileXml).Element(ns + "name")!.Value;
        var completion = new ConnectionCompletion(ssid, profileName, progress);
        if (!_connections.TryAdd(interfaceId, completion)) throw new WifiConnectionException(WifiConnectionFailure.Busy);
        var pointer = IntPtr.Zero;
        try
        {
            pointer = Marshal.StringToHGlobalUni(profileXml);
            var parameters = new WlanConnectionParameters
            { Mode = 1, Profile = pointer, BssType = Dot11BssType.Infrastructure };
            NativeWifiException.ThrowIfError(NativeWifiMethods.WlanConnect(_handle, interfaceId, ref parameters, IntPtr.Zero), "WlanConnect");
        }
        catch { _connections.TryRemove(interfaceId, out _); throw; }
        finally { if (pointer != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(pointer); }
        return WaitForConnectionAsync(interfaceId, adapter.Description, completion, timeout, token);
    }

    private async Task<WifiConnectionInfo> WaitForConnectionAsync(Guid id, string adapterName, ConnectionCompletion completion,
        TimeSpan timeout, CancellationToken token)
    {
        try
        {
            var reason = await completion.Task.WaitAsync(timeout, token).ConfigureAwait(false);
            if (reason != 0) throw ConnectionCompletion.Failure(reason, completion.LastReason);
            var connected = QueryConnection(id, adapterName);
            if (connected is null || !connected.SsidBytes!.SequenceEqual(completion.Ssid))
                throw new WifiConnectionException(WifiConnectionFailure.NetworkUnavailable);
            return connected;
        }
        catch (Exception exception) when (exception is OperationCanceledException or TimeoutException)
        {
            try { await DisconnectAsync(id, TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false); }
            catch { /* Best effort abort. Never replace cancellation with a cleanup exception. */ }
            if (exception is TimeoutException) throw new WifiConnectionException(WifiConnectionFailure.Timeout, completion.LastReason);
            throw;
        }
        finally { _connections.TryRemove(id, out _); }
    }

    internal async Task DisconnectAsync(Guid id, TimeSpan timeout, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        RegisterNotifications();
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_disconnects.TryAdd(id, completion)) throw new WifiConnectionException(WifiConnectionFailure.Busy);
        try
        {
            if (QueryConnection(id, string.Empty) is null && !_connections.ContainsKey(id)) return;
            var code = NativeWifiMethods.WlanDisconnect(_handle, id, IntPtr.Zero);
            if (code == 5023) return;
            NativeWifiException.ThrowIfError(code, "WlanDisconnect");
            try { await completion.Task.WaitAsync(timeout, token).ConfigureAwait(false); }
            catch (TimeoutException)
            {
                if (QueryConnection(id, string.Empty) is not null) throw new WifiConnectionException(WifiConnectionFailure.Timeout);
            }
        }
        finally { _disconnects.TryRemove(id, out _); }
    }

    internal WifiConnectionInfo? GetCurrentConnection(Guid? preferred)
    {
        var adapters = GetAdapters().OrderByDescending(a => a.Id == preferred);
        foreach (var adapter in adapters.Where(a => a.State == WifiAdapterState.Connected))
            if (QueryConnection(adapter.Id, adapter.Description) is { } connection) return connection;
        return null;
    }

    private WifiConnectionInfo? QueryConnection(Guid id, string adapterName)
    {
        var code = NativeWifiMethods.WlanQueryInterface(_handle, id, 7, IntPtr.Zero, out var size, out var memory, out _);
        try
        {
            if (code == 5023) return null; // ERROR_INVALID_STATE: no associated connection.
            NativeWifiException.ThrowIfError(code, "WlanQueryInterface");
            if (memory == IntPtr.Zero || size < Marshal.SizeOf<WlanConnectionAttributes>())
                throw new WifiConnectionException(WifiConnectionFailure.Unexpected);
            var value = Marshal.PtrToStructure<WlanConnectionAttributes>(memory);
            if (value.State != WifiAdapterState.Connected) return null;
            if (value.Association.Ssid.Length is 0 or > 32) throw new WifiConnectionException(WifiConnectionFailure.InvalidSsid);
            var bytes = value.Association.Ssid.Bytes[..(int)value.Association.Ssid.Length];
            var cipher = value.Security.Cipher switch { 0 => WifiCipherType.None, 1 => WifiCipherType.Wep40, 2 => WifiCipherType.Tkip,
                5 => WifiCipherType.Wep104,
                4 => WifiCipherType.Ccmp, 8 => WifiCipherType.Gcmp, 9 => WifiCipherType.Gcmp256, _ => WifiCipherType.Unknown };
            var auth = value.Security.Authentication;
            var security = new WifiSecurityInfo
            {
                Protocol = value.Security.SecurityEnabled == 0 ? WifiSecurityProtocol.Open : auth switch
                { 1 or 2 when cipher is WifiCipherType.Wep40 or WifiCipherType.Wep104 => WifiSecurityProtocol.Wep,
                    3 or 4 or 5 => WifiSecurityProtocol.Wpa, 6 or 7 => WifiSecurityProtocol.Wpa2,
                    8 or 9 or 11 => WifiSecurityProtocol.Wpa3, 10 => WifiSecurityProtocol.Owe, _ => WifiSecurityProtocol.Unknown },
                Authentication = value.Security.SecurityEnabled == 0 ? WifiAuthenticationType.Open :
                    value.Security.OneXEnabled != 0 ? WifiAuthenticationType.Enterprise :
                    auth is 4 or 7 or 9 ? WifiAuthenticationType.Personal :
                    auth == 2 ? WifiAuthenticationType.Shared : WifiAuthenticationType.Unknown,
                PairwiseCiphers = Array.AsReadOnly(new[] { cipher }), GroupCipher = WifiCipherType.Unknown,
                Source = WifiSecuritySource.WindowsNetworkList
            };
            return new(id, adapterName, Encoding.UTF8.GetString(bytes),
                string.Join(":", value.Association.Bssid.Select(b => b.ToString("X2"))), security, Array.AsReadOnly(bytes));
        }
        finally { if (memory != IntPtr.Zero) NativeWifiMethods.WlanFreeMemory(memory); }
    }

    private void OnConnectionNotification(ref WlanNotificationData notification)
    {
        if (notification.Code == 21 && _disconnects.TryGetValue(notification.InterfaceId, out var disconnected)) disconnected.TrySetResult();
        if (!_connections.TryGetValue(notification.InterfaceId, out var pending)) return;
        if (notification.Code == 14) { pending.Fail(WifiConnectionFailure.NoAdapter); return; }
        if (notification.Code == 18) { pending.Fail(WifiConnectionFailure.NetworkUnavailable); return; }
        if (notification.Code is not (9 or 10 or 11 or 18 or 21)) return;
        if (notification.Data == IntPtr.Zero || notification.DataSize < Marshal.SizeOf<WlanConnectionNotification>()) return;
        pending.Observe(notification.Code, Marshal.PtrToStructure<WlanConnectionNotification>(notification.Data));
    }
}

internal sealed class ConnectionCompletion(byte[] ssid, string profileName, IProgress<WifiConnectionState> progress)
{
    private readonly TaskCompletionSource<uint> _source = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public Task<uint> Task => _source.Task;
    public byte[] Ssid { get; } = ssid;
    public uint LastReason { get; private set; }
    public void Fail(WifiConnectionFailure failure) => _source.TrySetException(new WifiConnectionException(failure));
    public void Observe(uint code, WlanConnectionNotification data)
    {
        if (data.Ssid.Length != Ssid.Length || !data.Ssid.Bytes.AsSpan(0, Ssid.Length).SequenceEqual(Ssid) ||
            !string.IsNullOrEmpty(data.ProfileName) && data.ProfileName != profileName) return;
        if (code == 9) progress.Report(WifiConnectionState.Authenticating);
        if (code == 11) LastReason = data.Reason; // An attempt can fail before another BSS succeeds.
        if (code == 10) _source.TrySetResult(data.Reason);
    }
    public static WifiConnectionException Failure(uint reason, uint previous = 0)
    {
        var effective = reason == 0x2800b && previous != 0 ? previous : reason;
        var kind = effective == 0x2800d || effective is >= 0x48001 and <= 0x4801b or >= 0x38004 and <= 0x38007
            ? WifiConnectionFailure.AuthenticationFailed : effective is 0x28002 or 0x2800b or 0x38014
            ? WifiConnectionFailure.NetworkUnavailable : WifiConnectionFailure.Unexpected;
        return new(kind, effective);
    }
}
