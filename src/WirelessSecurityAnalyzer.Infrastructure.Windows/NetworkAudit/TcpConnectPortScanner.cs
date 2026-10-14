using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.NetworkAudit;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NetworkAudit;

public sealed class TcpConnectPortScanner : IPortScanner
{
    public async Task<PortScanConnection> ConnectAsync(LocalNetworkInfo network, IPAddress address, int port,
        TimeSpan timeout, CancellationToken cancellationToken)
    {
        if (!network.Subnet.ContainsHost(address) || address.AddressFamily != AddressFamily.InterNetwork || port is < 1 or > 65535)
            throw new ArgumentException("Цель должна принадлежать текущей локальной подсети.");
        cancellationToken.ThrowIfCancellationRequested();
        var watch = Stopwatch.StartNew();
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try
        {
            socket.Bind(new IPEndPoint(network.LocalIpv4, 0));
            IdentitySocketScope.SelectInterface(socket, network);
            await socket.ConnectAsync(new IPEndPoint(address, port), deadline.Token).ConfigureAwait(false);
            return new(new(address, port, PortState.Open, watch.Elapsed), new NetworkStream(socket, ownsSocket: true));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { socket.Dispose(); return new(new(address, port, PortState.Timeout, watch.Elapsed, "Timeout")); }
        catch (SocketException ex)
        {
            socket.Dispose(); cancellationToken.ThrowIfCancellationRequested();
            var state = ex.SocketErrorCode switch
            {
                SocketError.ConnectionRefused => PortState.Closed,
                SocketError.TimedOut => PortState.Timeout,
                SocketError.NetworkUnreachable or SocketError.HostUnreachable or SocketError.NetworkDown or
                    SocketError.AddressNotAvailable => PortState.Unavailable,
                _ => PortState.Error
            };
            return new(new(address, port, state, watch.Elapsed, ex.SocketErrorCode.ToString()));
        }
        catch { socket.Dispose(); throw; }
    }
}
