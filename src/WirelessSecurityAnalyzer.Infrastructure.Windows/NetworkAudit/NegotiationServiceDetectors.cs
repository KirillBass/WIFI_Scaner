using System.Buffers.Binary;
using WirelessSecurityAnalyzer.Core.NetworkAudit;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NetworkAudit;

public sealed class RdpServiceDetector : IServiceDetector
{
    public string Name => "RDP";
    public bool IsPassive => false;
    public bool IsPreferred(int port) => port is 3389 or 3390;
    public async Task<ServiceIdentity?> DetectAsync(ServiceProbe probe, CancellationToken cancellationToken)
    {
        var stream = await probe.OpenStreamAsync(cancellationToken).ConfigureAwait(false);
        // TPKT + X.224 Connection Request + RDP_NEG_REQ (TLS/CredSSP). No authentication follows.
        byte[] request = [3,0,0,19,14,224,0,0,0,0,0,1,0,8,0,11,0,0,0];
        await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);
        var frame = await ProbeIo.ReadFrameAsync(stream, true, cancellationToken).ConfigureAwait(false);
        if (frame.Length != 19 || frame[4] != 14 || frame[5] != 0xd0 || frame[10] != 0 ||
            BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(13)) != 8) return null;
        var value = BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(15));
        var valid = frame[11] == 2 && value is 0 or 1 or 2 or 8 ||
            frame[11] == 3 && frame[12] == 0 && value is >= 1 and <= 7;
        if (!valid) return null;
        var description = frame[11] == 3 ? $"RDP_NEG_FAILURE: {value}" : $"RDP_NEG_RSP: {value switch { 0 => "RDP", 1 => "TLS", 2 => "CredSSP", _ => "CredSSP + Early Authorization" }}";
        return new("RDP", null, null, ServiceConfidence.High, description,
            "Подтверждена только RDP negotiation. Производитель, версия ОС и вход не определялись.");
    }
}

public sealed class SmbServiceDetector : IServiceDetector
{
    public string Name => "SMB";
    public bool IsPassive => false;
    public bool IsPreferred(int port) => port == 445;
    public async Task<ServiceIdentity?> DetectAsync(ServiceProbe probe, CancellationToken cancellationToken)
    {
        var stream = await probe.OpenStreamAsync(cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(CreateRequest(), cancellationToken).ConfigureAwait(false);
        var frame = await ProbeIo.ReadFrameAsync(stream, false, cancellationToken).ConfigureAwait(false);
        var data = frame.AsSpan(4);
        if (data.Length < 128 || !data[..4].SequenceEqual(new byte[] { 0xfe, 0x53, 0x4d, 0x42 }) ||
            BinaryPrimitives.ReadUInt16LittleEndian(data[4..]) != 64 ||
            BinaryPrimitives.ReadUInt32LittleEndian(data[8..]) != 0 ||
            BinaryPrimitives.ReadUInt16LittleEndian(data[12..]) != 0 ||
            (BinaryPrimitives.ReadUInt32LittleEndian(data[16..]) & 1) == 0 ||
            BinaryPrimitives.ReadUInt32LittleEndian(data[20..]) != 0 ||
            BinaryPrimitives.ReadUInt64LittleEndian(data[24..]) != 0 ||
            BinaryPrimitives.ReadUInt16LittleEndian(data[64..]) != 65) return null;
        var dialect = BinaryPrimitives.ReadUInt16LittleEndian(data[68..]);
        var version = dialect switch { 0x0202 => "2.0.2", 0x0210 => "2.1", 0x0300 => "3.0", 0x0302 => "3.0.2", _ => null };
        var bufferOffset = BinaryPrimitives.ReadUInt16LittleEndian(data[120..]);
        var bufferLength = BinaryPrimitives.ReadUInt16LittleEndian(data[122..]);
        if (version is null || bufferLength > 0 && (bufferOffset < 128 || bufferOffset + bufferLength > data.Length)) return null;
        var signing = (BinaryPrimitives.ReadUInt16LittleEndian(data[66..]) & 2) != 0;
        return new(dialect >= 0x0300 ? "SMB3" : "SMB2", null, version, ServiceConfidence.High,
            $"SMB2 NEGOTIATE Response; dialect 0x{dialect:X4} ({version}).",
            $"Подпись обязательна: {(signing ? "да" : "нет")}. Только NEGOTIATE; вход, ресурсы и файлы не запрашивались.\nПредложены диалекты 2.0.2–3.0.2; это согласованный диалект, а не максимальная версия сервера.");
    }
    internal static byte[] CreateRequest()
    {
        var packet = new byte[112]; // Direct TCP header 4 + SMB2 header 64 + NEGOTIATE 36 + four dialects 8.
        packet[3] = 108; var data = packet.AsSpan(4);
        new byte[] { 0xfe,0x53,0x4d,0x42 }.CopyTo(data);
        BinaryPrimitives.WriteUInt16LittleEndian(data[4..], 64);
        BinaryPrimitives.WriteUInt16LittleEndian(data[14..], 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data[64..], 36);
        BinaryPrimitives.WriteUInt16LittleEndian(data[66..], 4);
        BinaryPrimitives.WriteUInt16LittleEndian(data[68..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data[72..], 0x40);
        Guid.NewGuid().TryWriteBytes(data[76..92]);
        ushort[] dialects = [0x0202,0x0210,0x0300,0x0302];
        for (var i = 0; i < dialects.Length; i++) BinaryPrimitives.WriteUInt16LittleEndian(data[(100 + i * 2)..], dialects[i]);
        return packet;
    }
}
