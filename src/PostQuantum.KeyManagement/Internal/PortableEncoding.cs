using System.Buffers.Binary;
using System.Text;

namespace PostQuantum.KeyManagement.Internal;

/// <summary>
/// Shared primitives for the library's compact, versioned, URL-safe token format: big-endian,
/// length-prefixed fields written to a stream and read back from a byte array with a moving cursor.
/// </summary>
internal static class PortableEncoding
{
    public static void WriteInt32(Stream stream, int value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(buffer, value);
        stream.Write(buffer);
    }

    public static void WriteBytes(Stream stream, ReadOnlySpan<byte> value)
    {
        WriteInt32(stream, value.Length);
        stream.Write(value);
    }

    public static void WriteString(Stream stream, string value)
        => WriteBytes(stream, Encoding.UTF8.GetBytes(value));

    public static byte ReadByte(byte[] data, ref int offset)
    {
        if (offset >= data.Length)
        {
            throw new FormatException("Truncated token.");
        }

        return data[offset++];
    }

    public static int ReadInt32(byte[] data, ref int offset)
    {
        if (offset + 4 > data.Length)
        {
            throw new FormatException("Truncated token.");
        }

        int value = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(offset, 4));
        offset += 4;
        return value;
    }

    public static byte[] ReadBytes(byte[] data, ref int offset)
    {
        int length = ReadInt32(data, ref offset);
        if (length < 0 || offset + length > data.Length)
        {
            throw new FormatException("Corrupt length prefix in token.");
        }

        byte[] value = data.AsSpan(offset, length).ToArray();
        offset += length;
        return value;
    }

    public static string ReadString(byte[] data, ref int offset)
        => Encoding.UTF8.GetString(ReadBytes(data, ref offset));

    public static string ToBase64Url(ReadOnlySpan<byte> data)
        => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] FromBase64Url(string token)
    {
        string padded = token.Replace('-', '+').Replace('_', '/');
        padded = (padded.Length % 4) switch
        {
            2 => padded + "==",
            3 => padded + "=",
            0 => padded,
            _ => throw new FormatException("Invalid Base64Url length."),
        };

        try
        {
            return Convert.FromBase64String(padded);
        }
        catch (FormatException ex)
        {
            throw new FormatException("Token is not valid Base64Url.", ex);
        }
    }
}
