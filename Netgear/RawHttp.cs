using System.Net.Security;
using System.Net.Sockets;
using System.Text;

namespace PurrRouter.Netgear;

/// <summary>
/// A tiny, forgiving HTTP/1.0 client for talking to the router. .NET's HttpClient is (rightly) strict,
/// but Netgear firmware sends things like a bare "BLOCK 44" line in its response headers, which
/// HttpClient rejects even though the request succeeded. One request per connection, like the router wants.
/// </summary>
public static class RawHttp
{
    public sealed record Response(int Status, List<KeyValuePair<string, string>> Headers, string Body)
    {
        public IEnumerable<string> All(string name) =>
            Headers.Where(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Select(h => h.Value);
        public string? First(string name) => All(name).FirstOrDefault();
    }

    public static async Task<Response> SendAsync(
        Uri url, string method, IEnumerable<(string Name, string Value)> headers, string? body,
        TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        var token = cts.Token;

        using var tcp = new TcpClient { NoDelay = true };
        await tcp.ConnectAsync(url.Host, url.Port, token);
        Stream stream = tcp.GetStream();
        if (url.Scheme == Uri.UriSchemeHttps)
        {
            // Netgear uses a self-signed certificate on its HTTPS port.
            var ssl = new SslStream(stream, false, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = url.Host }, token);
            stream = ssl;
        }

        await using (stream)
        {
            var bodyBytes = body is null ? [] : Encoding.UTF8.GetBytes(body);
            var sb = new StringBuilder();
            sb.Append(method).Append(' ').Append(url.PathAndQuery).Append(" HTTP/1.0\r\n");
            sb.Append("Host: ").Append(url.Authority).Append("\r\n");
            foreach (var (n, v) in headers) sb.Append(n).Append(": ").Append(v).Append("\r\n");
            if (body is not null) sb.Append("Content-Length: ").Append(bodyBytes.Length).Append("\r\n");
            sb.Append("Connection: close\r\n\r\n");

            // Send headers + body in a single write; some embedded servers only read the first packet.
            var head = Encoding.ASCII.GetBytes(sb.ToString());
            var all = new byte[head.Length + bodyBytes.Length];
            head.CopyTo(all, 0);
            bodyBytes.CopyTo(all, head.Length);
            await stream.WriteAsync(all, token);
            await stream.FlushAsync(token);

            using var ms = new MemoryStream();
            await stream.CopyToAsync(ms, token);
            return Parse(ms.ToArray());
        }
    }

    static Response Parse(byte[] raw)
    {
        if (raw.Length == 0) throw new IOException("The router closed the connection without answering.");

        var split = IndexOf(raw, "\r\n\r\n"u8, out var sepLen);
        if (split < 0) split = IndexOf(raw, "\n\n"u8, out sepLen);
        var headText = Encoding.Latin1.GetString(raw, 0, split < 0 ? raw.Length : split);
        var bodyBytes = split < 0 ? [] : raw[(split + sepLen)..];

        var lines = headText.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        var statusParts = lines.Count > 0 ? lines[0].Split(' ', 3) : [];
        var status = statusParts.Length > 1 && int.TryParse(statusParts[1], out var s) ? s : 0;
        if (status == 0) throw new IOException($"Unexpected reply from the router: '{(lines.Count > 0 ? lines[0] : "")}'");

        var headers = new List<KeyValuePair<string, string>>();
        foreach (var line in lines.Skip(1))
        {
            var colon = line.IndexOf(':');
            if (colon <= 0) continue; // junk like "BLOCK 44": ignore it
            headers.Add(new(line[..colon].Trim(), line[(colon + 1)..].Trim()));
        }

        if (headers.Any(h => h.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)
                             && h.Value.Contains("chunked", StringComparison.OrdinalIgnoreCase)))
            bodyBytes = Dechunk(bodyBytes);

        return new Response(status, headers, Encoding.UTF8.GetString(bodyBytes));
    }

    static int IndexOf(byte[] data, ReadOnlySpan<byte> pattern, out int len)
    {
        len = pattern.Length;
        return data.AsSpan().IndexOf(pattern);
    }

    static byte[] Dechunk(byte[] data)
    {
        using var outp = new MemoryStream();
        var i = 0;
        while (i < data.Length)
        {
            var eol = Array.IndexOf(data, (byte)'\n', i);
            if (eol < 0) break;
            var sizeText = Encoding.ASCII.GetString(data, i, eol - i).Trim().Split(';')[0];
            if (!int.TryParse(sizeText, System.Globalization.NumberStyles.HexNumber, null, out var size) || size == 0) break;
            i = eol + 1;
            outp.Write(data, i, Math.Min(size, data.Length - i));
            i += size + 2; // skip CRLF after chunk
        }
        return outp.ToArray();
    }
}
