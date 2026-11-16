using System.Net;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace PurrRouter.Netgear;

/// <summary>
/// Talks to a Netgear router through its built-in SOAP API (the same API the Nighthawk app and
/// Home Assistant's pynetgear use). Every request is serialized: Netgear's SOAP server is fragile
/// and doesn't like parallel calls.
/// </summary>
public sealed partial class NetgearClient : IDisposable
{
    const string SessionId = "A7D88AE69687E58D9A00";
    const string ServicePrefix = "urn:NETGEAR-ROUTER:service:";

    public const string DeviceInfo = "DeviceInfo:1";
    public const string DeviceConfig = "DeviceConfig:1";
    public const string WanIp = "WANIPConnection:1";
    public const string WanEthernet = "WANEthernetLinkConfig:1";
    public const string Wlan = "WLANConfiguration:1";
    public const string LanConfig = "LANConfigSecurity:1";
    public const string Parental = "ParentalControl:1";

    readonly string _soapUrl;
    readonly string _webBase;
    readonly string _user;
    readonly string _password;
    readonly SemaphoreSlim _lock = new(1, 1);
    readonly HashSet<string> _unsupported = [];
    readonly ILogger _log;

    string? _cookie;          // v2 login cookie
    bool _loggedInV1;         // v1 login is IP-bound, no cookie

    public NetgearClient(RouterSettings s, ILogger log)
    {
        _log = log;
        _user = s.Username;
        _password = s.Password ?? "";
        var scheme = s.UseHttps ? "https" : "http";
        _soapUrl = $"{scheme}://{s.Host}:{s.Port}/soap/server_sa/";
        _webBase = $"{scheme}://{s.Host}:{s.Port}/";
    }

    static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    public void Dispose() => _lock.Dispose();

    // ───────────────────────── public API ─────────────────────────

    /// <summary>Logs in and returns null on success, or an error message.</summary>
    public async Task<string?> TestLoginAsync(CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try { return await LoginCoreAsync(ct) ? null : "Router rejected the login. Double-check the username and password."; }
        catch (Exception ex) { return $"Couldn't reach the router: {ex.Message}"; }
        finally { _lock.Release(); }
    }

    /// <summary>Calls a read method. Returns the response fields, or null if it failed or isn't supported.</summary>
    public async Task<Dictionary<string, string?>?> GetAsync(string service, string method, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var r = await CallCoreAsync(service, method, null, ct);
            return r is null ? null : ParseFields(r, method);
        }
        finally { _lock.Release(); }
    }

    /// <summary>Tries each method in turn (different firmware names the same thing differently).</summary>
    public async Task<Dictionary<string, string?>?> GetFirstAsync(string service, string[] methods, CancellationToken ct = default)
    {
        foreach (var m in methods)
            if (await GetAsync(service, m, ct) is { } r) return r;
        return null;
    }

    public async Task<List<RouterDevice>?> GetAttachedDevicesAsync(CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            // GetAttachDevice2 has richer XML; older firmware only has the delimited GetAttachDevice.
            var xml = await CallCoreAsync(DeviceInfo, "GetAttachDevice2", null, ct);
            if (xml is not null && ParseDevices2(xml) is { } d2) return d2;

            var legacy = await CallCoreAsync(DeviceInfo, "GetAttachDevice", null, ct);
            return legacy is null ? null : ParseDevices1(legacy);
        }
        finally { _lock.Release(); }
    }

    /// <summary>
    /// Reads the router's own Attached Devices web page (HTTP Basic auth, same admin login) to learn which
    /// MACs are wired / 2.4 GHz / 5 GHz. Returns null if the page can't be read.
    /// </summary>
    public async Task<Dictionary<string, string>?> GetBandMapAsync(CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var resp = await WebGetCoreAsync("setup.cgi?todo=nbtscan&next_file=DEV_devices.htm", ct);
            if (resp.Status != 200) return null;
            var html = resp.Body;

            // Sections appear in this order: Wired, 2.4GHz, 5GHz, then VPN clients.
            int Find(string what, int from) => from < 0 ? -1 : html.IndexOf(what, from, StringComparison.OrdinalIgnoreCase);
            var wired = Find("Wired Devices", 0);
            var g24 = Find("2.4GHz", Math.Max(wired, 0));
            var g5 = Find("5GHz", g24 < 0 ? Math.Max(wired, 0) : g24 + 6);
            var end = Find("VPN Client Devices", Math.Max(g5, 0));
            if (end < 0) end = html.Length;
            if (g24 < 0 && g5 < 0) return null;

            var map = new Dictionary<string, string>();
            void Take(int from, int to, string band)
            {
                if (from < 0 || to <= from) return;
                foreach (Match m in MacRx().Matches(html[from..to])) map[m.Value.ToUpperInvariant()] = band;
            }
            Take(wired, g24 >= 0 ? g24 : g5, "wired");
            Take(g24, g5 >= 0 ? g5 : end, "2.4");
            Take(g5, end, "5");
            Diag.Log($"  band map: {map.Count(kv => kv.Value == "wired")} wired, {map.Count(kv => kv.Value == "2.4")} on 2.4, {map.Count(kv => kv.Value == "5")} on 5");
            return map;
        }
        catch (Exception ex) when (ex is IOException or System.Net.Sockets.SocketException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            Diag.Log($"WEB DEV_devices.htm → EXCEPTION {Diag.Chain(ex)}");
            return null;
        }
        finally { _lock.Release(); }
    }

    string? _webCookie;

    /// <summary>GET a page from the router's web UI (Basic auth, plus the token cookie some firmware wants).</summary>
    async Task<RawHttp.Response> WebGetCoreAsync(string pathAndQuery, CancellationToken ct)
    {
        var url = new Uri(_webBase + pathAndQuery.TrimStart('/'));
        var basic = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_user}:{_password}"));
        List<(string, string)> hdrs = [("Authorization", basic), ("User-Agent", "Mozilla/5.0 PurrRouter")];
        if (_webCookie is not null) hdrs.Add(("Cookie", _webCookie));

        var resp = await RawHttp.SendAsync(url, "GET", hdrs, null, Timeout, ct);
        LogWeb(resp, pathAndQuery);

        if (resp.Status == 401 && resp.All("Set-Cookie").Any())
        {
            _webCookie = string.Join("; ", resp.All("Set-Cookie").Select(c => c.Split(';')[0].Trim()));
            hdrs.RemoveAll(h => h.Item1 == "Cookie");
            hdrs.Add(("Cookie", _webCookie));
            resp = await RawHttp.SendAsync(url, "GET", hdrs, null, Timeout, ct);
            LogWeb(resp, pathAndQuery);
        }
        return resp;
    }

    /// <summary>Read-only fetch of a router web page (used by the page viewer). Returns (status, body).</summary>
    public async Task<(int Status, string Body)> GetWebPageAsync(string pathAndQuery, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var r = await WebGetCoreAsync(pathAndQuery, ct);
            return (r.Status, r.Body);
        }
        catch (Exception ex) when (ex is IOException or System.Net.Sockets.SocketException || ex is OperationCanceledException && !ct.IsCancellationRequested)
        {
            throw new RouterUnreachableException(ex);
        }
        finally { _lock.Release(); }
    }

    static void LogWeb(RawHttp.Response r, string path) => Diag.Log(
        $"{"WEB " + path.Split('?')[0].Split('=').Last(),-28} → HTTP {r.Status} len={r.Body.Length}"
        + (r.First("WWW-Authenticate") is { } wa ? $" auth=\"{wa}\"" : "")
        + (r.All("Set-Cookie").Any() ? $" set-cookie={Diag.Shape(string.Join(", ", r.All("Set-Cookie")))}" : "")
        + $" headers=[{string.Join(",", r.Headers.Select(h => h.Key))}]");

    /// <summary>Runs a write method inside a ConfigurationStarted / ConfigurationFinished session.</summary>
    public async Task<bool> SetAsync(string service, string method, IReadOnlyList<(string Key, string Value)>? args = null, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            if (await CallCoreAsync(DeviceConfig, "ConfigurationStarted", [("NewSessionID", SessionId)], ct) is null)
                return false;

            var ok = await CallCoreAsync(service, method, args, ct) is not null;

            // Reboot never returns to finish the session.
            if (method == "Reboot") return ok;

            var finished = await CallCoreAsync(DeviceConfig, "ConfigurationFinished", [("NewStatus", "ChangesApplied")], ct) is not null;
            return ok && finished;
        }
        finally { _lock.Release(); }
    }

    // ───────────────────────── SOAP plumbing ─────────────────────────

    async Task<bool> LoginCoreAsync(CancellationToken ct)
    {
        _cookie = null;
        _loggedInV1 = false;

        // v2: SOAPLogin, session lives in a cookie.
        var v2 = await SendAsync(DeviceConfig, "SOAPLogin",
            CallBody(DeviceConfig, "SOAPLogin", [("Username", _user), ("Password", _password)]), auth: false, ct);
        if (v2.Ok && v2.Cookie is not null)
        {
            _cookie = v2.Cookie;
            return true;
        }

        // v1: Authenticate, session bound to our IP.
        var body = $"""
            <SOAP-ENV:Body>
            <Authenticate>
              <NewUsername>{Esc(_user)}</NewUsername>
              <NewPassword>{Esc(_password)}</NewPassword>
            </Authenticate>
            </SOAP-ENV:Body>
            """;
        var v1 = await SendAsync(Parental, "Authenticate", body, auth: false, ct);
        if (!v1.Ok) return false;

        _loggedInV1 = true;
        var check = await SendAsync(DeviceInfo, "GetInfo", CallBody(DeviceInfo, "GetInfo", null), auth: true, ct);
        _loggedInV1 = check.Ok;
        return check.Ok;
    }

    async Task<string?> CallCoreAsync(string service, string method, IReadOnlyList<(string, string)>? args, CancellationToken ct)
    {
        var key = $"{service}#{method}";
        if (_unsupported.Contains(key)) return null;

        if (_cookie is null && !_loggedInV1 && !await LoginCoreAsync(ct))
            throw new RouterAuthException("Router login failed. Check your username and password in Settings.");

        var body = CallBody(service, method, args);
        if (args is { Count: > 0 } && method.StartsWith("Set"))
            Diag.Log($"  {method}({string.Join(", ", args.Select(x => $"{x.Item1}={x.Item2}"))})");
        var isWrite = method.StartsWith("Set") || method.StartsWith("Configuration") || method is "Reboot" or "EnableTrafficMeter";
        for (var attempt = 0; attempt < 3; attempt++)
        {
            SoapResult r;
            try { r = await SendAsync(service, method, body, auth: true, ct); }
            catch (RouterUnreachableException ex) when (ex.InnerException is IOException)
            {
                if (isWrite)
                {
                    // The router occasionally drops a write; it's a hiccup, not "unsupported". Breathe and retry.
                    if (attempt < 2) { await Task.Delay(1200, ct); continue; }
                    throw;
                }
                // Some firmware (e.g. R6350's GetAttachDevice2) hangs up instead of answering a method it can't handle.
                // Other calls work fine, so a repeat hang-up means "this method isn't supported here".
                if (attempt == 0) continue;
                _unsupported.Add(key);
                Diag.Log($"  {key} keeps dropping the connection → treating it as unsupported");
                return null;
            }
            if (r.Ok) return r.Text;

            switch (r.Code)
            {
                case 401: // session expired → log in again, retry once
                    if (attempt == 0 && await LoginCoreAsync(ct)) continue;
                    throw new RouterAuthException("Router login failed. Check your username and password in Settings.");
                case 503: // overloaded
                    await Task.Delay(3000, ct);
                    continue;
                case null when r.Status == HttpStatusCode.OK: // incomplete response
                    await Task.Delay(2000, ct);
                    continue;
                case 501 or 404: // method/service not on this firmware: remember and stop asking
                    _unsupported.Add(key);
                    _log.LogInformation("Router doesn't support {Key}", key);
                    return null;
                default:
                    _log.LogWarning("{Key} failed: HTTP {Status}, ResponseCode {Code}", key, (int)r.Status, r.Code);
                    return null;
            }
        }
        return null;
    }

    async Task<SoapResult> SendAsync(string service, string method, string body, bool auth, CancellationToken ct)
        => await SendWithCookieAsync(service, method, body, auth ? _cookie : null, ct);

    async Task<SoapResult> SendWithCookieAsync(string service, string method, string body, string? cookieHeader, CancellationToken ct)
    {
        var envelope = $"""
            <?xml version="1.0" encoding="utf-8" standalone="no"?>
            <SOAP-ENV:Envelope xmlns:SOAPSDK1="http://www.w3.org/2001/XMLSchema"
              xmlns:SOAPSDK2="http://www.w3.org/2001/XMLSchema-instance"
              xmlns:SOAPSDK3="http://schemas.xmlsoap.org/soap/encoding/"
              xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
            <SOAP-ENV:Header>
            <SessionID>{SessionId}</SessionID>
            </SOAP-ENV:Header>
            {body}
            </SOAP-ENV:Envelope>
            """;

        List<(string, string)> hdrs =
        [
            ("SOAPAction", $"{ServicePrefix}{service}#{method}"),
            ("Cache-Control", "no-cache"),
            ("User-Agent", "PurrRouter"),
            ("Content-Type", "multipart/form-data"),
        ];
        if (cookieHeader is not null) hdrs.Add(("Cookie", cookieHeader));

        RawHttp.Response resp;
        try
        {
            resp = await RawHttp.SendAsync(new Uri(_soapUrl), "POST", hdrs, envelope, Timeout, ct);
        }
        catch (Exception ex) when (ex is IOException or System.Net.Sockets.SocketException || ex is OperationCanceledException && !ct.IsCancellationRequested)
        {
            Diag.Log($"{method,-28} cookie={Diag.Shape(cookieHeader)} body={envelope.Length}B  → EXCEPTION {Diag.Chain(ex)}");
            throw new RouterUnreachableException(ex);
        }
        var text = resp.Body;
        var status = (HttpStatusCode)resp.Status;

        int? code = ResponseCodeRx().Match(text) is { Success: true } m ? int.Parse(m.Groups[1].Value) : null;
        if (status is HttpStatusCode.Unauthorized or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.NotImplemented or HttpStatusCode.NotFound)
            code ??= (int)status;

        // 0–3 are all "success" flavours on Netgear (1 = in progress, etc.)
        var ok = status == HttpStatusCode.OK && code is >= 0 and <= 3;

        var setCookies = resp.All("Set-Cookie").ToList();
        string? cookie = setCookies.Count > 0 ? string.Join(", ", setCookies) : null;
        Diag.Log($"{method,-28} cookie={Diag.Shape(cookieHeader)} body={envelope.Length}B  → HTTP {(int)status} code={code?.ToString() ?? "none"} len={text.Length}"
            + (cookie is null ? "" : $" set-cookie={Diag.Shape(cookie)}"));
        return new SoapResult(ok, status, code, text, cookie);
    }

    static string CallBody(string service, string method, IReadOnlyList<(string Key, string Value)>? args)
    {
        var sb = new StringBuilder();
        if (args is not null)
            foreach (var (k, v) in args) sb.Append('<').Append(k).Append('>').Append(Esc(v)).Append("</").Append(k).Append(">\n");

        return $"""
            <SOAP-ENV:Body>
            <M1:{method} xmlns:M1="{ServicePrefix}{service}">
            {sb}</M1:{method}>
            </SOAP-ENV:Body>
            """;
    }

    static string Esc(string s) => SecurityElement.Escape(s) ?? "";

    // ───────────────────────── parsing ─────────────────────────

    static XElement? Load(string text)
    {
        try { return XDocument.Parse(IllegalXmlRx().Replace(text, "")).Root; }
        catch { return null; }
    }

    static Dictionary<string, string?>? ParseFields(string text, string method)
    {
        var node = Load(text)?.Descendants().FirstOrDefault(e => e.Name.LocalName == method + "Response");
        return node?.Elements().ToDictionary(e => e.Name.LocalName, e => Clean(e.Value));
    }

    static string? Clean(string? v) => v is null || v.Trim() is "" or "--" or "<unknown>" or "&lt;unknown&gt;"
        || v.Trim().Equals("unknown", StringComparison.OrdinalIgnoreCase) ? null : v.Trim();

    static List<RouterDevice>? ParseDevices2(string text)
    {
        var node = Load(text)?.Descendants().FirstOrDefault(e => e.Name.LocalName == "NewAttachDevice");
        if (node is null) return null;

        string? F(XElement d, string n) => Clean(d.Elements().FirstOrDefault(e => e.Name.LocalName == n)?.Value);

        return node.Elements().Where(e => e.Name.LocalName == "Device").Select(d => new RouterDevice
        {
            Ip = F(d, "IP"),
            Name = F(d, "Name"),
            Mac = F(d, "MAC")?.ToUpperInvariant() ?? "",
            ConnectionType = F(d, "ConnectionType"),
            LinkRate = F(d, "Linkspeed"),
            Signal = int.TryParse(F(d, "SignalStrength"), out var sig) ? sig : null,
            Access = F(d, "AllowOrBlock"),
            Ssid = F(d, "SSID"),
            Model = F(d, "DeviceModel"),
        }).Where(d => d.Mac != "").ToList();
    }

    static List<RouterDevice>? ParseDevices1(string text)
    {
        var raw = Load(text)?.Descendants().FirstOrDefault(e => e.Name.LocalName == "NewAttachDevice")?.Value;
        if (raw is null) return null;

        var entries = raw.Trim().Replace("&lt;unknown&gt;", "<unknown>").Split('@');
        if (entries.Length > 1) entries = entries[1..]; // first entry is the device count

        var list = new List<RouterDevice>();
        foreach (var e in entries)
        {
            var f = e.Split(';');
            if (f.Length < 4) continue;
            list.Add(new RouterDevice
            {
                Ip = Clean(f[1]),
                Name = Clean(f[2]),
                Mac = Clean(f[3])?.ToUpperInvariant() ?? "",
                ConnectionType = f.Length > 4 ? Clean(f[4]) : null,
                LinkRate = f.Length > 5 ? Clean(f[5]) : null,
                Signal = f.Length > 6 && int.TryParse(f[6], out var s) ? s : null,
                Access = f.Length > 7 ? Clean(f[7]) : null,
            });
        }
        return list.Where(d => d.Mac != "").ToList();
    }

    [GeneratedRegex(@"\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")]
    private static partial Regex MacRx();

    [GeneratedRegex(@"<ResponseCode>\s*(\d+)\s*</ResponseCode>")]
    private static partial Regex ResponseCodeRx();

    [GeneratedRegex(@"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x84\x86-\x9F﷐-﷟￾￿]")]
    private static partial Regex IllegalXmlRx();

    record SoapResult(bool Ok, HttpStatusCode Status, int? Code, string Text, string? Cookie);
}

public sealed class RouterAuthException(string message) : Exception(message);

/// <summary>Couldn't talk to the router at all (refused, dropped, timed out).</summary>
public sealed class RouterUnreachableException(Exception inner)
    : Exception($"Couldn't reach the router: {inner.Message}", inner);

public sealed class RouterDevice
{
    public string Mac { get; init; } = "";
    public string? Ip { get; init; }
    public string? Name { get; init; }
    public string? ConnectionType { get; init; }
    public string? LinkRate { get; init; }
    public int? Signal { get; init; }
    public string? Access { get; init; }
    public string? Ssid { get; init; }
    public string? Model { get; init; }
}
