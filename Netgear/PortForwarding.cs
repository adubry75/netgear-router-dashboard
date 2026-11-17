using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace PurrRouter.Netgear;

public record PortForward(int Number, string Name, string ExternalPorts, string InternalPorts, string Ip, string? Protocol = null);

/// <summary>
/// Port forwarding through the router's own web pages (the SOAP API doesn't cover it on the R6350).
/// Mirrors exactly what FW_forward.htm / FW_forward_service.htm post to setup.cgi.
/// Every change loads the page first: its form action carries a fresh "setup.cgi?id=…" token.
/// </summary>
public sealed partial class NetgearClient
{
    const string FwList = "FW_forward.htm";
    const string FwService = "FW_forward_service.htm";

    public static readonly string[] Protocols = ["BOTH", "TCP", "UDP"]; // router's select order = h_pfw_proto index

    // The list page doesn't include protocols, and reading one costs a ~6 s todo=edit round trip on the R6350
    // (measured: the router takes ~6.2 s before its first byte). So remember each rule's protocol, keyed by
    // everything the list page does show; a rule changed in any listed field gets a new key and is read again.
    readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _pfProtocols = new();
    static string PfKey(PortForward r) => $"{r.Name}|{r.ExternalPorts}|{r.InternalPorts}|{r.Ip}";
    void RememberProtocol(PortForward r) { if (r.Protocol is { } p) _pfProtocols[PfKey(r)] = p; }

    public async Task<List<PortForward>> GetPortForwardsAsync(CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var page = await WebPageOrThrowAsync(FwList, ct);
            return WithProtocols(ParseForwardList(page));
        }
        finally { _lock.Release(); }
    }

    /// <summary>Opens a rule in the router's editor to read its full details (incl. protocol). Changes nothing.</summary>
    public async Task<PortForward?> GetPortForwardAsync(int number, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var edit = await OpenEditorAsync(number, ct);
            if (edit is null) return null;
            var rule = EditorToRule(number, edit);
            RememberProtocol(rule);
            return rule;
        }
        finally { _lock.Release(); }
    }

    public async Task<List<PortForward>> AddPortForwardAsync(PortForward rule, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            // List first, then the form: always post with the token from the most recently loaded page.
            var before = ParseForwardList(await WebPageOrThrowAsync(FwList, ct));
            var page = await WebPageOrThrowAsync($"setup.cgi?todo=nbtscan&next_file={FwService}", ct);
            var action = FormAction(page);
            var result = await PostFormCoreAsync(action, ServiceForm(rule, edit: false, ruleSelect: "0", page), ct);
            var after = ParseForwardList(result.Contains("PortForwarding") ? result : await WebPageOrThrowAsync(FwList, ct));

            if (after.Count <= before.Count || !after.Any(r => SameRule(r, rule)))
                throw new RouterRejectedException(RouterMessage(result) ?? "The router didn't save the new rule.");
            RememberProtocol(rule);
            return WithProtocols(after);
        }
        finally { _lock.Release(); }
    }

    public async Task<List<PortForward>> UpdatePortForwardAsync(int number, PortForward rule, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var editor = await OpenEditorAsync(number, ct)
                ?? throw new RouterRejectedException($"Rule #{number} doesn't exist anymore. Refresh and try again.");
            var action = FormAction(editor.Page);
            var ruleSelect = Field(editor.Page, "h_ruleSelect") ?? number.ToString();
            var result = await PostFormCoreAsync(action, ServiceForm(rule, edit: true, ruleSelect, editor.Page), ct);
            var after = ParseForwardList(result.Contains("PortForwarding") ? result : await WebPageOrThrowAsync(FwList, ct));

            if (!after.Any(r => SameRule(r, rule)))
                throw new RouterRejectedException(RouterMessage(result) ?? "The router didn't save the change.");
            RememberProtocol(rule);
            return WithProtocols(after);
        }
        finally { _lock.Release(); }
    }

    public async Task<List<PortForward>> DeletePortForwardAsync(int number, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var page = await WebPageOrThrowAsync(FwList, ct);
            var before = ParseForwardList(page);
            var target = before.FirstOrDefault(r => r.Number == number)
                ?? throw new RouterRejectedException($"Rule #{number} doesn't exist anymore. Refresh and try again.");

            var result = await PostFormCoreAsync(FormAction(page), ListForm(page, "delete", number), ct);
            var after = ParseForwardList(result.Contains("PortForwarding") ? result : await WebPageOrThrowAsync(FwList, ct));

            if (after.Count >= before.Count)
                throw new RouterRejectedException(RouterMessage(result) ?? $"The router didn't delete “{target.Name}”.");
            return WithProtocols(after);
        }
        finally { _lock.Release(); }
    }

    // ───────────────────────── form plumbing ─────────────────────────

    sealed record Editor(string Page);

    async Task<Editor?> OpenEditorAsync(int number, CancellationToken ct)
    {
        var list = await WebPageOrThrowAsync(FwList, ct);
        if (!ParseForwardList(list).Any(r => r.Number == number)) return null;
        var page = await PostFormCoreAsync(FormAction(list), ListForm(list, "edit", number), ct);
        return page.Contains("name=\"portname\"") ? new Editor(page) : null;
    }

    static PortForward EditorToRule(int number, Editor e)
    {
        var proto = int.TryParse(Field(e.Page, "h_srvtype"), out var p) && p is >= 0 and < 3 ? Protocols[p] : null;
        return new PortForward(number,
            Decode(Field(e.Page, "portname") ?? ""),
            Field(e.Page, "ex_port_range") ?? "",
            Field(e.Page, "in_port_range") ?? "",
            Field(e.Page, "c4_server_ip") ?? "",
            proto);
    }

    /// <summary>The fields FW_forward.htm submits for Edit/Delete (same as the browser sends).</summary>
    static List<(string, string)> ListForm(string page, string todo, int number)
    {
        var lan = Field(page, "lanIP") ?? "";
        var parts = lan.Split('.');
        return
        [
            ("serv_type", "pf"),
            ("svs_gm", "FTP"),
            ("SV_IP1", parts.ElementAtOrDefault(0) ?? ""), ("SV_IP2", parts.ElementAtOrDefault(1) ?? ""),
            ("SV_IP3", parts.ElementAtOrDefault(2) ?? ""), ("SV_IP4", ""),
            ("RouteSelect", number.ToString()),
            ("lanIP", lan),
            ("h_pfw_name", ""), ("c4_pfw_ip", ""), ("h_pfw_proto", ""), ("h_pfw_ex_range", ""), ("h_pfw_in_range", ""),
            ("h_ruleSelect", number.ToString()), ("ruleSelect", number.ToString()),
            ("edit", ""), ("todo", todo),
            ("this_file", FwList), ("next_file", FwList), ("SID", Field(page, "SID") ?? ""),
        ];
    }

    /// <summary>The fields FW_forward_service.htm submits on Apply (Check() + Final()).</summary>
    static List<(string, string)> ServiceForm(PortForward r, bool edit, string ruleSelect, string page)
    {
        var ip = r.Ip.Split('.');
        var protoIndex = Math.Max(0, Array.IndexOf(Protocols, r.Protocol ?? "BOTH"));
        List<(string, string)> f =
        [
            ("portname", r.Name),
            ("srvtype", Protocols[protoIndex]),
            ("ex_port_range", r.ExternalPorts),
        ];
        if (r.ExternalPorts == r.InternalPorts) f.Add(("same_range", "use_same_port"));
        f.AddRange(
        [
            ("in_port_range", r.InternalPorts),
            ("server_ip1", ip[0]), ("server_ip2", ip[1]), ("server_ip3", ip[2]), ("server_ip4", ip[3]),
            ("todo", "pfw_add"),
            ("h_pfw_name", r.Name),
            ("c4_pfw_ip", r.Ip),
            ("h_pfw_proto", protoIndex.ToString()),
            ("h_pfw_ex_range", r.ExternalPorts),
            ("h_pfw_in_range", r.InternalPorts),
            ("h_ruleSelect", ruleSelect),
            ("ruleSelect", edit ? ruleSelect : ""),
            ("edit", edit ? "1" : "0"),
            ("lanIP", Field(page, "lanIP") ?? ""),
            ("h_srvtype", Field(page, "h_srvtype") ?? ""),
            ("c4_server_ip", Field(page, "c4_server_ip") ?? ""),
            ("this_file", FwService),
            ("next_file", FwList),
            ("SID", Field(page, "SID") ?? ""),
        ]);
        return f;
    }

    async Task<string> WebPageOrThrowAsync(string path, CancellationToken ct)
    {
        try
        {
            var r = await WebGetCoreAsync(path, ct);
            if (r.Status == 401) throw new RouterAuthException("The router rejected the web login. Check your password in Settings.");
            if (r.Status != 200) throw new RouterRejectedException($"The router answered HTTP {r.Status} for {path.Split('?')[0]}.");
            return r.Body;
        }
        catch (Exception ex) when (ex is IOException or System.Net.Sockets.SocketException || ex is OperationCanceledException && !ct.IsCancellationRequested)
        {
            throw new RouterUnreachableException(ex);
        }
    }

    async Task<string> PostFormCoreAsync(string action, List<(string Key, string Value)> fields, CancellationToken ct)
    {
        var body = string.Join("&", fields.Select(f => $"{WebUtility.UrlEncode(f.Key)}={WebUtility.UrlEncode(f.Value)}"));
        var url = new Uri(_webBase + action);
        var basic = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_user}:{_password}"));
        List<(string, string)> hdrs =
        [
            ("Authorization", basic),
            ("User-Agent", "Mozilla/5.0 PurrRouter"),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ];
        if (_webCookie is not null) hdrs.Add(("Cookie", _webCookie));

        var todo = fields.FirstOrDefault(f => f.Key == "todo").Value;
        Diag.Log($"  WEB POST todo={todo} {string.Join(", ", fields.Where(f => f.Key is "h_pfw_name" or "c4_pfw_ip" or "h_pfw_proto" or "h_pfw_ex_range" or "h_pfw_in_range" or "ruleSelect" or "edit").Select(f => $"{f.Key}={f.Value}"))}");
        try
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var r = await RawHttp.SendAsync(url, "POST", hdrs, body, Timeout, ct);
            Diag.Log($"{"WEB POST " + todo,-28} → HTTP {r.Status} len={r.Body.Length} {sw.ElapsedMilliseconds}ms");
            if (r.Status == 401) throw new RouterAuthException("The router rejected the web login. Check your password in Settings.");
            if (r.Status != 200) throw new RouterRejectedException($"The router answered HTTP {r.Status}.");
            return r.Body;
        }
        catch (Exception ex) when (ex is IOException or System.Net.Sockets.SocketException || ex is OperationCanceledException && !ct.IsCancellationRequested)
        {
            throw new RouterUnreachableException(ex);
        }
    }

    // ───────────────────────── parsing ─────────────────────────

    List<PortForward> WithProtocols(List<PortForward> list) =>
        list.Select(r => _pfProtocols.TryGetValue(PfKey(r), out var p) ? r with { Protocol = p } : r).ToList();

    static List<PortForward> ParseForwardList(string html)
    {
        html = HtmlCommentRx().Replace(html, ""); // the page ships a commented-out sample row
        return ForwardRowRx().Matches(html).Select(m => new PortForward(
            int.Parse(m.Groups[1].Value),
            Decode(m.Groups[2].Value),
            m.Groups[3].Value.Trim(),
            m.Groups[4].Value.Trim(),
            m.Groups[5].Value.Trim())).ToList();
    }

    static string FormAction(string page) =>
        FormActionRx().Match(page) is { Success: true } m ? WebUtility.HtmlDecode(m.Groups[1].Value)
        : throw new RouterRejectedException("Couldn't find the router's form on that page (session expired?). Try again.");

    static string? Field(string page, string name)
    {
        // <input ... name="X" ... value="Y">  (attribute order varies)
        foreach (Match m in InputRx().Matches(page))
        {
            var tag = m.Value;
            if (!Regex.IsMatch(tag, $@"\bname\s*=\s*[""']{Regex.Escape(name)}[""']", RegexOptions.IgnoreCase)) continue;
            var v = Regex.Match(tag, @"\bvalue\s*=\s*""([^""]*)""", RegexOptions.IgnoreCase);
            return v.Success ? WebUtility.HtmlDecode(v.Groups[1].Value) : "";
        }
        return null;
    }

    static string Decode(string s) => WebUtility.HtmlDecode(s).Replace(' ', ' ').Trim();

    static bool SameRule(PortForward a, PortForward b) =>
        a.Name.Equals(b.Name, StringComparison.Ordinal) && a.Ip == b.Ip
        && a.ExternalPorts == b.ExternalPorts && a.InternalPorts == b.InternalPorts;

    /// <summary>Pulls an alert('...') message out of the router's reply, if it complained.</summary>
    static string? RouterMessage(string html) =>
        AlertRx().Match(html) is { Success: true } m ? m.Groups[1].Value : null;

    [GeneratedRegex(@"<!--.*?-->", RegexOptions.Singleline)]
    private static partial Regex HtmlCommentRx();

    [GeneratedRegex(@"name=""RouteSelect""\s+value=""(\d+)"".*?<span class=ttext>(.*?)</span>.*?<span class=ttext>(.*?)</span>.*?<span class=ttext>(.*?)</span>.*?<span class=ttext>(.*?)</span>",
        RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex ForwardRowRx();

    [GeneratedRegex(@"<form[^>]*\baction=""(setup\.cgi[^""]*)""", RegexOptions.IgnoreCase)]
    private static partial Regex FormActionRx();

    [GeneratedRegex(@"<input\b[^>]*>", RegexOptions.IgnoreCase)]
    private static partial Regex InputRx();

    [GeneratedRegex(@"alert\(\s*[""']([^""']{4,200})[""']\s*\)")]
    private static partial Regex AlertRx();
}

/// <summary>The router answered but refused / ignored the change.</summary>
public sealed class RouterRejectedException(string message) : Exception(message);
