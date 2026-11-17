using System.Net;
using System.Text.RegularExpressions;

namespace PurrRouter.Netgear;

/// <summary>One line of Administration > Logs. Time is the router's own clock (no time zone given), null if unparsable.</summary>
public record LogEntry(string Category, string Message, string? Time);

/// <summary>One row of Router Status > Show Statistics.</summary>
public record PortStat(string Port, string Status, long? TxPkts, long? RxPkts, long? Collisions, long? TxBps, long? RxBps, string? UpTime);

/// <summary>Router Status > Show Statistics + Connection Status (read-only; Release/Renew are left alone).</summary>
public record RouterStatus(string? SystemUpTime, List<PortStat> Ports, Dictionary<string, string> Connection);

/// <summary>
/// Administration pages, read-only: FW_log.htm (the log textarea), RST_stattbl.htm (the "Show Statistics" table)
/// and RST_wanstat.htm, which meta-refreshes to the connection-status page for the WAN type (e.g. RST_st_dhcp.htm).
/// Nothing here posts a form, so nothing can change a setting.
/// </summary>
public sealed partial class NetgearClient
{
    public async Task<List<LogEntry>> GetLogsAsync(CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var page = await WebPageOrThrowAsync("FW_log.htm&todo=cfg_init", ct);
            var m = LogTextRx().Match(page);
            if (!m.Success) throw new RouterRejectedException("Couldn't find the log on the router's Logs page (session expired?). Try again.");
            var list = WebUtility.HtmlDecode(m.Groups[1].Value)
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(ParseLogLine).ToList();
            // The router's log buffer cuts the oldest line mid-way ("[Access Control] Device UNKNOWN with MAC address FC:F1:").
            if (list.Count > 0 && list[^1] is { Time: null } last && last.Message.StartsWith('[')) list.RemoveAt(list.Count - 1);
            return list;
        }
        finally { _lock.Release(); }
    }

    public async Task<RouterStatus> GetRouterStatusAsync(CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var stats = await WebPageOrThrowAsync("RST_stattbl.htm", ct);
            var rows = Rows(stats);
            var up = rows.FirstOrDefault(r => r.Count >= 2 && r[0].StartsWith("System Up Time", StringComparison.OrdinalIgnoreCase))?[1]
                ?? (UpTimeRx().Match(StripTags(stats)) is { Success: true } um ? um.Groups[1].Value : null);
            var ports = rows
                .Where(r => r.Count >= 2 && r[0] != "Port" && !r[0].StartsWith("System Up Time", StringComparison.OrdinalIgnoreCase))
                .Select(r => new PortStat(r[0], r[1], Num(r, 2), Num(r, 3), Num(r, 4), Num(r, 5), Num(r, 6), r.Count > 7 && r[7] != "--" ? r[7] : null))
                .ToList();

            // RST_wanstat.htm is just a meta refresh to the page for the current WAN type; follow it if it's a plain page.
            var conn = new Dictionary<string, string>();
            var wan = await WebPageOrThrowAsync("RST_wanstat.htm", ct);
            if (MetaRefreshRx().Match(wan) is { Success: true } mr && SafeStatusPageRx().IsMatch(mr.Groups[1].Value.Trim()))
            {
                var detail = await WebPageOrThrowAsync(mr.Groups[1].Value.Trim(), ct);
                foreach (var r in Rows(detail).Where(r => r.Count >= 2))
                    conn[r[0].TrimEnd(':', ' ')] = string.Join(" ", r.Skip(1));
            }
            return new RouterStatus(up, ports, conn);
        }
        finally { _lock.Release(); }
    }

    static LogEntry ParseLogLine(string line)
    {
        var m = LogLineRx().Match(line);
        if (!m.Success) return new LogEntry("", line.Trim(), null);
        var when = DateTime.TryParseExact($"{m.Groups["mon"].Value} {m.Groups["day"].Value} {m.Groups["year"].Value} {m.Groups["time"].Value}",
            "MMMM d yyyy HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var t)
            ? t.ToString("yyyy-MM-ddTHH:mm:ss") : null;
        return new LogEntry(m.Groups["cat"].Value.Trim(), m.Groups["msg"].Value.Trim().TrimEnd(','), when);
    }

    static List<List<string>> Rows(string html)
    {
        html = HtmlCommentRx().Replace(html, "");
        html = ScriptRx().Replace(html, "");
        return RowRx().Matches(html)
            .Select(r => CellRx().Matches(r.Groups[1].Value).Select(c => StripTags(c.Groups[1].Value)).Where(c => c.Length > 0).ToList())
            .Where(r => r.Count > 0).ToList();
    }

    static string StripTags(string s) => Regex.Replace(WebUtility.HtmlDecode(Regex.Replace(s, "<[^>]+>", " ")), @"\s+", " ").Trim();
    static long? Num(List<string> r, int i) => r.Count > i && long.TryParse(r[i], out var v) ? v : null;

    [GeneratedRegex(@"<textarea[^>]*name=""log_detail""[^>]*>(.*?)</textarea>", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex LogTextRx();

    [GeneratedRegex(@"^\[(?<cat>[^\]]+)\]\s*(?<msg>.*?)\s*,?\s*(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday),\s*(?<mon>[A-Za-z]+)\s+(?<day>\d{1,2}),\s*(?<year>\d{4})\s+(?<time>\d{1,2}:\d{2}:\d{2})\s*$")]
    private static partial Regex LogLineRx();

    [GeneratedRegex(@"<tr[^>]*>(.*?)</tr>", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex RowRx();

    [GeneratedRegex(@"<t[dh][^>]*>(.*?)</t[dh]>", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex CellRx();

    [GeneratedRegex(@"<script.*?</script>", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex ScriptRx();

    [GeneratedRegex(@"System Up Time\s*([0-9:]+(?:\s*days?[^<]*)?)", RegexOptions.IgnoreCase)]
    private static partial Regex UpTimeRx();

    [GeneratedRegex(@"http-equiv=""?REFRESH""?\s+content=""\d+;\s*URL=\s*([^""]+)""", RegexOptions.IgnoreCase)]
    private static partial Regex MetaRefreshRx();

    [GeneratedRegex(@"^(?:setup\.cgi\?next_file=)?RST_st_[a-z0-9_]+\.htm$")]
    private static partial Regex SafeStatusPageRx();
}
