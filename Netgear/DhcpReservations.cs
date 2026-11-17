using System.Text.RegularExpressions;

namespace PurrRouter.Netgear;

/// <summary>One "Address Reservation" row on LAN Setup. Number is 1-based like the router's table.</summary>
public record DhcpReservation(int Number, string Ip, string Name, string Mac);

/// <summary>LAN Setup's DHCP server state plus its reservation table.</summary>
public record DhcpInfo(bool? Enabled, string? PoolStart, string? PoolEnd, string? LanIp, string? Mask, List<DhcpReservation> Reservations);

/// <summary>
/// DHCP address reservations through the router's own pages (Setup > LAN Setup), mirroring exactly what
/// LAN_lan.htm and LAN_reserv_add.htm / LAN_reserv_edit.htm post to setup.cgi.
/// Edit and Delete post the WHOLE LAN Setup form (LAN IP, DHCP on/off, pool, RIP) with todo=edit/delete, so
/// <see cref="LanForm"/> rebuilds it field by field the way the page's own JS would (dataToVisible → dataToHidden),
/// keeping every LAN setting exactly as the router reported it.
/// </summary>
public sealed partial class NetgearClient
{
    const string LanPage = "LAN_lan.htm";
    const string RsvAdd = "LAN_reserv_add.htm";
    const string RsvEdit = "LAN_reserv_edit.htm";

    public async Task<DhcpInfo> GetDhcpAsync(CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try { return ParseLanPage(await WebPageOrThrowAsync(LanPage, ct)); }
        finally { _lock.Release(); }
    }

    public async Task<DhcpInfo> AddReservationAsync(DhcpReservation r, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var before = ParseLanPage(await WebPageOrThrowAsync(LanPage, ct));
            CheckNoClash(before, r, except: null);
            var page = await WebPageOrThrowAsync(RsvAdd, ct); // its form carries the token to post with
            RequireFields(page, RsvAdd, "rsv_ip1", "rsv_ip4", "rsv_mac", "dv_name", "c4_rsv_ip");
            var result = await PostFormCoreAsync(FormAction(page), ReservationForm(r, page, submitter: ("Add", " Add ")), ct);
            var after = await LanAfterAsync(result, ct);
            if (!after.Reservations.Any(x => Same(x, r)))
                throw new RouterRejectedException(RouterMessage(result) ?? "The router didn't save the reservation.");
            return after;
        }
        finally { _lock.Release(); }
    }

    public async Task<DhcpInfo> UpdateReservationAsync(int number, string expectMac, DhcpReservation r, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var (lan, before, target) = await LoadTargetAsync(number, expectMac, ct);
            CheckNoClash(before, r, except: target);
            // The edit page also treats a matching NAME as a clash and offers to "overwrite" (effect unknown): refuse instead.
            if (before.Reservations.FirstOrDefault(x => x.Number != number && x.Name == r.Name) is { } twin)
                throw new ValidationException($"Reservation #{twin.Number} is already named “{r.Name}”. Pick a different name.");

            // Opening the editor changes nothing: it's the router's own "select a row, click Edit" step.
            var editor = await PostFormCoreAsync(FormAction(lan), LanForm(lan, "edit", number - 1), ct);
            RequireFields(editor, RsvEdit, "rsv_ip1", "rsv_ip4", "rsv_mac", "dv_name", "c4_rsv_ip", "h_ruleSelect", "edit");
            if (!SameMac(Field(editor, "rsv_mac") ?? "", target.Mac))
                throw new RouterRejectedException("The router opened a different reservation than expected. Nothing was changed; reload and try again.");

            var result = await PostFormCoreAsync(FormAction(editor), ReservationForm(r, editor, submitter: ("apply", " Apply ")), ct);
            var after = await LanAfterAsync(result, ct);
            var ok = after.Reservations.Any(x => Same(x, r))
                && after.Reservations.Count == before.Reservations.Count
                && (SameMac(target.Mac, r.Mac) || !after.Reservations.Any(x => SameMac(x.Mac, target.Mac)));
            if (!ok) throw new RouterRejectedException(RouterMessage(result) ?? "The router didn't save the change.");
            return after;
        }
        finally { _lock.Release(); }
    }

    public async Task<DhcpInfo> DeleteReservationAsync(int number, string expectMac, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var (lan, before, target) = await LoadTargetAsync(number, expectMac, ct);
            var result = await PostFormCoreAsync(FormAction(lan), LanForm(lan, "delete", number - 1), ct);
            var after = await LanAfterAsync(result, ct);
            if (after.Reservations.Count >= before.Reservations.Count || after.Reservations.Any(x => SameMac(x.Mac, target.Mac)))
                throw new RouterRejectedException(RouterMessage(result) ?? $"The router didn't delete the reservation for {target.Name}.");
            return after;
        }
        finally { _lock.Release(); }
    }

    // ───────────────────────── plumbing ─────────────────────────

    /// <summary>Loads LAN Setup and finds row #number, refusing if it's no longer the device the user picked.</summary>
    async Task<(string Page, DhcpInfo Info, DhcpReservation Target)> LoadTargetAsync(int number, string expectMac, CancellationToken ct)
    {
        var lan = await WebPageOrThrowAsync(LanPage, ct);
        var info = ParseLanPage(lan);
        var target = info.Reservations.FirstOrDefault(x => x.Number == number);
        if (target is null || !SameMac(target.Mac, expectMac))
            throw new RouterRejectedException("The reservation list changed on the router since it loaded. Reload and try again.");
        return (lan, info, target);
    }

    async Task<DhcpInfo> LanAfterAsync(string result, CancellationToken ct) =>
        ParseLanPage(result.Contains("all_reserve") ? result : await WebPageOrThrowAsync(LanPage, ct));

    /// <summary>The router's add page offers to silently OVERWRITE an entry with the same IP or MAC; never let that happen by accident.</summary>
    static void CheckNoClash(DhcpInfo info, DhcpReservation r, DhcpReservation? except)
    {
        // Same check as the add page's badIP(…, 254) + IsLanIpValid(dev_ip, dev_mask, ip).
        var b = System.Net.IPAddress.Parse(r.Ip).GetAddressBytes();
        if (System.Net.IPAddress.TryParse(info.LanIp, out var lan) && System.Net.IPAddress.TryParse(info.Mask, out var m))
        {
            var lb = lan.GetAddressBytes(); var mb = m.GetAddressBytes();
            if (Enumerable.Range(0, 4).Any(k => (b[k] & mb[k]) != (lb[k] & mb[k])))
                throw new ValidationException($"{r.Ip} isn't on your home network ({info.LanIp} / {info.Mask}).");
            if (lan.Equals(System.Net.IPAddress.Parse(r.Ip))) throw new ValidationException("That's the router's own address.");
        }
        if (b[3] is 0 or 255) throw new ValidationException($"{r.Ip} isn't a usable device address.");

        foreach (var x in info.Reservations)
        {
            if (except is not null && x.Number == except.Number) continue;
            if (SameMac(x.Mac, r.Mac)) throw new ValidationException($"{r.Mac} already has a reservation (#{x.Number} {x.Name} → {x.Ip}). Edit that one instead.");
            if (x.Ip == r.Ip) throw new ValidationException($"{r.Ip} is already reserved for {x.Name} (#{x.Number}).");
        }
    }

    /// <summary>
    /// The add/edit page's fields as the browser submits them after checkData() + dataToHidden(): the submit button
    /// (it sits above the fields), the visible fields, then every hidden input in page order (add page: c4_rsv_ip, todo,
    /// this_file, next_file, SID; edit page adds h_ruleSelect and edit=1), with c4_rsv_ip rebuilt from the IP octets.
    /// </summary>
    static List<(string, string)> ReservationForm(DhcpReservation r, string page, (string Name, string Value) submitter)
    {
        var ip = r.Ip.Split('.');
        List<(string, string)> f =
        [
            submitter,
            ("rsv_ip1", ip[0]), ("rsv_ip2", ip[1]), ("rsv_ip3", ip[2]), ("rsv_ip4", ip[3]),
            ("rsv_mac", r.Mac),
            ("dv_name", r.Name),
        ];
        foreach (var (name, value) in HiddenInputs(page))
            f.Add((name, name == "c4_rsv_ip" ? r.Ip : value));
        return f;
    }

    static IEnumerable<(string Name, string Value)> HiddenInputs(string page)
    {
        foreach (Match m in InputRx().Matches(HtmlCommentRx().Replace(page, "")))
        {
            if (!Regex.IsMatch(m.Value, @"\btype\s*=\s*[""']?hidden\b", RegexOptions.IgnoreCase)) continue;
            var n = Regex.Match(m.Value, @"\bname\s*=\s*[""']([^""']+)[""']", RegexOptions.IgnoreCase);
            if (!n.Success) continue;
            var v = Regex.Match(m.Value, @"\bvalue\s*=\s*""([^""]*)""", RegexOptions.IgnoreCase);
            yield return (n.Groups[1].Value, v.Success ? System.Net.WebUtility.HtmlDecode(v.Groups[1].Value) : "");
        }
    }

    /// <summary>
    /// LAN_lan.htm's form exactly as the browser submits it for Edit/Delete: onLoad runs dataToVisible() + loadcheck(),
    /// the user ticks a row's radio, then stdAction() sets todo and runs dataToHidden() before submit().
    /// Disabled fields (pool start/end octets 1–3) and buttons are not sent; the DHCP checkbox only when checked.
    /// </summary>
    static List<(string, string)> LanForm(string page, string todo, int index)
    {
        RequireFields(page, LanPage, "device_name", "c4_sysLANIPAddr", "c4_sysLANSubnetMask", "c4_sysPoolStartingAddr",
            "c4_sysPoolFinishAddr", "h_rip_direction", "h_sysRIPVersion", "h_dhcp_server", "h_wds", "h_apmode", "h_ruleSelect", "SID");
        if (Field(page, "h_wds") == "enable" && Field(page, "h_apmode") == "1")
            throw new RouterRejectedException("The router is in WDS/repeater mode, which locks LAN Setup. Change reservations on the router's own page.");

        string[] Ip4(string name) { var p = (Field(page, name) ?? "").Split('.'); return [.. Enumerable.Range(0, 4).Select(k => p.ElementAtOrDefault(k) ?? "")]; }
        static string Join(string[] p) => p[0].Length > 0 ? string.Join('.', p.Select(x => int.TryParse(x, out var v) ? v.ToString() : "NaN")) : ""; // ip4to1()

        var lanIp = Ip4("c4_sysLANIPAddr");
        var mask = Ip4("c4_sysLANSubnetMask");
        var start = Ip4("c4_sysPoolStartingAddr");
        var end = Ip4("c4_sysPoolFinishAddr");

        // Select values after dataToVisible + loadcheck; dataToHidden then copies the option VALUE into h_*.
        var rip = (Field(page, "h_rip_direction") ?? "") switch
        {
            "both" => "Both", "out" => "Out only", "in" => "In only",
            var h => SelectMatch(h, [("Both", "Both"), ("In only", "In Only"), ("Out only", "Out Only")]),
        };
        var ripVer = (Field(page, "h_sysRIPVersion") ?? "") switch
        {
            "0" => "Disable", "1" => "RIP_1", "2B" => "RIP_2B", "2M" => "RIP_2M",
            var h => SelectMatch(h, [("Disable", "Disabled"), ("RIP_1", "RIP_1"), ("RIP_2B", "RIP_2B"), ("RIP_2M", "RIP_2M")]),
        };
        var dhcpOn = Field(page, "h_dhcp_server") == "enable";
        var sel = index.ToString();

        List<(string, string)> f =
        [
            ("device_name", Field(page, "device_name") ?? ""),
            ("sysLANIPAddr1", lanIp[0]), ("sysLANIPAddr2", lanIp[1]), ("sysLANIPAddr3", lanIp[2]), ("sysLANIPAddr4", lanIp[3]),
            ("sysLANSubnetMask1", mask[0]), ("sysLANSubnetMask2", mask[1]), ("sysLANSubnetMask3", mask[2]), ("sysLANSubnetMask4", mask[3]),
            ("rip_direction", rip),
            ("sysRIPVersion", ripVer),
        ];
        if (dhcpOn) f.Add(("dhcp_server", "dhcp_server"));
        f.AddRange(
        [
            ("sysPoolStartingAddr4", start[3]),
            ("sysPoolFinishAddr4", end[3]),
            ("ruleSelect", sel),
            ("h_rip_direction", rip),
            ("h_sysRIPVersion", ripVer),
            ("h_dhcp_server", dhcpOn ? "enable" : "disable"),
            ("c4_sysLANIPAddr", Join(lanIp)),
            ("c4_sysLANSubnetMask", Join(mask)),
            ("c4_sysPoolStartingAddr", Join(start)),
            ("c4_sysPoolFinishAddr", Join(end)),
            ("h_wds", Field(page, "h_wds") ?? ""),
            ("h_apmode", Field(page, "h_apmode") ?? ""),
            ("h_ruleSelect", sel),
            ("todo", todo),
            ("this_file", LanPage),
            ("next_file", LanPage),
            ("SID", Field(page, "SID") ?? ""),
        ]);
        return f;
    }

    /// <summary>getSelIndex(): match an option's value or text exactly, else the first option.</summary>
    static string SelectMatch(string h, (string Value, string Text)[] options) =>
        h.Length == 0 ? options[0].Value : options.FirstOrDefault(o => o.Value == h || o.Text == h, options[0]).Value;

    static void RequireFields(string page, string file, params string[] names)
    {
        var missing = names.Where(n => Field(page, n) is null).ToList();
        if (missing.Count > 0)
            throw new RouterRejectedException($"{file} doesn't look like the R6350 page PurrRouter knows (missing {string.Join(", ", missing)}). Nothing was changed.");
    }

    static DhcpInfo ParseLanPage(string html)
    {
        var m = AllReserveRx().Match(html);
        if (!m.Success) throw new RouterRejectedException("Couldn't find the reservation table on LAN Setup (session expired?). Try again.");
        var list = m.Groups[1].Value.Split('\x02', StringSplitOptions.RemoveEmptyEntries)
            .Select(e => e.Split('\x01'))
            .Where(p => p.Length >= 3)
            .Select((p, i) => new DhcpReservation(i + 1, p[0].Trim(), Decode(p[1]), p[2].Trim().ToUpperInvariant()))
            .ToList();
        return new DhcpInfo(
            Field(html, "h_dhcp_server") is { } d ? d == "enable" : null,
            NullIfEmpty(Field(html, "c4_sysPoolStartingAddr")),
            NullIfEmpty(Field(html, "c4_sysPoolFinishAddr")),
            NullIfEmpty(Field(html, "c4_sysLANIPAddr")),
            NullIfEmpty(Field(html, "c4_sysLANSubnetMask")),
            list);
    }

    static string? NullIfEmpty(string? s) => string.IsNullOrWhiteSpace(s) ? null : s;
    static bool SameMac(string a, string b) => Norm(a) == Norm(b);
    static string Norm(string mac) => new([.. mac.Where(Uri.IsHexDigit).Select(char.ToUpperInvariant)]);
    static bool Same(DhcpReservation a, DhcpReservation b) => SameMac(a.Mac, b.Mac) && a.Ip == b.Ip && a.Name == b.Name;

    [GeneratedRegex(@"var\s+all_reserve\s*=\s*""([^""]*)""")]
    private static partial Regex AllReserveRx();
}
