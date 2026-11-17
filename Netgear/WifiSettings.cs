namespace PurrRouter.Netgear;

/// <summary>One band's primary network as Setup > Wireless Setup shows it (no password: that's revealed on demand).</summary>
public record WifiBandSettings(string Band, string Ssid, bool Broadcast, string Channel, string[] ChannelOptions,
    string Mode, string Security, bool RadioOn);

public record WifiSettings(string Region, List<WifiBandSettings> Bands);

/// <summary>What the user may change per band. Null = keep the router's current value.</summary>
public record WifiBandChange(string? Ssid, string? Password, string? Channel, bool? Broadcast);

/// <summary>
/// Wireless Setup through the router's own pages, mirroring what WLG_dualband_idx.htm submits on Apply.
/// The page is a wrapper form full of hidden fields plus one iframe per band (WLG_2g_wireless2.htm /
/// WLG_5g_wireless2.htm). On Apply each iframe's checkData() → loadData() copies its fields into the wrapper's
/// hidden inputs, then the wrapper posts ALL its hidden inputs (its region select is disabled on US units, so it
/// isn't sent). So: load the pages in the browser's order, start from every hidden input as the router served it,
/// overwrite exactly the fields loadData() writes, and post. Untouched settings go back exactly as they were.
/// </summary>
public sealed partial class NetgearClient
{
    const string WlIdx = "WLG_dualband_idx.htm";
    const string Wl2g = "WLG_2g_wireless2.htm";
    const string Wl5g = "WLG_5g_wireless2.htm";
    const string WlAdv = "WLG_dualband_adv.htm";

    // Channel lists for the United States region, ported from the pages' setChannel() (StartChannel/FinishChannel
    // index 22 for 2.4 GHz; Band1 + Band4 for 5 GHz, no DFS outside Europe/China/India, 165 only at 20 MHz).
    static readonly string[] Us24 = ["0", .. Enumerable.Range(1, 11).Select(i => i.ToString())];
    static string[] Us5(bool twentyMhz) => ["0", "36", "40", "44", "48", "149", "153", "157", "161", .. twentyMhz ? new[] { "165" } : []];

    public async Task<WifiSettings> GetWifiSettingsAsync(CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var (idx, p24, p5) = await LoadWirelessAsync(ct);
            var adv = await WebPageOrThrowAsync(WlAdv, ct);
            return ParseWireless(idx, p24, p5, adv);
        }
        finally { _lock.Release(); }
    }

    public async Task<WifiSettings> SaveWifiSettingsAsync(WifiBandChange? b24, WifiBandChange? b5, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var (idx, p24, p5) = await LoadWirelessAsync(ct);
            var fields = WirelessForm(idx, p24, p5, b24, b5);
            var result = await PostFormCoreAsync(FormAction(idx), fields, ct);

            // Read back what the router now reports and make sure every requested change stuck.
            var (idx2, q24, q5) = await LoadWirelessAsync(ct);
            var adv = await WebPageOrThrowAsync(WlAdv, ct);
            var now = ParseWireless(idx2, q24, q5, adv);
            var problems = new List<string>();
            void Check(string band, WifiBandChange? c, string ssidField, string passField)
            {
                if (c is null) return;
                var b = now.Bands.First(x => x.Band == band);
                if (c.Ssid is { } s && b.Ssid != s) problems.Add($"{band} GHz name");
                if (c.Channel is { } ch && b.Channel != ch) problems.Add($"{band} GHz channel");
                if (c.Broadcast is { } bc && b.Broadcast != bc) problems.Add($"{band} GHz broadcast");
                if (c.Password is { } pw && (Field(idx2, passField) ?? "") != pw) problems.Add($"{band} GHz password");
            }
            Check("2.4", b24, "ssid", "passphrase");
            Check("5", b5, "ssid_an", "passphrase_an");
            if (problems.Count > 0)
                throw new RouterRejectedException((RouterMessage(result) ?? "The router didn't save everything.") + $" Not applied: {string.Join(", ", problems)}.");
            return now;
        }
        finally { _lock.Release(); }
    }

    /// <summary>The wrapper first, then its two iframes (with the same todo= the wrapper's iframe src uses), like a browser.</summary>
    async Task<(string Idx, string P24, string P5)> LoadWirelessAsync(CancellationToken ct)
    {
        var idx = await WebPageOrThrowAsync(WlIdx + "&todo=cfg_init", ct);
        var p24 = await WebPageOrThrowAsync(Wl2g + "&todo=wifi_primary_init", ct);
        var p5 = await WebPageOrThrowAsync(Wl5g + "&todo=wifi_primary_init", ct);
        RequireFields(idx, WlIdx, "ssid", "ssid_an", "passphrase", "passphrase_an", "h_w_channel", "h_w_channel_an", "h_ssid_bc",
            "h_ssid_bc_an", "h_opmode", "h_opmode_an", "h_security_type", "h_security_type_an", "h_enable_ap", "h_enable_ap_an",
            "h_enable_bss_coexist", "h_ssidSelect", "h_ssidSelect_an", "h_WRegion", "h_ssid_class", "load_2g_frame", "load_5g_frame", "SID");
        RequireFields(p24, Wl2g, "ssid", "passphrase", "h_enable_bssid", "h_enable_bss_coexist", "h_ssid_bc", "h_w_channel", "h_opmode", "h_security_type");
        RequireFields(p5, Wl5g, "ssid_an", "passphrase_an", "h_enable_bssid_an", "h_ssid_bc_an", "h_w_channel_an", "h_opmode_an", "h_security_type_an", "h_ssidSelect_an");
        return (idx, p24, p5);
    }

    static bool IsUsRegion(string idx) =>
        Field(idx, "h_WRegion") == "United States" && System.Text.RegularExpressions.Regex.IsMatch(idx, @"var\s+SKU\s*=\s*""(NA|US)""");

    static bool Is20Mhz5g(string idx) => Field(idx, "h_opmode_an") == "145"; // "Up to 400 Mbps" = first (20 MHz) option

    static WifiSettings ParseWireless(string idx, string p24, string p5, string adv)
    {
        var us = IsUsRegion(idx);
        var region = Field(idx, "h_WRegion") ?? "unknown";
        string Mode24(string? v) => v switch { "54" => "Up to 54 Mbps", "145" => "Up to 145 Mbps", "300" => "Up to 300 Mbps", _ => v ?? "unknown" };
        string Mode5(string? v) => v switch { "145" => "Up to 400 Mbps", "300" => "Up to 800 Mbps", "450" => "Up to 1733 Mbps", _ => v ?? "unknown" };
        return new WifiSettings(region,
        [
            new("2.4", Field(idx, "ssid") ?? "", Field(idx, "h_ssid_bc") == "enable", Field(idx, "h_w_channel") ?? "0",
                us ? Us24 : [], Mode24(Field(idx, "h_opmode")), Field(idx, "h_security_type") ?? "", Field(adv, "h_enable_ap") == "enable"),
            new("5", Field(idx, "ssid_an") ?? "", Field(idx, "h_ssid_bc_an") == "enable", Field(idx, "h_w_channel_an") ?? "0",
                us ? Us5(Is20Mhz5g(idx)) : [], Mode5(Field(idx, "h_opmode_an")), Field(idx, "h_security_type_an") ?? "", Field(adv, "h_enable_ap_an") == "enable"),
        ]);
    }

    /// <summary>
    /// WLG_dualband_idx.htm's form as the browser posts it on Apply: every hidden input in page order, with the
    /// values the two iframes' loadData() write (after their dataToVisible() on load and dataToHidden() on Apply).
    /// </summary>
    static List<(string, string)> WirelessForm(string idx, string p24, string p5, WifiBandChange? b24, WifiBandChange? b5)
    {
        if (!IsUsRegion(idx))
            throw new RouterRejectedException($"PurrRouter only knows this router's Wi-Fi channel rules for the United States region (router says “{Field(idx, "h_WRegion")}”). Nothing was changed.");
        if (Field(idx, "h_ssid_class") != "primary")
            throw new RouterRejectedException("The router's Wireless page isn't showing the main networks right now. Nothing was changed; try again.");
        if (Field(idx, "show_wps_alert") is { } wps && wps != "0")
            throw new RouterRejectedException("A WPS pairing is in progress on the router. Wait for it to finish and try again.");
        if (Field(idx, "wifi_smart_connect_enable") == "1")
            throw new RouterRejectedException("Smart Connect is on, which ties both bands together. PurrRouter doesn't handle that yet. Nothing was changed.");
        if (Field(idx, "h_security_type") != "WPA2-PSK" || Field(idx, "h_security_type_an") != "WPA2-PSK")
            throw new RouterRejectedException("PurrRouter only edits networks secured with WPA2-PSK. Nothing was changed.");

        // Each iframe's controls start from ITS fields (dataToVisible: a checkbox is checked when its h_ value is
        // "enable"; a select falls back to its first option, Auto, when the stored channel isn't in its list).
        string On(string page, string name) => Field(page, name) == "enable" ? "enable" : "";
        string F(string page, string name) => Field(page, name) ?? throw new RouterRejectedException($"Wi-Fi page is missing {name}. Nothing was changed.");
        string Ch(string page, string name, string[] list) => list.Contains(F(page, name)) ? F(page, name) : "0";
        var v = new Dictionary<string, string>
        {
            // 2.4 GHz loadData()
            ["h_enable_ap"] = On(p24, "h_enable_bssid"),
            ["h_ssid_bc"] = b24?.Broadcast is { } bc24 ? (bc24 ? "enable" : "") : On(p24, "h_ssid_bc"),
            ["h_enable_bss_coexist"] = On(p24, "h_enable_bss_coexist"),
            ["ssid"] = b24?.Ssid ?? F(p24, "ssid"),
            ["h_w_channel"] = b24?.Channel ?? Ch(p24, "h_w_channel", Us24),
            ["h_opmode"] = F(p24, "h_opmode"),
            ["h_security_type"] = F(p24, "h_security_type"),
            ["h_ssidSelect"] = F(idx, "h_ssidSelect"), // preinit() copies the wrapper's into the iframe
            ["passphrase"] = b24?.Password ?? F(p24, "passphrase"),
            ["load_2g_frame"] = Wl2g,
            // 5 GHz loadData()
            ["h_enable_ap_an"] = On(p5, "h_enable_bssid_an"),
            ["h_ssid_bc_an"] = b5?.Broadcast is { } bc5 ? (bc5 ? "enable" : "") : On(p5, "h_ssid_bc_an"),
            ["ssid_an"] = b5?.Ssid ?? F(p5, "ssid_an"),
            ["h_w_channel_an"] = b5?.Channel ?? Ch(p5, "h_w_channel_an", Us5(Is20Mhz5g(idx))),
            ["h_opmode_an"] = F(p5, "h_opmode_an"),
            ["h_security_type_an"] = F(p5, "h_security_type_an"),
            ["passphrase_an"] = b5?.Password ?? F(p5, "passphrase_an"),
            ["h_ssidSelect_an"] = F(p5, "h_ssidSelect_an"),
            ["load_5g_frame"] = Wl5g,
            // the wrapper's own dataToHidden(): its (disabled) region select is "United States"
            ["h_WRegion"] = "United States",
        };

        if (b24?.Channel is { } c24 && !Us24.Contains(c24)) throw new ValidationException($"2.4 GHz channel {c24} isn't allowed here.");
        if (b5?.Channel is { } c5 && !Us5(Is20Mhz5g(idx)).Contains(c5)) throw new ValidationException($"5 GHz channel {c5} isn't allowed with the current 5 GHz mode.");

        var f = HiddenInputs(idx).Select(h => (h.Name, v.TryGetValue(h.Name, out var nv) ? nv : h.Value)).ToList();
        var missing = v.Keys.Where(k => !f.Any(x => x.Name == k)).ToList();
        if (missing.Count > 0) throw new RouterRejectedException($"{WlIdx} is missing {string.Join(", ", missing)}. Nothing was changed.");
        return f;
    }
}
