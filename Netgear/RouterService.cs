using System.Globalization;

namespace PurrRouter.Netgear;

/// <summary>Owns the router connection and turns raw SOAP fields into a tidy snapshot for the UI.</summary>
public sealed class RouterService(SettingsStore store, ILogger<RouterService> log) : IDisposable
{
    NetgearClient? _client;
    readonly SemaphoreSlim _snapLock = new(1, 1);
    Snapshot? _cached;
    DateTime _cachedAt;

    // Things that rarely change get fetched every few minutes, not every refresh (the R6350 is easily overwhelmed).
    Dictionary<string, string?>? _info, _lan, _w24, _w5, _blockOn, _meterOn;
    DateTime _staticAt;
    Dictionary<string, string> _bands = [];
    DateTime _bandsAt;

    public bool IsConfigured => store.State.Router is not null;

    NetgearClient Client => _client ??= new NetgearClient(
        store.State.Router ?? throw new InvalidOperationException("Router not configured"), log);

    public void Dispose() => _client?.Dispose();

    public async Task<string?> ConfigureAsync(RouterSettings s, CancellationToken ct)
    {
        using var test = new NetgearClient(s, log);
        if (await test.TestLoginAsync(ct) is { } error) return error;

        store.SaveRouter(s);
        Reset();
        return null;
    }

    public void Forget() { store.ForgetRouter(); Reset(); }

    void Reset()
    {
        _client?.Dispose(); _client = null; _cached = null;
        _staticAt = _bandsAt = default; _bands = [];
    }

    public RouterSettings? CurrentSettings => store.State.Router;

    // ───────────────────────── snapshot ─────────────────────────

    public async Task<Snapshot> GetSnapshotAsync(bool force, CancellationToken ct)
    {
        await _snapLock.WaitAsync(ct);
        try
        {
            if (!force && _cached is not null && DateTime.UtcNow - _cachedAt < TimeSpan.FromSeconds(5))
                return _cached;

            _cached = await BuildSnapshotAsync(ct);
            _cachedAt = DateTime.UtcNow;
            return _cached;
        }
        finally { _snapLock.Release(); }
    }

    async Task<Snapshot> BuildSnapshotAsync(CancellationToken ct)
    {
        var c = Client;
        const string DI = NetgearClient.DeviceInfo, DC = NetgearClient.DeviceConfig, W = NetgearClient.Wlan;

        if (_info is null || DateTime.UtcNow - _staticAt > TimeSpan.FromMinutes(5))
        {
            _info = await c.GetAsync(DI, "GetInfo", ct);
            _lan = await c.GetAsync(NetgearClient.LanConfig, "GetInfo", ct);
            _w24 = await c.GetAsync(W, "GetInfo", ct);
            _w5 = await c.GetAsync(W, "Get5GInfo", ct);
            _blockOn = await c.GetAsync(DC, "GetBlockDeviceEnableStatus", ct);
            _meterOn = await c.GetAsync(DC, "GetTrafficMeterEnabled", ct);
            _staticAt = DateTime.UtcNow;
        }
        var (info, lan, w24, w5, blockOn, meterOn) = (_info, _lan, _w24, _w5, _blockOn, _meterOn);

        var wan = await c.GetAsync(NetgearClient.WanIp, "GetInfo", ct);
        var link = await c.GetAsync(NetgearClient.WanEthernet, "GetEthernetLinkStatus", ct);
        var g24 = await c.GetFirstAsync(W, ["GetGuestAccessEnabled", "GetGuestAccessEnabled2"], ct);
        var g5 = await c.GetFirstAsync(W, ["Get5GGuestAccessEnabled", "Get5G1GuestAccessEnabled", "Get5GGuestAccessEnabled2"], ct);
        var meter = await c.GetAsync(DC, "GetTrafficMeterStatistics", ct);
        var sys = await c.GetAsync(DI, "GetSystemInfo", ct);
        var devices = await c.GetAttachedDevicesAsync(ct) ?? [];

        // Band info: only when the SOAP list doesn't already say, refreshed every minute or when someone new shows up.
        if (devices.Any(d => NormalizeBand(d.ConnectionType, d.Ssid, []) is not ("wired" or "2.4" or "5"))
            && (DateTime.UtcNow - _bandsAt > TimeSpan.FromMinutes(1) || devices.Any(d => !_bands.ContainsKey(d.Mac))))
        {
            if (await c.GetBandMapAsync(ct) is { } map) _bands = map;
            _bandsAt = DateTime.UtcNow;
        }

        var wifi = new List<WifiBand>();
        if (w24 is not null) wifi.Add(Band("2.4", w24, Bool(g24)));
        if (w5 is not null) wifi.Add(Band("5", w5, Bool(g5)));

        return new Snapshot
        {
            FetchedAt = DateTimeOffset.Now,
            Router = new RouterInfo(
                V(info, "ModelName") ?? "Netgear",
                V(info, "DeviceName"),
                V(info, "Firmwareversion"),
                V(info, "SerialNumber"),
                V(info, "FirstUseDate"),
                Num(V(sys, "NewCPUUtilization")),
                Num(V(sys, "NewMemoryUtilization"))),
            Wan = new WanInfo(
                V(wan, "NewExternalIPAddress"),
                V(wan, "NewConnectionType") ?? V(wan, "NewAddressingType"),
                V(wan, "NewDefaultGateway"),
                V(wan, "NewDNSServers"),
                V(wan, "NewMACAddress"),
                V(link, "NewEthernetLinkStatus")),
            Lan = new LanInfo(V(lan, "NewLANIP"), V(lan, "NewLANSubnet"), V(lan, "NewLANMACAddress"), Bool(V(lan, "NewDHCPEnabled"))),
            Wifi = wifi,
            AccessControlOn = Bool(blockOn),
            Traffic = meter is null ? null : new Traffic(
                Bool(meterOn) ?? true,
                Usage(meter, "Today"), Usage(meter, "Yesterday"), Usage(meter, "Week"),
                Usage(meter, "Month"), Usage(meter, "LastMonth")),
            Devices = ToDtos(devices, wifi),
        };
    }

    List<DeviceDto> ToDtos(List<RouterDevice> devices, List<WifiBand> wifi)
    {
        var st = store.State;
        if (!st.KnownMacsSeeded && devices.Count > 0)
            store.Update(s => { s.KnownMacs.UnionWith(devices.Select(d => d.Mac)); s.KnownMacsSeeded = true; });

        return devices.Select(d => new DeviceDto(
            d.Mac,
            d.Ip,
            d.Name,
            st.Nicknames.GetValueOrDefault(d.Mac),
            _bands.GetValueOrDefault(d.Mac) is { } b && NormalizeBand(d.ConnectionType, d.Ssid, wifi) is not ("wired" or "2.4" or "5")
                ? b : NormalizeBand(d.ConnectionType, d.Ssid, wifi),
            d.ConnectionType,
            d.Ssid,
            d.Signal,
            d.LinkRate,
            d.Access,
            d.Model,
            IsPrivateMac(d.Mac),
            !st.KnownMacs.Contains(d.Mac)
        )).OrderBy(d => IpSortKey(d.Ip)).ToList();
    }

    // ───────────────────────── actions ─────────────────────────

    public Task<bool> SetAccessAsync(string mac, bool allow, CancellationToken ct)
    {
        _cached = null;
        _staticAt = default;
        return Client.SetAsync(NetgearClient.DeviceConfig, "SetBlockDeviceByMAC",
            [("NewAllowOrBlock", allow ? "Allow" : "Block"), ("NewMACAddress", mac)], ct);
    }

    public async Task<bool> SetGuestAsync(string band, bool enabled, CancellationToken ct)
    {
        _cached = null;
        _staticAt = default;
        string[] setters = band == "5"
            ? ["Set5GGuestAccessEnabled", "Set5G1GuestAccessEnabled2", "Set5GGuestAccessEnabled2"]
            : ["SetGuestAccessEnabled", "SetGuestAccessEnabled2"];
        string[] getters = band == "5"
            ? ["Get5GGuestAccessEnabled", "Get5G1GuestAccessEnabled", "Get5GGuestAccessEnabled2"]
            : ["GetGuestAccessEnabled", "GetGuestAccessEnabled2"];

        foreach (var m in setters)
        {
            if (!await Client.SetAsync(NetgearClient.Wlan, m, [("NewGuestAccessEnabled", enabled ? "1" : "0")], ct)) continue;
            if (Bool(await Client.GetFirstAsync(NetgearClient.Wlan, getters, ct)) == enabled) return true;
        }
        return false;
    }

    public async Task<string?> GetWifiPasswordAsync(string band, CancellationToken ct)
    {
        var r = await Client.GetAsync(NetgearClient.Wlan, band == "5" ? "Get5GWPASecurityKeys" : "GetWPASecurityKeys", ct);
        return V(r, "NewWPAPassphrase");
    }

    // ───────────────────────── port forwarding ─────────────────────────

    public Task<List<PortForward>> GetPortForwardsAsync(CancellationToken ct) => Client.GetPortForwardsAsync(ct);
    public Task<PortForward?> GetPortForwardAsync(int n, CancellationToken ct) => Client.GetPortForwardAsync(n, ct);

    public async Task<List<PortForward>> SavePortForwardAsync(int? number, PortForwardInput input, CancellationToken ct)
    {
        var rule = ValidatePortForward(input, number ?? 0);
        return number is null
            ? await Client.AddPortForwardAsync(rule, ct)
            : await Client.UpdatePortForwardAsync(number.Value, rule, ct);
    }

    public Task<List<PortForward>> DeletePortForwardAsync(int n, CancellationToken ct) => Client.DeletePortForwardAsync(n, ct);

    /// <summary>Same rules as the router's own form (FW_forward_service.htm Check()), so it never gets junk.</summary>
    PortForward ValidatePortForward(PortForwardInput i, int number)
    {
        var name = (i.Name ?? "").Trim();
        if (name.Length is 0 or > 30 || name.Any(ch => ch is < ' ' or > '~'))
            throw new ValidationException("Name must be 1–30 plain characters (letters, numbers, spaces, punctuation).");

        var proto = (i.Protocol ?? "BOTH").ToUpperInvariant();
        if (!NetgearClient.Protocols.Contains(proto)) throw new ValidationException("Protocol must be TCP/UDP, TCP or UDP.");

        var ext = NormalizePorts(i.ExternalPorts, "External ports");
        var inn = string.IsNullOrWhiteSpace(i.InternalPorts) ? ext : NormalizePorts(i.InternalPorts, "Internal ports");
        var e = ext.Split(','); var n = inn.Split(',');
        if (e.Length != n.Length) throw new ValidationException("External and internal ports need the same number of entries.");
        for (var k = 0; k < e.Length; k++)
        {
            int Width(string r) { var p = r.Split('-'); return int.Parse(p[1]) - int.Parse(p[0]); }
            if (Width(e[k]) != Width(n[k])) throw new ValidationException($"Ranges {e[k]} and {n[k]} must be the same size.");
        }

        if (!System.Net.IPAddress.TryParse((i.Ip ?? "").Trim(), out var ip) || ip.GetAddressBytes() is not { Length: 4 } b)
            throw new ValidationException("Pick a device or enter a valid IPv4 address.");
        var lanIp = V(_lan, "NewLANIP") ?? store.State.Router?.Host ?? "";
        var mask = V(_lan, "NewLANSubnet") ?? "255.255.255.0";
        if (System.Net.IPAddress.TryParse(lanIp, out var lan) && System.Net.IPAddress.TryParse(mask, out var m))
        {
            var lb = lan.GetAddressBytes(); var mb = m.GetAddressBytes();
            if (Enumerable.Range(0, 4).Any(k => (b[k] & mb[k]) != (lb[k] & mb[k])))
                throw new ValidationException($"{ip} isn't on your home network ({lanIp} / {mask}).");
            if (ip.Equals(lan)) throw new ValidationException("That's the router's own address.");
        }
        if (b[3] is 0 or 255) throw new ValidationException($"{ip} isn't a usable device address.");

        return new PortForward(number, name, ext, inn, ip.ToString(), proto);
    }

    /// <summary>"80, 8000-8010" → "80-80,8000-8010" (the router's stored format). Ports 1–65534 like the router allows.</summary>
    static string NormalizePorts(string? raw, string label)
    {
        var items = (raw ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (items.Length == 0) throw new ValidationException($"{label}: enter a port like 8080 or a range like 5000-5010.");
        var output = new List<string>();
        foreach (var it in items)
        {
            var p = it.Split('-', StringSplitOptions.TrimEntries);
            if (p.Length > 2 || p.Any(x => !int.TryParse(x, out var v) || v is < 1 or > 65534))
                throw new ValidationException($"{label}: “{it}” isn't a valid port or range (1–65534).");
            var a = int.Parse(p[0]); var z = p.Length == 2 ? int.Parse(p[1]) : a;
            output.Add($"{Math.Min(a, z)}-{Math.Max(a, z)}");
        }
        return string.Join(",", output);
    }

    // ───────────────────────── Wi-Fi settings ─────────────────────────

    public Task<WifiSettings> GetWifiSettingsAsync(CancellationToken ct) => Client.GetWifiSettingsAsync(ct);

    public Task<WifiSettings> SaveWifiSettingsAsync(WifiSaveInput input, CancellationToken ct)
    {
        var b24 = ValidateBand("2.4 GHz", input.B24);
        var b5 = ValidateBand("5 GHz", input.B5);
        if (b24 is null && b5 is null) throw new ValidationException("Nothing to change.");
        return Client.SaveWifiSettingsAsync(b24, b5, ct);
    }

    /// <summary>Same rules as the Wireless pages' checkData(): SSID 1–32 printable chars, WPA2 key 8–63 printable or 64 hex.</summary>
    static WifiBandChange? ValidateBand(string label, WifiBandChange? c)
    {
        if (c is null) return null;
        if (c.Ssid is { } s && (s.Length is 0 or > 32 || s.Trim().Length == 0 || s.Any(ch => ch is < ' ' or > '~')))
            throw new ValidationException($"{label} network name must be 1–32 plain characters (letters, numbers, spaces, punctuation).");
        var pw = string.IsNullOrEmpty(c.Password) ? null : c.Password;
        if (pw is not null)
        {
            var hex64 = pw.Length == 64 && pw.All(Uri.IsHexDigit);
            if (!hex64 && (pw.Length is < 8 or > 63 || pw.Any(ch => ch is < ' ' or > '~')))
                throw new ValidationException($"{label} password must be 8–63 plain characters (or exactly 64 hex digits).");
        }
        if (c.Channel is { } ch && !System.Text.RegularExpressions.Regex.IsMatch(ch, "^[0-9]{1,3}$"))
            throw new ValidationException($"{label} channel must be Auto or a channel number.");
        return c with { Password = pw };
    }

    // ───────────────────────── DHCP reservations ─────────────────────────

    public Task<DhcpInfo> GetDhcpAsync(CancellationToken ct) => Client.GetDhcpAsync(ct);

    public async Task<DhcpInfo> SaveReservationAsync(int? number, ReservationInput input, CancellationToken ct)
    {
        var r = ValidateReservation(input);
        if (number is null) return await Client.AddReservationAsync(r, ct);
        var expect = (input.OriginalMac ?? "").Trim();
        if (expect.Length == 0) throw new ValidationException("Missing the reservation's original MAC address. Reload and try again.");
        return await Client.UpdateReservationAsync(number.Value, expect, r with { Number = number.Value }, ct);
    }

    public Task<DhcpInfo> DeleteReservationAsync(int n, string? mac, CancellationToken ct) =>
        string.IsNullOrWhiteSpace(mac)
            ? throw new ValidationException("Missing the reservation's MAC address. Reload and try again.")
            : Client.DeleteReservationAsync(n, mac, ct);

    /// <summary>Same rules as LAN_reserv_add.htm's checkData(), plus no quotes/backslashes (they'd break the router's own JS list).</summary>
    DhcpReservation ValidateReservation(ReservationInput i)
    {
        var name = (i.Name ?? "").Trim();
        if (name.Length is 0 or > 20 || name.Any(ch => ch is < ' ' or > '~' or '"' or '\\'))
            throw new ValidationException("Name must be 1–20 plain characters (letters, numbers, spaces, punctuation; no quotes or backslashes).");
        if (name is "UNKNOWN" or "UNKNOWN NAME") throw new ValidationException("Give the device a real name (the router refuses “UNKNOWN”).");

        var hex = new string([.. (i.Mac ?? "").Where(Uri.IsHexDigit)]).ToUpperInvariant();
        var macOk = hex.Length == 12 && System.Text.RegularExpressions.Regex.IsMatch((i.Mac ?? "").Trim(), @"^[0-9A-Fa-f]{2}([:-]?)([0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}$");
        if (!macOk) throw new ValidationException("MAC address must look like 44:61:32:2A:48:F6.");
        if ((Convert.ToByte(hex[..2], 16) & 1) == 1 || hex is "000000000000" or "FFFFFFFFFFFF")
            throw new ValidationException("That's not a device's MAC address (it's a multicast/broadcast one).");
        var mac = string.Join(':', Enumerable.Range(0, 6).Select(k => hex.Substring(k * 2, 2)));

        // Syntax only here; the client checks the subnet against LAN Setup's own LAN IP / mask right before saving.
        var raw = (i.Ip ?? "").Trim();
        if (raw.Split('.').Length != 4 || !System.Net.IPAddress.TryParse(raw, out var ip) || ip.GetAddressBytes().Length != 4)
            throw new ValidationException("Enter a valid IPv4 address like 192.168.1.50.");
        return new DhcpReservation(0, ip.ToString(), name, mac);
    }

    public Task<(int Status, string Body)> GetRouterPageAsync(string path, CancellationToken ct) =>
        Client.GetWebPageAsync(path, ct);

    public Task<bool> RebootAsync(CancellationToken ct)
    {
        _cached = null;
        return Client.SetAsync(NetgearClient.DeviceConfig, "Reboot", null, ct);
    }

    public void SetNickname(string mac, string? name)
    {
        store.Update(s =>
        {
            if (string.IsNullOrWhiteSpace(name)) s.Nicknames.Remove(mac);
            else s.Nicknames[mac] = name.Trim();
        });
        _cached = null;
    }

    public void Acknowledge(IEnumerable<string> macs)
    {
        store.Update(s => s.KnownMacs.UnionWith(macs));
        _cached = null;
    }

    // ───────────────────────── helpers ─────────────────────────

    static WifiBand Band(string band, Dictionary<string, string?> d, bool? guest) => new(
        band, V(d, "NewSSID"), V(d, "NewChannel"), V(d, "NewWirelessMode"),
        V(d, "NewStatus"), Bool(V(d, "NewEnable")), V(d, "NewWPAEncryptionModes") ?? V(d, "NewBasicEncryptionModes"), guest);

    static string? V(Dictionary<string, string?>? d, string k) => d is not null && d.TryGetValue(k, out var v) ? v : null;

    static bool? Bool(Dictionary<string, string?>? d) => d is { Count: 1 } ? Bool(d.Values.First()) : null;

    static bool? Bool(string? v) => v?.Trim().ToLowerInvariant() switch
    {
        "1" or "true" or "on" or "enabled" or "up" => true,
        "0" or "false" or "off" or "disabled" or "down" => false,
        _ => null,
    };

    static double? Num(string? v)
    {
        if (v is null) return null;
        v = v.Replace(",", "");
        if (v.Contains('/')) v = v.Split('/')[0];          // "total/avg"
        v = new string(v.TakeWhile(ch => char.IsDigit(ch) || ch == '.').ToArray());
        return double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out var n) ? n : null;
    }

    static Usage Usage(Dictionary<string, string?> m, string period) =>
        new(Num(V(m, $"New{period}Download")), Num(V(m, $"New{period}Upload")), V(m, $"New{period}ConnectionTime"));

    static string NormalizeBand(string? type, string? ssid, List<WifiBand> wifi)
    {
        var t = (type ?? "").ToLowerInvariant().Replace(" ", "");
        if (t.Contains("wired") || t.Contains("lan") || t.Contains("ethernet")) return "wired";
        if (t.Contains("5g")) return "5";
        if (t.Contains("2.4") || t.Contains("2g")) return "2.4";
        if (ssid is not null && wifi.FirstOrDefault(w => w.Ssid == ssid) is { } b) return b.Band;
        return t == "" ? "unknown" : t;
    }

    /// <summary>Phones randomize their MAC per network; those set the "locally administered" bit.</summary>
    static bool IsPrivateMac(string mac) =>
        mac.Length >= 2 && "26AE".Contains(char.ToUpperInvariant(mac[1]));

    static long IpSortKey(string? ip) =>
        System.Net.IPAddress.TryParse(ip, out var a) && a.GetAddressBytes() is { Length: 4 } b
            ? ((long)b[0] << 24) | ((long)b[1] << 16) | ((long)b[2] << 8) | b[3]
            : long.MaxValue;
}

public sealed class Snapshot
{
    public DateTimeOffset FetchedAt { get; init; }
    public required RouterInfo Router { get; init; }
    public required WanInfo Wan { get; init; }
    public required LanInfo Lan { get; init; }
    public required List<WifiBand> Wifi { get; init; }
    public bool? AccessControlOn { get; init; }
    public Traffic? Traffic { get; init; }
    public required List<DeviceDto> Devices { get; init; }
}

public record PortForwardInput(string? Name, string? Protocol, string? ExternalPorts, string? InternalPorts, string? Ip);
public record ReservationInput(string? Name, string? Mac, string? Ip, string? OriginalMac);
public record WifiSaveInput(WifiBandChange? B24, WifiBandChange? B5);
public sealed class ValidationException(string message) : Exception(message);

public record RouterInfo(string Model, string? Name, string? Firmware, string? Serial, string? FirstUse, double? Cpu, double? Memory);
public record WanInfo(string? ExternalIp, string? ConnectionType, string? Gateway, string? Dns, string? Mac, string? LinkStatus);
public record LanInfo(string? Ip, string? Subnet, string? Mac, bool? Dhcp);
public record WifiBand(string Band, string? Ssid, string? Channel, string? Mode, string? Status, bool? Enabled, string? Security, bool? GuestEnabled);
public record Usage(double? DownMb, double? UpMb, string? ConnectionTime);
public record Traffic(bool Enabled, Usage Today, Usage Yesterday, Usage Week, Usage Month, Usage LastMonth);
public record DeviceDto(
    string Mac, string? Ip, string? Name, string? Nickname, string Band, string? ConnectionType,
    string? Ssid, int? Signal, string? LinkRate, string? Access, string? Model, bool PrivateMac, bool IsNew);
