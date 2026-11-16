using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;

namespace PurrRouter.Netgear;

public sealed class RouterSettings
{
    public string Host { get; set; } = "192.168.1.1";
    public int Port { get; set; } = 80;
    public bool UseHttps { get; set; }
    public string Username { get; set; } = "admin";

    /// <summary>Password encrypted with ASP.NET Data Protection (keys are DPAPI-protected on Windows).</summary>
    public string? ProtectedPassword { get; set; }

    [JsonIgnore] public string? Password { get; set; }
}

public sealed class AppState
{
    public RouterSettings? Router { get; set; }
    public Dictionary<string, string> Nicknames { get; set; } = [];
    public HashSet<string> KnownMacs { get; set; } = [];
    public bool KnownMacsSeeded { get; set; }
}

/// <summary>Persists settings to %LOCALAPPDATA%\PurrRouter\state.json.</summary>
public sealed class SettingsStore
{
    static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    readonly string _path;
    readonly IDataProtector _protector;
    readonly Lock _gate = new();

    public SettingsStore(IDataProtectionProvider dp)
    {
        _path = Path.Combine(DataDir, "state.json");
        _protector = dp.CreateProtector("RouterDash.RouterPassword");
        State = File.Exists(_path) ? JsonSerializer.Deserialize<AppState>(File.ReadAllText(_path)) ?? new() : new();

        if (State.Router?.ProtectedPassword is { } p)
        {
            try { State.Router.Password = _protector.Unprotect(p); }
            catch { State.Router = null; } // keys lost → ask for setup again
        }
    }

    public static string DataDir { get; } = ResolveDataDir();

    /// <summary>%LOCALAPPDATA%\PurrRouter (moved over from the old RouterDash folder on first run).</summary>
    static string ResolveDataDir()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var dir = Path.Combine(local, "PurrRouter");
        var old = Path.Combine(local, "RouterDash");
        if (!Directory.Exists(dir) && Directory.Exists(old))
        {
            try { Directory.Move(old, dir); }
            catch { CopyDir(old, dir); } // e.g. old app still running
        }
        return Directory.CreateDirectory(dir).FullName;
    }

    static void CopyDir(string from, string to)
    {
        Directory.CreateDirectory(to);
        foreach (var f in Directory.GetFiles(from)) File.Copy(f, Path.Combine(to, Path.GetFileName(f)), true);
        foreach (var d in Directory.GetDirectories(from)) CopyDir(d, Path.Combine(to, Path.GetFileName(d)));
    }

    public AppState State { get; }

    public void SaveRouter(RouterSettings s)
    {
        s.ProtectedPassword = _protector.Protect(s.Password ?? "");
        lock (_gate) { State.Router = s; Save(); }
    }

    public void ForgetRouter()
    {
        lock (_gate) { State.Router = null; Save(); }
    }

    public void Update(Action<AppState> change)
    {
        lock (_gate) { change(State); Save(); }
    }

    void Save() => File.WriteAllText(_path, JsonSerializer.Serialize(State, Json));
}
