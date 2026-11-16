using System.Text.RegularExpressions;

namespace PurrRouter.Netgear;

/// <summary>Diagnostic log of every SOAP exchange: %LOCALAPPDATA%\PurrRouter\soap.log. Never logs passwords or cookie values.</summary>
static class Diag
{
    static readonly Lock Gate = new();
    public static string Path { get; } = System.IO.Path.Combine(SettingsStore.DataDir, "soap.log");

    public static void Log(string line)
    {
        lock (Gate)
        {
            try { File.AppendAllText(Path, $"{DateTime.Now:HH:mm:ss.fff}  {line}{Environment.NewLine}"); } catch { }
        }
    }

    /// <summary>"SID=[32 chars]; path=/" — keeps the structure, hides the value.</summary>
    public static string Shape(string? cookie) => cookie is null ? "none"
        : "\"" + Regex.Replace(cookie, @"=([^;,]*)", m => m.Groups[1].Length > 12 ? $"=[{m.Groups[1].Length} chars]" : m.Value) + "\"";

    public static string Chain(Exception ex)
    {
        var parts = new List<string>();
        for (Exception? e = ex; e is not null; e = e.InnerException) parts.Add($"{e.GetType().Name}: {e.Message}");
        return string.Join(" → ", parts);
    }
}
