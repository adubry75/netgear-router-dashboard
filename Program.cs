using System.Diagnostics;
using Microsoft.AspNetCore.DataProtection;
using PurrRouter.Netgear;

var builder = WebApplication.CreateBuilder(args);

// Local-only: the app holds your router password, so never listen on the network.
builder.WebHost.UseUrls(builder.Configuration["Urls"] ?? "http://127.0.0.1:5280");

var dp = builder.Services.AddDataProtection()
    .SetApplicationName("RouterDash") // keep: changing it would make the saved password unreadable
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(SettingsStore.DataDir, "keys")));
if (OperatingSystem.IsWindows()) dp.ProtectKeysWithDpapi();

builder.Services.AddSingleton<SettingsStore>();
builder.Services.AddSingleton<RouterService>();
builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.DefaultIgnoreCondition =
    System.Text.Json.Serialization.JsonIgnoreCondition.Never);

var app = builder.Build();

// Block other websites from poking this API (CSRF / DNS rebinding): require a localhost Host
// and a custom header on writes, which browsers won't send cross-origin without a preflight we never allow.
app.Use(async (ctx, next) =>
{
    var host = ctx.Request.Host.Host;
    if (host is not ("localhost" or "127.0.0.1" or "[::1]" or "::1"))
    {
        ctx.Response.StatusCode = 421;
        return;
    }
    if (ctx.Request.Path.StartsWithSegments("/api") && !HttpMethods.IsGet(ctx.Request.Method)
        && ctx.Request.Headers["X-PurrRouter"] != "1")
    {
        ctx.Response.StatusCode = 403;
        return;
    }
    await next();
});

app.UseDefaultFiles();   // "/" → "/index.html"
app.UseStaticFiles(new StaticFileOptions // plain static files: works from dotnet run, a built DLL, or a publish
{
    // Revalidate every load (cheap 304s on localhost) so an updated app.js/app.css never shows up stale.
    OnPrepareResponse = c => c.Context.Response.Headers.CacheControl = "no-cache",
});

var api = app.MapGroup("/api");

api.MapGet("/status", (RouterService r) => new
{
    configured = r.IsConfigured,
    host = r.CurrentSettings?.Host,
    port = r.CurrentSettings?.Port,
    useHttps = r.CurrentSettings?.UseHttps,
    username = r.CurrentSettings?.Username,
});

api.MapPost("/setup", async (SetupRequest req, RouterService r, CancellationToken ct) =>
{
    var settings = new RouterSettings
    {
        Host = string.IsNullOrWhiteSpace(req.Host) ? "192.168.1.1" : req.Host.Trim(),
        Port = req.Port is > 0 and < 65536 ? req.Port.Value : (req.UseHttps ? 443 : 80),
        UseHttps = req.UseHttps,
        Username = string.IsNullOrWhiteSpace(req.Username) ? "admin" : req.Username.Trim(),
        Password = req.Password ?? "",
    };
    return await r.ConfigureAsync(settings, ct) is { } error
        ? Results.BadRequest(new { error })
        : Results.Ok(new { ok = true });
});

api.MapPost("/forget", (RouterService r) => { r.Forget(); return Results.Ok(); });

api.MapGet("/snapshot", (bool? force, RouterService r, CancellationToken ct) =>
    Guard(async () => Results.Ok(await r.GetSnapshotAsync(force == true, ct))));

api.MapPost("/devices/{mac}/access", (string mac, AccessRequest req, RouterService r, CancellationToken ct) =>
    Guard(async () => await r.SetAccessAsync(mac, req.Allow, ct)
        ? Results.Ok()
        : Results.Problem("The router didn't accept that change. Access Control may be turned off.")));

api.MapPost("/devices/{mac}/nickname", (string mac, NicknameRequest req, RouterService r) =>
{
    r.SetNickname(mac.ToUpperInvariant(), req.Name);
    return Results.Ok();
});

api.MapPost("/devices/acknowledge", (AckRequest req, RouterService r) =>
{
    r.Acknowledge(req.Macs.Select(m => m.ToUpperInvariant()));
    return Results.Ok();
});

api.MapPost("/wifi/{band}/guest", (string band, GuestRequest req, RouterService r, CancellationToken ct) =>
    Guard(async () => await r.SetGuestAsync(band, req.Enabled, ct)
        ? Results.Ok()
        : Results.Problem("The router didn't accept the guest network change.")));

api.MapGet("/wifi/{band}/password", (string band, RouterService r, CancellationToken ct) =>
    Guard(async () => Results.Ok(new { password = await r.GetWifiPasswordAsync(band, ct) })));

api.MapGet("/diag", () => Results.Text(File.Exists(Diag.Path)
    ? string.Join('\n', File.ReadLines(Diag.Path).TakeLast(200)) : "(no log yet)"));

// Read-only viewer for router web pages (to map features). Only plain page loads are allowed:
// no setup.cgi "todo=" actions, no POSTs, so nothing here can change a setting.
api.MapGet("/router-page", (string path, RouterService r, CancellationToken ct) => Guard(async () =>
{
    path = path.TrimStart('/');
    // Allowed: plain files, "page.htm&todo=cfg_init" (what the router's own menu loads), setup.cgi?next_file=page.
    var ok = System.Text.RegularExpressions.Regex.IsMatch(path,
        @"^(?:[A-Za-z0-9_\-./]+\.(?:htm|html|js|xml|css|txt)(?:&todo=cfg_init)?|setup\.cgi\?next_file=[A-Za-z0-9_\-./]+\.(?:htm|html|xml|js))$");
    if (!ok || path.Contains("..")) return Results.BadRequest(new { error = "Only plain page paths (or setup.cgi?next_file=page.htm) are allowed." });
    var (status, body) = await r.GetRouterPageAsync(path, ct);
    // Hide session tokens (SID etc.): they're not needed to understand a page.
    body = System.Text.RegularExpressions.Regex.Replace(body,
        @"((?:SID|sid|token|Token|TOKEN|session|csrf|xsrf)\w*[""']?\s*(?:[=:]|value=)\s*[""']?)[A-Za-z0-9+/=_\-]{6,}", "$1[hidden]");
    return Results.Text(body, "text/plain; charset=utf-8", statusCode: status);
}));

// ───── port forwarding ─────
api.MapGet("/portforwards", (RouterService r, CancellationToken ct) =>
    Guard(async () => Results.Ok(await r.GetPortForwardsAsync(ct))));
api.MapGet("/portforwards/{n:int}", (int n, RouterService r, CancellationToken ct) =>
    Guard(async () => await r.GetPortForwardAsync(n, ct) is { } rule ? Results.Ok(rule) : Results.NotFound(new { error = "That rule doesn't exist anymore." })));
api.MapPost("/portforwards", (PortForwardInput input, RouterService r, CancellationToken ct) =>
    Guard(async () => Results.Ok(await r.SavePortForwardAsync(null, input, ct))));
api.MapPut("/portforwards/{n:int}", (int n, PortForwardInput input, RouterService r, CancellationToken ct) =>
    Guard(async () => Results.Ok(await r.SavePortForwardAsync(n, input, ct))));
api.MapDelete("/portforwards/{n:int}", (int n, RouterService r, CancellationToken ct) =>
    Guard(async () => Results.Ok(await r.DeletePortForwardAsync(n, ct))));

// ───── DHCP reservations (LAN Setup) ─────
api.MapGet("/dhcp", (RouterService r, CancellationToken ct) =>
    Guard(async () => Results.Ok(await r.GetDhcpAsync(ct))));
api.MapPost("/dhcp/reservations", (ReservationInput input, RouterService r, CancellationToken ct) =>
    Guard(async () => Results.Ok(await r.SaveReservationAsync(null, input, ct))));
api.MapPut("/dhcp/reservations/{n:int}", (int n, ReservationInput input, RouterService r, CancellationToken ct) =>
    Guard(async () => Results.Ok(await r.SaveReservationAsync(n, input, ct))));
api.MapDelete("/dhcp/reservations/{n:int}", (int n, string? mac, RouterService r, CancellationToken ct) =>
    Guard(async () => Results.Ok(await r.DeleteReservationAsync(n, mac, ct))));

api.MapPost("/reboot", (RouterService r, CancellationToken ct) =>
    Guard(async () => await r.RebootAsync(ct) ? Results.Ok() : Results.Problem("Reboot request failed.")));

app.Lifetime.ApplicationStarted.Register(() =>
{
    var url = app.Urls.FirstOrDefault()?.Replace("127.0.0.1", "localhost");
    Console.WriteLine($"\n  😺 PurrRouter is running at {url}\n     Close this window to stop it.\n");
    if (url is not null && !args.Contains("--no-browser"))
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); } catch { /* no browser, fine */ }
    }
});

app.Run();

static async Task<IResult> Guard(Func<Task<IResult>> action)
{
    try { return await action(); }
    catch (RouterAuthException ex) { return Results.Json(new { error = ex.Message }, statusCode: 401); }
    catch (ValidationException ex) { return Results.Json(new { error = ex.Message }, statusCode: 400); }
    catch (RouterRejectedException ex) { return Results.Json(new { error = ex.Message }, statusCode: 422); }
    catch (InvalidOperationException ex) { return Results.Json(new { error = ex.Message }, statusCode: 409); }
    catch (Exception ex) when (ex is RouterUnreachableException or HttpRequestException or IOException or System.Net.Sockets.SocketException or TaskCanceledException)
    {
        // Show the whole chain: HttpRequestException's own message is useless, the inner one has the real cause.
        Console.Error.WriteLine(ex);
        var chain = new List<string>();
        for (Exception? e = ex; e is not null; e = e.InnerException) chain.Add($"{e.GetType().Name}: {e.Message}");
        return Results.Json(new { error = $"Couldn't reach the router. {string.Join(" → ", chain.Skip(ex is RouterUnreachableException ? 1 : 0))}" }, statusCode: 502);
    }
}

record SetupRequest(string? Host, int? Port, bool UseHttps, string? Username, string? Password);
record AccessRequest(bool Allow);
record NicknameRequest(string? Name);
record AckRequest(string[] Macs);
record GuestRequest(bool Enabled);
