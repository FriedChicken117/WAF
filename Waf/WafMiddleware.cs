using System.Text;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;

namespace WafProyecto.Waf;

// Intercepta cada petición antes de que llegue a la aplicación destino, la inspecciona y si detecta un ataque responde 403 y lo registra.
public sealed class WafMiddleware
{
    // Métodos que pueden traer cuerpo. La ruta y la query se inspeccionan siempre (GET incluido).
    private static readonly HashSet<string> BodyMethods =
        new(StringComparer.OrdinalIgnoreCase) { "POST", "PUT", "PATCH" };

    private readonly RequestDelegate _next;
    private readonly SignatureEngine _engine;
    private readonly AuditLogger _audit;
    private readonly WafOptions _options;

    public WafMiddleware(RequestDelegate next, SignatureEngine engine, AuditLogger audit, IOptions<WafOptions> options)
    {
        _next = next;
        _engine = engine;
        _audit = audit;
        _options = options.Value;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var request = context.Request;
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "desconocida";

        // RawTarget es la URL tal como la envió el cliente sin decodificar
        var rawTarget = context.Features.Get<IHttpRequestFeature>()?.RawTarget
                        ?? $"{request.Path}{request.QueryString}";
        var (rawPath, rawQuery) = SplitTarget(rawTarget);

        // 1) Inspección de ruta y parámetros GET
        (Detection Detection, string Origin)? finding = null;

        if (_engine.Inspect(rawPath) is { } inPath)
        {
            finding = (inPath, "Ruta");
        }
        else if (_engine.Inspect(rawQuery) is { } inQuery)
        {
            finding = (inQuery, "Query");
        }
        // 2) Inspección del cuerpo (POST/PUT/PATCH)
        else if (BodyMethods.Contains(request.Method))
        {
            var (text, tooLarge) = await ReadBodyAsync(request);

            if (tooLarge)
            {
                _audit.Record(DateTimeOffset.Now, ip, SignatureCatalog.BodyTooLarge.Type,
                    SignatureCatalog.BodyTooLarge.Id, request.Method, "Body", rawTarget, "cuerpo mayor al límite");
                await RejectAsync(context, StatusCodes.Status413PayloadTooLarge,
                    "413 Payload Too Large: la petición excede el tamaño permitido.");
                return;
            }

            if (_engine.Inspect(text) is { } inBody)
                finding = (inBody, "Body");
        }

        // 3) Decisión: bloquear y auditar, o dejar pasar
        if (finding is { } f)
        {
            _audit.Record(DateTimeOffset.Now, ip, f.Detection.Signature.Type, f.Detection.Signature.Id,
                request.Method, f.Origin, rawTarget, f.Detection.Excerpt);

            await RejectAsync(context, StatusCodes.Status403Forbidden,
                "403 Forbidden: la petición fue bloqueada por el WAF.");
            return;
        }

        await _next(context);
    }

    // Lee el cuerpo sin consumirlo
    private async Task<(string Text, bool TooLarge)> ReadBodyAsync(HttpRequest request)
    {
        var limit = _options.MaxBodyBytes;

        if (request.ContentLength is long declared && declared > limit)
            return (string.Empty, true);

        // Permite leer el cuerpo y luego rebobinarlo
        request.EnableBuffering(bufferThreshold: 64 * 1024, bufferLimit: limit);

        try
        {
            using var reader = new StreamReader(request.Body, Encoding.UTF8,
                detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true);
            return (await reader.ReadToEndAsync(), false);
        }
        catch (InvalidDataException)
        {
            return (string.Empty, true);
        }
        finally
        {
            if (request.Body.CanSeek) request.Body.Position = 0; // rebobinar
        }
    }

    private static (string Path, string Query) SplitTarget(string target)
    {
        var i = target.IndexOf('?');
        return i < 0 ? (target, string.Empty) : (target[..i], target[(i + 1)..]);
    }

    private static Task RejectAsync(HttpContext context, int statusCode, string message)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "text/plain; charset=utf-8";
        return context.Response.WriteAsync(message); // no se revela qué regla se activó
    }
}
