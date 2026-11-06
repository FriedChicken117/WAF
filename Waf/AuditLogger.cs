using System.Text;
using Microsoft.Extensions.Options;

namespace WafProyecto.Waf;

// Escribe una línea por evento en un archivo local.
// Formato fecha | hora | IP | tipo de ataque | regla | método | origen | destino | fragmento
public sealed class AuditLogger
{
    private readonly string _path;
    private readonly object _lock = new();
    private readonly ILogger<AuditLogger> _logger;

    public AuditLogger(IOptions<WafOptions> options, IHostEnvironment env, ILogger<AuditLogger> logger)
    {
        _logger = logger;

        var configured = options.Value.LogPath;
        _path = Path.IsPathRooted(configured)
            ? configured
            : Path.Combine(env.ContentRootPath, configured);

        var directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
    }

    public void Record(DateTimeOffset when, string ip, AttackType type, string ruleId,
                       string method, string origin, string target, string excerpt)
    {
        var line = string.Join(" | ",
            when.ToString("yyyy-MM-dd"),
            when.ToString("HH:mm:ss"),
            Clean(ip, 45),
            type.Label(),
            ruleId,
            Clean(method, 10),
            origin,
            Clean(target, 200),
            Clean(excerpt, 100));

        try
        {
            lock (_lock)
            {
                File.AppendAllText(_path, line + Environment.NewLine, Encoding.UTF8);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Si el log falla el bloqueo igual se aplica y solo se avisa por la consola.
            _logger.LogError(ex, "No se pudo escribir en el log de auditoría: {Line}", line);
        }
    }

    private static string Clean(string value, int maxLength)
    {
        var sb = new StringBuilder(Math.Min(value.Length, maxLength));

        foreach (var c in value)
        {
            if (sb.Length >= maxLength) { sb.Append('…'); break; }
            sb.Append(char.IsControl(c) ? ' ' : c == '|' ? '/' : c);
        }

        return sb.ToString();
    }
}
