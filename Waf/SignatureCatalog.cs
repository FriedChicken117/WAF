namespace WafProyecto.Waf;

//Una firma de ataque: identificador, tipo, expresión regular y descripción
public sealed record Signature(string Id, AttackType Type, string Pattern, string Description);

/// Diccionario de reglas:
/// Notación: \x27 = comilla simple y \x22 = comilla doble
public static class SignatureCatalog
{
    public static readonly IReadOnlyList<Signature> All = new List<Signature>
    {
        // ---------- Inyección SQL ----------
        new("SQLI-01", AttackType.SqlInjection, @"\bunion\b(?:\s|/\*.*?\*/)+(?:all\b(?:\s|/\*.*?\*/)+)?select\b", "UNION SELECT"),
        new("SQLI-02", AttackType.SqlInjection, @"['\x22]\s*(?:or|and)\b\s*['\x22(]?\s*\w*['\x22)]?\s*(?:=|<|>|like\b)", "Tautología tras comilla (' OR '1'='1)"),
        new("SQLI-03", AttackType.SqlInjection, @"\b(?:or|and)\s*\(?\s*(?:(\d+)\s*=\s*\1|(['\x22])\w*\2\s*=\s*['\x22]?\w*)", "Tautología numérica o de texto (OR 1=1)"),
        new("SQLI-04", AttackType.SqlInjection, @"[\w)]['\x22]\s*(?:--|/\*|#\s*$)", "Comilla seguida de comentario SQL"),
        new("SQLI-05", AttackType.SqlInjection, @";\s*(?:drop\s+(?:table|database)|delete\s+from|insert\s+into|update\s+\w+\s+set|alter\s+table|truncate\s+table|create\s+(?:table|user)|exec(?:ute)?\b|shutdown\b)", "Consultas apiladas"),
        new("SQLI-06", AttackType.SqlInjection, @"\b(?:sleep\s*\(\s*\d+|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay\b)", "Inyección ciega por tiempo"),
        new("SQLI-07", AttackType.SqlInjection, @"\b(?:information_schema|sysobjects|syscolumns|pg_catalog|xp_cmdshell|sqlite_master)\b", "Acceso a metadatos o procedimientos peligrosos"),
        new("SQLI-08", AttackType.SqlInjection, @"\(\s*select\b.{1,200}?\bfrom\b", "Subconsulta SELECT ... FROM"),
        new("SQLI-09", AttackType.SqlInjection, @"@@(?:version|servername|spid|language|rowcount|identity)\b", "Variables globales de SQL Server"),
        new("SQLI-10", AttackType.SqlInjection, @"\b(?:order|group)\s+by\s+\d+\s*(?:--|#|/\*|;|$)|\bhaving\s+\d+\s*=\s*\d+", "Sondeo de columnas (ORDER BY n, HAVING 1=1)"),
        new("SQLI-11", AttackType.SqlInjection, @"\b(?:extractvalue|updatexml|load_file)\s*\(|\binto\s+(?:out|dump)file\b", "Funciones de extracción de datos"),
        new("SQLI-12", AttackType.SqlInjection, @"['\x22]\s*(?:\|\||&&)", "Concatenación u operador lógico tras comilla"),

        // ---------- Cross Site Scripting ----------
        new("XSS-01", AttackType.Xss, @"<\s*/?\s*script\b", "Etiqueta <script>"),
        new("XSS-02", AttackType.Xss, @"\bon(?:error|load|click|dblclick|mouse[a-z]+|key[a-z]+|focus[a-z]*|blur|submit|change|toggle|input|animation[a-z]+|pointer[a-z]+|begin|start)\s*=", "Manejador de eventos HTML (onerror=, onload=...)"),
        new("XSS-03", AttackType.Xss, @"\bj\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:|\bvbscript\s*:", "Esquema javascript: o vbscript:"),
        new("XSS-04", AttackType.Xss, @"<\s*(?:iframe|object|embed|applet|svg|math|style|base)\b", "Etiquetas HTML peligrosas"),
        new("XSS-05", AttackType.Xss, @"\bdata\s*:\s*text/html|\bsrcdoc\s*=", "data:text/html o srcdoc"),
        new("XSS-06", AttackType.Xss, @"\bdocument\s*\.\s*(?:cookie|write|location|domain)|\bwindow\s*\.\s*location|\beval\s*\(|\bString\s*\.\s*fromCharCode\s*\(", "API de JavaScript usada en ataques"),

        // ---------- Path Traversal ----------
        new("PT-01", AttackType.PathTraversal, @"\.\.[/\\]|[/\\]\.\.(?:$|[?#;])", "Secuencia ../ o ..\\"),
        new("PT-02", AttackType.PathTraversal, @"%c0%(?:af|ae|2f)|%c1%(?:9c|1c)", "Codificación UTF-8 sobrelarga de / o ."),
        new("PT-03", AttackType.PathTraversal, @"/etc/(?:passwd|shadow|group|hosts)\b|/proc/self/|\bboot\.ini\b|\bwin\.ini\b|windows[/\\]+system32|\b[a-z]:[/\\]+windows", "Archivo sensible del sistema"),
        new("PT-04", AttackType.PathTraversal, @"\x00", "Byte nulo"),
    };

    // Firmas sin patrón, las usa el middleware cuando falla una condición de seguridad
    public static readonly Signature RegexTimeout =
        new("WAF-TIMEOUT", AttackType.Anomaly, "", "La evaluación excedió el tiempo límite (posible ReDoS)");

    public static readonly Signature BodyTooLarge =
        new("WAF-SIZE", AttackType.Anomaly, "", "Cuerpo mayor al límite permitido");
}
