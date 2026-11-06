namespace WafProyecto.Waf;

//Configuración del WAF, enlazada al appsettings.json
public sealed class WafOptions
{
    public const string SectionName = "Waf";

    public bool Enabled { get; set; } = true;

    // Ruta del archivo de logs
    public string LogPath { get; set; } = "logs/waf-audit.log";

    //Tamaño máximo del cuerpo que el WAF acepta inspeccionar
    public int MaxBodyBytes { get; set; } = 1_048_576;

    //Tiempo máximo por expresión regular
    public int RegexTimeoutMs { get; set; } = 100;
}
