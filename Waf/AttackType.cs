namespace WafProyecto.Waf;

public enum AttackType
{
    SqlInjection,
    Xss,
    PathTraversal,
    Anomaly
}

public static class AttackTypeExtensions
{
    //Nombre corto que se escribe en los logs
    public static string Label(this AttackType type) => type switch
    {
        AttackType.SqlInjection => "SQLi",
        AttackType.Xss => "XSS",
        AttackType.PathTraversal => "PathTraversal",
        _ => "Anomalia"
    };
}
