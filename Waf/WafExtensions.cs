namespace WafProyecto.Waf;

public static class WafExtensions
{
    //Registra la configuración, el motor de reglas y los logs
    public static IServiceCollection AddWaf(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<WafOptions>(configuration.GetSection(WafOptions.SectionName));
        services.AddSingleton<SignatureEngine>();
        services.AddSingleton<AuditLogger>();
        return services;
    }

    // Agrega el WAF al pipeline. Debe ir antes de cualquier endpoint
    public static IApplicationBuilder UseWaf(this IApplicationBuilder app) => app.UseMiddleware<WafMiddleware>();
}
