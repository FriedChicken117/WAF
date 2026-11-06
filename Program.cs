using System.Text;
using WafProyecto.Waf;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddWaf(builder.Configuration);

var app = builder.Build();

// El WAF va primero y todo lo que está debajo es la aplicación destino que solo recibe las peticiones que superaron los controles.
// El Waf:Enabled = false permite comparar el comportamiento sin esta protección.
if (app.Configuration.GetValue("Waf:Enabled", true))
    app.UseWaf();
else
    app.Logger.LogWarning("WAF DESACTIVADO (Waf:Enabled = false). Solo para comparar en el laboratorio.");

// ---------- Aplicación destino ----------
app.MapGet("/", () => "Aplicación destino protegida por el WAF.");

// GET con parámetro
app.MapGet("/search", (string? q) => Results.Ok(new { consulta = q, resultados = 0 }));

// GET con nombre de archivo
app.MapGet("/files", (string? name) => Results.Ok(new { archivo = name }));

// POST con cuerpo
app.MapPost("/comment", async (HttpRequest request) =>
{
    using var reader = new StreamReader(request.Body, Encoding.UTF8);
    var body = await reader.ReadToEndAsync();
    return Results.Ok(new { caracteresRecibidos = body.Length });
});

app.Run();
