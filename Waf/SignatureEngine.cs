using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace WafProyecto.Waf;

//Resultado de una detección
public sealed record Detection(Signature Signature, string Excerpt);

//Contrasta un texto contra todas las firmas del diccionario
public sealed class SignatureEngine
{
    private readonly (Signature Signature, Regex Regex)[] _compiled;

    public SignatureEngine(IOptions<WafOptions> options)
    {
        var timeout = TimeSpan.FromMilliseconds(options.Value.RegexTimeoutMs);
        const RegexOptions flags = RegexOptions.IgnoreCase
                                 | RegexOptions.CultureInvariant
                                 | RegexOptions.Singleline
                                 | RegexOptions.Compiled;

        _compiled = SignatureCatalog.All
            .Select(s => (s, new Regex(s.Pattern, flags, timeout)))
            .ToArray();
    }

    // Devuelve la primera detección encontrada o null si el texto parece limpio
    public Detection? Inspect(string? rawInput)
    {
        if (string.IsNullOrEmpty(rawInput)) return null;

        try
        {
            foreach (var input in InputNormalizer.Variants(rawInput))
            {
                foreach (var (signature, regex) in _compiled)
                {
                    var match = regex.Match(input);
                    if (match.Success) return new Detection(signature, match.Value);
                }
            }

            return null;
        }
        catch (RegexMatchTimeoutException)
        {
            // Si no se pudo evaluar a tiempo, se trata como sospechoso.
            return new Detection(SignatureCatalog.RegexTimeout, "tiempo de evaluación excedido");
        }
    }
}
