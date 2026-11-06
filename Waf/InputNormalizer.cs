using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace WafProyecto.Waf;

/// Deja la entrada en su forma real antes de aplicar las RegEx
public static class InputNormalizer
{
    private const int MaxPasses = 3; // cubre doble y triple codificación

    private static readonly Regex JsonUnicode = new(
        @"\\u([0-9a-fA-F]{4})",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    private static readonly Regex SqlComment = new(
        @"/\*.*?\*/",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.Singleline,
        TimeSpan.FromMilliseconds(100));

    // Formas del texto que se deben inspeccionar: la normalizada y si trae comentarios /**/ u
    // otra sin ellos: UNION/**/SELECT (que se lee como UNION SELECT) 
    // Se revisan las dos porque quitar comentarios podría esconder un XSS escrito dentro de uno
    public static IEnumerable<string> Variants(string input)
    {
        var normalized = Normalize(input);
        yield return normalized;

        var stripped = SqlComment.Replace(normalized, " ");
        if (stripped != normalized) yield return stripped;
    }

    public static string Normalize(string input)
    {
        var current = input;

        for (var pass = 0; pass < MaxPasses; pass++)
        {
            var decoded = current.Replace('+', ' ');   
            decoded = Uri.UnescapeDataString(decoded);  
            decoded = JsonUnicode.Replace(decoded, m =>
                ((char)Convert.ToInt32(m.Groups[1].Value, 16)).ToString());
            decoded = WebUtility.HtmlDecode(decoded);

            if (decoded == current) break;
            current = decoded;
        }

        try
        {
            // Convierte caracteres a su forma normal
            return current.Normalize(NormalizationForm.FormKC);
        }
        catch (ArgumentException)
        {
            return current; // texto Unicode inválido que se inspecciona tal cual
        }
    }
}
