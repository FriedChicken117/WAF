#!/usr/bin/env python3
"""Ejecuta casos.csv contra el WAF y resume los resultados (Red Team simulado).

Uso:
  python3 ejecutar_casos.py                      # contra http://localhost:5080
  python3 ejecutar_casos.py --base http://192.168.56.10:5080 --hilos 16
  python3 ejecutar_casos.py --solo SQLI          # una sola categoría (SQLI, XSS, PT, IRREG, LEGIT)
Código de salida: 0 si todos los casos dieron el resultado esperado, 1 si no.
"""
import argparse, collections, csv, http.client, os, sys, time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urlsplit

AQUI = os.path.dirname(os.path.abspath(__file__))
OVERSIZE = "@@OVERSIZE@@"


def enviar(base, caso, timeout=20):
    partes = urlsplit(base)
    destino = quote(caso["destino"], safe="%/?&=:;,+@$!*'()~#[]-._\\")  # solo escapa lo no ASCII
    cuerpo = caso["cuerpo"]
    if cuerpo == OVERSIZE:
        cuerpo = "comentario=" + "A" * 1_200_000
    datos = cuerpo.encode("utf-8") if cuerpo else None
    cabeceras = {"Connection": "close"}
    if caso["tipo_contenido"]:
        cabeceras["Content-Type"] = caso["tipo_contenido"]
    if datos is not None:
        cabeceras["Content-Length"] = str(len(datos))
    con = http.client.HTTPConnection(partes.hostname, partes.port or 80, timeout=timeout)
    try:
        con.request(caso["metodo"], destino, body=datos, headers=cabeceras)
        return con.getresponse().status
    except Exception as ex:                      # el servidor cortó la conexión, etc.
        return f"ERR:{type(ex).__name__}"
    finally:
        con.close()


def verificar_servidor(base):
    """Prueba una petición simple antes de lanzar los 770 casos y explica el error si no hay conexión."""
    estado = enviar(base, {"metodo": "GET", "destino": "/", "tipo_contenido": "", "cuerpo": ""}, timeout=5)
    if isinstance(estado, int):
        return
    print(f"No se pudo conectar con {base}  ({estado})")
    if "gaierror" in estado:
        print("  El nombre del servidor no existe: revisa que la URL esté bien escrita, por ejemplo http://localhost:5080")
    else:
        print("  Revisa que la aplicación esté corriendo y, si usas Docker, que el puerto publicado coincida con el que escucha la app.")
        print("  Prueba primero en el navegador: " + base + "/")
    sys.exit(2)


def cumple(esperado, estado):
    if not isinstance(estado, int):
        return False
    return estado < 500 if esperado == "no5xx" else str(estado) == esperado


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:5080")
    ap.add_argument("--csv", default=os.path.join(AQUI, "casos.csv"))
    ap.add_argument("--hilos", type=int, default=8)
    ap.add_argument("--solo", help="categoría a ejecutar")
    args = ap.parse_args()

    with open(args.csv, encoding="utf-8", newline="") as f:
        casos = [c for c in csv.DictReader(f) if not args.solo or c["categoria"] == args.solo]
    verificar_servidor(args.base)
    print(f"Ejecutando {len(casos)} casos contra {args.base} con {args.hilos} hilos...")

    t0 = time.time()
    with ThreadPoolExecutor(args.hilos) as pool:
        estados = list(pool.map(lambda c: enviar(args.base, c), casos))
    seg = time.time() - t0

    resumen = collections.defaultdict(lambda: [0, 0])
    fallos = []
    for c, e in zip(casos, estados):
        ok = cumple(c["esperado"], e)
        resumen[c["categoria"]][0] += 1
        resumen[c["categoria"]][1] += ok
        if not ok:
            fallos.append((c, e))

    print(f"\n{'Categoría':<8}{'Casos':>7}{'Correctos':>11}{'Fallos':>8}")
    for k, (total, bien) in resumen.items():
        print(f"{k:<8}{total:>7}{bien:>11}{total - bien:>8}")
    total = sum(v[0] for v in resumen.values())
    bien = sum(v[1] for v in resumen.values())
    print(f"{'TOTAL':<8}{total:>7}{bien:>11}{total - bien:>8}   ({seg:.1f} s)")

    if fallos:
        print("\nCasos con resultado inesperado (máx. 30):")
        for c, e in fallos[:30]:
            print(f"  {c['id']}  {c['subtipo']}  esperado={c['esperado']}  obtenido={e}")
            print(f"      {c['metodo']} {c['destino'][:90]}")
    sys.exit(1 if fallos else 0)


if __name__ == "__main__":
    main()
