#!/usr/bin/env bash
# Pruebas del WAF con cURL. Uso: ./pruebas.sh [url-base]   (por defecto http://localhost:5080)
BASE="${1:-http://localhost:5080}"
FALLOS=0

# check "descripción" código-esperado [argumentos de curl...]
check() {
  local desc="$1" esperado="$2"; shift 2
  local codigo
  codigo=$(curl -s -o /dev/null -w '%{http_code}' --path-as-is "$@")
  if [[ "$codigo" == "$esperado" ]]; then
    printf 'OK     %-45s -> %s\n' "$desc" "$codigo"
  else
    printf 'FALLO  %-45s -> %s (esperado %s)\n' "$desc" "$codigo" "$esperado"
    FALLOS=1
  fi
}

echo "=== Tráfico legítimo (esperado 200) ==="
check "GET búsqueda normal"            200 -G "$BASE/search" --data-urlencode "q=zapatos rojos"
check "GET con apóstrofe (O'Reilly)"   200 -G "$BASE/search" --data-urlencode "q=O'Reilly"
check "GET texto con 'and' y 'or'"     200 -G "$BASE/search" --data-urlencode "q=rock and roll or jazz"
check "POST formulario normal"         200 "$BASE/comment" --data-urlencode "comentario=Excelente producto"
check "POST JSON normal"               200 "$BASE/comment" -H 'Content-Type: application/json' --data-raw '{"comentario":"Muy buen servicio"}'

echo
echo "=== SQL Injection (esperado 403) ==="
check "GET  ' OR '1'='1"               403 -G "$BASE/search" --data-urlencode "q=' OR '1'='1"
check "GET  UNION SELECT"              403 -G "$BASE/search" --data-urlencode "q=1 UNION SELECT username,password FROM users--"
check "GET  DROP TABLE apilado"        403 -G "$BASE/search" --data-urlencode "q=1; DROP TABLE users"
check "GET  SLEEP (ciega por tiempo)"  403 -G "$BASE/search" --data-urlencode "q=1 AND SLEEP(5)"
check "GET  OR 1=1"                    403 -G "$BASE/search" --data-urlencode "q=1 OR 1=1"
check "POST ' OR '1'='1"               403 "$BASE/comment" --data-urlencode "usuario=admin' --"

echo
echo "=== XSS (esperado 403) ==="
check "GET  <script>"                  403 -G "$BASE/search" --data-urlencode "q=<script>alert(1)</script>"
check "GET  <img onerror>"             403 -G "$BASE/search" --data-urlencode "q=<img src=x onerror=alert(1)>"
check "GET  javascript:"               403 -G "$BASE/search" --data-urlencode "q=javascript:alert(1)"
check "POST <script>"                  403 "$BASE/comment" --data-urlencode "comentario=<script>alert(1)</script>"
check "POST JSON con \\u003cscript"    403 "$BASE/comment" -H 'Content-Type: application/json' --data-raw '{"comentario":"<script>alert(1)</script>"}'

echo
echo "=== Path Traversal (esperado 403) ==="
check "GET  ../../etc/passwd"          403 -G "$BASE/files" --data-urlencode "name=../../etc/passwd"
check "GET  ..%2f..%2f codificado"     403 "$BASE/files?name=..%2f..%2fetc%2fpasswd"
check "GET  doble codificación %252e"  403 "$BASE/files?name=%252e%252e%252fsecreto.txt"
check "GET  ruta ..%2f en la URL"      403 "$BASE/..%2f..%2fetc/passwd"
check "GET  ..\\..\\windows\\win.ini"  403 "$BASE/files?name=..%5c..%5cwindows%5cwin.ini"

echo
echo "=== Registro de auditoría (últimas líneas) ==="
tail -n 8 "$(dirname "$0")/logs/waf-audit.log" 2>/dev/null || echo "(no se encontró logs/waf-audit.log)"

exit $FALLOS
