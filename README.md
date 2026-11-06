# WafProyecto: WAF lógico a nivel de middleware (.NET 8)

## Ejecutar
```bash
dotnet run --urls http://localhost:5080     # sin Docker
./pruebas.sh                                # 20 pruebas rápidas con cURL
python3 casos/ejecutar_casos.py             # 770 casos (687 de ataque o irregulares y 83 legítimos)
```
Para probar desde otra máquina (modo Host-Only), usa `--urls http://0.0.0.0:5080`
y `--base http://IP-DE-LA-VM:5080` en el ejecutor.

### Con Docker
La aplicación ya no fija el puerto en `appsettings.json`: la imagen de .NET 8 escucha en el **8080** del contenedor.
```bash
docker run -p 5080:8080 ...                 # puerto 5080 de tu equipo -> 8080 del contenedor
python3 casos/ejecutar_casos.py --base http://localhost:5080
```
- La URL base es la del puerto **publicado en tu equipo** (`5080`), no la del contenedor (`8080`).
- Si `docker logs` muestra `Now listening on: http://localhost:5080`, el puerto está fijado dentro de la app y el mapeo `5080:8080` no llega a ella.

## Estructura
| Archivo | Rol |
|---|---|
| `Program.cs` | Pipeline: el WAF va primero; debajo, la aplicación destino de prueba |
| `Waf/WafMiddleware.cs` | Intercepta, inspecciona, bloquea (403) y audita |
| `Waf/SignatureCatalog.cs` | Diccionario de reglas (RegEx de SQLi, XSS y Path Traversal) |
| `Waf/SignatureEngine.cs` | Motor de evaluación (RegEx compiladas, con tiempo límite) |
| `Waf/InputNormalizer.cs` | Decodifica la entrada para evitar evasiones por codificación |
| `Waf/AuditLogger.cs` | Módulo forense: escribe `logs/waf-audit.log` |
| `casos/` | Corpus de pruebas: `casos.csv`, colección de Postman, ejecutor y generador |

## Casos de prueba (carpeta `casos/`)
- **Postman:** importa `waf.postman_collection.json`, ajusta la variable `baseUrl` y ejecuta la colección con el
  Collection Runner (o con Newman: `newman run casos/waf.postman_collection.json`). Cada petición ya trae su prueba.
  Postman puede normalizar algunos caracteres al enviar; el ejecutor en Python envía la URL exactamente como está en el CSV.
- **Ejecutor:** `python3 casos/ejecutar_casos.py [--base URL] [--hilos N] [--solo SQLI|XSS|PT|IRREG|LEGIT]`.
- **Generador:** `python3 casos/generar_casos.py` regenera el CSV y la colección. Para agregar casos, añade
  payloads a las listas `SQLI`, `XSS` o `PT`.
- Valores de `esperado`: `403` bloquear, `200` tráfico legítimo, `413` cuerpo grande, `no5xx` el servidor no debe fallar.

## Formato del log
`fecha | hora | IP | tipo de ataque | regla | método | origen (Ruta/Query/Body) | destino | fragmento`

## Limitaciones conocidas
- Detección por firmas: no reemplaza consultas parametrizadas ni codificación de salida en la aplicación.
- Los casos se generaron junto con las reglas: pasar el corpus no demuestra que no existan evasiones nuevas.
- El cuerpo se lee como UTF-8; otras codificaciones (por ejemplo UTF-16) no se inspeccionan bien.
- No se inspeccionan cabeceras ni cookies.
- La IP es la de la conexión directa; detrás de un proxy habría que configurar `ForwardedHeaders` con proxies de confianza.
