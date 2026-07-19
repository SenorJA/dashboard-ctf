# Módulos Nuevos — Documentación Técnica

Nueve módulos integrados desde [CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects)
como herramientas API-based (sin dependencia de SSH/Kali).

---

## Índice

| #  | Módulo | Archivo | Endpoint |
|----|--------|---------|----------|
| 1  | HTTP Headers Scanner | `backend/headers_scanner.py` | `GET /api/headers/scan` |
| 2  | Secrets Scanner | `backend/secrets_scanner.py` | `GET /api/secrets/scan` |
| 3  | Port Scanner | `backend/port_scanner.py` | `GET /api/port/scan` |
| 4  | Subdomain Scanner | `backend/subdomain_scanner.py` | `GET /api/subdomain/scan` |
| 5  | DNS Lookup | `backend/dns_lookup.py` | `GET /api/dns/lookup` + `GET /api/dns/reverse` |
| 6  | Hash Cracker | `backend/hash_cracker.py` | `GET /api/hash/crack` |
| 7  | Steganography Tool | `backend/stego_tool.py` | `GET /api/stego/analyze` |
| 8  | Security News Scraper | `backend/news_scraper.py` | `GET /api/news` |
| 9  | API Security Scanner | `backend/api_scanner.py` | `GET /api/apiscan` |

---

## 1. HTTP Headers Scanner

**Archivo:** `backend/headers_scanner.py`
**Endpoint:** `GET /api/headers/scan`

Escanea los headers de seguridad HTTP de una URL y asigna una calificación A–F.

### Parámetros (Query)

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `url` | string | — | URL completa con scheme (http:// o https://) |
| `timeout` | float | 10.0 | Timeout de la petición en segundos |

### Respuesta

```json
{
  "ok": true,
  "url": "https://example.com",
  "status_code": 200,
  "score": 0,
  "grade": "F",
  "missing_headers": ["Strict-Transport-Security", "Content-Security-Policy", ...],
  "present_headers": {"server": "nginx/1.24.0", ...},
  "findings": [...]
}
```

### Clases principales

- `HeaderResult(url, status_code, score, grade, missing_headers, present_headers)`
- Función `scan(url, timeout) → HeaderResult`
- Función `report_to_mirv_findings(result) → list[dict]`

### Reglas de puntuación

- Strict-Transport-Security: +20
- X-Content-Type-Options: +15
- X-Frame-Options: +15
- Content-Security-Policy: +20
- X-XSS-Protection: +10
- Referrer-Policy: +10
- Permissions-Policy: +10
- A: 90-100, B: 70-89, C: 50-69, D: 30-49, E: 10-29, F: 0-9

---

## 2. Secrets Scanner

**Archivo:** `backend/secrets_scanner.py`
**Endpoint:** `GET /api/secrets/scan`

Detecta secretos (API keys, tokens, passwords) en el contenido de una URL o texto plano usando 25 patrones regex.

### Parámetros (Query)

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `url` | string | — | URL a escanear (alternativo a raw) |
| `raw` | string | — | Texto directo a escanear (alternativo a url) |

### Respuesta

```json
{
  "ok": true,
  "source": "https://example.com",
  "lines_scanned": 150,
  "secrets_found": 3,
  "findings": [...]
}
```

### Patrones detectados (25)

| Patrón | Ejemplo |
|--------|---------|
| AWS Access Key | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Key | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |
| GitHub Token | `ghp_xxxxxxxxxxxxxxxxxxxx` |
| Google API Key | `AIzaSyxxxxxxxxxxxxxxxxxxxxxx` |
| JWT Token | `eyJhbGciOiJIUzI1NiIs...` |
| Slack Token | `xoxb-xxxxxxxxxxxx-xxxxxxxxxxxx-xxxxxxxxx` |
| Generic Password | `password\s*[:=]["']?[^"'\s]+` |
| + 18 más (ver código fuente) |

---

## 3. Port Scanner

**Archivo:** `backend/port_scanner.py`
**Endpoint:** `GET /api/port/scan`

Escáner TCP asíncrono de puertos. Escanea ~1600 puertos comunes por defecto.

### Parámetros (Query)

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `target` | string | — | IP o hostname a escanear |
| `ports` | string | — | Puertos personalizados: "22,80,443" |
| `timeout` | float | 2.0 | Timeout por conexión (segundos) |
| `concurrency` | int | 100 | Conexiones simultáneas |
| `banner` | bool | false | Intentar banner grab |

### Respuesta

```json
{
  "ok": true,
  "target": "127.0.0.1",
  "resolved_ip": "127.0.0.1",
  "ports_scanned": 1600,
  "open_ports": 1,
  "results": [{"port": 8000, "service": "http", "banner": null}],
  "duration_seconds": 0.5,
  "findings": [...]
}
```

### Notas

- Usa `asyncio.open_connection()` con `asyncio.Semaphore` para concurrencia
- Servicios identificados vía `socket.getservbyport()` con fallback try/except
- Banner grabbing opcional con timeout de 3s

---

## 4. Subdomain Scanner

**Archivo:** `backend/subdomain_scanner.py`
**Endpoint:** `GET /api/subdomain/scan`

Enumeración de subdominios vía resolución DNS. ~700 prefijos comunes.

### Parámetros (Query)

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `domain` | string | — | Dominio a escanear (ej. "example.com") |
| `timeout` | float | 3.0 | Timeout por resolución DNS |
| `concurrency` | int | 50 | Resoluciones simultáneas |

### Respuesta

```json
{
  "ok": true,
  "domain": "example.com",
  "total_checked": 700,
  "found": 1,
  "results": [{"subdomain": "www", "full_domain": "www.example.com", "ips": ["93.184.216.34"], "cname": null}],
  "duration_seconds": 2.1,
  "findings": [...]
}
```

### Notas

- Usa `asyncio` + `socket` para resolución DNS
- Detecta CNAME, A/AAAA records
- Omite subdominios con wildcard DNS

---

## 5. DNS Lookup

**Archivo:** `backend/dns_lookup.py`
**Endpoints:** `GET /api/dns/lookup`, `GET /api/dns/reverse`

Consultas DNS múltiples vía DNS-over-HTTPS (Cloudflare). Sin dependencias externas.

### Parámetros (Query)

#### `/api/dns/lookup`
| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `domain` | string | — | Dominio a consultar |
| `types` | string | "A,AAAA,MX,TXT,NS,CNAME,SOA" | Tipos de registro (separados por coma) |
| `reverse` | bool | false | Intentar resolución inversa |

#### `/api/dns/reverse`
| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `ip` | string | — | IP a resolver inversamente |

### Respuesta

```json
{
  "ok": true,
  "domain": "google.com",
  "records": {
    "A": [{"name": "google.com", "type": "A", "ttl": 300, "value": "142.250.184.78"}],
    "MX": [{"name": "google.com", "type": "MX", "ttl": 600, "value": "10 smtp.google.com"}],
    ...
  },
  "reverse_dns": "mad01s26-in-f14.1e100.net",
  "duration_seconds": 0.21,
  "findings": [...]
}
```

### Notas

- Usa DNS-over-HTTPS via `https://cloudflare-dns.com/dns-query`
- Formato JSON (RFC 8427)
- No necesita `dnspython` ni otras librerías

---

## 6. Hash Cracker

**Archivo:** `backend/hash_cracker.py`
**Endpoint:** `GET /api/hash/crack`

Identificador de tipo de hash + crackeo offline contra rainbow table incorporada.

### Parámetros (Query)

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `hash` | string | — | Hash único a procesar |
| `hashes` | string | — | Lista de hashes separados por coma |
| `identify_only` | bool | false | Solo identificar, no crackear |

### Tipos detectables (20)

MD5, SHA1, SHA256, SHA384, SHA512, SHA224, NTLM, MD4, MD2, RIPEMD160, MySQL5, MySQL3, bcrypt, sha256crypt, sha512crypt, LM, CRC32, Adler32, GOST, Whirlpool

### Rainbow Table

- 200+ contraseñas comunes
- 4 hash types: MD5, SHA1, SHA256, SHA512
- Generada en memoria en primera ejecución (`_build_rainbow()`)

### Respuesta

```json
{
  "ok": true,
  "total": 3,
  "cracked": 2,
  "results": [
    {"hash": "5f4dcc...", "types": ["MD5","NTLM","MD4","MD2","LM"], "cracked": true, "plaintext": "password", "method": "rainbow"},
    {"hash": "e99a18...", "types": ["MD5","NTLM","MD4","MD2","LM"], "cracked": true, "plaintext": "abc123", "method": "rainbow"},
    {"hash": "unknown...", "types": [], "cracked": false, "plaintext": null, "method": null}
  ],
  "duration_seconds": 0.0,
  "findings": [...]
}
```

### Notas

- NTLM usa rainbow table de MD5 (best-effort, no exacto)
- Hashes bcrypt/sha256crypt/sha512crypt se identifican pero no se crackean offline
- No necesita hashcat ni john

---

## 7. Steganography Tool

**Archivo:** `backend/stego_tool.py`
**Endpoint:** `GET /api/stego/analyze`

Analiza imágenes PNG/BMP en busca de contenido oculto (LSB + trailing data).

### Parámetros (Query)

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `url` | string | — | URL de la imagen a analizar |
| `extract_lsb` | bool | true | Extraer datos LSB de píxeles |
| `lsb_length` | int | 4096 | Bytes máximos a escanear para LSB |

### Técnicas implementadas

- **LSB (Least Significant Bit):** Extrae el bit menos significativo de cada canal de color en píxeles PNG/BMP
- **Trailing data:** Detecta datos añadidos después del chunk IEND (PNG) o del final del bitmap
- **Firma de archivo:** Verifica cabeceras PNG (89 50 4E 47) y BMP (42 4D)
- **Decodificación texto:** Intenta interpretar datos LSB como UTF-8 o ASCII

### Respuesta

```json
{
  "ok": true,
  "format": "png",
  "width": 272,
  "height": 92,
  "file_size": 8712,
  "lsb_suspicious": false,
  "lsb_message": null,
  "lsb_extracted_length": 4096,
  "trailing_data_found": false,
  "trailing_data_size": 0,
  "anomalies": [],
  "duration_seconds": 0.22,
  "findings": [...]
}
```

### Notas

- Puro Python, sin PIL/Pillow ni dependencias externas
- Parseo manual de chunks PNG (IHDR, IDAT, IEND) con zlib
- Soporte para BMP de 24/32 bits
- LSB análisis byte a byte, incluyendo bytes de filtro (estándar en análisis forense)

---

## 8. Security News Scraper

**Archivo:** `backend/news_scraper.py`
**Endpoint:** `GET /api/news`

Agregador de noticias de ciberseguridad desde 9 fuentes RSS/Atom.

### Fuentes incluidas

| ID | Nombre | URL |
|----|--------|-----|
| `hackernews` | The Hacker News | feeds.feedburner.com/TheHackerNews |
| `bleepingcomputer` | Bleeping Computer | www.bleepingcomputer.com/feed/ |
| `krebs` | Krebs on Security | krebsonsecurity.com/feed/ |
| `portswigger` | PortSwigger Research | portswigger.net/research/rss |
| `schneier` | Schneier on Security | www.schneier.com/blog/atom.xml |
| `darkreading` | Dark Reading | www.darkreading.com/rss.xml |
| `threatpost` | Threatpost | threatpost.com/feed/ |
| `securityweek` | SecurityWeek | www.securityweek.com/feed/ |
| `helpnetsecurity` | Help Net Security | www.helpnetsecurity.com/feed/ |

### Parámetros (Query)

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `sources` | string | — | IDs de fuente separados por coma (todas por defecto) |
| `max_per_source` | int | 5 | Máx artículos por fuente |

### Respuesta

```json
{
  "ok": true,
  "total_articles": 14,
  "sources_ok": 7,
  "sources_failed": 2,
  "articles": [
    {"title": "...", "link": "...", "published": "2026-07-20T...", "source_name": "Bleeping Computer", "summary": "...", "category": "news", "author": ""}
  ],
  "duration_seconds": 1.07,
  "findings": [...]
}
```

### Notas

- Parseo de RSS 2.0 y Atom
- Detección automática de formato
- Timeout individual por fuente (15s)
- Fallos por fuente no afectan al resto

---

## 9. API Security Scanner

**Archivo:** `backend/api_scanner.py`
**Endpoint:** `GET /api/apiscan`

Escáner de seguridad para APIs REST. Prueba 65+ endpoints comunes, headers de seguridad, CORS, y exposición de datos.

### Parámetros (Query)

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `url` | string | — | URL base de la API |
| `timeout` | float | 10.0 | Timeout por petición HTTP |
| `concurrency` | int | 10 | Peticiones simultáneas (máx 30) |

### Paths probados (65+)

Categorías:
- `/api`, `/api/v1`, `/api/v2`...
- `/api/users`, `/api/admin`, `/api/health`...
- `/api/auth`, `/api/login`, `/api/token`...
- `/api/swagger`, `/api/docs`, `/openapi.json`...
- `/api/graphql`, `/graphql`...
- `/.env`, `/.git/config`, `/robots.txt`...
- Spring Boot: `/actuator`, `/actuator/health`...

### Comprobaciones

| Categoría | Qué detecta |
|-----------|-------------|
| Headers ausentes | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy |
| Info disclosure | Server, X-Powered-By, X-AspNet-Version |
| CORS | Access-Control-Allow-Origin: * |
| Datos sensibles | password, secret, token, api_key en response body |
| Métodos HTTP | OPTIONS → Allow header con PUT/DELETE habilitados |
| Endpoints abiertos | Paths que devuelven 200 sin autenticación |
| GraphQL | Introspección query |

### Respuesta

```json
{
  "ok": true,
  "base_url": "https://api.github.com",
  "endpoints_scanned": 55,
  "issues_count": 5,
  "open_endpoints_count": 1,
  "cors_enabled": true,
  "auth_required": true,
  "missing_headers": ["Strict-Transport-Security", ...],
  "info_disclosures": ["Server version disclosure: github.com"],
  "issues": [
    {"severity": "medium", "title": "Missing security headers", "endpoint": "/", "category": "headers"},
    {"severity": "medium", "title": "CORS allows all origins (*)", "endpoint": "/", "category": "cors"},
    ...
  ],
  "duration_seconds": 1.91,
  "findings": [...]
}
```

---

## Arquitectura común

Todos los módulos siguen el mismo patrón:

```
backend/
  modulo.py              ← Lógica + dataclasses + función scan/analyze/fetch
  main.py                ← Endpoint FastAPI con import local + JSONResponse

frontend/js/main.v2.js   ← ARSENAL_GROUPS entry + case + API handler + OPSEC rule
frontend/index.html      ← (opcional) badge count si cambia el número de tools
```

### Patrón de integración (cada módulo nuevo requiere 6 cambios en frontend)

1. `ARSENAL_GROUPS` → añadir `{ id, name, desc }` en la categoría correspondiente
2. `toolExamples` → añadir hint de extraFlags
3. `needsTarget` → añadir id si requiere target
4. `launchTool switch` → añadir `case 'id': description = ...`
5. API handler → bloque `if (tool === 'id') { fetch(...) }` antes del SSH block
6. `_OPSEC_RULES` → añadir `'id': { silent: null, covert: null }`

### Dependencias

- Todos usan `httpx` (ya en `requirements.txt`)
- Ninguno necesita Kali Linux ni conexión SSH
- Ninguno necesita tabla nueva en Supabase
