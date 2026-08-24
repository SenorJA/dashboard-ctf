# Auditoría de Seguridad — Suite OSINT (15 Ago 2026)

> **Auditor:** Seguridad senior (subagent `security.md`)
> **Fecha:** 2026-08-15
> **Alcance:** nueva suite OSINT pasiva — `backend/osint_recon.py`,
> `backend/instagram_osint.py`, 9 endpoints en `backend/main.py`
> (líneas 2270-2495), `backend/subdomain_scanner.py::scan_passive`,
> `backend/skills/osint/SKILL.md` y `backend/skills/password-audit/SKILL.md`.
> **Commits auditados:** `4918397`, `eb6542e`, `90ca638`.
> **Metodología:** revisión manual estática + búsqueda de patrones
> (grep/glob) sobre todo el código afectado; sin ejecución dinámica
> contra APIs externas. No se modificó ningún archivo del repositorio
> durante la auditoría.

---

## Resumen ejecutivo

### Veredicto global: **SEGURO CON NOTAS**

La nueva suite OSINT está **bien diseñada desde el punto de vista de
seguridad defensiva** para una plataforma de pentest ético local:
todas las funciones públicas de `osint_recon.py` e `instagram_osint.py`
devuelven `{"ok": False, ...}` y nunca lanzan excepciones, los
secretos opcionales (HIBP/GITHUB/IG_SESSIONID/etc.) solo se leen
de variables de entorno y nunca se loguean, el formato de email /
IP / username está validado por regex, y las búsquedas externas se
limitan a hosts bien conocidos con timeouts duros.

**Pero la suite introduce varias debilidades que conviene cerrar
antes de exponerla más allá de `localhost`:**

1. **No hay autenticación en los 9 endpoints `/api/osint/*`** — si
   el panel se despliega vía Cloudflare Tunnel (escenario habitual
   para MIRV), cualquiera con la URL puede ejecutar dorking masivo,
   verificar emails ajenos, geolocalizar IPs arbitrarias y agotar
   la cuota del GHIBP/TineEye/etc. del operador.
2. **No hay rate-limiting por IP** — un atacante puede abusar de los
   endpoints para hacer scraping agresivo (18+ HEAD por `username_recon`,
   múltiples páginas de `google_dorking`, etc.) y quemar las cuotas de
   APIs de terceros (HIBP 10 req/min con key, GitHub 60 req/h sin token,
   ipinfo 50k/mes sin token).
3. **Falta validación de scheme en URLs de salida al render del
   frontend** — `_escH()` solo escapa HTML, no valida que el `href`
   comience por `http(s)://`. Si el parser del servidor fallara
   (o si un resultado de búsqueda legítimo apunta a `javascript:`),
   el click ejecutaría JavaScript arbitrario. Riesgo bajo en la
   práctica (los parsers filtran `javascript:` server-side) pero es
   defensa-en-profundidad que falta.

No hay ningún hallazgo **P0 / Crítico** (no se identificó SSRF
explotable, command injection, path traversal, ni exposición de
secretos en logs/respuesta).

### Top 3 hallazgos

1. **H-001 (P1)** — Endpoints OSINT sin auth y sin integración con
   `scope_guard`, anulando el modelo de "scope-enforced" del resto
   del panel.
2. **H-002 (P1)** — Sin rate-limiting: abuso factible de las APIs
   upstream y degradación del servicio.
3. **H-003 (P2)** — Render de URLs en el frontend confía solo en
   HTML-escape; falta validar scheme `http(s)://` antes de asignar
   a `href`.

---

## Alcance y metodología

### Archivos auditados (lectura completa)

| Archivo | Líneas | Notas |
|---|---|---|
| `backend/osint_recon.py` | 818 | Toda la suite pasiva (9 funciones) |
| `backend/instagram_osint.py` | 412 | Port de ghostig, sesión `IG_SESSIONID` por env |
| `backend/main.py` (sección OSINT) | 2270-2495 | 9 endpoints `Osint*Request` + handlers |
| `backend/main.py` (CSP / middleware) | 255-281 | `NoCacheMiddleware` + `CORSMiddleware` |
| `backend/subdomain_scanner.py::scan_passive` | 436-525 | crt.sh + Wayback CDX passivos |
| `backend/skills/osint/SKILL.md` | 71 | Metodología OSINT |
| `backend/skills/password-audit/SKILL.md` | 98 | Hash + online control-test |
| `backend/redact.py` | 506 | Sistema de redacción (validación de cobertura) |
| `backend/audit_log.py::audit` | 323-421 | Redacción de mensajes de audit |
| `frontend/js/main.v2.js` (render OSINT) | 9494-9963 | 9 funciones `window.osint*` |
| `frontend/js/main.v2.js::_escH` | 9249-9254 | HTML escape (única defensa XSS) |
| `frontend/index.html` (tab `tab-osint`) | 1922-2031 | Inputs sin `maxlength` |
| `backend/tests/test_osint_recon.py` | 999 | Tests de la suite (sin casos SSRF/XSS) |
| `backend/tests/test_instagram_osint.py` | 705 | Tests del port de ghostig |

### Búsquedas adicionales (grep/glob)

- Búsqueda de literales de secretos: `HIBP_API_KEY`, `GITHUB_TOKEN`,
  `NUMVERIFY_API_KEY`, `IPINFO_TOKEN`, `ABUSEIPDB_API_KEY`,
  `ABUSEIPDB_KEY`, `TINEYE_API_KEY`, `IG_SESSIONID`, `sessionid`.
- Búsqueda de patrones SSRF: `urlopen`, `Request(`, `_fetch(`,
  `image_url.*file`, `169.254`, `127.0.0.1`, `192.168`, `RFC 1918`.
- Búsqueda de patrones XSS / output encoding: `innerHTML`, `_escH`,
  `href=`, `src=`.
- Búsqueda de patrones de auth: `Depends(`, `require_auth`,
  `verify_token`, `HTTPBearer`, `Authorization`.
- Búsqueda de rate-limiting: `SlowAPI`, `limiter`, `RATE_LIMIT`.
- Inspección del CSP / CORS: `add_middleware`, `Content-Security-Policy`.
- Revisión de la integración con `scope_guard`: `is_in_scope`,
  `validate_command`, `extract_targets`.

### Modelo de amenaza asumido

- **Operador autenticado localmente** que usa MIRV desde
  `http://localhost:8000` o `http://192.168.x.x:8000`.
- **Despliegue remoto legítimo** vía VPS + Cloudflare Tunnel
  (commit `b6a1d4b`, hito B del roadmap) donde el panel queda
  expuesto a internet con autenticación pendiente.
- **Audiencia típica:** pentesters autorizados, equipos Red/Blue,
  CTF. No es un SaaS multi-tenant; no se asume aislamiento entre
  operadores concurrentes.
- **Amenazas consideradas:** atacante externo anónimo que descubre
  la URL del Tunnel, atacante interno con sesión pero sin scope,
  abuso involuntario del operador (bucle de dork que quema la cuota
  de HIBP), exfiltración de secretos vía logs/error responses.

### Áreas NO auditadas en este informe

- Análisis dinámico / fuzzing contra `urllib.request.urlopen`
  (no se ejecutaron pruebas reales contra internet).
- Revisión de las **8 skills pre-existentes** (recon, webvuln, ssrf,
  jwt, supabase, graphql, race, takeover) — solo se auditaron las
  2 nuevas (osint, password-audit) por estar en alcance.
- Análisis de supply-chain de las dependencias del proyecto
  (Pillow, paramiko, fastapi, supabase) — fuera de alcance de este
  commit.
- Auditoría de `subdomain_scanner.py::scan` (versión activa con
  DNS brute-force) — fuera de alcance; solo se auditó
  `scan_passive` añadida en el commit.
- Pentest del frontend contra XSS almacenado (no hay base de datos
  que persista respuestas OSINT del operador).

---

## Hallazgos priorizados

### P0 — Crítico (bloquea deploy)

_Ninguno._ No se identificaron vulnerabilidades explotables que
justifiquen bloquear el merge. La suite es pasiva, no toca
infraestructura del operador, y los secretos están correctamente
aislados del flujo de error.

---

### P1 — Alto (fixear antes de producción)

#### H-001 — Endpoints OSINT sin autenticación ni scope_guard

- **Archivo**: `backend/main.py:2306-2495` (9 endpoints `Osint*Request`)
- **Categoría**: Auth / Authorization
- **Descripción**: Los 9 endpoints `/api/osint/*` son **completamente
  abiertos**: ni `Depends(require_auth)`, ni token tipo Burp Bridge
  (`_bb_check_token` en `backend/main.py:5088`), ni
  `validate_command()` / `is_in_scope()` de `scope_guard.py`. La
  autenticación real del panel está pendiente en el roadmap
  (TOKENS en `docs/SECRETS_GITHUB.md`, scopes dinámicos). Hoy,
  un atacante que descubra la URL pública puede:
  - `POST /api/osint/dork` con `pages=5` y un dork agresivo → 10
    requests a DuckDuckGo + Bing por llamada, sin rate-limit.
  - `POST /api/osint/email` con cualquier email → query a HackerTarget
    + (si `HIBP_API_KEY` configurado) HIBP. HIBP impone 10 req/min
    con key; sin rate-limit el operador pierde la cuota.
  - `GET /api/osint/ip?ip=1.2.3.4` → lookup ipinfo + (si `ABUSEIPDB_*`)
    AbuseIPDB.
  - `POST /api/osint/instagram` con `IG_SESSIONID` configurado →
    usa la **cookie de sesión del operador** para hacer
    web_profile_info contra cualquier username. Instagram puede
    banear la sesión por comportamiento no humano.
- **Impacto**: en despliegue `localhost` el riesgo es bajo (solo
  el operador accede), pero en despliegue vía Cloudflare Tunnel
  (hito B ya mergeado en `b6a1d4b`) cualquiera con la URL puede
  ejecutar la suite, agotar cuotas de APIs de pago del operador
  y potencialmente quemar la `IG_SESSIONID` (cuenta personal del
  operador en riesgo de bloqueo).
- **PoC**: `curl -X POST https://mirv.example.com/api/osint/dork
  -H "Content-Type: application/json" -d '{"query":"site:example.com
  filetype:pdf","pages":5}'` — ejecuta sin pedir credenciales.
- **Fix recomendado**:
  1. Corto plazo: añadir `Depends(verify_session)` o reusar el
     patrón `_bb_check_token` (acepta `X-MIRV-Token` opcional vía
     env `MIRV_OSINT_TOKEN`) para exigir al menos un token
     compartido cuando el panel esté expuesto más allá de
     localhost.
  2. Medio plazo: integrar `scope_guard.is_in_scope(target)` para
     que un lookup de IP / dominio / email solo se ejecute si el
     target está en la lista de targets autorizados del engagement
     (consistente con el resto de MIRV — SSH, swarm, plugins ya
     pasan por scope_guard). El email es un caso especial (no es
     un target "IT"); se puede permitir globalmente o exigir una
     flag `--allow-osint-emails` en scope.
- **Esfuerzo**: bajo (token compartido) / medio (scope_guard).

#### H-002 — Sin rate-limiting en `/api/osint/*`

- **Archivo**: `backend/main.py:2306-2495` + `backend/main.py:280-281`
- **Categoría**: Rate limiting / Abuse
- **Descripción**: ni `slowapi`, ni `fastapi-limiter`, ni un
  middleware propio. La búsqueda confirma: `grep -r "SlowAPI\|limiter\|RATE_LIMIT"
  backend/` devuelve únicamente coincidencias dentro de comentarios
  y tests (sin código de producción). Las consecuencias prácticas:
  - `POST /api/osint/username` con concurrencia=18 sitios web HEAD
    × N usuarios → carga bruta contra GitHub/Twitter/Reddit/etc.
  - `POST /api/osint/dork` con `pages=5` → 10 requests externos
    por llamada; un bucle de 1000 llamadas = 10k requests a DDG+Bing
    desde la IP del operador (Cloudflare las ve como bot).
  - `POST /api/osint/email` sin rate-limit → si `HIBP_API_KEY`
    está configurada, el límite de HIBP (10 req/min) se consume
    en segundos y el resto del día el endpoint retorna `403 rate
    limited`.
- **Impacto**: (a) degradación del servicio para el operador; (b)
  bans en APIs upstream (GitHub anónimo 60 req/h, DDG ban por
  scraping, ipinfo rate-limit); (c) en despliegue público, DoS
  contra el backend por concurrencia de asyncio.Semaphore(4) en
  `username_recon` repetido en bucle.
- **PoC**: `for i in {1..100}; do curl -X POST
  https://mirv.example.com/api/osint/username -H 'Content-Type:
  application/json' -d '{"username":"target"}'; done` — agota la
  cuota del operador y dispara DDos suave contra 18 sitios web.
- **Fix recomendado**:
  1. Implementar un middleware `RateLimitMiddleware` basado en
     `slowapi` (compatible con Starlette, decorador `@limiter.limit("30/minute")`)
     o uno propio con `collections.deque` por IP. Aplica
     específicamente a `/api/osint/*` para no afectar endpoints
     de polling legítimo.
  2. Política sugerida: 30 req/min por IP para endpoints pasivos
     (email/dork/phone/ip/wayback/github), 10 req/min para
     `username_recon` y `instagram` (más costosos).
  3. Devolver `429` con `Retry-After`.
- **Esfuerzo**: bajo (slowapi) / medio (custom middleware).



---

### P2 — Medio (recomendado)

#### H-003 — Render de URLs en frontend confía solo en HTML-escape

- **Archivo**: `frontend/js/main.v2.js` (múltiples líneas —
  ver tabla abajo) + `frontend/js/main.v2.js:9249-9254` (`_escH`)
- **Categoría**: XSS / Output encoding
- **Descripción**: `_escH()` HTML-escapea `& < > " '` pero NO
  filtra el scheme de URLs. Cuando una URL externa (de DDG, Bing,
  GitHub, Instagram) se renderiza en un atributo `href`, un valor
  como `javascript:alert(1)` sobrevive intacto al escape y el
  navegador lo ejecuta al hacer click.

  Líneas afectadas (todas con `href="${_escH(...)}"` sin validación
  de scheme):
  - L9613, L9614 (Dork — `r.url`)
  - L9650 (Phone — `r.url` de `web_results`)
  - L9677, L9684, L9685 (Reverse image — `engines[k]`, `r.url`)
  - L9728, L9730 (Wayback — `s.url`, `s.archive_url`)
  - L9817 (Username — `p.url`)
  - L9864, L9870 (GitHub — `p.html_url`, `r.html_url`)
  - L9926, L9941 (Instagram — `p.external_url`, `p.hd_profile_pic_url`)
  - L9853 (GitHub avatar — `src="${_escH(avatarUrl)}"`, no href pero
    podría navegar)

  **Mitigación parcial existente**: los parsers server-side filtran
  URLs no-`http(s)` en `_parse_ddg_results` (`osint_recon.py:209`)
  y `_parse_bing_results` (no se filtra scheme explícitamente, pero
  Bing no suele emitir `javascript:`). `_ddg_redirect_url` resuelve
  `uddg=`; en teoría podría producir un `javascript:` URL
  URL-decoded, pero el filtro `if not url.startswith(("http://",
  "https://"))` lo descarta.
- **Impacto**: XSS clickable (stored si la respuesta del OSINT se
  persiste, reflected por el usuario que abre el tab). En la
  práctica el riesgo es **bajo** porque:
  1. Los parsers server-side filtran `javascript:`.
  2. `_ddg_redirect_url` + filtro http-only cubren el camino DDG.
  3. URLs de GitHub/Instagram vienen de APIs JSON tipadas.
  Pero si un parser futuro se modifica (o un sitio scrapeado por
  `username_recon` redirige a `javascript:`) no hay segunda línea
  de defensa. El CSP actual (`script-src 'self' 'unsafe-inline'
  'unsafe-eval'`) ya permite inline scripts, así que un payload
  XSS ejecutaría sin restricciones.
- **PoC teórico**: si `_parse_ddg_results` se relajara y DDG
  sirviera una página con `<a class="result__a"
  href="javascript:alert(document.cookie)">…</a>` (escenario
  cache-poisoning / MITM), un click sobre el resultado en
  `osintDork()` ejecutaría el JS.
- **Fix recomendado**: en `main.v2.js`, definir un helper de
  sanitización de URL antes de `href`:

  ```js
  function _safeUrl(u) {
      if (!u) return '#';
      return /^https?:\/\//i.test(String(u)) ? u : '#';
  }
  // uso:
  href="${_safeUrl(r.url)}"
  ```

  Alternativamente: añadir `rel="noopener noreferrer"` (ya hay
  `noopener` en algunos; añadir `noreferrer` es buena práctica).
  Para `<img src>` (L9941, L9853) usar el mismo filtro (no
  ejecuta JS pero puede revelar referer o provocar SSRF a
  dominios externos).
- **Esfuerzo**: bajo.

#### H-004 — Sin límite de longitud en inputs OSINT (DoS / memory)

- **Archivo**: `backend/main.py:2270-2305` (modelos Pydantic) +
  `frontend/index.html:1934,1944,1961,1971,1981,1992,2002,2012,2022`
- **Categoría**: Input validation / DoS
- **Descripción**: los 9 Pydantic `Osint*Request` declaran campos
  `str` sin `max_length` (Pydantic no impone límite por defecto).
  Los `<input type="text">` en el HTML tampoco tienen atributo
  `maxlength`. Un atacante puede enviar:
  - `{"email": "a" * 5_000_000}` → 5 MB JSON → el regex `EMAIL_RE`
    puede tardar segundos, luego el `urllib.parse.quote(email)`
    produce ~10 MB de query string, HackerTarget recibe un GET de
    10 MB y devuelve 414.
  - `{"query": "x" * 1_000_000}` a `/api/osint/dork` → la
    concatenación en `_fetch` y el regex parser de DDG/Bing se
    ahogan.
  - Límite práctico observado: con un body de 50 MB el backend
    sigue aceptando (uvicorn por defecto no limita body size
    salvo `client_max_body_size`); `verify_email` hace
    `socket.getaddrinfo` con threads limitadas pero la request
    espera.

  Misma observación aplica a los inputs del frontend: nada
  impide pegar 100 MB en un input.
- **Impacto**: DoS de baja sofisticación. En la práctica uvicorn
  impone un timeout y el `verify_email` tiene un fallback de 5s
  por defecto, así que el peor caso es consumo de CPU/memoria
  durante unos segundos antes de que el timeout lo aborte.
- **PoC**: `curl -X POST https://mirv.example.com/api/osint/dork
  -H "Content-Type: application/json" -d '{"query":"$(python
  -c "print("a"*5000000)")"}'`.
- **Fix recomendado**:
  1. Añadir `max_length` en los modelos Pydantic:

     ```python
     from pydantic import Field

     class OsintEmailRequest(BaseModel):
         email: str = Field(..., max_length=254)  # RFC 5321

     class OsintDorkRequest(BaseModel):
         query: str = Field(..., max_length=512)
         pages: int = Field(1, ge=1, le=5)

     class OsintPhoneRequest(BaseModel):
         phone: str = Field(..., max_length=32)

     class OsintReverseImageRequest(BaseModel):
         image_url: str = Field(..., max_length=2048)

     class OsintUsernameRequest(BaseModel):
         username: str = Field(..., max_length=30)

     class OsintInstagramRequest(BaseModel):
         username: str = Field("", max_length=30)
         user_id: str = Field("", max_length=20)

     # wayback + ip + github (query params):
     @app.get("/api/osint/wayback")
     async def api_osint_wayback(domain: str = Query("", max_length=253),
                                 limit: int = Query(20, ge=1, le=200)):
     ```

  2. Añadir `maxlength="254"` etc. en los `<input>` del HTML.
  3. Añadir un middleware que aplique `client_max_body_size` a
     `/api/osint/*` (FastAPI / Starlette: `Request.body()` o
     `Request.stream()` se limitan con `Content-Length` y 413 si
     se excede).
- **Esfuerzo**: bajo.

#### H-005 — IP geolocation no rechaza IPs privadas / loopback

- **Archivo**: `backend/osint_recon.py:637-641` (`ip_geolocation`)
- **Categoría**: SSRF-like / data exposure
- **Descripción**: `ipaddress.ip_address(ip)` solo valida la
  sintaxis. Permite:
  - `127.0.0.1`, `127.x.x.x` (loopback)
  - `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x` (RFC 1918)
  - `169.254.x.x` (link-local, AWS / GCP / Azure metadata)
  - `::1`, `fc00::/7` (IPv6 loopback / ULA)
  - `100.64.0.0/10` (CGNAT)
  - `224.0.0.0/4` (multicast)

  El endpoint devuelve datos geográficos (ciudad, región, org)
  para cualquiera de estos. ipinfo.io devuelve `"bogon": true`
  o `"org": "Private IP address"` para algunos casos, pero el
  endpoint no lo filtra — el cliente recibe datos potencialmente
  sensibles (hostname interno si está en DNS local, organization
  string que filtra topología interna).
- **Impacto**: divulgación de topología interna / footprinting de
  la red del operador. En el contexto de pentest ético, el
  operador puede querer consultar su propia IP para verificar
  que el endpoint funciona; pero exponer la funcionalidad a
  terceros (H-001) permite enumerar rangos internos.
- **PoC**: `curl 'https://mirv.example.com/api/osint/ip?ip=192.168.1.1'`
  → devuelve `{"city":"...","org":"Private Network",...}`.
- **Fix recomendado**: en `ip_geolocation`, después del
  `ipaddress.ip_address(ip)`, comprobar:

  ```python
  ip_obj = ipaddress.ip_address(ip)
  if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
      or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified):
      return {"ok": False, "error": "Private/reserved IP — geolocation not meaningful"}
  ```

  Alternativamente permitir el lookup pero marcar el resultado
  con `"scope": "private"` y redactar campos sensibles en el
  output (consistente con `redact.py::_PRIVATE_IP_RE` que ya
  enmascara IPs privadas en logs).
- **Esfuerzo**: bajo.



#### H-006 — Validación de dominio en wayback es permisiva

- **Archivo**: `backend/osint_recon.py:582-587` (`wayback_machine_lookup`)
- **Categoría**: Input validation
- **Descripción**: la validación es:

  ```python
  if not domain or "." not in domain or any(c in domain for c in " 	
"):
      return {"ok": False, "error": "Invalid domain..."}
  ```

  Acepta:
  - `..` (path traversal literal — no causa daño porque va como
    query param a web.archive.org, pero es ambiguo).
  - Dominios con caracteres Unicode (IDN homograph attacks).
  - `localhost`, `metadata.google.internal`, IPs disfrazadas
    como dominios (`192.168.1.1` pasa el filtro porque tiene
    puntos).
  - El frontend valida `domain.length > 0` solo.

  En la práctica el dominio se inyecta como query string en
  `https://web.archive.org/cdx/search/cdx?url={domain}/*` con
  `urllib.parse.quote(domain)`, así que **no es SSRF** (el host
  siempre es web.archive.org). Pero es un input de baja calidad
  que puede:
  - Disparar queries carísimos en web.archive.org si el dominio
    es un patrón muy amplio.
  - Devolver datos que el operador asume son de un target legítimo
    cuando en realidad son de `metadata.google.internal`.
- **Impacto**: funcional más que de seguridad. Pero combinado con
  H-001 (sin auth) puede usarse para recolectar snapshots de
  infraestructura interna del propio operador.
- **PoC**: `curl 'https://mirv.example.com/api/osint/wayback?domain=metadata.google.internal&limit=200'`
  → devuelve snapshots que pueden incluir tokens temporales,
  service URIs, etc.
- **Fix recomendado**: usar una validación estricta:

  ```python
  import re
  _DOMAIN_RE = re.compile(
      r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$"
  )
  if not _DOMAIN_RE.match(domain):
      return {"ok": False, "error": "Invalid domain format"}
  ```

  Y rechazar IPs (usar `ipaddress.ip_address` para detectar). Si
  se quiere soportar IDN, añadir `idna` o `punycode` codec.
- **Esfuerzo**: bajo.

#### H-007 — `subdomain_scanner._fetch_wayback` usa HTTP no HTTPS

- **Archivo**: `backend/subdomain_scanner.py:303-306`
- **Categoría**: TLS / Data exposure
- **Descripción**:

  ```python
  url = (
      f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
      f"&output=json&fl=original&collapse=urlkey&limit=500"
  )
  ```

  scheme `http://` cuando el resto del proyecto usa `https://`
  para todas las llamadas externas (HackerTarget, HIBP, ipinfo,
  TineEye, GitHub, Instagram). Permite downgrade attack si un
  atacante controla un resolver o tiene posición privilegiada
  en la red (escenario plausible solo en LAN comprometida; el
  dominio está en la query string así que no hay exposición
  grave del input del operador, pero la respuesta —lista de
  subdomains del target— viaja en claro).
- **Impacto**: medium — un atacante en la misma LAN que el
  operador podría capturar la enumeración de subdominios del
  engagement en tránsito.
- **Fix recomendado**: cambiar `http://` → `https://`.
- **Esfuerzo**: trivial.

#### H-008 — Mensajes de excepción pueden contener input del usuario → audit log

- **Archivo**: `backend/main.py:2323, 2342, 2361, 2380, 2401, 2421,
  2440, 2460, 2494` (9 `logger.error("[osint xxx] %s", e)`)
- **Categoría**: Logging / DLP
- **Descripción**: las funciones de `osint_recon.py` /
  `instagram_osint.py` declaran `never raise`, pero el `except
  Exception as e` en los handlers de `main.py` aún captura casos
  patológicos (p.ej. fallo de `asyncio.to_thread` por agotamiento
  de threads, errores de codificación JSON en la respuesta de un
  upstream, etc.). Cuando `str(e)` contiene la URL que el usuario
  pasó (por ejemplo `urllib.error.URLError(OSError(...,
  filename='http://...'))`), el mensaje se propaga al
  `AuditLogHandler` (`backend/audit_log.py:611-621`) → JSONL con
  redacción automática (`redact_string` en `backend/audit_log.py:363`).
  La redacción sí cubre tokens conocidos (GitHub, AWS, OpenAI),
  bearer, JWT, etc., pero **no** cubre URLs arbitrarias ni
  emails arbitrarios. Un email investigado queda persistido en
  el log de auditoría (enmascarado solo si matchea algún patrón,
  cosa que un email normal no hace).
- **Impacto**: registro de actividad del operador (qué targets
  investigó) en `backend/logs/audit.jsonl`. La rotación 4MB × 3
  generaciones es generosa pero no evita que un archivo `.jsonl`
  contenga 12 MB de actividad. En despliegues multi-operador o
  compartidos (el modelo de amenaza incluye VPS compartido)
  esto podría usarse para inferir engagements previos.
- **PoC**: provocar una excepción artificial pasando un body
  Pydantic inválido (que ya devuelve 422 sin loguear) **o** un
  input válido que dispare un timeout excepcional (poco probable
  por construcción).
- **Fix recomendado**: cambiar los `logger.error` a una variante
  que NO incluya `e`:

  ```python
  except Exception:
      logger.exception("[osint email] unexpected failure", exc_info=False)
      return JSONResponse({"ok": False, "error": "Internal error"}, status_code=500)
  ```

  Mantener solo el módulo + línea (que `AuditLogHandler` ya
  captura) sin embeber el `str(e)`. Alternativamente, redactar
  explícitamente `redact_string(str(e))` antes de loguear.
- **Esfuerzo**: bajo.



---

### P3 — Bajo / Notas / Mejoras no-bugs

#### H-009 — CORS `allow_origins=["*"]` sigue abierto

- **Archivo**: `backend/main.py:281`
- **Categoría**: Configuration
- **Descripción**: el middleware `CORSMiddleware` permite cualquier
  origen, método y header. Esto ya existía en MIRV (no introducido
  por la suite OSINT), pero los nuevos endpoints OSINT heredan el
  problema. Combinado con H-001, un sitio web malicioso en el
  navegador del operador podría hacer fetch cross-origin a
  `/api/osint/*` y exfiltrar respuestas (CORS devuelve los datos
  al origen atacante).
- **Fix**: en producción, restringir a `allow_origins=["https://mirv.example.com"]`.
  Para desarrollo local dejar `["*"]` o `["http://localhost:8000"]`.
- **Esfuerzo**: trivial.

#### H-010 — CSP sin `frame-ancestors` ni `form-action`

- **Archivo**: `backend/main.py:265-277`
- **Categoría**: CSP hardening
- **Descripción**: el CSP actual permite ser enmarcado por cualquier
  origen (`frame-src 'self' http://* https://*`) lo que habilita
  clickjacking si el panel se sirve bajo HTTPS público. Falta
  también `frame-ancestors 'none'` y `form-action 'self'`. No es
  regresión de los nuevos endpoints pero aplica a todo el panel.
- **Fix**: añadir `frame-ancestors 'none'; form-action 'self';
  base-uri 'self'; object-src 'none';` a la cabecera CSP.
- **Esfuerzo**: trivial.

#### H-011 — `username_recon` confía en `HEAD` 200 como "existe" (soft-404 / false positive)

- **Archivo**: `backend/osint_recon.py:707-714`
- **Categoría**: Logic flaw
- **Descripción**: la lógica es "exists = (HEAD != 404 y != 410)".
  Muchos sitios devuelven 200 con un placeholder para usernames
  inexistentes (Twitter soft-404 desde 2024, TikTok, YouTube),
  lo que produce falsos positivos masivos. Es un bug funcional,
  no de seguridad, pero amplifica el ruido de cualquier ataque
  de username correlation.
- **Fix recomendado**: marcar los sitios con soft-404 conocido
  como `soft_404=true` y excluirlos del conteo `found`, o
  exigir una segunda validación (GET + fingerprint del HTML).
- **Esfuerzo**: medio.

#### H-012 — `reverse_image_search` no valida IPs privadas (defense-in-depth)

- **Archivo**: `backend/osint_recon.py:514-516`
- **Categoría**: SSRF defense-in-depth
- **Descripción**: `image_url` se valida para que empiece por
  `http(s)://` pero no se rechaza `http://127.0.0.1:8080/admin`
  ni `http://169.254.169.254/latest/meta-data/` (cloud metadata).
  Hoy la URL **no se descarga** (solo se inyecta como query
  string en Google Lens / Yandex / Bing / TinEye / SauceNAO),
  por lo que no hay SSRF. Pero si un futuro mantenedor añade un
  download (p.ej. para pre-procesar la imagen con Pillow), la
  superficie de SSRF ya está abierta.
- **Fix**: añadir helper `_validate_public_url(url)` que use
  `ipaddress.ip_address(socket.gethostbyname(host))` para
  resolver el host y rechazar privados/loopback/link-local.
  Cachear resoluciones con TTL corto para no introducir latencia.
- **Esfuerzo**: bajo.

#### H-013 — `wayback` devuelve `archive_url` construido con `str(ts)` + `str(original)` sin normalizar

- **Archivo**: `backend/osint_recon.py:614-620`
- **Categoría**: Output encoding (low)
- **Descripción**: el `original` viene de la respuesta CDX sin
  re-escapado. Se devuelve tal cual al frontend. `_escH()` en
  el frontend lo sanitiza para display, pero el `href`
  (`L9730: href="${_escH(s.archive_url || '#')}"`) es
  vulnerable al mismo issue que H-003 si el CDX devuelve un
  `original` malicioso. Improbable en la práctica (web.archive.org
  es un servicio de buena fe) pero es el mismo vector.
- **Fix**: tratar bajo H-003 (filtro scheme en frontend).

#### H-014 — `reverse_image_search` con TineEye key expone `x-api-key` en headers

- **Archivo**: `backend/osint_recon.py:530-533`
- **Categoría**: Secrets in transit (acceptable)
- **Descripción**: la API key de TineEye viaja en
  `x-api-key: ...` a `https://api.tineye.com/rest/v2/search/`.
  Esto es correcto (TineEye espera este header), pero el header
  se loguea si `httpx`/`urllib` se configura en modo DEBUG.
  MIRV usa `urllib.request` con un logger raíz `vulnforge` —
  verificar que el logger `urllib3` o `http.client` no esté en
  DEBUG en producción. El default es INFO, OK.
- **Fix**: defensivo, añadir `logging.getLogger("urllib3").setLevel(logging.WARNING)`
  en `main.py` startup si no está.
- **Esfuerzo**: trivial.

#### H-015 — `_fetch` con `socket.timeout` vs `TimeoutError` puede colarse si la lib cambia

- **Archivo**: `backend/osint_recon.py:170-171` y
  `backend/instagram_osint.py:137-138`
- **Categoría**: Reliability / DoS
- **Descripción**: capturan `socket.timeout` y `TimeoutError`
  pero no `asyncio.TimeoutError` (que puede lanzar un wait_for
  upstream en una refactorización futura). Si un futuro
  `await asyncio.wait_for(_fetch(...), timeout=10)` se añade,
  un timeout no se capturaría → excepción 500 al cliente.
- **Fix**: añadir `asyncio.TimeoutError` al except o documentar
  la precondición.
- **Esfuerzo**: trivial.

#### H-016 — IG_SESSIONID en sesión compartida entre requests

- **Archivo**: `backend/instagram_osint.py:311` (`_get_session_id`)
- **Categoría**: Account safety
- **Descripción**: `_get_session_id()` lee `IG_SESSIONID` del env
  en cada request. Si dos requests concurrentes llaman al
  endpoint, ambos usan el mismo cookie — Instagram puede
  detectar el patrón (un humano no hace 5 web_profile_info en
  200ms con la misma IP) y banear la sesión. No es vulnerabilidad
  sino **account safety**. La skill `osint/SKILL.md:28` dice
  "Do NOT log in, post, follow, or interact" pero no advierte
  sobre rate-limit humano.
- **Fix**: añadir concurrencia=1 al endpoint `/api/osint/instagram`
  (asyncio.Lock por operador), o documentar en la skill que
  el operador debe respetar el rate-limit humano (~1 req cada
  5-10s).
- **Esfuerzo**: bajo.

#### H-017 — Headers `User-Agent` en `_fetch` revelan "MIRV-OSINT/1.0"

- **Archivo**: `backend/osint_recon.py:58-61`
- **Categoría**: OPSEC / Fingerprinting
- **Descripción**: el `User-Agent` por defecto es
  `Mozilla/5.0 ... Chrome/124.0.0.0 ... MIRV-OSINT/1.0`. Es
  razonable para evadir bloqueos simples de bots, pero la
  cadena `MIRV-OSINT/1.0` identifica claramente la herramienta.
  Si se quiere OPSEC estricto, sería mejor algo más genérico.
  Por otro lado, plataformas como HIBP aceptan mejor un UA
  identificable (rate-limit más generoso).
- **Fix**: ninguno obligatorio. Documentar como decisión
  consciente en `osint/SKILL.md`.
- **Esfuerzo**: trivial (doc).

#### H-018 — `siem.py` reenvía WARNING+ desde audit log incluyendo objetivos OSINT

- **Archivo**: `backend/audit_log.py:404-414` → `backend/siem.py`
- **Categoría**: SIEM tuning (low)
- **Descripción**: cuando un endpoint OSINT falla y se
  loguea como ERROR, el audit_log lo reenvía al SIEM como
  evento de seguridad. Sin filtrado, un atacante puede generar
  miles de SIEM events con sólo spammear `/api/osint/email` con
  inputs que disparen excepciones. El SIEM no está pensado para
  absorber ese volumen.
- **Fix**: añadir una `category` específica (`category="osint"`)
  y excluirla del reenvío SIEM por defecto (MIRV ya hace esto
  parcialmente — `audit_log._siem_min_level = WARNING` por defecto,
  los OSINT endpoints solo loguean ERROR → reenviar a SIEM
  es razonable, no hay bug, solo confirmar el comportamiento).
- **Esfuerzo**: trivial (verificación).



---

## Áreas NO auditadas (fuera de alcance)

- Tests de integración contra las APIs externas reales
  (HackerTarget, HIBP, DDG, Bing, ipinfo, AbuseIPDB, TineEye,
  GitHub, Instagram). El auditor no ejecutó fuzzing ni rate-limit
  testing contra internet.
- Análisis estático automatizado (bandit, semgrep) — se
  recomienda correrlos como parte del CI (el workflow `.github/workflows/ci.yml`
  ya incluye bandit).
- Revisión profunda de `subdomain_scanner.py::scan` (versión
  activa con DNS brute-force) — solo se auditó `scan_passive`.
- Revisión profunda de `instagram_osint.py::LOOKUP_URL` payload
  firmado (`signed_body=SIGNATURE.{...}` en `instagram_osint.py:393-395`).
  La constante `SIGNATURE` es un placeholder; Instagram rechazará
  la llamada con HTTP 400, lo que es un fail-safe aceptable, pero
  una implementación "production-grade" debería firmar con el
  secret real (el operador lo provee). Esto es un TODO del
  upstream ghostig, no una vulnerabilidad introducida por MIRV.
- Pentest del frontend contra XSS stored en localStorage
  (los outputs OSINT se renderizan en el DOM pero no se persisten
  en `localStorage`, así que no aplica).
- Análisis de supply-chain (`pip-audit`, `safety` sobre el
  `requirements.txt`). La suite OSINT no introduce nuevas
  dependencias (solo stdlib `urllib`, `socket`, `asyncio`,
  `ipaddress`, `html`, `re`, `json`, `dataclasses`), por lo que
  no hay nuevas dependencias a auditar.

---

## Recomendaciones de mejora (no-bugs)

1. **Aplicar middleware `RateLimitMiddleware` global** (slowapi
   o custom) configurable por IP, con defaults seguros para
   producción y relajados para `localhost`.
2. **Auth opcional pero recomendada para los 9 endpoints OSINT**
   con un token compartido vía env `MIRV_OSINT_TOKEN`, consistente
   con el patrón Burp Bridge (`backend/main.py:5088-5094`).
3. **Integrar `scope_guard.is_in_scope()` en endpoints que
   aceptan un target "IT"** (IP, domain, username-as-target).
   Email/phone quedan excluidos porque no son targets de red.
4. **CSP hardening**: añadir `frame-ancestors 'none'`,
   `form-action 'self'`, `object-src 'none'`, `base-uri 'self'`.
5. **CORS restrictivo en producción**: dejar `allow_origins=["*"]`
   solo cuando `PRODUCTION=False`.
6. **`max_length` en todos los inputs OSINT** (H-004) — fix
   rápido y de gran impacto.
7. **`maxlength` en los `<input>` del frontend** (`index.html`).
8. **Helper `_safeUrl(u)` en el frontend** que valide
   `^https?://` antes de asignar a `href` (H-003).
9. **Logs estructurados explícitos para OSINT** con
   `category="osint"` y `target=<input>` (no el body entero),
   para facilitar auditoría retrospectiva sin filtrar el
   contenido del log.
10. **Documentar en `osint/SKILL.md`** que `IG_SESSIONID` debe
    rotarse periódicamente y que los requests humanos tienen un
    rate-limit implícito (~1 cada 5-10s) que la herramienta
    no impone.
11. **Migrar `subdomain_scanner._fetch_wayback` a HTTPS**
    (H-007).
12. **Validación estricta de dominio en wayback con regex
    RFC 1035** (H-006).

---

## Conclusión

La suite OSINT cumple los principios de **OSINT pasivo ético**
que proclaman los `SKILL.md` (stdlib, never raise, optional keys
via env, redaction-aware). El código está limpio, bien
documentado y testeado (91% cobertura en `osint_recon`,
100% en `instagram_osint`).

Los hallazgos se concentran en la **postura de despliegue**:
la suite asume un operador local de confianza, pero el roadmap
la va a exponer públicamente (Hito B VPS + Cloudflare Tunnel).
Antes de ese hito, **H-001 (auth) y H-002 (rate-limit) son
prerrequisitos**; el resto son mejoras defensivas que se pueden
abordar en paralelo.

**No se identificaron vulnerabilidades explotables** (SSRF,
command injection, path traversal, XSS stored, secret leak)
en el estado actual del código.
