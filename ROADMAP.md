# 🗺️ VulnForge — Roadmap de Mejoras

## ✅ Completado

### Conexión SSH
- [x] Conexión SSH interactiva con `invoke_shell()` + PTY
- [x] Reconexión dinámica por WebSocket
- [x] Gestión de conexiones guardadas (localStorage)
- [x] Puerto personalizable (no solo 22)
- [x] Sudo automático con `-S` + password

### Terminal
- [x] Prompt limpio (Powerlevel10k desactivado)
- [x] Filtro ANSI completo (colores, títulos, DEC privados)
- [x] Filtro Nerd Font / Powerline (caracteres PUA)
- [x] Manejo de `\r` en progresos tipo apt
- [x] Click en terminal → focus en input
- [x] Historial de comandos con flechas ↑/↓ (últimos 100)

### Despliegue
- [x] Backend local funcional (uvicorn + FastAPI)
- [x] Plan de producción guardado (`PRODUCTION_PLAN.md`)
- [x] cloudflared instalado en Kali (2026.6.1)

---

## 🚧 En Progreso / Pendientes

---

## FASE 1 — Parser de Resultados + Findings Panel

**Objetivo:** Que los resultados de las herramientas no se pierdan en la terminal, sino que se estructuren y muestren en un panel visual.

### Frontend
- [ ] Nueva pestaña **"Findings"** (al lado de Reports/Bounty/AI)
- [ ] Parsear outputs de herramientas comunes:
  - `nmap` → puertos abiertos, servicios, versiones
  - `gobuster`/`dirb`/`ffuf` → directorios encontrados + códigos HTTP
  - `nikto` → vulnerabilidades detectadas
  - `whatweb` → tecnologías detectadas
  - `wpscan` → usuarios, plugins, vulns
- [ ] Mostrar hallazgos en tarjetas con severidad (🔴 crítica, 🟡 alta, 🟠 media, 🔵 baja)
- [ ] Botón "Añadir a informe" en cada hallazgo

### Backend
- [ ] Detectar fin de comando en el output del shell (patrón de prompt)
- [ ] Canalizar output completo a la función de parseo
- [ ] Endpoint WebSocket para enviar hallazgos estructurados

### Archivos a modificar/crear
- `frontend/index.html` — nueva pestaña Findings
- `frontend/js/main.v2.js` — lógica de parseo + render
- `frontend/css/style.css` — estilos de tarjetas
- `backend/main.py` — canalización de resultados

---

## FASE 2 — Sugerencias IA + Conexión de Hallazgos

**Objetivo:** La IA en la pestaña AI Writeup recibe los hallazgos y sugiere el siguiente paso.

### Frontend
- [ ] Botón "🔍 Sugerir siguiente paso" basado en findings
- [ ] Auto-rellenar target + findings en el prompt de la IA
- [ ] Mostrar historial de sugerencias IA por sesión
- [ ] Selector de proveedor IA (OpenAI, Anthropic, OpenRouter, Gemini)

### Backend
- [ ] Endpoint `/api/suggest` que recibe findings y devuelve sugerencia
- [ ] Integración con Gemini API (ya tienes clave)
- [ ] Integración con OpenAI / Anthropic / OpenRouter
- [ ] Almacenar sugerencias en el historial de la misión

### Archivos a modificar
- `frontend/js/main.v2.js` — nuevo panel de sugerencias
- `backend/main.py` — nuevo endpoint /suggest
- `backend/requirements.txt` — añadir httpx/requests

---

## FASE 3 — Op Admiral (Planificador de Misión)

**Objetivo:** Describes el target en lenguaje natural, la IA genera un plan de ataque paso a paso.

### Frontend
- [ ] Campo de texto "Describe el objetivo:" con botón "Generar plan"
- [ ] Plan de ataque en tarjetas expandibles
- [ ] Cada paso del plan → botón "Ejecutar este paso" o "Ejecutar todo"
- [ ] Barra de progreso de la misión

### Backend
- [ ] Agente "Op Admiral" que genera plan basado en target + findings
- [ ] Ejecución secuencial con aprobación humana por paso
- [ ] Almacenamiento de planes de misión (localStorage / SQLite)
- [ ] Detección de herramientas disponibles en Kali

### Archivos a crear
- `frontend/js/planner.js` — lógica del planificador
- `backend/planner.py` — agente Op Admiral
- `backend/mission_store.py` — almacén de misiones

---

## FASE 4 — Multi-Operador (Swarm)

**Objetivo:** Varios roles de agente trabajando en paralelo, como T3MP3ST.

### Roles
- [ ] **Recon** → enumeración inicial (nmap, whatweb, dnsrecon)
- [ ] **Scanner** → búsqueda de vulnerabilidades (nikto, wpscan, nuclei)
- [ ] **Exploiter** → explotación de hallazgos (metasploit, sqlmap)
- [ ] **Report** → generación de informe final

### Backend
- [ ] Sistema de colas de tareas por rol
- [ ] Pizarra compartida entre agentes (hallazgos compartidos)
- [ ] Coordinador que evita conflictos
- [ ] Logs de cada operador por separado

### Archivos a crear
- `backend/operators/` — directorio con cada operador
- `backend/swarm.py` — coordinador del swarm
- `frontend/js/swarm.js` — visualización del swarm

---

## FASE 5 — Hallazgos Persistentes + Reportes Automáticos

**Objetivo:** Los hallazgos no se pierden al recargar. La IA genera informes automáticos.

### Frontend
- [ ] Hallazgos guardados en localStorage + exportables
- [ ] Informe automático con Findings + outputs + sugerencias IA
- [ ] Exportar informe completo en MD/HTML/PDF con un clic

### Backend
- [ ] API REST para hallazgos (CRUD)
- [ ] Almacenamiento persistente (SQLite)
- [ ] Endpoint `/api/report/generate` que compila informe

### Archivos a crear
- `backend/findings_db.py` — base de datos de hallazgos
- `backend/report_generator.py` — generador de informes
- `frontend/js/reports_v2.js` — nueva UI de informes

---

## FASE 6 — Contención de Alcance (Scope)

**Objetivo:** Evitar que las herramientas escaneen hosts fuera del objetivo.

### Backend
- [ ] Configuración de alcance (IP/rango/dominio)
- [ ] Proxy wrapper que intercepta comandos y bloquea off-scope
- [ ] Modo "solo target" y "red local permitida"

### Archivos a crear
- `backend/scope_guard.py` — validador de alcance
- `frontend/js/scope.js` — UI de configuración de alcance

---

## FASE 7 — Producción + Cloudflare Tunnel

**Objetivo:** Acceso desde cualquier lugar sin Render.

### Pasos
- [ ] Comprar dominio (3-5€/año)
- [ ] Configurar Cloudflare DNS
- [ ] Crear túnel nombrado permanente
- [ ] Servicio systemd para cloudflared (auto-arranque)
- [ ] HTTPS automático por Cloudflare

### Archivos de referencia
- `PRODUCTION_PLAN.md` — pasos detallados

---

## 🐛 Bugs Conocidos por Corregir

- [ ] Terminal: flechas ↑/↓ navegan historial pero a veces no se actualiza el input visualmente
- [ ] Upload file: falla si el archivo es muy grande (>1MB)
- [ ] Reconexión: al reconectar, el prompt limpio no se re-aplica en algunos casos
- [ ] sudo -S: contraseñas con caracteres especiales pueden fallar (solo afecta si la pass tiene $, ", \, `)
- [ ] Scroll: al recibir mucho output, el auto-scroll a veces no sigue

---

## 📊 Resumen

| Fase | Descripción | Prioridad | Esfuerzo |
|------|------------|-----------|----------|
| Fase 1 | Parser de resultados + Findings Panel | 🔴 Alta | 3-4 días |
| Fase 2 | Sugerencias IA | 🔴 Alta | 2-3 días |
| Fase 3 | Op Admiral (planificador) | 🟡 Media | 5-7 días |
| Fase 4 | Multi-operador (Swarm) | 🟡 Media | 7-10 días |
| Fase 5 | Hallazgos persistentes + informes | 🟢 Baja | 3-4 días |
| Fase 6 | Contención de alcance | 🟢 Baja | 1-2 días |
| Fase 7 | Producción (dominio + tunnel) | 🟡 Media | 1 día |
| Bugs | Correcciones pendientes | 🔴 Alta | 1-2 días |

---

*Última actualización: Julio 2026*
