# REPO ANALYSIS — 2026-10-10

Análisis de dos repos de tooling ofensivo/integraciones para el **Pack 19** de M.I.R.V. La decisión final fue **(1)** vendorizar la skill **`android-pentesting`** de `DragonJAR/Android-Pentesting-Skill`, **(2)** crear una skill **`wireless-audit`** doc-only con la referencia GUI `martin-olivier/airgorah`, y **(3)** añadir un módulo **`backend/wireless_analyzer.py`** host-only (SSH a un Kali físico con aircrack-ng).

## Candidatos

| Repo | Autor | Core | Estado en Pack 19 |
|------|-------|------|-------------------|
| `DragonJAR/Android-Pentesting-Skill` | DragonJAR SAS | Skill en Markdown (referencias MASTG/OWASP, scripts frida, benchmarks) — **Apache-2.0** | ✅ **Elegido (vendorizado)** |
| `martin-olivier/airgorah` | Martin Olivier | GUI Rust/GTK4 sobre aircrack-ng (monitor mode) — **GPL-3.0** | 🔶 **Solo referencia** (doc) |

## Por qué cada uno

- **Android-Pentesting-Skill** encaja con la categoría `mobile` ya existente (`apk-reverse`) y aporta material de auditoría **holística** (MASTG/CVSS/RASP, intent injection, deep links, repackaging, source-to-sink) que complementa las skills RE puntuales. Es Markdown puro → se integra con el sistema de playbooks sin tocar código.
  - **Licencia Apache-2.0** → vendorizar es legal con `ATTRIBUTION.md` (mismo patrón que `agency-agents` MIT).
  - **Frontmatter incompatible**: el original usa claves con guiones (`allowed-tools`, multiline `>`) que el parser MIRV (`skill_playbooks.py:_parse_skill_md`) no soporta. Se reescribió un `SKILL.md` propio compatible (`category: mobile`, `allowed_tools` con `_`) y se conservó el original como `SKILL.original.md`.
- **airgorah** es una **GUI Linux** que envuelve aircrack-ng: requiere adaptador Wi-Fi en **monitor mode** + polkit → **imposible en Docker** (el contenedor no tiene passthrough de USB ni rfkill). Se documenta como **referencia de escritorio** dentro de la skill `wireless-audit`, pero el flujo real de M.I.R.V. es **host-only vía SSH** a un Kali físico.

## Alcance del Pack 19

- **Skill `android-pentesting`** vendorizada en `backend/skills/android-pentesting/`: `references/`, `assets/frida-scripts/`, `scripts/`, `benchmarks/`, `LICENSE` (Apache-2.0) + `ATTRIBUTION.md`. `SKILL.md` MIRV-compatible; `allowed_tools: apktool/jadx/frida/adb/objection/python3/aapt2/apksigner/zipalign/apkid`.
- **Skill `wireless-audit`** doc-only (`category: recon`): flujo aircrack-ng (airmon-ng → airodump-ng → aireplay-ng deauth → aircrack-ng crack), OPSEC, notas de legalidad, referencia airgorah.
- **Router `R39 wireless-audit`** en `skills/router/routing.json` (routes/priority **39→40**, R0–R39). La ruta android holística **no** se añadió como PRIMARY para no desplazar `R10 apk-reverse` (el benchmark de 99 casos espera R10 para hints de frida/pinning).
- **Módulo `backend/wireless_analyzer.py`** (~117 L): `WirelessSession` dataclass + `WirelessRegistry` thread-safe + `_ssh_client()` (paramiko **opcional**, env `MIRV_WIRELESS_HOST/PORT/USER/KEY/PASS`, timeout 10 s) + `run_host_cmd(cmd, timeout=60) -> (out, err, rc)` con fallo elegante `"wireless host not configured (MIRV_WIRELESS_HOST)"`.
- **5 endpoints** `/api/wireless/*`: `GET/POST /sessions`, `GET /sessions/{sid}`, `POST /host/check`, `POST /host/exec` (cmd ≤ 4096).
- **19 tests** hermeneuticos (`test_wireless_analyzer.py`, SSH mockeado). Suite completa **5250 passed, 1 deselected**.

## Invariantes respetadas

- **Sin tablas nuevas en Supabase** — `registry` es **in-memory**; `test_pack_purity.py` fija el esquema en **18 tablas**.
- **Sin red/BD en el módulo** — `paramiko` es dependencia opcional con `try/except`; sin host configurado responde con error controlado (sin excepción).
- **Docker**: el módulo **no funciona** dentro del contenedor por diseño (sin Wi-Fi). Degrada elegantemente (`/api/wireless/*` devuelve `ok:false`/`not configured`) sin romper el arranque.
