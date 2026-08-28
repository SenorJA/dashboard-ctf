# Changelog — M.I.R.V.

All notable changes to this project are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/), auto-generated from Conventional Commits.

## [Unreleased] — 28 Ago 2026

### Added
- `9db256` — feat(ronda4): a11y + i18n completa + README + auditoria UI
- `408c717` — feat(ronda3): correlacion OSINT + docs rondas 1-3 + slow test fixes
- `4bb319d` — feat(ronda2): security hardening — fix P1+P2 de la auditoria OSINT
- `09680e8` — feat(ronda1): responsive OSINT tab + security audit + coverage 100% osint_recon
- `eb6542e` — feat(osint): fase 3 — skill `password-audit` + Instagram OSINT (ghostig port)
- `4918397` — feat(osint): passive OSINT recon suite — skill, subdomain passive sources (crt.sh + Wayback), módulo `osint_recon.py` + tab OSINT
- `b6a1d4b` — feat(deploy): VPS bootstrap + Cloudflare Tunnel scaffold (Hitos A/B) — `deploy/bootstrap-vps.sh`
- `92f4fa3` — feat(pdf): professional findings PDF export with per-finding detail + VPS secrets docs
- `022f349` — browser-capture-mcp: 7 MCP tools para importar/analizar HAR y convertir en findings del session store
- `2f5ef00` — feat: real light theme — bloque `body.light`, theme toggle de 3 estados (neon/light/mono), contraste WCAG AA, colores JS theme-aware
- `dedfda6` — feat: swarm full mode — operadores OSINT/Web/Vuln + selector de modo (pipeline de 7 ops)

### Fixed
- `09db256` — fix(a11y): P1 UI audit fixes + 2 plugin_watcher timing tests marcados slow
- `ee1d844` — fix(a11y): P1 UI audit — contraste WCAG AA + tab roles + labels + modales + arsenal
- `3cb20fb` — fix(ci): green suite on empty-env (no Supabase, `KALI_IP=""`, watchdog)
- `d8569d8` — fix(audit_log): stop runaway recursion in `AuditLogHandler.emit` (CI #47/#48)
- `4bb319d` — fix(security): hardening P1+P2 del audit OSINT (token, rate limit, `_safeUrl`, max_length, IPs privadas, dominio estricto, HTTPS, logger sin input)
- `cff28aa` — fix(ci): excluir `@pytest.mark.slow` por marker (`-m 'not slow'`)
- `72c5db3` — fix(audit_log): add re-entrancy guard to `AuditLogHandler.emit`
- `82e9fa0` — fix(ci): pytest-timeout 60s + timeout 20min — evitar que tests colgados (red/timers) bloqueen el pipeline horas
- `80cb2a0` — fix(deploy): usar `env.VPS_HOST` en `if:` — secrets no es válido en condiciones `if` de GitHub Actions

### Documentation
- `1be1583` — docs(tomorrow): ronda 4 documentada — a11y + i18n 100% + README + auditoria UI
- `c522089` — docs(tomorrow): corregir postmortem flake — causa real fue httpbin.org, no OOM (fix 90ca638)
- `dec0290` — docs(tomorrow): hito Fase 3 OSINT cerrado (eb6542e + 945b726) + postmortem runner flake
- `a0ac863` — docs(tomorrow): hito suite OSINT pasivo cerrado (4918397) — 31 módulos, 236 endpoints, 4030 tests, 26 tabs
- `59525b9` — docs(tomorrow): andamiaje Hitos A/B listo (b6a1d4b), pasos manuales usuario
- `910cb15` — docs(tomorrow/roadmap): hito PDF profesional cerrado (92f4fa3) + hitos abiertos VPS/Cloudflare
- `1947218` — docs(tomorrow): mark CI 100% green milestone + postmortem for 11 unmasked failures
- `b1a79d4` — docs(tomorrow): document 11 pre-existing CI failures unmasked after watchdog fix
- `8e7456a` — docs: secrets Docker Hub configurados (`DOCKERHUB_USERNAME` + TOKEN)
- `3fea21c` — docs: marcar browser MCP, swarm ops y light theme como completados en ROADMAP/TOMORROW
- `acf6a99` — docs: coverage refresh — main.py 100%, 3834 tests, 76 test files, pending phases updated

### Tests
- `90ca638` — test(api_scanner): mark 9 httpbin.org integration tests as `@pytest.mark.slow`
- `6cfa6e6` — test(watcher): accelerate plugin watcher tests 4.4s -> 1.8s + kill 2 latent races
- `2b2d227` — test(coverage): exif_osint + dlp_scanner to 100%
- `525ea54` — test(plugin_manager): fix watchdog_gaps teardown assertion (CI Linux installs watchdog)
- `25d6204` — test(imports): unify `backend.*` prefix + conftest `sys.modules` alias + fix IPv6 subdomain test
- `d9c0754` — test: main.py 100% — REST gap coverage (test_main_gaps 295) + websocket `read_shell`/`WebSocketDisconnect` paths (test_main_websocket_gaps 19)

### CI/CD
- `945b726` — ci: diagnostic `head+wc` of `pytest.log` on failure — job eb6542e killed mid-run (140s, no FAILED lines)
- `6de6c15` — ci: diagnostic `--cov-fail-under=0` (isolate coverage vs test failures) + upload pytest log artifact
- `800d9d7` — ci: emit pytest verdict as `::error::` annotations (queryable via API)
- `01492cd` — ci: add step-summary diagnostic for failing pytest run (log too large for UI)

[Unreleased]: https://github.com/SenorJA/dashboard-ctf/compare/main...HEAD
