# SIEM Dashboard Module — Plan de Implementación

## Objetivo
Sistema de monitoreo de eventos de seguridad (SIEM ligero) con logs en tiempo real, correlación de eventos y alertas.

## Arquitectura

```
backend/siem.py              → Lógica: eventos, reglas, alertas
backend/main.py              → Endpoints REST + WebSocket (futuro)
frontend/index.html          → Pestaña "SIEM"
frontend/js/main.v2.js       → UI lógica
```

## Endpoints

| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | /api/siem/event | Ingestar un evento |
| GET | /api/siem/events | Listar eventos (con filtros: severity, source, since) |
| GET | /api/siem/stats | Estadísticas: total eventos, por severidad, por fuente |
| GET | /api/siem/alerts | Listar alertas generadas |
| POST | /api/siem/rules | Crear regla de correlación |
| GET | /api/siem/rules | Listar reglas |
| DELETE | /api/siem/rules/{id} | Eliminar regla |

## Tipos de evento

| Campo | Tipo | Descripción |
|-------|------|-------------|
| id | str | UUID |
| timestamp | str | ISO timestamp |
| source | str | origen (ssh, docker, api, canary, dlp, etc.) |
| severity | str | info, low, medium, high, critical |
| title | str | Título corto |
| detail | str | Descripción larga |
| raw | dict | Datos originales del evento |
| tags | list | Etiquetas para correlación |

## Reglas de correlación

| Regla | Condición | Acción |
|-------|-----------|--------|
| brute-force | 5+ failed auth events en 60s desde misma IP | Crear alerta CRITICAL |
| port-scan | 10+ conexiones a diferentes puertos en 30s | Crear alerta HIGH |
| canary-trigger | Evento de canary-token activation | Crear alerta CRITICAL |
| dlp-leak | 3+ DLP findings high en 5 min | Crear alerta HIGH |
