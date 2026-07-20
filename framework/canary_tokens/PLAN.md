# Canary Tokens Module — Plan de Implementación

## Objetivo
Sistema de honeytokens / canary tokens para detección de intrusiones. Genera señuelos (API keys, credenciales, URLs, archivos) que alertan cuando un atacante los utiliza.

## Arquitectura

```
backend/canary_tokens.py     → Lógica de generación + tracking
backend/main.py              → Endpoints REST
frontend/index.html          → Pestaña "Canary"
frontend/js/main.v2.js       → UI lógica
```

## Endpoints

| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | /api/canary/token | Generar nuevo token señuelo |
| GET | /api/canary/tokens | Listar todos los tokens activos |
| GET | /api/canary/activate/{token_id} | Endpoint de activación (cuando usan el token) |
| GET | /api/canary/events | Listar eventos de activación |
| DELETE | /api/canary/token/{token_id} | Eliminar un token |

## Tipos de tokens

| Tipo | Descripción | Formato |
|------|-------------|---------|
| api-key | API key falsa | `sk-...` / `pk-...` |
| db-url | Database URL | `postgresql://user:pass@host/db` |
| jwt | JWT token falso | `eyJ...` |
| aws-key | AWS credentials | `AKIA...` |
| slack-token | Slack token | `xoxb-...` |
| generic-url | URL de callback | `https://.../webhook` |
| env-file | Archivo .env descargable | texto con creds falsas |
| config-file | Archivo de configuración | XML/JSON/YAML |

## Activación
Cuando alguien visita `GET /api/canary/activate/{token_id}`, se registra:
- Timestamp exacto
- IP de origen
- User-Agent
- Referer (si existe)
- País aproximado (por IP)

## Almacenamiento
- En memoria (diccionario) con persistencia opcional a JSON
- Los tokens expiran tras 30 días por defecto
