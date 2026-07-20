# DLP Scanner Module — Plan de Implementación

## Objetivo
Escáner de Prevención de Pérdida de Datos (DLP) que detecta Información Personal Identificable (PII) en archivos, texto y URLs. Útil para auditorías de cumplimiento (GDPR, CCPA, PCI-DSS).

## Patrones detectados

| Tipo | Patrón | Severidad | Ejemplo |
|------|--------|-----------|---------|
| Credit Card | `\b(?:\d[ -]*?){13,16}\b` (Luhn) | **high** | 4111-1111-1111-1111 |
| SSN | `\b\d{3}-\d{2}-\d{4}\b` | **high** | 123-45-6789 |
| Email | `\b[\w.+-]+@[\w-]+\.[\w.-]+\b` | **medium** | user@example.com |
| Phone | `\b(?:\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b` | **medium** | +1 (555) 123-4567 |
| IPv4 | `\b(?:\d{1,3}\.){3}\d{1,3}\b` | **low** | 192.168.1.1 |
| API Key | `(?i)(?:sk|pk|api[_-]?key|secret)[\s:=]+['\"]?[\w-]{16,}['\"]?` | **high** | API_KEY=sk-abc123... |
| Passport | `\b[A-Z]{1,2}\d{6,9}\b` | **high** | AB1234567 |
| IBAN | `\b[A-Z]{2}\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b` | **medium** | ES12 3456 7890 1234 5678 |

## Arquitectura

```
backend/dlp_scanner.py       → Lógica de escaneo con regex + Luhn
backend/main.py              → Endpoints REST
frontend/index.html          → Pestaña "DLP"
frontend/js/main.v2.js       → UI lógica
```

## Endpoints

| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | /api/dlp/scan | Escanea texto enviado en body |
| POST | /api/dlp/scan-file | Escanea archivo subido (multipart) |
| GET | /api/dlp/scan-url?url=... | Descarga URL y escanea |
