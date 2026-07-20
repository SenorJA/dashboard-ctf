# EXIF OSINT Module — Plan de Implementación

## Objetivo
Módulo de OSINT para extraer, visualizar y reportar metadatos EXIF de imágenes (JPEG, PNG, TIFF, WebP, HEIC). 
Orientado a auditorías de privacidad, reconocimiento pasivo y educación en seguridad de la información.

## Arquitectura

```
frontend/                     backend/                        framework/exif_osint/
  index.html (tab)              main.py (endpoint)              core/
  js/main.v2.js (UI)            exif_osint.py (module)            exif_engine.py
                                                                  gps_utils.py
                                                               modules_osint/
                                                                  social_scraper.py
                                                               tests/
                                                                  test_exif.py
                                                               docs/
                                                                  USAGE.md
```

## Flujo de datos

```
Usuario (drag&drop o URL)
  → API /api/exif/analyze (POST multipart o GET query)
    → exif_osint.py: analyze_image() 
      → Pillow + PIL.ExifTags
        → Extrae: GPS, Camera, DateTime, Software, Thumbnail
      → Si GPS disponible → geocoding reverse (Nominatim)
    → report_to_mirv_findings()
  → Frontend muestra:
    - Metadatos en tabla
    - Mapa (Leaflet) con marcador GPS
    - Severidad calculada (GPS > Camera > Software)
    - Botón "Export Report" (MD/HTML/PDF)
  → Findings integrados en pestaña Findings existente
```

## Endpoints

### POST /api/exif/analyze (multipart)
- `file`: imagen a analizar (hasta 20MB)
- Response: JSON con todos los metadatos EXIF + GPS reverse geocoding

### GET /api/exif/analyze?url=...
- `url`: URL pública de imagen
- Descarga + analiza igual que POST

## Datos extraídos

| Categoría | Campos |
|-----------|--------|
| **GPS** | Latitud, Longitud, Altitud, GPS Timestamp, Map URL (OpenStreetMap) |
| **Camera** | Make, Model, Lens, Focal Length, Aperture (FNumber), ISO, Exposure |
| **Image** | Width, Height, Format, Color Space, Orientation, Software |
| **Metadata** | DateTimeOriginal, DateTimeDigitized, Artist, Copyright, Description |
| **Thumbnail** | Has thumbnail, size, format |
| **Geocoding** | Reverse geocode: country, city, street (si hay GPS) |

## Severidad findings

| Condición | Severidad | Razón |
|-----------|-----------|-------|
| GPS presente | **high** | Revela ubicación exacta |
| Camera Make/Model | **medium** | Identifica dispositivo |
| Software (editing) | **medium** | Revela herramientas usadas |
| Artist/Copyright | **low** | Información personal |
| Sin EXIF | **info** | No hay datos extraíbles |

## Integración frontend

- Nueva pestaña "EXIF" en el grupo OSINT (o como sub-sección de OSINT)
- Drag & drop zone con preview de imagen
- Tabla de metadatos con tooltips de explicación
- Mapa Leaflet condicional (solo si GPS)
- Botón "Open in Google Maps"/"Open in OpenStreetMap"
- Export findings al sistema existente
- Compatible con i18n (en/es)

## Integración backend

- Módulo independiente `backend/exif_osint.py`
- Endpoint en `main.py` (post multipart + get url)
- Findings en formato MIRV estándar (`tool: "exif-osint"`)
- Reporte exportable en MD/HTML/PDF

## Dependencias nuevas

- `Pillow>=10.0.0` (análisis EXIF)
- `httpx` (descarga remota, ya existe en requirements)
- `aiofiles` (opcional, para manejo async de archivos)

## Tareas

### FASE A — Backend module (backend/exif_osint.py)
- [ ] Dataclasses: EXIFResult, GPSInfo, CameraInfo
- [ ] `analyze_image(file_bytes, filename)`: extrae EXIF con Pillow
- [ ] `analyze_url(url)`: descarga imagen + llama analyze_image
- [ ] `reverse_geocode(lat, lon)`: consulta Nominatim
- [ ] `calculate_severity(exif_data)`: asigna severidad
- [ ] `report_to_mirv_findings(result)`: convierte a findings MIRV

### FASE B — API endpoint (main.py)
- [ ] Importar módulo
- [ ] POST /api/exif/analyze (multipart file upload)
- [ ] GET /api/exif/analyze?url=... (URL remota)
- [ ] Manejo de errores (formato inválido, sin EXIF, timeout)

### FASE C — Frontend UI (index.html + main.v2.js)
- [ ] Nueva pestaña "tab-exif" en navegación
- [ ] Drag & drop zone con FileReader preview
- [ ] Tabla de resultados con categorías colapsables
- [ ] Mapa Leaflet condicional
- [ ] Botones exportar y copiar
- [ ] i18n entries

### FASE D — Tests (framework/exif_osint/tests/)
- [ ] Test analizar imagen local con GPS
- [ ] Test analizar imagen sin EXIF
- [ ] Test severidad calculada correctamente
- [ ] Test report_to_mirv_findings formato

### FASE E — Integración
- [ ] Verificar findings aparecen en pestaña Findings
- [ ] Export MD/HTML/PDF funcional
- [ ] i18n consistente
