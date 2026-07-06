# Plan de Producción — VulnForge

## Escenario
- **PC de mesa**: Kali + Backend VulnForge (localhost:8000)
- **Portátil**: solo navegador, desde fuera de casa
- Objetivo: acceder a VulnForge sin exponer la IP local

## Arquitectura final
```
Portátil → navegador → Cloudflare Tunnel → Kali (backend + SSH local)
                        https://vulnforge.midominio.com
```

Backend y Kali en la misma máquina → SSH por localhost, sin túneles TCP.

## Requisitos
- Dominio en Cloudflare (~3-5€/año en Namecheap o Cloudflare Registrar)
- cloudflared instalado en Kali ✅ (versión 2026.6.1)

## Pasos (pendientes)

### 1. Comprar dominio
- Namecheap.com o Cloudflare Registrar
- Configurar DNS en Cloudflare (nameservers)

### 2. Login cloudflared
```bash
cloudflared tunnel login
```
Abrir link → autorizar con cuenta Cloudflare.

### 3. Crear túnel nombrado
```bash
cloudflared tunnel create vulnforge-web
```
Guarda el ID que devuelve.

### 4. Configurar túnel
Editar `~/.cloudflared/config.yml`:
```yaml
tunnel: vulnforge-web
credentials-file: /home/javi/.cloudflared/<ID>.json
ingress:
  - hostname: vulnforge.tudominio.com
    service: http://localhost:8000
  - service: http_status:404
```

### 5. Ruta DNS
```bash
cloudflared tunnel route dns vulnforge-web vulnforge.tudominio.com
```

### 6. Iniciar túnel (permanente)
```bash
cloudflared tunnel run vulnforge-web
```

### 7. Servicio systemd (opcional)
Para que arranque solo al encender el PC:
```bash
sudo cloudflared service install ~/.cloudflared/config.yml
```

## A tener en cuenta
- Si el proceso de cloudflared se cae, se pierde el acceso
- Usar `systemd` lo hace automático al arrancar el PC
- No necesita Render — el backend corre en localhost
- El portátil solo necesita navegador, no instalar nada
