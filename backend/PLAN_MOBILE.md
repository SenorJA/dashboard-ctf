# 📱 Mobile Lab — Plan de Implementación

## API Contract

### APK Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/mobile/upload` | Upload APK (multipart) → returns `{apk_id, package, version, ...}` |
| GET | `/api/mobile/apks` | List all analyzed APKs |
| GET | `/api/mobile/analyze/{apk_id}` | Run full static analysis on APK |
| DELETE | `/api/mobile/apks/{apk_id}` | Delete APK and analysis |

### Dynamic Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/mobile/devices` | List ADB devices connected |
| POST | `/api/mobile/adb/connect` | Connect ADB to a device |
| POST | `/api/mobile/frida/run` | Run a Frida script on device |
| GET | `/api/mobile/frida/scripts` | List available Frida scripts |

### Response Format

All endpoints return:
```json
{"ok": true, "data": {...}}
```
Or error:
```json
{"ok": false, "error": "message"}
```

## Static Analysis Rules (built-in)

1. **Dangerous Permissions** — CAMERA, RECORD_AUDIO, READ_SMS, etc.
2. **Exported Components** — Activities, Services, Providers, Receivers
3. **WebView Insecurities** — JS enabled, file access, mixed content
4. **Hardcoded Secrets** — API keys, tokens, passwords, URLs in strings/smali
5. **SSL Pinning** — Check if implemented (TrustManager, OkHttp, etc.)
6. **Root Detection** — Check for common detection methods
7. **Weak Crypto** — DES, MD4, RC4, ECB mode, custom crypto
8. **Backup Flag** — `android:allowBackup=true`
9. **Debuggable** — `android:debuggable=true`
10. **Cleartext Traffic** — `android:usesCleartextTraffic=true`

## Frida Scripts (bundled in scripts/frida/)

- `ssl-bypass.js` — Universal SSL pinning bypass
- `root-bypass.js` — Root detection bypass
- `pin-bypass.js` — PIN/pattern bypass
- `frida-script-template.js` — Template for custom scripts

## File Structure

```
backend/
  mobile_analyzer.py    # Static APK analysis engine
  adb_controller.py     # ADB/Frida dynamic interface

frontend/
  js/mobile.js          # Mobile Lab UI

scripts/
  frida/
    ssl-bypass.js
    root-bypass.js
    pin-bypass.js
    template.js
```
