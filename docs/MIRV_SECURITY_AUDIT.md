# MIRV Security Audit — Local Instance (Port 8000)

**Date:** 2026-10-26  
**Scope:** http://127.0.0.1:8000 (MIRV local instance running in Docker)  
**Type:** Authorized self-audit (own application)

## Executive Summary

| Category | Status | Notes |
|---|---|---|
| Auth Guard (API) | ✅ PASS | All /api/* protected by token (401 without/invalid), exempt: /api/health, /api/auth/status |
| Path Traversal | ✅ PASS | Static file routes blocked traversal attempts (403/404) |
| WebSocket Auth | ✅ PASS | Requires mirv_token cookie + first message must be JSON auth |
| Security Headers | ⚠️ MEDIUM | CSP present but uses 'unsafe-inline'/'unsafe-eval' (common for SPA but relaxes policy) |
| Input Validation | ✅ PASS | Scope validate, OSINT endpoints reject shell metachars (validated), AI protected by ingest_guard |
| Public Endpoints | ℹ️ INFO | /api/health, /api/auth/status public (by design). /phishing/* outside guard |
| Hardcoded Credentials | 🔴 HIGH | Default Kali SSH credentials hardcoded in main.py |

## Detailed Findings

### 1) Hardcoded SSH Credentials (HIGH)
**Location:** `backend/main.py:6123-6126`, `6487-6488`  
**Issue:** Defaults `192.168.214.142`, `javi/javi` hardcoded for Kali SSH.  
**Risk:** If env vars not set and code changes, defaults remain.  
**Recommendation:** Remove hardcoded defaults. Require explicit env/config. Fail closed if not configured.  
**Status:** Identified (requires fix)

### 2) CSP 'unsafe-inline'/'unsafe-eval' (MEDIUM)
**Location:** main.py CSP middleware  
**Issue:** Uses 'unsafe-inline' and 'unsafe-eval' for compatibility with Tailwind CDN and inline scripts.  
**Risk:** Reduces XSS protection.  
**Recommendation:** Migrate to nonces/hashes where possible, remove 'unsafe-eval' if not needed.  
**Status:** Accepted trade-off for current SPA architecture

### 3) Public phishing endpoints (INFO)
**Location:** /phishing/*  
**Issue:** Outside API auth guard (by design for training simulations).  
**Status:** Intentional, documented as training-only

## Positive Findings
- API token auth with constant-time comparison
- Path traversal protection
- WebSocket requires cookie + JSON auth flow
- OSINT endpoints validate hosts (regex)
- Ingest Guard protects AI chat from prompt injection
- Scope Guard + Permission Gate present

## Recommendations
1. **Fix HIGH:** Remove hardcoded `javi/javi` defaults, use env-only or fail closed
2. **Improve CSP:** Consider stricter policy in production
3. **Add rate limiting:** Consider per-IP limits on sensitive endpoints
4. **Rotate token:** Current token visible in session context — rotate for production

## Tests Performed
- Auth bypass attempts (no token/invalid/empty) → all rejected
- Path traversal variants (encoded/double-encoded/backslash) → all blocked
- WS without cookie / malformed JSON / auth failures → all rejected
- SQLi/XSS/prompt injection attempts → protected/validated
- OSINT DNS with shell metachars → rejected by validation
