---
name: api-security
description: "API-layer security testing: OAuth/OIDC authorization flows (authorization-code, token reuse/replay, scope escalation), mass assignment, business-logic flaws (double-spend, wallet balance), rate limiting / IDOR/UUID enumeration, shadow and unauthenticated APIs, 401/403 bypass, HTTP parameter pollution and path normalization."
category: webvuln
allowed_tools:
  - curl
  - wfuzz
  - jwt_tool
  - mitmproxy
version: "1.0.0"
author: "MIRV"
requires_scope: true
---

# API Security Testing Methodology

## 1. Map the API surface
- Discover endpoints (openapi/swagger, JS bundles, mobile traffic), then fill a matrix: auth → endpoint → method.
- Tag shadow endpoints (unversioned, debug, admin) and unauthenticated routes from HAR/Burp captures.

## 2. Auth & authorization
- **OAuth/OIDC**: walk authorization-code/PKCE flows; test token reuse, replay across scopes, `scope` escalation, `aud`/`azp` confusion, token baking in URL vs body.
- **401/403 bypass**: `X-Original-URL`, `X-Rewrite-URL`, verb tampering, trailing slash/`;`/`..;` normalization, version-header manipulation.
- **Mass assignment**: extra fields (`is_admin`) in JSON/PATCH, missing `@JsonIgnoreProperties`-style key filtering.

## 3. Business logic
- Price/balance manipulation: double-spend, negative values, currency array injection, idempotency-key replay.
- Rate limiting: bypass via IP rotation, `X-Forwarded-For` spoofing, cache-key vs rate-limit-key divergence.
- UUID/id enumeration + IDOR with predictable IDs (`uuid.?enum`, `id.?oracle` probing).

## 4. Layer hygiene
- HTTP parameter pollution, path normalization (`.` / encoded `%2f`), `origin` header reflection, CORS on authenticated APIs.
- Hand off pure injection/XSS/SSTI/SQLi to `webvuln` (R3) when they surface.

## 5. Findings
- Evidence: request/response pairs, token flow trace, and the failing/broken assumption.
- Reproducible PoC: `curl` one-liners + token replay sequence (redact credentials).