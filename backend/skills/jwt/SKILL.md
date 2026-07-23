---
name: jwt
description: "JSON Web Token abuse: algorithm confusion, kid abuse, weak secrets, validation flaws."
category: jwt
allowed_tools:
  - curl
  - ffuf
  - hash_cracker
version: "1.0.0"
author: "MIRV"
---

# JWT Methodology

## 1. Decode & inventory
- Split into `header.payload.signature` and base64url-decode
- Capture expiry (`exp`), issuer, audience, role claims
- Identify library from `header.kid` patterns / `typ` / `cty`

## 2. Algorithm confusion (alg=none / HS↔RS)
- Set `{"alg":"none"}` and drop signature → send payload only
- HS↔RS confusion: if server uses RS256 and verifies with public key, forge HS256 signed with that public key as HMAC secret
- Tools: `jwt_tool`, `jwt-forgery` — try every public key on disk

## 3. `kid` header abuse
- `kid` is often a filesystem path or SQL: try `kid: /dev/null`, `kid: ../../etc/hosts`
- SQL injection in `kid`: `kid: ' UNION SELECT 'known-secret'-- -`
- Path traversal to an attacker-controlled file on the server

## 4. Weak secrets
- Crack HMAC with rockyou: `hashcat -m 16500 jwt.txt wordlist`
- Common secrets: `secret`, `password`, `key`, `your-256-bit-secret`, the JWT itself
- Brute-force symmetric secret with `jwt_tool -C -d rockyou.txt`

## 5. Validation flaws
- Claim injection: `{"admin": true}` if app trusts undefined claims
- `exp` bypass: set `exp` far in future OR remove `exp` (if library tolerates)
- `nbf` / `iat` tampering
- Audience bypass: drop `aud` or set to `*`
- Case sensitivity in `iss` / `aud` claims
- JWK header injection: register your own public key inside the JWT (jwk / x5c / jku)
- `jku` / `x5u` URL tricks: server fetches your JWKS from attacker host

## 6. Token reuse & fixation
- Logout endpoint that does NOT invalidate tokens → reuse
- Token rotation: does the server issue a new token on role change? If not, forge role claim
- Refresh token replay

## 7. Crypto pitfalls
- None-compliant library trusting `alg: none` for legacy reasons
- Truncated signatures: pad-truncate attacks
- Mixed alg across header / verifier (PEP.put header=HS256, verify_path=RS256)

## IMPORTANT
- For every successful forgery, demonstrate authenticated access to a privileged endpoint
- Never report `alg:none` blindly — confirm the server actually accepts it
- Record request + decoded JWT + signature proofs as evidence