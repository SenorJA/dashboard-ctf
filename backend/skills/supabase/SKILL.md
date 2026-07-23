---
name: supabase
description: "Supabase / PostgreSQL security: Row-Level Security mistakes, anonymous key abuse, storage exposure."
category: supabase
allowed_tools:
  - curl
  - nmap
  - ffuf
version: "1.0.0"
author: "MIRV"
---

# Supabase Methodology

## 1. Identify the project
- Look for `*.supabase.co` API keys in client-side JS bundles
- Two keys per project:
  - **anon** key — meant for unauthenticated client use
  - **service_role** key — full DB bypass (MUST NEVER leak)
- Capture both from network traffic / `supabase-js` config

## 2. Test anon key reachability
- `curl "https://<proj>.supabase.co/rest/v1/<table>?select=*" -H "apikey: <anon>"`
- Anon key alone should let you read ANY table without RLS
- Enumerate tables by name (`/rest/v1/users`, `/rest/v1/profiles`, `/rest/v1/admin_*`)
- Check PostgREST OpenAPI: `/rest/v1/` returns API spec listing every public table/view

## 3. Row-Level Security (RLS) mistakes
- Table without RLS policy = readable by anyone with anon key
- Policy using `auth.role() = 'anon'` = true for unauthenticated → data leak
- Policy using `true` ("policy exists but always passes")
- Permissive `USING (true) WITH CHECK (true)` — read wins, write wins
- `auth.uid()` is null for anon — any policy `auth.uid() = id`-only returns nothing,
  but `auth.uid() IS NOT NULL OR <other-true-condition>` may leak

## 4. Storage bucket exposure
- `/storage/v1/object/public/<bucket>/<file>` — public bucket
- List objects: `GET /storage/v1/object/list/<bucket>`
- Private buckets + anon key: try signed URL forging or `auth.ops` misuse
- Storage policies often weaker than DB policies → check them independently
- Try uploading: `POST /storage/v1/object/<bucket>/pwned.txt` with anon key

## 5. Auth endpoints
- `/auth/v1/signup`, `/auth/v1/token` — password strength, email enumeration
- Magic link email enumeration via response divergence
- OAuth redirect (`/auth/v1/authorize?provider=github&redirect_to=...`) → open redirect
- `/auth/v1/signup` ignoring `confirm` flag — instant account creation
- Password reset token reuse / predictable tokens

## 6. Realtime / Edge Functions
- Realtime channels: broadcast permissions often `true` for anon
- Edge Functions: read source if exposed; check for env leak in response (`Deno.env.get("SUPABASE_SERVICE_ROLE")`)

## 7. Escalation patterns
- Get anon key → read users table → find admin email → reset attack / OAuth steal
- Find `service_role` key in client bundle = critical (full DB bypass)
- RLS bypass via UPDATE in a policy that has `USING (false) WITH CHECK (true)` (rare but seen)
- USE statement / RPC functions (`/rest/v1/rpc/<function>`) bypass RLS if `SECURITY DEFINER` without explicit checks

## 8. Verification payload
```bash
curl "https://<proj>.supabase.co/rest/v1/users?id=eq.1&select=id,email" \
  -H "apikey: <anon>" \
  -H "Authorization: Bearer <anon>"
```
- 200 with rows = RLS bypass confirmed
- 401 = anon key rejected (unusual) or RLS enforces auth
- 403 with `{"code":"42501"}` = RLS active → try policy bypass tricks

## IMPORTANT
- The **service_role** key bypasses RLS entirely — finding it is `critical` immediately
- Always operate with explicit authorization on your own test project first
- Capture anon key, table list, and one leaky row as PoC; never exfiltrate real user data
- Document which policy is misconfigured (paste the SQL `pg_policies` row if accessible)