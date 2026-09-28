import json, subprocess, sys, urllib.request

BASE = "http://localhost:8000"
ENV = r"C:\Users\34678\Desktop\Proyecto ciber\.env"

def cli():
    tok = ""
    for line in open(ENV, encoding="utf-8"):
        if line.startswith("MIRV_API_TOKEN="):
            tok = line.split("=", 1)[1].strip()
    return tok

def req(path, method="GET", body=None):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method,
                               headers={"X-MIRV-Token": cli(),
                                        "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")

def main():
    results = []
    def check(name, cond, extra=""):
        results.append((name, cond))
        print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra else ""))

    # 1. crear finding (escritura real a Supabase)
    st, d = req("/api/findings", "POST", {
        "tool": "e2e-manual", "target": "10.0.0.9", "type": "manual",
        "severity": "medium", "title": "E2E smoke finding (temporal)",
        "detail": "prueba de escritura real Supabase", "recommendation": "borrar"})
    fid = (d.get("data") or {}).get("id") if isinstance(d.get("data"), dict) else None
    check("finding creado", st == 201 and bool(fid), f"status={st} id={fid}")

    # 2. patch lifecycle
    st2, d2 = req(f"/api/findings/{fid}", "PATCH", {"lifecycle_status": "verified"})
    check("lifecycle -> verified", st2 == 200 and d2.get("ok") is True, f"status={st2}")

    # 3. está en la lista
    st3, d3 = req("/api/findings")
    items = d3.get("findings") or d3.get("data") or []
    check("apparece en GET /api/findings", any(str(f.get("id")) == str(fid) for f in items),
          f"total={len(items)}")

    # 4. borrar
    st4, d4 = req(f"/api/findings/{fid}", "DELETE")
    check("finding borrado", st4 == 200 and d4.get("ok") is True, f"status={st4}")

    # 5. assessment in-memory create/delete
    st5, d5 = req("/api/assessments", "POST", {"name": "E2E temp", "status": "planning"})
    aid = (d5.get("assessment") or {}).get("id")
    check("assessment creado", st5 == 200 and bool(aid), f"id={aid}")
    st6, d6 = req(f"/api/assessments/{aid}", "DELETE")
    check("assessment borrado", st6 == 200 and d6.get("ok") is True, f"status={st6}")

    # 6. audit log recibe los eventos
    st7, d7 = req("/api/audit/stats")
    check("audit stats ok", st7 == 200 and d7.get("ok") is True,
          f"total={d7.get('total_events')}")

    ok = all(c for _, c in results)
    print("\nRESULTADO:", "OK ✅" if ok else "FALLO ❌")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()