"""Applica la migracion de esquema a Supabase (una vez, idempotente).

Prioridad de metodos (en orden):
  1) POST {SUPABASE_URL}/pg/query con la service key  (solo si el proyecto lo expone)
  2) DATABASE_URL en .env  ->  psycopg2 (pip install psycopg2-binary si falta)
  3) si nada disponible: imprime el SQL y las instrucciones manuales (exit 2)

Uso:
  python backend/tests/manual_schema_migrate.py
"""

import json
import sys
import urllib.request
import urllib.error
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCHEMA = REPO / "backend" / "supabase_schema.sql"
ENV = REPO / ".env"


def load_env():
    env = {}
    if ENV.exists():
        for line in ENV.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def sql_text() -> str:
    return SCHEMA.read_text(encoding="utf-8")


def method_pg_query(env, sql):
    url = env.get("SUPABASE_URL", "").rstrip("/")
    key = env.get("SUPABASE_KEY", "")
    if not url or not key:
        return None, "no SUPABASE_URL/KEY"
    req = urllib.request.Request(
        url + "/pg/query",
        data=json.dumps({"query": sql}).encode(),
        headers={"Authorization": "Bearer " + key, "apikey": key,
                 "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            return True, f"/pg/query {r.status} {r.read().decode()[:120]}"
    except urllib.error.HTTPError as e:
        return None, f"/pg/query HTTP {e.code}: {e.read().decode()[:120]}"


def method_database_url(env, sql):
    dsn = env.get("DATABASE_URL", "")
    if not dsn:
        return None, "no DATABASE_URL en .env"
    try:
        import psycopg2
    except ImportError:
        return False, "psycopg2 no instalado: pip install psycopg2-binary"
    try:
        conn = psycopg2.connect(dsn, connect_timeout=10)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.close()
        return True, "psycopg2: esquema aplicado"
    except Exception as e:
        return False, f"psycopg2 error: {e}"


def main():
    env = load_env()
    sql = sql_text()
    applied = False
    for name, fn in (("pg_query",  method_pg_query),
                     ("database", method_database_url)):
        ok, msg = fn(env, sql)
        print(f"[{name}] {msg}")
        if ok:
            applied = True
            break
    if applied:
        print("MIGRACION APLICADA OK")
        return 0
    print("\nNo se pudo aplicar automaticamente.\n")
    print("Opcion A - Dashboard: https://supabase.com/dashboard -> en tu proyecto")
    print("  SQL Editor -> New query -> pega backend/supabase_schema.sql -> Run.\n")
    print("Opcion B - Automatica: anade a .env una linea y relanza este script:")
    print("  DATABASE_URL=postgresql://postgres.<ref>:<password>@aws-0-<region>"
          ".pooler.supabase.com:6543/postgres")
    print("  (Dashboard -> Connect -> Transaction pooler / direct connection)")
    return 2


if __name__ == "__main__":
    sys.exit(main())