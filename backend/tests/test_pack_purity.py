"""Pack 16/17 — pureza de los módulos file-based (sin Supabase, sin red).

Los módulos nuevos (skill_router, skill_playbooks, agency_agents) y la
infraestructura que los soporta son **100% file-based**: si alguno empezara a
importar ``backend.database`` / ``supabase`` / un cliente HTTP, aparecerían
tablas nuevas en Supabase sin migración y la app rompería en CI (que corre con
``SUPABASE_URL=""``). Estos tests son la red de seguridad de esa invariant:

1. AST check — ningún import de BD/red en los módulos file-based.
2. Subprocess check — importarlos no carga ``backend.database``.
3. Esquema — la lista de tablas de ``database.py`` sigue en 18 y no contiene
   tablas de personas/router.
4. Packaging — el spec de PyInstaller y el Dockerfile empaquetan
   ``backend/agents`` (sin eso el binario de escritorio no tiene personas).
"""
from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[1]
_REPO = _BACKEND.parent

# Módulos que deben seguir siendo solo-archivo.
FILE_BASED_MODULES = ("agency_agents", "skill_router", "skill_playbooks")

FORBIDDEN_IMPORT_ROOTS = {
    "database", "supabase", "psycopg2", "asyncpg", "sqlalchemy",
    "httpx", "requests", "urllib", "socket", "http", "aiosqlite",
    "redis", "boto3",
}


def _imports_of(path: Path) -> set[str]:
    """Return every module root imported by ``path`` (AST-based, never execs)."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
            # "from . import x" / "from .sibling import y"
            if node.level and node.module:
                roots.add(node.module.split(".")[0])
    return roots


# ════════════════════════════════════════════════════════════════
#  1. Sin imports de BD / red
# ════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("module", FILE_BASED_MODULES)
def test_file_based_module_has_no_db_or_network_imports(module):
    found = _imports_of(_BACKEND / f"{module}.py")
    banned = sorted(found & FORBIDDEN_IMPORT_ROOTS)
    assert not banned, (
        f"{module}.py importa {banned} — los módulos file-based no deben "
        "tocar Supabase ni la red (añadiría tablas/migraciones nuevas)."
    )


@pytest.mark.parametrize("module", FILE_BASED_MODULES)
def test_file_based_module_never_names_persist_workspace_or_db_layer(module):
    src = (_BACKEND / f"{module}.py").read_text(encoding="utf-8")
    for token in ("MIRV_PERSIST_WORKSPACE", "workspace_store", "backend.database"):
        assert token not in src, f"{module}.py menciona '{token}'"
    # "supabase" como import (el skill homónimo es un nombre de playbook, ok).
    assert not re.search(r"^\s*(?:import|from)\s+[\w.]*supabase",
                         src, flags=re.M | re.I), (
        f"{module}.py importa supabase"
    )


# ════════════════════════════════════════════════════════════════
#  2. Importarlos no carga la capa de BD
# ════════════════════════════════════════════════════════════════

def test_importing_file_based_modules_does_not_load_database():
    code = (
        "import sys\n"
        "import backend.agency_agents, backend.skill_router, backend.skill_playbooks\n"
        "bad = [m for m in sys.modules if m.startswith('backend.database')\n"
        "       or m.startswith('supabase') or m.startswith('psycopg2')]\n"
        "print('LOADED=' + ','.join(bad))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(_REPO), capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "LOADED=\n" in proc.stdout or proc.stdout.strip().endswith("LOADED="), (
        f"se cargaron módulos de BD al importar los módulos file-based:\n{proc.stdout}"
    )


# ════════════════════════════════════════════════════════════════
#  3. El esquema de Supabase no crece con los packs nuevos
# ════════════════════════════════════════════════════════════════

def test_supabase_schema_still_has_exactly_the_original_18_tables():
    schema = (_BACKEND / "database.py").read_text(encoding="utf-8")
    tables = re.findall(r"CREATE TABLE IF NOT EXISTS\s+(\w+)", schema, flags=re.I)
    assert len(tables) == 18, f"tablas encontradas ({len(tables)}): {sorted(tables)}"
    forbidden = [t for t in tables if re.search(r"persona|agent|router|skill", t, re.I)]
    assert not forbidden, f"tablas inesperadas derivadas de packs nuevos: {forbidden}"


def test_persona_and_router_state_live_only_on_disk():
    """Personas y rutas del router se persisten en ficheros, no en tablas."""
    assert (_BACKEND / "agents").is_dir()
    assert (_BACKEND / "skills" / "routing.json").is_file() is False  # vive en skills/router/
    assert (_BACKEND / "skills" / "router" / "routing.json").is_file()
    assert (_BACKEND / "skills" / "router" / "benchmarks.json").is_file()


# ════════════════════════════════════════════════════════════════
#  4. Empaquetado — escritorio (PyInstaller) y Docker
# ════════════════════════════════════════════════════════════════

def test_pyinstaller_spec_bundles_agents_skills_and_plugins():
    spec = (_BACKEND / "mirv-backend.spec").read_text(encoding="utf-8")
    for folder in ("agents", "skills", "plugins"):
        assert f'os.path.join(backend_dir, "{folder}")' in spec, (
            f'mirv-backend.spec no empaqueta backend/{folder}: el binario de '
            "escritorio arrancaría sin esos ficheros."
        )


def test_dockerfile_copies_the_whole_backend_tree():
    """``COPY backend/`` incluye backend/agents (personas en la imagen)."""
    dockerfile = (_BACKEND / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY backend/ /app/backend/" in dockerfile
    assert not re.search(r"^COPY backend/\S+ /app/backend/\S+\s*$",
                         dockerfile, flags=re.M), (
        "COPY selectivo de backend/ rompería backend/agents en la imagen"
    )


def test_agents_dir_is_not_ignored_by_docker_or_git():
    dockerignore = _REPO / ".dockerignore"
    if dockerignore.exists():
        text = dockerignore.read_text(encoding="utf-8")
        assert "backend/agents" not in text and "agents/" not in text.splitlines()


# ════════════════════════════════════════════════════════════════
#  5. Build de escritorio (path local) — el .bat debe seguir al spec
# ════════════════════════════════════════════════════════════════

def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def test_build_backend_bat_bundles_agents_skills_and_plugins():
    bat = _read(_BACKEND / "build_backend.bat")
    for folder in ("skills", "plugins", "agents"):
        assert f'--add-data "{folder};backend/{folder}"' in bat, (
            f"build_backend.bat (--onefile) no incluye backend/{folder}"
        )


def test_build_desktop_copies_the_onefile_sidecar_with_target_triple():
    """El build local debe copiar dist/mirv-backend.exe con el nombre de externalBin.

    El spec es one-file: cualquier ``xcopy`` de la carpeta ``dist/mirv-backend``
    (layout antiguo) falla y dejaba en ``binaries/`` un sidecar obsoleto.
    """
    bat = _read(_REPO / "desktop" / "build_desktop.bat")
    assert "dist\\mirv-backend.exe" in bat, "no copia el .exe one-file"
    assert "mirv-backend-x86_64-pc-windows-msvc.exe" in bat, (
        "falta el nombre target-triple que exige tauri.conf.json externalBin"
    )
    assert 'xcopy /E /I /Y "..\\backend\\dist\\mirv-backend"' not in bat


def test_tauri_external_bin_points_at_the_copied_sidecar():
    import json
    conf = json.loads(_read(_REPO / "desktop" / "src-tauri" / "tauri.conf.json"))
    assert conf["bundle"]["externalBin"] == ["binaries/mirv-backend"]


def test_sidecar_binary_copies_use_the_target_triple_name():
    """Si binaries/ existe localmente, su .exe debe coincidir con externalBin.

    Un sidecar con otro nombre (o un stub) ignora el backend y la ventana de
    escritorio queda sin API. En CI el directorio no existe — se omite.
    """
    import json
    binaries = _REPO / "desktop" / "src-tauri" / "binaries"
    if not binaries.is_dir():
        pytest.skip("binaries/ solo existe tras un build local de sidecar")
    conf = json.loads(_read(_REPO / "desktop" / "src-tauri" / "tauri.conf.json"))
    external = conf["bundle"]["externalBin"][0].rsplit("/", 1)[-1]
    expected = {f"{external}-x86_64-pc-windows-msvc.exe"}
    found = {p.name for p in binaries.glob("*.exe")}
    assert found == expected, (
        f"binaries/ {sorted(found)} != {sorted(expected)} — tauri no encontrará "
        "el sidecar"
    )
    size = (binaries / next(iter(expected))).stat().st_size
    assert size > 5_000_000, (
        f"sidecar de {size} bytes — parece un stub, no el build de mirv-backend.exe"
    )


def test_desktop_versions_are_aligned_across_manifests():
    import json
    conf = json.loads(_read(_REPO / "desktop" / "src-tauri" / "tauri.conf.json"))
    pkg = json.loads(_read(_REPO / "desktop" / "package.json"))
    cargo = _read(_REPO / "desktop" / "src-tauri" / "Cargo.toml")
    lock = _read(_REPO / "desktop" / "src-tauri" / "Cargo.lock")
    cargo_ver = re.search(r'(?m)^version = "([^"]+)"', cargo).group(1)
    lock_ver = re.search(
        r'name = "mirv-desktop"\nversion = "([^"]+)"', lock
    ).group(1)
    assert conf["version"] == pkg["version"] == cargo_ver == lock_ver, (
        f"versiones dispersas: conf={conf['version']} pkg={pkg['version']} "
        f"cargo={cargo_ver} lock={lock_ver}"
    )
    readme = _read(_REPO / "README.md")
    assert f"v{conf['version']}" in readme, (
        f"README.md no menciona v{conf['version']} (bump de versión incompleto)"
    )
