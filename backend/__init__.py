"""
M.I.R.V. Backend Package

Automatically adds the project root to ``sys.path`` so that all
``from backend.xxx import ...`` imports resolve correctly regardless
of the current working directory or how uvicorn spawns the reloader
subprocess.

This runs once when Python first imports ``backend`` — before any
submodule (``backend.main``, ``backend.database``, etc.) is loaded.
Without this, running ``uvicorn backend.main:app`` from the project
root would fail in the reloader subprocess with
``ModuleNotFoundError: No module named 'backend'``.
"""

import os
import sys

_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)
