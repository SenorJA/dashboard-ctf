# -*- coding: utf-8 -*-
"""
M.I.R.V. — Prompt Library (Fase A)
==================================
Curated prompts from awesome-chatgpt-prompts filtered for pentesting/blue team.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

DATA_FILE = Path(__file__).parent / "data" / "prompts" / "pentesting_prompts.json"

_CACHE: List[Dict[str, Any]] = []


def _load() -> List[Dict[str, Any]]:
    global _CACHE
    if _CACHE:
        return _CACHE
    try:
        if DATA_FILE.exists():
            with open(DATA_FILE, encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    _CACHE = data
                    return _CACHE
    except Exception:
        pass
    _CACHE = []
    return _CACHE


def list_prompts(q: str = "", tag: str = "") -> List[Dict[str, Any]]:
    items = _load()
    res = []
    ql = (q or '').lower()
    tl = (tag or '').lower()
    for it in items:
        if ql and ql not in (it.get('title','') + ' ' + ' '.join(it.get('tags',[]))).lower():
            continue
        if tl and tl not in [t.lower() for t in it.get('tags',[])]:
            continue
        res.append({k: it[k] for k in ('id','title','tags','source') if k in it})
    return res


def get_prompt(pid: str) -> Optional[Dict[str, Any]]:
    for it in _load():
        if it.get('id') == pid:
            return it
    return None


def count() -> int:
    return len(_load())
