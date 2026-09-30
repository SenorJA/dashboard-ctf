"""
phishing_sim.py -- MIRV Module

Phishing awareness simulation (GoPhish-style, TRAINING ONLY).

Generates generic, clearly-branded landing pages meant for security-awareness
drills: there are no cloned real logins and no OTP interception. When a
trainee "logs in", the submission is recorded with the credentials hashed
(sha256 prefixes, never stored in plaintext), a click counter is bumped and
main.py turns it into a SIEM event + a high-severity finding to track
susceptibility over time.

Guards
------
* Every campaign requires an explicit ``authorized_by`` operator label
  (reflects written consent; recorded by the audit log in main.py).
* Campaigns only serve the landing page while ``status == "active"``.
* Nothing is sent to anyone by this module; it has no outbound mail or
  webhook. Persistence is opt-in via ``workspace_store`` (key ``"phishing"``),
  exactly like ``assets.py``.
"""

from __future__ import annotations

import hashlib
import html
import json
import logging
import secrets
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

try:
    from backend import workspace_store as _store
except ImportError:  # pragma: no cover
    _store = None  # type: ignore[assignment]

logger = logging.getLogger("vulnforge.phishing_sim")

MAX_CAMPAIGNS = 200
_HASH_LEN = 16

TRAINING_TEMPLATES = {
    "generic_portal": {
        "id": "generic_portal",
        "name": "Portal genérico",
        "category": "credenciales",
        "description": "Login corporativo genérico (formación interna).",
    },
    "invoice_notice": {
        "id": "invoice_notice",
        "name": "Aviso de factura",
        "category": "señuelo",
        "description": "Página de «descarga de factura» que pide identificación.",
    },
    "it_password_reset": {
        "id": "it_password_reset",
        "name": "Reseteo de contraseña TI",
        "category": "soporte",
        "description": "Ventana simulada de reseteo de contraseña de la empresa.",
    },
}

_BANNER = (
    '<div style="background:#7f1d1d;color:#fff;padding:10px 16px;font-family:'
    'Segoe UI,Tahoma,sans-serif;font-size:14px;font-weight:600;text-align:center">'
    "⚠ SIMULACIÓN DE PHISHING CONTROLADA · Formación y concienciación — "
    "NO introduzcas credenciales reales.</div>"
)

_REGISTRY: Dict[str, "PhishingCampaign"] = {}
_LOCK = threading.Lock()
_HYDRATED = False


@dataclass
class PhishingCampaign:
    """A single training campaign (in-memory, opt-in persistence)."""

    id: str
    name: str
    template_id: str
    target: str
    authorized_by: str
    status: str = "planning"  # planning | active | done | archived
    clicks: int = 0
    submissions: int = 0
    hashes: List[dict] = field(default_factory=list)  # [{u,p,at}] sha256[:16]
    notes: str = ""
    created_at: str = ""
    started_at: str = ""
    finished_at: str = ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _gen_id() -> str:
    return f"ph-{secrets.token_hex(4)}"


def _p_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:_HASH_LEN]


def _persist() -> None:
    if _store and _store.is_enabled():
        payload = [asdict(c) for c in _REGISTRY.values()]
        _store.upsert("phishing", payload)


_CAMPAIGN_FIELDS = frozenset(asdict(PhishingCampaign("", "", "", "", "")).keys())


def _hydrate() -> None:
    global _HYDRATED
    if _HYDRATED:
        return
    _HYDRATED = True
    if not _store or not _store.is_enabled():
        return
    try:
        rows = _store.load("phishing")
        if not rows:
            return
        for row in rows:
            camp = PhishingCampaign(**{
                k: v for k, v in row.items() if k in _CAMPAIGN_FIELDS
            })
            _REGISTRY[camp.id] = camp
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("phishing_sim hydrate failed: %s", exc)


def templates() -> list:
    return [dict(t) for t in TRAINING_TEMPLATES.values()]


def stats() -> dict:
    _hydrate()
    by_status = {}
    for c in _REGISTRY.values():
        by_status[c.status] = by_status.get(c.status, 0) + 1
    return {
        "total": len(_REGISTRY),
        "by_status": by_status,
        "total_clicks": sum(c.clicks for c in _REGISTRY.values()),
        "total_submissions": sum(c.submissions for c in _REGISTRY.values()),
    }


def list_campaigns() -> List[dict]:
    _hydrate()
    return [asdict(c) for c in sorted(_REGISTRY.values(), key=lambda c: c.created_at, reverse=True)]


def get_campaign(campaign_id: str) -> Optional[PhishingCampaign]:
    _hydrate()
    return _REGISTRY.get(campaign_id)


def create_campaign(
    name: str,
    template_id: str,
    target: str,
    authorized_by: str,
    notes: str = "",
) -> Tuple[Optional[PhishingCampaign], Optional[str]]:
    """Create a campaign in ``planning``. Returns (campaign, error)."""
    _hydrate()
    name = (name or "").strip()
    target = (target or "").strip()
    authorized_by = (authorized_by or "").strip()
    if not name or not target or not authorized_by:
        return None, "name, target y authorized_by son obligatorios"
    if template_id not in TRAINING_TEMPLATES:
        return None, f"plantilla desconocida: {template_id}"
    if len(_REGISTRY) >= MAX_CAMPAIGNS:  # pragma: no cover - bound guard
        return None, f"límite alcanzado ({MAX_CAMPAIGNS} campañas)"
    campaign = PhishingCampaign(
        id=_gen_id(),
        name=name,
        template_id=template_id,
        target=target,
        authorized_by=authorized_by,
        notes=(notes or "").strip(),
        created_at=_now(),
    )
    _REGISTRY[campaign.id] = campaign
    _persist()
    return campaign, None


def activate_campaign(campaign_id: str) -> Tuple[Optional[PhishingCampaign], Optional[str]]:
    """Mark a campaign as ``active`` (only the active ones serve the landing)."""
    _hydrate()
    campaign = _REGISTRY.get(campaign_id)
    if not campaign:
        return None, "campaña no encontrada"
    if campaign.status == "archived":
        return None, "campaña archivada no se puede reactivar"
    campaign.status = "active"
    if not campaign.started_at:
        campaign.started_at = _now()
    campaign.finished_at = ""
    _persist()
    return campaign, None


def archive_campaign(campaign_id: str) -> Tuple[Optional[PhishingCampaign], Optional[str]]:
    _hydrate()
    campaign = _REGISTRY.get(campaign_id)
    if not campaign:
        return None, "campaña no encontrada"
    if campaign.status == "active":
        campaign.finished_at = _now()
    campaign.status = "archived"
    _persist()
    return campaign, None


def delete_campaign(campaign_id: str) -> bool:
    _hydrate()
    removed = _REGISTRY.pop(campaign_id, None) is not None
    if removed:
        _persist()
    return removed


def record_click(campaign_id: str) -> Tuple[Optional[PhishingCampaign], Optional[str]]:
    """Bump the click counter when a trainee opens the landing URL."""
    _hydrate()
    campaign = _REGISTRY.get(campaign_id)
    if not campaign:
        return None, "campaña no encontrada"
    if campaign.status != "active":
        return None, "campaña no activa"
    campaign.clicks += 1
    _persist()
    return campaign, None


def record_submission(
    campaign_id: str,
    username: str,
    password: str,
) -> Tuple[Optional[dict], Optional[str]]:
    """Record a trainee submission with hashed credentials (never plaintext)."""
    _hydrate()
    campaign = _REGISTRY.get(campaign_id)
    if not campaign:
        return None, "campaña no encontrada"
    if campaign.status != "active":
        return None, "campaña no activa"
    entry = {
        "u": _p_hash(username or ""),
        "p": _p_hash(password or ""),
        "at": _now(),
    }
    campaign.hashes.append(entry)
    campaign.submissions += 1
    _persist()
    return {
        "campaign_id": campaign.id,
        "campaign_name": campaign.name,
        "at": entry["at"],
        "username_hash": entry["u"],
        "password_hash": entry["p"],
    }, None


def _render_card(campaign: PhishingCampaign) -> str:
    title = TRAINING_TEMPLATES.get(campaign.template_id, {}).get("name", "Simulación")
    desc = TRAINING_TEMPLATES.get(campaign.template_id, {}).get("description", "")
    safe_name = html.escape(campaign.name)
    safe_target = html.escape(campaign.target)
    return f"""
<div style="max-width:420px;margin:40px auto;background:#0b1220;border:1px solid #1f2937;
     border-radius:10px;padding:28px;color:#e5e7eb;font-family:Segoe UI,Tahoma,sans-serif">
  <h2 style="margin:0 0 6px;color:#22d3ee">{html.escape(title)}</h2>
  <p style="font-size:13px;color:#9ca3af;margin:0 0 18px">{html.escape(desc)} · {safe_name} · {safe_target}</p>
  <form method="post" action="/phishing/{campaign.id}/submit">
    <label style="display:block;font-size:13px;margin-bottom:6px">Usuario</label>
    <input type="text" name="username" autocomplete="off" required
      style="width:100%;box-sizing:border-box;padding:10px;margin-bottom:14px;border-radius:6px;
             border:1px solid #374151;background:#0f172a;color:#e5e7eb">
    <label style="display:block;font-size:13px;margin-bottom:6px">Contraseña</label>
    <input type="password" name="password" autocomplete="off" required
      style="width:100%;box-sizing:border-box;padding:10px;margin-bottom:18px;border-radius:6px;
             border:1px solid #374151;background:#0f172a;color:#e5e7eb">
    <button type="submit"
      style="width:100%;padding:11px;border:0;border-radius:6px;background:#06b6d4;color:#0b1220;
             font-weight:700;cursor:pointer">Iniciar sesión (simulación)</button>
  </form>
  <p style="font-size:11px;color:#6b7280;margin-top:14px;text-align:center">
    Entorno de formación MIRV · no se almacenan credenciales reales.</p>
</div>"""


def render_landing(campaign_id: str) -> Tuple[Optional[str], Optional[str]]:
    """Public landing HTML for a trainee (only while active)."""
    campaign = get_campaign(campaign_id)
    if not campaign:
        return None, "campaña no encontrada"
    if campaign.status != "active":
        return None, "campaña no activa"
    return (
        "<!doctype html><html lang='es'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<body style='margin:0;background:#060a12'>{_BANNER}{_render_card(campaign)}</body></html>",
        None,
    )


def render_result(campaign_id: str) -> Tuple[Optional[str], Optional[str]]:
    """Public 'you fell for it' page shown right after a submission."""
    campaign = get_campaign(campaign_id)
    if not campaign:
        return None, "campaña no encontrada"
    return (
        "<!doctype html><html lang='es'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<body style='margin:0;background:#060a12'>{_BANNER}"
        "<div style='max-width:520px;margin:60px auto;background:#0b1220;border:1px solid #1f2937;"
        "border-radius:10px;padding:28px;color:#e5e7eb;font-family:Segoe UI,Tahoma,sans-serif'>"
        "<h2 style='margin:0 0 10px;color:#fbbf24'>Has picado en la simulación 🎣</h2>"
        "<p style='font-size:14px;line-height:1.6'>Esto era una campaña controlada de concienciación. "
        "En una simulación de phishing real así es como un atacante captura tus credenciales. "
        "Regla de oro: si un enlace te pide usuario y contraseña, verifícalo por un canal distinto.</p>"
        f"<p style='font-size:12px;color:#9ca3af'>Campaña: {html.escape(campaign.name)}</p>"
        "</div></body></html>",
        None,
    )