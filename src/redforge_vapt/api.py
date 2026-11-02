import json
import os
import secrets

import yaml
from fastapi import Depends, FastAPI, Header, HTTPException

from .adapters import OPTIONAL, REGISTRY, validate_nuclei_templates
from .engine import get_scan, list_scans
from .reporting import render_report

app = FastAPI(title="RedForge VAPT Engine", version="0.1.0")


def identity(authorization: str | None = Header(default=None)):
    """Tokens are supplied via environment, mapped to roles and engagement IDs."""
    try:
        users = json.loads(os.environ.get("REDFORGE_API_TOKENS", "{}"))
    except json.JSONDecodeError:
        raise HTTPException(503, "API authentication is misconfigured") from None
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Bearer token required")
    token = authorization[7:]
    for expected, user in users.items():
        if secrets.compare_digest(token, expected):
            if user.get("role") not in ("operator", "reviewer", "administrator"):
                break
            return user
    raise HTTPException(401, "Invalid token")


def permitted(user, engagement_id):
    if user["role"] != "administrator" and engagement_id not in user.get("engagements", []):
        raise HTTPException(403, "Engagement access denied")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/tools")
def tools(user=Depends(identity)):
    statuses = {name: "ready" if adapter.available() else "unavailable" for name, adapter in REGISTRY.items()}
    if statuses["nuclei"] == "ready":
        try:
            validate_nuclei_templates(os.environ.get("REDFORGE_NUCLEI_SAFE_TEMPLATES", ""))
        except (ValueError, OSError, yaml.YAMLError):
            statuses["nuclei"] = "unconfigured"
    if statuses["semgrep"] == "ready" and not os.environ.get("REDFORGE_SEMGREP_RULES"):
        statuses["semgrep"] = "unconfigured"
    return {**statuses, **OPTIONAL}


@app.get("/scans")
def scans(user=Depends(identity)):
    result = list_scans()
    return result if user["role"] == "administrator" else [s for s in result if s["engagement_id"] in user.get("engagements", [])]


@app.get("/scans/{scan_id}")
def scan(scan_id: str, user=Depends(identity)):
    try:
        result = get_scan(scan_id)
    except KeyError:
        raise HTTPException(404, "Scan not found") from None
    permitted(user, result["engagement_id"])
    return result


@app.get("/scans/{scan_id}/reports/{fmt}")
def report(scan_id: str, fmt: str, user=Depends(identity)):
    if fmt not in ("html", "json"):
        raise HTTPException(400, "Only HTML and JSON are available through this API")
    try:
        result = get_scan(scan_id)
    except KeyError:
        raise HTTPException(404, "Scan not found") from None
    permitted(user, result["engagement_id"])
    path = render_report(scan_id, fmt)
    from fastapi.responses import FileResponse
    return FileResponse(path, media_type="text/html" if fmt == "html" else "application/json")
