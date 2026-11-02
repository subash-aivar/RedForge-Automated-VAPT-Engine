import hashlib
import ipaddress
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import yaml
from sqlalchemy import select

from .adapters import REGISTRY, redact, validate_nuclei_templates
from .db import Audit, Base, Engagement, Finding, Scan, connect
from .policy import (
    EngagementConfig,
    PolicyError,
    authorize,
    check_asset,
    check_target,
    parse_target,
)


def load_config(path):
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError("engagement config must be a mapping")
    return EngagementConfig.model_validate(data)


def fingerprint(candidate):
    key = [candidate.title.lower().strip(), candidate.asset.lower().strip(), candidate.location.lower().strip()]
    return hashlib.sha256(json.dumps(key).encode()).hexdigest()


def plan(config, profile, *, fixture=False):
    authorize(config, profile, fixture=fixture)
    if not fixture:
        if len(config.targets) != 1:
            raise PolicyError("Phase 1 live scans require exactly one target")
        for target in config.targets:
            check_target(config, target)
            host, _, _ = parse_target(target)
            if "/" in host:
                raise PolicyError("Phase 1 live scans require a single host, not a CIDR")
            try:
                ipaddress.ip_address(host)
            except ValueError:
                if any(REGISTRY[name].network for name in config.scanners if name in REGISTRY):
                    raise PolicyError("Phase 1 live network scans require a public IP literal to avoid DNS rebinding") from None
    actions = []
    for name in config.scanners:
        adapter = REGISTRY.get(name)
        if not adapter:
            actions.append({"tool": name, "status": "unavailable", "reason": "adapter not implemented"})
            continue
        if adapter.network and profile == "passive" and not fixture:
            actions.append({"tool": name, "status": "skipped", "reason": "network scanner requires safe-active profile"})
        elif name == "nmap" and not fixture and "tcp" not in config.protocols:
            actions.append({"tool": name, "status": "skipped", "reason": "TCP scanning not permitted"})
        elif name == "nuclei" and not fixture and not any(p in config.protocols for p in ("http", "https")):
            actions.append({"tool": name, "status": "skipped", "reason": "HTTP(S) scanning not permitted"})
        elif adapter.network and not fixture and not config.authorization.scanner_permissions.get(name, False):
            actions.append({"tool": name, "status": "skipped", "reason": "scanner permission not granted"})
        elif name == "nuclei" and not fixture and not os.environ.get("REDFORGE_NUCLEI_SAFE_TEMPLATES"):
            actions.append({"tool": name, "status": "skipped", "reason": "curated safe templates not configured"})
        elif name == "nuclei" and not fixture:
            try:
                validate_nuclei_templates(os.environ["REDFORGE_NUCLEI_SAFE_TEMPLATES"], config.max_requests)
            except (ValueError, OSError, yaml.YAMLError) as exc:
                actions.append({"tool": name, "status": "skipped", "reason": f"unsafe or invalid templates: {exc}"})
                continue
            actions.append({"tool": name, "status": "ready" if adapter.available() else "unavailable", "reason": "approved" if adapter.available() else "binary not installed"})
        elif name == "semgrep" and not fixture and not os.environ.get("REDFORGE_SEMGREP_RULES"):
            actions.append({"tool": name, "status": "skipped", "reason": "local Semgrep rules not configured"})
        elif not fixture and not adapter.available():
            actions.append({"tool": name, "status": "unavailable", "reason": "binary not installed"})
        else:
            actions.append({"tool": name, "status": "ready", "reason": "fixture" if fixture else "approved"})
    return actions


def _artifact_dir(scan_id):
    root = Path(os.environ.get("REDFORGE_ARTIFACT_DIR", "./artifacts")).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    folder = root / scan_id
    folder.mkdir(mode=0o700, exist_ok=False)
    return folder


def _persist_raw(folder, name, raw):
    path = folder / f"{name}.raw"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(redact(raw))
    return str(path)


def run_scan(config, profile="passive", *, fixture_dir=None, db_url=None):
    fixture = fixture_dir is not None
    actions = plan(config, profile, fixture=fixture)
    engine, sessions = connect(db_url)
    Base.metadata.create_all(engine)
    scan_id = str(uuid.uuid4())
    folder = _artifact_dir(scan_id)
    with sessions.begin() as session:
        engagement = session.get(Engagement, config.id)
        if engagement is None:
            engagement = Engagement(id=config.id, client=config.client, operator=config.operator, scope=config.model_dump(mode="json"))
            session.add(engagement)
        else:
            engagement.scope = config.model_dump(mode="json")
        session.add(Scan(id=scan_id, engagement_id=config.id, profile=profile, mode="fixture" if fixture else "live", status="running", tool_status={}))
        session.add(Audit(actor=config.operator, action="scan_launch", engagement_id=config.id, details={"scan_id": scan_id, "profile": profile, "mode": "fixture" if fixture else "live"}))
    statuses = {}
    for action in actions:
        name = action["tool"]
        if action["status"] != "ready":
            statuses[name] = {"status": action["status"], "reason": action["reason"], "findings": 0}
            continue
        adapter = REGISTRY[name]
        target = config.targets[0] if adapter.network else config.source_path or "."
        if name == "nmap" and "://" in target:
            target = parse_target(target)[0]
        if name == "nuclei" and "://" not in target:
            scheme = "https" if "https" in config.protocols else "http"
            target = f"{scheme}://{target}"
        try:
            status, candidates, reason, raw = adapter.run(config, target, fixture_dir=fixture_dir)
        except (ValueError, OSError) as exc:
            status, candidates, reason, raw = "failed", [], str(exc), ""
        raw_path = _persist_raw(folder, name, raw) if raw else None
        count = 0
        with sessions.begin() as session:
            for item in candidates:
                if not item.asset or not item.title:
                    continue
                if adapter.network and not fixture:
                    try:
                        check_asset(config, item.asset)
                    except PolicyError:
                        continue
                fp = fingerprint(item)
                existing = session.scalar(select(Finding).where(Finding.scan_id == scan_id, Finding.fingerprint == fp))
                evidence = [redact(str(x))[:2000] for x in item.evidence]
                source = {"tool": name, "raw_artifact": raw_path}
                if existing:
                    existing.sources = [*existing.sources, source]
                    existing.evidence = list(dict.fromkeys([*existing.evidence, *evidence]))
                    existing.last_detected = datetime.now(UTC)
                else:
                    previous = session.scalar(select(Finding).where(Finding.engagement_id == config.id, Finding.fingerprint == fp).order_by(Finding.first_detected.asc()).limit(1))
                    session.add(Finding(id=str(uuid.uuid4()), scan_id=scan_id, engagement_id=config.id, fingerprint=fp, title=redact(item.title)[:500], description=redact(item.description), asset=redact(item.asset)[:500], location=redact(item.location)[:500], severity=item.severity, confidence=item.confidence, verification="unverified", references=[redact(str(ref)) for ref in item.references], sources=[source], evidence=evidence, remediation=redact(item.remediation), first_detected=previous.first_detected if previous else datetime.now(UTC)))
                    count += 1
        statuses[name] = {"status": status, "reason": reason, "findings": count}
    complete = [x for x in statuses.values() if x["status"] == "completed"]
    failed = [x for x in statuses.values() if x["status"] in ("failed", "unavailable", "skipped")]
    overall = "completed" if complete and not failed else "partial" if complete else "failed"
    with sessions.begin() as session:
        scan = session.get(Scan, scan_id)
        scan.status = overall
        scan.finished_at = datetime.now(UTC)
        scan.tool_status = statuses
    return scan_id, overall, statuses


def get_scan(scan_id, db_url=None):
    engine, sessions = connect(db_url)
    Base.metadata.create_all(engine)
    with sessions() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise KeyError(scan_id)
        findings = session.scalars(select(Finding).where(Finding.scan_id == scan_id)).all()
        return {
            "scan_id": scan.id, "engagement_id": scan.engagement_id, "client": scan.engagement.client,
            "operator": scan.engagement.operator, "profile": scan.profile, "mode": scan.mode,
            "status": scan.status, "created_at": scan.created_at.isoformat(),
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "scope": scan.engagement.scope, "tool_status": scan.tool_status,
            "findings": [{"id": f.id, "title": f.title, "description": f.description, "asset": f.asset,
                          "location": f.location, "severity": f.severity, "confidence": f.confidence,
                          "verification": f.verification, "references": f.references, "sources": f.sources,
                          "evidence": f.evidence, "remediation": f.remediation,
                          "first_detected": f.first_detected.isoformat(), "last_detected": f.last_detected.isoformat()}
                         for f in findings],
        }


def list_scans(db_url=None):
    engine, sessions = connect(db_url)
    Base.metadata.create_all(engine)
    with sessions() as session:
        return [{"scan_id": s.id, "engagement_id": s.engagement_id, "status": s.status,
                 "created_at": s.created_at.isoformat()} for s in session.scalars(select(Scan).order_by(Scan.created_at.desc())).all()]
