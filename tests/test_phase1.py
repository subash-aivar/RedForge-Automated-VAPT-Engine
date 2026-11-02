import json
import socket
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect
from typer.testing import CliRunner

from redforge_vapt.adapters import (
    REGISTRY,
    Adapter,
    parse_nmap,
    parse_nuclei,
    parse_semgrep,
    parse_trivy,
    redact,
    validate_nuclei_templates,
)
from redforge_vapt.api import app
from redforge_vapt.cli import app as cli_app
from redforge_vapt.engine import get_scan, load_config, plan, run_scan
from redforge_vapt.policy import PolicyError, check_asset, check_redirect, check_target
from redforge_vapt.reporting import render_report

ROOT = Path(__file__).resolve().parents[1]


def config():
    return load_config(ROOT / "engagements/demo.yaml")


def test_scope_authorization_and_redirects():
    cfg = config()
    assert check_target(cfg, "127.0.0.1", resolve=False) == "127.0.0.1"
    with pytest.raises(PolicyError):
        check_target(cfg, "example.com", resolve=False)
    with pytest.raises(PolicyError):
        check_redirect(cfg, "https://example.com/")
    with pytest.raises(PolicyError):
        check_asset(cfg, "http://example.com/private")
    with pytest.raises(PolicyError):
        plan(cfg, "passive")
    assert all(row["status"] == "ready" for row in plan(cfg, "passive", fixture=True))


def test_dns_private_rejection():
    cfg = config()
    with (
        patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))]),
        pytest.raises(PolicyError),
    ):
        check_target(cfg, "127.0.0.1")


def test_parsers_and_redaction():
    fixture = ROOT / "fixtures/demo"
    assert len(parse_nmap((fixture / "nmap.xml").read_text())) == 1
    assert len(parse_nuclei((fixture / "nuclei.jsonl").read_text())) == 1
    assert len(parse_semgrep((fixture / "semgrep.json").read_text())) == 1
    assert len(parse_trivy((fixture / "trivy.json").read_text())) == 1
    assert "secret-value" not in redact("Authorization: secret-value")
    assert REGISTRY["nmap"].command(config(), "127.0.0.1")[-1] == "127.0.0.1"


def test_offline_end_to_end_and_api(tmp_path, monkeypatch):
    db = f"sqlite:///{tmp_path / 'db.sqlite'}"
    monkeypatch.setenv("REDFORGE_DATABASE_URL", db)
    monkeypatch.setenv("REDFORGE_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    scan_id, status, tools = run_scan(config(), fixture_dir=ROOT / "fixtures/demo", db_url=db)
    assert status == "completed"
    assert all(item["status"] == "completed" for item in tools.values())
    record = get_scan(scan_id, db)
    assert len(record["findings"]) == 4
    assert all(item["verification"] == "unverified" for item in record["findings"])
    html = render_report(scan_id, "html", output_dir=tmp_path / "reports", db_url=db)
    data = render_report(scan_id, "json", output_dir=tmp_path / "reports", db_url=db)
    assert "Missing demo security header" in html.read_text()
    assert len(json.loads(data.read_text())["findings"]) == 4
    monkeypatch.setenv("REDFORGE_API_TOKENS", json.dumps({"reviewer-token": {"role": "reviewer", "engagements": ["demo-local-001"]}, "other-token": {"role": "reviewer", "engagements": ["other"]}}))
    client = TestClient(app)
    assert client.get(f"/scans/{scan_id}").status_code == 401
    assert client.get(f"/scans/{scan_id}", headers={"Authorization": "Bearer other-token"}).status_code == 403
    response = client.get(f"/scans/{scan_id}", headers={"Authorization": "Bearer reviewer-token"})
    assert response.status_code == 200
    assert response.json()["scan_id"] == scan_id


def test_missing_scanner_is_not_success(tmp_path, monkeypatch):
    monkeypatch.setenv("REDFORGE_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    cfg = config().model_copy(update={"scanners": ["nmap", "zap"]})
    scan_id, status, tools = run_scan(cfg, fixture_dir=ROOT / "fixtures/demo", db_url=f"sqlite:///{tmp_path / 'db.sqlite'}")
    assert status == "partial"
    assert tools["zap"]["status"] == "unavailable"
    assert get_scan(scan_id, f"sqlite:///{tmp_path / 'db.sqlite'}")["status"] == "partial"


def test_cli_dry_run_and_invalid_scope():
    runner = CliRunner()
    result = runner.invoke(cli_app, ["scan", "--config", str(ROOT / "engagements/demo.yaml"), "--fixture-dir", str(ROOT / "fixtures/demo"), "--dry-run"])
    assert result.exit_code == 0
    assert '"status": "ready"' in result.stdout
    rejected = runner.invoke(cli_app, ["scan", "--config", str(ROOT / "engagements/demo.yaml"), "--dry-run"])
    assert rejected.exit_code == 1


def test_deduplication(tmp_path, monkeypatch):
    fixture = tmp_path / "fixtures"
    fixture.mkdir()
    line = (ROOT / "fixtures/demo/nuclei.jsonl").read_text()
    (fixture / "nuclei.jsonl").write_text(line + line)
    monkeypatch.setenv("REDFORGE_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    cfg = config().model_copy(update={"scanners": ["nuclei"]})
    db = f"sqlite:///{tmp_path / 'db.sqlite'}"
    scan_id, status, _ = run_scan(cfg, fixture_dir=fixture, db_url=db)
    findings = get_scan(scan_id, db)["findings"]
    assert status == "completed"
    assert len(findings) == 1
    assert len(findings[0]["sources"]) == 2


def test_nuclei_template_scope(tmp_path):
    template = tmp_path / "safe.yaml"
    template.write_text("id: safe\ninfo: {name: Safe, severity: info}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/']\n")
    validate_nuclei_templates(tmp_path)
    template.write_text("id: unsafe\ninfo: {name: Unsafe, severity: info}\nhttp:\n  - method: POST\n    path: ['https://example.com/']\n")
    with pytest.raises(ValueError):
        validate_nuclei_templates(tmp_path)


def test_scanner_timeout_kills_process(monkeypatch):
    class Sleeper(Adapter):
        name = "sleeper"
        executable = sys.executable
        parser = staticmethod(lambda raw: [])
        fixture_suffix = "txt"

        def command(self, config, target):
            return [sys.executable, "-c", "import time; time.sleep(30)"]

    with patch("redforge_vapt.adapters.time.monotonic", side_effect=[0, 100]):
        status, findings, reason, _ = Sleeper().run(config(), ".")
    assert (status, findings, reason) == ("failed", [], "scanner timeout")


def test_initial_migration(tmp_path):
    db = tmp_path / "migration.sqlite"
    alembic = Config(str(ROOT / "alembic.ini"))
    alembic.set_main_option("sqlalchemy.url", f"sqlite:///{db}")
    with patch.dict("os.environ", {"REDFORGE_DATABASE_URL": f"sqlite:///{db}"}):
        command.upgrade(alembic, "head")
    tables = inspect(create_engine(f"sqlite:///{db}")).get_table_names()
    assert {"engagements", "scans", "findings", "audit_logs", "alembic_version"}.issubset(tables)
