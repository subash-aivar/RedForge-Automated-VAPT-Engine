import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import yaml


def redact(value: str) -> str:
    import re
    value = re.sub(r"(?i)(authorization|x-api-key|cookie|set-cookie)(\s*[:=]\s*)[^\r\n]+", r"\1\2[REDACTED]", value)
    value = re.sub(r"(?i)(password|token|secret|api_key)(\s*[:=]\s*)[^\s&]+", r"\1\2[REDACTED]", value)
    return value


@dataclass
class Candidate:
    title: str
    asset: str
    location: str = ""
    severity: str = "info"
    description: str = ""
    confidence: str = "unknown"
    references: list[str] = field(default_factory=list)
    remediation: str = ""
    evidence: list[str] = field(default_factory=list)


class Adapter:
    name: str
    executable: str
    parser: Callable[[str], list[Candidate]]
    fixture_suffix: str
    network: bool = False

    def available(self):
        return shutil.which(self.executable) is not None

    def command(self, config, target):
        raise NotImplementedError

    def run(self, config, target, *, fixture_dir=None):
        if fixture_dir:
            path = Path(fixture_dir) / f"{self.name}.{self.fixture_suffix}"
            if not path.is_file():
                return "skipped", [], "fixture unavailable", ""
            raw = path.read_text(encoding="utf-8")
        else:
            if not self.available():
                return "unavailable", [], "binary not installed", ""
            args = self.command(config, target)
            try:
                with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                    process = subprocess.Popen(
                        args, stdout=stdout, stderr=stderr,
                        cwd=Path.cwd(),
                        env={k: v for k, v in os.environ.items() if k not in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY")},
                        start_new_session=True,
                    )
                    deadline = time.monotonic() + min(config.request_timeout * 6, 300)
                    failure = None
                    while process.poll() is None:
                        if stdout.tell() > 10_000_000 or stderr.tell() > 1_000_000:
                            failure = "scanner output exceeded size limit"
                            break
                        if time.monotonic() >= deadline:
                            failure = "scanner timeout"
                            break
                        time.sleep(0.05)
                    if failure:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                        return "failed", [], failure, ""
                    if stdout.tell() > 10_000_000 or stderr.tell() > 1_000_000:
                        return "failed", [], "scanner output exceeded size limit", ""
                    stdout.seek(0)
                    stderr.seek(0)
                    raw = stdout.read().decode("utf-8", errors="replace")
                    error = stderr.read().decode("utf-8", errors="replace")
            except OSError as exc:
                return "failed", [], f"scanner launch failed: {type(exc).__name__}", ""
            if process.returncode not in self.success_codes:
                return "failed", [], f"scanner exited {process.returncode}: {redact(error)[:300]}", raw
        try:
            return "completed", self.parser(raw), "", raw
        except (ValueError, KeyError, AttributeError, ET.ParseError, TypeError) as exc:
            return "failed", [], f"invalid scanner output: {type(exc).__name__}", raw

    success_codes = (0,)


def _severity(value):
    value = str(value or "info").lower()
    return value if value in ("critical", "high", "medium", "low", "info") else "info"


def parse_nmap(raw):
    root = ET.fromstring(raw)
    if root.tag != "nmaprun":
        raise ValueError("not Nmap XML")
    findings = []
    for host in root.findall("host"):
        address = host.find("address")
        if address is None:
            continue
        asset = address.attrib.get("addr", "")
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            number = port.attrib.get("portid", "")
            protocol = port.attrib.get("protocol", "")
            service = port.find("service")
            label = service.attrib.get("name", "unknown") if service is not None else "unknown"
            findings.append(Candidate(f"Open {label} service", asset, f"{protocol}/{number}", "info", "Nmap observed an open port. This is an inventory observation, not a vulnerability.", "high", evidence=[f"Nmap port {protocol}/{number} open"]))
    return findings


def parse_nuclei(raw):
    findings = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        info = item.get("info") or {}
        findings.append(Candidate(
            str(info.get("name") or item.get("template-id") or "Nuclei finding"),
            str(item.get("host") or item.get("matched-at") or ""),
            str(item.get("matched-at") or ""), _severity(info.get("severity")),
            str(info.get("description") or ""), "medium",
            [str(x) for x in (info.get("reference") or [])] if isinstance(info.get("reference"), list) else [],
            str(info.get("remediation") or ""),
            [str(item.get("matcher-name") or item.get("template-id") or "template match")],
        ))
    return findings


def parse_semgrep(raw):
    data = json.loads(raw)
    findings = []
    for item in data.get("results", []):
        extra = item.get("extra") or {}
        meta = extra.get("metadata") or {}
        findings.append(Candidate(
            str(item.get("check_id") or "Semgrep finding"), str(item.get("path") or ""),
            f"line {item.get('start', {}).get('line', '?')}",
            {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(str(extra.get("severity", "INFO")).upper(), "info"),
            str(extra.get("message") or ""), "medium",
            [str(x) for x in meta.get("references", [])] if isinstance(meta.get("references"), list) else [],
            str(meta.get("fix") or ""), [str(extra.get("lines") or "rule match")],
        ))
    return findings


def parse_trivy(raw):
    data = json.loads(raw)
    findings = []
    for result in data.get("Results", []):
        asset = str(result.get("Target") or "")
        for item in result.get("Vulnerabilities") or []:
            findings.append(Candidate(
                str(item.get("VulnerabilityID") or "Trivy vulnerability"), asset,
                str(item.get("PkgName") or ""), _severity(item.get("Severity")),
                str(item.get("Description") or item.get("Title") or ""), "medium",
                [str(item.get("PrimaryURL"))] if item.get("PrimaryURL") else [],
                f"Update to {item['FixedVersion']}" if item.get("FixedVersion") else "Review vendor advisory.",
                [f"Installed version: {item.get('InstalledVersion', 'unknown')}"]))
        for item in result.get("Misconfigurations") or []:
            findings.append(Candidate(str(item.get("ID") or "Trivy misconfiguration"), asset, str((item.get("CauseMetadata") or {}).get("StartLine") or ""), _severity(item.get("Severity")), str(item.get("Description") or ""), "medium", remediation=str(item.get("Resolution") or ""), evidence=[str(item.get("Message") or "rule match")]))
    return findings


def validate_nuclei_templates(directory, max_requests=100):
    """Accept fixed in-scope HTTP requests only."""
    import re

    if not directory:
        raise ValueError("Nuclei template directory is not configured")
    root = Path(directory)
    if not root.is_dir():
        raise ValueError("Nuclei template directory does not exist")
    files = sorted([*root.rglob("*.yaml"), *root.rglob("*.yml")])
    if not files:
        raise ValueError("Nuclei template directory contains no YAML templates")
    request_keys = {"method", "path", "matchers", "matchers-condition", "stop-at-first-match"}
    request_count = 0
    for path in files:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 100_000:
            raise ValueError("Nuclei template must be a small regular file")
        template = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(template, dict) or set(template) - {"id", "info", "http"}:
            raise ValueError("Nuclei template has unsupported top-level features")
        requests = template.get("http")
        if not isinstance(requests, list) or not requests:
            raise ValueError("Nuclei template requires HTTP requests")
        for request in requests:
            if not isinstance(request, dict) or set(request) - request_keys:
                raise ValueError("Nuclei request has unsupported features")
            method = request.get("method", "GET")
            if not isinstance(method, str) or method.upper() not in ("GET", "HEAD"):
                raise ValueError("Nuclei request method is not allowed")
            paths = request.get("path")
            if not isinstance(paths, list) or not paths:
                raise ValueError("Nuclei request needs fixed paths")
            request_count += len(paths)
            if request_count > max_requests:
                raise ValueError("Nuclei templates exceed max_requests budget")
            for value in paths:
                if not isinstance(value, str) or not re.fullmatch(r"\{\{BaseURL\}\}/[A-Za-z0-9/_-]*", value):
                    raise ValueError("Nuclei path must stay under BaseURL without dynamic values")


class Nmap(Adapter):
    name, executable, parser, fixture_suffix, network = "nmap", "nmap", staticmethod(parse_nmap), "xml", True

    def command(self, config, target):
        return ["nmap", "-sT", "-Pn", "-n", "--max-retries", "0", "--max-rate", str(config.max_request_rate), "--host-timeout", f"{config.request_timeout * 6}s", "-p", ",".join(map(str, config.ports)), "-oX", "-", "--", target]


class Nuclei(Adapter):
    name, executable, parser, fixture_suffix, network = "nuclei", "nuclei", staticmethod(parse_nuclei), "jsonl", True

    def command(self, config, target):
        templates = os.environ.get("REDFORGE_NUCLEI_SAFE_TEMPLATES")
        if not templates or not Path(templates).is_dir():
            raise ValueError("curated safe Nuclei template directory is required")
        validate_nuclei_templates(templates, config.max_requests)
        return ["nuclei", "-u", target, "-t", templates, "-j", "-silent", "-or", "-ot", "-dr", "-ni", "-nh", "-duc", "-retries", "0", "-rl", str(config.max_request_rate), "-c", str(config.max_concurrency), "-timeout", str(config.request_timeout)]


class Semgrep(Adapter):
    name, executable, parser, fixture_suffix = "semgrep", "semgrep", staticmethod(parse_semgrep), "json"
    success_codes = (0, 1)

    def command(self, config, target):
        source = Path(config.source_path or ".").resolve()
        if not source.is_dir():
            raise ValueError("source_path must be an existing directory")
        rules = os.environ.get("REDFORGE_SEMGREP_RULES")
        if not rules or not Path(rules).is_file():
            raise ValueError("local Semgrep rules file is required")
        return ["semgrep", "scan", "--config", rules, "--json", "--metrics", "off", "--disable-version-check", str(source)]


class Trivy(Adapter):
    name, executable, parser, fixture_suffix = "trivy", "trivy", staticmethod(parse_trivy), "json"

    def command(self, config, target):
        source = Path(config.source_path or ".").resolve()
        if not source.is_dir():
            raise ValueError("source_path must be an existing directory")
        return ["trivy", "fs", "--format", "json", "--skip-db-update", "--skip-java-db-update", str(source)]


REGISTRY = {adapter.name: adapter for adapter in (Nmap(), Nuclei(), Semgrep(), Trivy())}
OPTIONAL = {name: "planned" for name in ("zap", "greenbone", "subfinder", "httpx", "sqlmap", "mobsf", "burp-import")}
