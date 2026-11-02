import json
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from .db import Audit, connect
from .engine import get_scan


def render_report(scan_id, fmt="html", *, output_dir="reports", db_url=None):
    data = get_scan(scan_id, db_url)
    out = Path(output_dir).resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = out / f"{scan_id}.{fmt}"
    if fmt == "json":
        content = json.dumps(data, indent=2, ensure_ascii=False)
        path.write_text(content, encoding="utf-8")
    elif fmt in ("html", "pdf"):
        env = Environment(loader=PackageLoader("redforge_vapt", "templates"), autoescape=select_autoescape(["html"]))
        html = env.get_template("report.html").render(report=data)
        if fmt == "html":
            path.write_text(html, encoding="utf-8")
        else:
            try:
                from weasyprint import HTML
            except ImportError as exc:
                raise RuntimeError("PDF support requires the optional pdf dependencies") from exc
            HTML(string=html, base_url=str(out)).write_pdf(str(path))
    else:
        raise ValueError("format must be html, json, or pdf")
    path.chmod(0o600)
    _, sessions = connect(db_url)
    with sessions.begin() as session:
        session.add(Audit(actor=data["operator"], action="report_export", engagement_id=data["engagement_id"], details={"scan_id": scan_id, "format": fmt}))
    return path
