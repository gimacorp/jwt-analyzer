"""HTML report rendering via jinja2."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")


def render_html(result: dict[str, Any], output_path: str) -> str:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")

    html = template.render(
        header=result["header"],
        payload_json=json.dumps(result["payload"], indent=2, ensure_ascii=False),
        header_json=json.dumps(result["header"], indent=2, ensure_ascii=False),
        vulnerabilities=result["vulnerabilities"],
        score=result["score"],
        decoded=result["decoded"],
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return output_path
