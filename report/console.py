"""Console rendering via rich."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

_SEVERITY_STYLE = {
    "Critical": "bold white on red",
    "High": "bold red",
    "Medium": "bold yellow",
    "Low": "cyan",
    "OK": "bold green",
}

_TAG_STYLE = {
    "Critical": "red",
    "High": "red",
    "Medium": "yellow",
    "Low": "cyan",
    "OK": "green",
}


def render_console(result: dict[str, Any], verbose: bool = False) -> None:
    console = Console()

    header = result["header"]
    payload = result["payload"]
    findings = result["vulnerabilities"]

    body = Text()
    if result["decoded"]:
        body.append("Token decoded successfully\n", style="green")
    else:
        body.append("Token could NOT be fully decoded\n", style="red")

    body.append(f"Algorithm : {header.get('alg', '—')}\n")

    exp = payload.get("exp")
    if exp:
        from datetime import datetime, timezone

        exp_dt = datetime.fromtimestamp(float(exp), tz=timezone.utc)
        body.append(f"Expires   : {exp_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    else:
        body.append("Expires   : not set\n")

    console.print(Panel(body, title="JWT Security Analyzer v1.0", border_style="blue", expand=False))

    if not findings:
        console.print("  [bold green][OK][/bold green] No issues detected.")
    else:
        for f in findings:
            sev = f["severity"]
            tag_style = _TAG_STYLE.get(sev, "white")
            line = Text()
            line.append(f"  [{sev.upper()}]", style=f"bold {tag_style}")
            line.append(f" {f['title']}")
            console.print(line)
            if verbose and f.get("detail"):
                console.print(Text(f"          {f['detail']}", style="dim"))

    # Score line
    counts = result["score"]
    score = Text("\n  Score: ")
    for sev in ["Critical", "High", "Medium", "Low"]:
        n = counts.get(sev, 0)
        if n:
            score.append(f"{n} {sev}  ", style=_TAG_STYLE.get(sev, "white"))
    ok = counts.get("OK", 0)
    if ok:
        score.append(f"{ok} OK", style="green")
    if not any(counts.get(s, 0) for s in ["Critical", "High", "Medium", "Low"]):
        score.append("clean", style="green")
    console.print(score)
