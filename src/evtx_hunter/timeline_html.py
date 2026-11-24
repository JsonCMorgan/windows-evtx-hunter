"""Simple HTML timeline export."""

from __future__ import annotations

import html
from typing import Any


def render_timeline_report(analysis: dict[str, Any], source: str) -> str:
    """Standalone HTML page for mentor review."""
    findings = analysis.get("findings") or []
    rows = []
    for f in findings:
        sev = html.escape(str(f.get("severity", "")))
        summary = html.escape(str(f.get("summary", "")))
        when = html.escape(str(f.get("time", "")))
        eid = html.escape(str(f.get("event_id", "")))
        rows.append(
            f"<tr><td>{when}</td><td>{eid}</td><td class='{sev}'>{sev}</td><td>{summary}</td></tr>"
        )
    body = "\n".join(rows) or "<tr><td colspan='4'>No findings</td></tr>"
    src = html.escape(source)
    risk = html.escape(str(analysis.get("risk_level", "low")))
    count = int(analysis.get("events_parsed") or 0)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>EVTX timeline</title>
<style>
body{{font-family:Segoe UI,sans-serif;background:#0c100a;color:#f0ebe2;padding:20px}}
table{{width:100%;border-collapse:collapse}} td,th{{border:1px solid #3d4f32;padding:8px}}
.critical{{color:#ff6b6b}}.high{{color:#ff9a3c}}.medium{{color:#d4b896}}.low{{color:#52e88a}}
</style></head><body>
<h1>Windows EVTX Hunter</h1>
<p>Source: <code>{src}</code> · Events: {count} · Risk: <strong>{risk}</strong></p>
<table><thead><tr><th>Time</th><th>Event ID</th><th>Severity</th><th>Summary</th></tr></thead>
<tbody>{body}</tbody></table>
<p>Portfolio lab tool. Pair with EVTX-ATTACK-SAMPLES for practice.</p>
</body></html>"""