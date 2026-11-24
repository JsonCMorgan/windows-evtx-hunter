"""Detection rules on parsed Windows Security events."""

from __future__ import annotations

from collections import Counter
from typing import Any

_BRUTE_THRESHOLD = 8


def analyze_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Flag brute force, new users, admin group adds, log clear, notable process create."""
    findings: list[dict[str, Any]] = []
    failed_by_ip: Counter[str] = Counter()

    for ev in events:
        eid = ev.get("event_id")
        fields = ev.get("fields") or {}
        base = {
            "time": ev.get("time"),
            "computer": ev.get("computer"),
            "event_id": eid,
        }

        if eid == 4625:
            ip = fields.get("IpAddress") or fields.get("SourceNetworkAddress") or "unknown"
            failed_by_ip[ip] += 1
            findings.append(
                {
                    **base,
                    "rule": "failed_logon",
                    "severity": "medium",
                    "summary": f"Failed logon for {fields.get('TargetUserName', '?')} from {ip}",
                }
            )
        elif eid == 4720:
            findings.append(
                {
                    **base,
                    "rule": "user_created",
                    "severity": "high",
                    "summary": f"New local user: {fields.get('TargetUserName', '?')}",
                }
            )
        elif eid == 4732:
            findings.append(
                {
                    **base,
                    "rule": "admin_group_add",
                    "severity": "high",
                    "summary": (
                        f"Member added to group {fields.get('TargetUserName', '?')}: "
                        f"{fields.get('MemberName', fields.get('SubjectUserName', '?'))}"
                    ),
                }
            )
        elif eid == 4688:
            proc = fields.get("NewProcessName") or fields.get("ProcessName") or ""
            if any(x in proc.lower() for x in ("powershell", "cmd.exe", "wscript", "mshta")):
                findings.append(
                    {
                        **base,
                        "rule": "process_create",
                        "severity": "low",
                        "summary": f"Process created: {proc}",
                    }
                )
        elif eid == 1102:
            findings.append(
                {
                    **base,
                    "rule": "audit_cleared",
                    "severity": "critical",
                    "summary": "Security audit log was cleared",
                }
            )

    for ip, count in failed_by_ip.items():
        if count >= _BRUTE_THRESHOLD and ip not in ("-", "127.0.0.1", "::1", "unknown"):
            findings.append(
                {
                    "rule": "brute_force_pattern",
                    "severity": "high",
                    "summary": f"{count} failed logons from {ip} (threshold {_BRUTE_THRESHOLD})",
                    "source_ip": ip,
                    "count": count,
                }
            )

    severity_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    worst = max(
        (severity_rank.get(f.get("severity", "low"), 0) for f in findings),
        default=0,
    )
    risk = {3: "critical", 2: "high", 1: "medium", 0: "low"}.get(worst, "low")

    return {
        "ok": True,
        "events_parsed": len(events),
        "findings_count": len(findings),
        "risk_level": risk if findings else "low",
        "findings": findings,
    }