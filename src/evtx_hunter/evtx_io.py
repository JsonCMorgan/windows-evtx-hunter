"""Read EVTX files into normalized event dicts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from evtx_hunter.xml_parse import parse_event_xml


def read_evtx_events(path: str | Path) -> list[dict[str, Any]]:
    """Load all records from an EVTX file."""
    from Evtx.Evtx import Evtx

    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(str(p))

    events: list[dict[str, Any]] = []
    with Evtx(str(p)) as log:
        for record in log.records():
            xml = record.xml()
            ev = parse_event_xml(xml)
            if ev:
                events.append(ev)
    return events