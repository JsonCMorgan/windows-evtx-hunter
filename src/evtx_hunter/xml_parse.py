"""Parse Windows Event XML into a flat dict for detectors."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_event_xml(xml: str) -> dict[str, Any] | None:
    """Return event_id, time, computer, fields map; None if unparseable."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None

    eid_el = root.find("e:System/e:EventID", _NS)
    time_el = root.find("e:System/e:TimeCreated", _NS)
    comp_el = root.find("e:System/e:Computer", _NS)
    if eid_el is None or eid_el.text is None:
        return None

    fields: dict[str, str] = {}
    for data in root.findall(".//e:EventData/e:Data", _NS):
        name = data.attrib.get("Name")
        if name and data.text is not None:
            fields[name] = data.text.strip()

    return {
        "event_id": int(eid_el.text),
        "time": (time_el.attrib.get("SystemTime") if time_el is not None else "") or "",
        "computer": (comp_el.text if comp_el is not None else "") or "",
        "fields": fields,
    }