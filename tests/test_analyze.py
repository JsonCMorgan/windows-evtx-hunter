from evtx_hunter.analyze import analyze_events
from evtx_hunter.xml_parse import parse_event_xml


def test_parse_4625():
    xml = open("tests/fixtures/event_4625.xml", encoding="utf-8").read()
    ev = parse_event_xml(xml)
    assert ev and ev["event_id"] == 4625
    assert ev["fields"]["IpAddress"] == "203.0.113.50"


def test_brute_force_threshold():
    events = []
    for _ in range(10):
        events.append(
            {
                "event_id": 4625,
                "time": "2026-01-15T10:00:00Z",
                "computer": "DC01",
                "fields": {"TargetUserName": "x", "IpAddress": "203.0.113.99"},
            }
        )
    r = analyze_events(events)
    rules = {f["rule"] for f in r["findings"]}
    assert "brute_force_pattern" in rules


def test_audit_cleared():
    r = analyze_events(
        [
            {
                "event_id": 1102,
                "time": "t",
                "computer": "c",
                "fields": {},
            }
        ]
    )
    assert r["risk_level"] == "critical"