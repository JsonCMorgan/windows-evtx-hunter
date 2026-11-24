"""CLI: python -m evtx_hunter sample.evtx --html report.html"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from evtx_hunter.analyze import analyze_events
from evtx_hunter.evtx_io import read_evtx_events
from evtx_hunter.timeline_html import render_timeline_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt in Windows EVTX logs (offline, local file).")
    parser.add_argument("evtx", help="Path to .evtx file")
    parser.add_argument("--html", metavar="FILE", help="Write HTML timeline report")
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout")
    args = parser.parse_args(argv)

    try:
        events = read_evtx_events(args.evtx)
    except OSError as exc:
        print(f"Could not read EVTX: {exc}", file=sys.stderr)
        return 2

    result = analyze_events(events)

    if args.html:
        Path(args.html).write_text(
            render_timeline_report(result, args.evtx),
            encoding="utf-8",
        )
        print(f"Wrote {args.html}", file=sys.stderr)

    if args.json or not args.html:
        print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())