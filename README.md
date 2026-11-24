# Windows EVTX Hunter

[![CI](https://github.com/JsonCMorgan/windows-evtx-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/JsonCMorgan/windows-evtx-hunter/actions/workflows/ci.yml)

## For mentors (30 seconds)

**What it is:** Point at a `.evtx` export and get a JSON finding list plus an optional HTML timeline: failed logons, brute-force patterns, new users, admin group adds, audit log cleared, noisy process creates.

**Why it exists:** Classic junior SOC skill: read Windows Security logs without opening a full SIEM. Offline, local file only.

**Practice data:** [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) on GitHub.

---

## Quick start

```powershell
cd C:\Dev\windows-evtx-hunter
pip install -e ".[dev]"
pytest -q
python -m evtx_hunter "C:\path\to\Security.evtx" --html report.html --json
```

---

## Detections (v0.1)

| Event ID | Signal |
|----------|--------|
| 4625 | Failed logon (+ brute force if same IP ≥ 8) |
| 4720 | User created |
| 4732 | Member added to security group |
| 4688 | PowerShell/cmd/wscript/mshta process create |
| 1102 | Security log cleared |

---

## License

MIT