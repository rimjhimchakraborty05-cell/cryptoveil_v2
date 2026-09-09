# CryptoVeil v2

**Real-time, multi-layer endpoint and browser security suite with behavioral anomaly detection, asynchronous event-driven architecture, and Merkle-tree tamper-evident forensic logging.**

---

## Architecture

```
cryptoveil_v2/
├── agent/
│   ├── bus/
│   │   ├── event_bus.py        # Async Pub/Sub broker (ALL inter-module comms)
│   │   └── events.py           # Pydantic v2 typed event models
│   ├── sensors/
│   │   ├── clipboard_watcher.py  # OS clipboard integrity (Windows push / poll fallback)
│   │   ├── entropy_watcher.py    # Filesystem burst entropy (watchdog push events)
│   │   └── process_watcher.py    # Process spawn/exit + anti-forensic detection
│   ├── engines/
│   │   ├── mitre_engine.py       # MITRE ATT&CK rule DSL + live process graph
│   │   └── network_engine.py     # C2 beacon (CoV) + DGA entropy classifier
│   ├── forensics/
│   │   ├── merkle_tree.py        # RFC 6962-style Merkle tree + inclusion proofs
│   │   └── audit_logger.py       # Hash chain + Merkle checkpoints + Ed25519 signing
│   └── server/
│       ├── main.py               # FastAPI + WebSocket broadcaster (lifespan wiring)
│       └── routes.py             # REST API: events, proofs, process graph, telemetry
├── extension/
│   ├── manifest.json             # MV3
│   ├── background.js             # Trust scoring, WS bridge, Shadow AI webRequest
│   └── content.js                # DOM obfuscation, masking, Shadow AI iframe monitor
├── dashboard/
│   ├── index.html                # Real-time Security HUD
│   ├── js/dashboard.js           # D3 process graph, event stream, MITRE badges
│   └── css/style.css             # Dark cyber theme
├── tests/
│   ├── test_merkle.py            # 12 Merkle unit tests (incl. RFC 6962 domain sep.)
│   ├── test_entropy.py           # 8 entropy sensor tests
│   └── attack_simulation.py      # Detection latency harness (evaluation chapter)
├── process_rules.json            # MITRE ATT&CK DSL rules (editable without code changes)
└── requirements.txt
```

---

## Architectural Constraints

1. **Decoupled Event-Driven**: All inter-module communication flows exclusively through the `EventBroker`. No module calls another's internal logic directly.
2. **Non-Blocking**: OS sensors run in background asyncio tasks or watchdog OS threads. The event loop is never blocked.
3. **Graceful Degradation**: Sensor failures are logged and dead-lettered; the audit logger and forensic chain continue uninterrupted.

---

## Quick Start

### 1. Launch Native Desktop Application (1-Click)

On Windows, double-click `Install_CryptoVeil_App.bat` or `start.bat`. It will automatically configure the virtual environment, install dependencies, create Windows Desktop/Start Menu shortcuts, and launch the native desktop application window.

Or run manually:
```bash
cd cryptoveil_v2
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
python desktop_app.py
```

### 2. Multi-Browser Profile & Email Discovery & 1-Click Extension Launch

CryptoVeil automatically scans installed browsers (Chrome, Edge, Brave) and their signed-in email accounts.
- In the **Browser & Extension Hub** tab on the dashboard, click **"🚀 1-Click Launch with Extension"** on any detected browser account (e.g. `rimjhimchakraborty05@gmail.com`).
- Or manually load the extension:
  1. Open `chrome://extensions` (Chrome) or `edge://extensions` (Edge).
  2. Enable **Developer Mode** in the top-right.
  3. Click **Load unpacked** and select the `extension/` folder.
  4. The extension popup lets you select which email ID is monitored.

### 3. Run unit tests

```bash
# Merkle tree & inclusion proofs
python tests/test_merkle.py

# Entropy burst sensor
python tests/test_entropy.py

# Browser profile & email discovery sensor
python tests/test_browser_profiles.py
```

### 4. Build Standalone Executable (.EXE)

To compile a standalone binary for Windows without requiring Python on client computers:
```bash
build_desktop_exe.bat
# Output generated in dist\CryptoVeil\CryptoVeil.exe
```

---

## REST API

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Agent health |
| GET | `/api/status` | Uptime, event count, client counts |
| GET | `/api/events?limit=200` | Recent event log entries |
| GET | `/api/browser/profiles` | Discovered Chrome/Edge/Brave profiles & email IDs |
| POST | `/api/browser/launch` | 1-Click launch browser with auto-attached extension |
| POST | `/api/browser/telemetry` | Ingest browser extension telemetry with user email |
| GET | `/api/forensics/verify_chain` | Hash chain integrity check |
| GET | `/api/forensics/proof/{seq}` | Merkle inclusion proof for event #seq |
| POST | `/api/forensics/verify_proof` | Verify a submitted proof (self-contained) |
| GET | `/api/process/graph` | Live process ancestry graph (nodes + edges) |
| GET | `/api/bus/dead_letters` | Failed handler log (diagnostics) |
| GET | `/api/reports` | List all generated daily reports (summary) |
| GET | `/api/reports/{date}` | Full report JSON for a given date (`YYYY-MM-DD`) |
| POST | `/api/reports/generate?date_str=YYYY-MM-DD` | Generate/regenerate a report on demand |
| GET | `/api/reports/{date}/download?format=pdf\|csv\|json` | Download a report in the given format |
| POST | `/api/forensics/simulate_tamper/{seq}` | **Demo only** — mutates one local record so `verify_chain` catches it live |
| GET | `/api/forensics/offhost/{seq}` | Retrieve the off-host copy of a sealed event |

---

## 24-Hour SOC Reports

CryptoVeil automatically generates a Daily SOC Report at UTC midnight,
covering Executive Summary, Browser Security, Endpoint Security, MITRE
ATT&CK detections, and Forensic Integrity — see `docs/PROJECT_VISION.md` §5
for the full section breakdown. Reports are persisted to
`data/reports/{date}.json` and remain downloadable (PDF/CSV/JSON) for as
long as the agent's data store exists, including across restarts — on
startup the scheduler back-fills yesterday's and today's report if missing.

```bash
curl http://127.0.0.1:8765/api/reports
curl http://127.0.0.1:8765/api/reports/2026-08-15
curl -OJ "http://127.0.0.1:8765/api/reports/2026-08-15/download?format=pdf"
```

## Forensic Tamper Demonstration

The panel demonstration script in `docs/PROJECT_VISION.md` §6 is fully
wired end-to-end:

```bash
curl http://127.0.0.1:8765/api/forensics/verify_chain          # verified: true
curl -X POST http://127.0.0.1:8765/api/forensics/simulate_tamper/2
curl http://127.0.0.1:8765/api/forensics/verify_chain          # verified: false, names seq 2
curl http://127.0.0.1:8765/api/forensics/offhost/2             # off-host copy still clean
```

`tests/attack_simulation.py sim_hash_chain_tamper` automates this exact
sequence and reports detection latency.

---

## MITRE ATT&CK Coverage

| Rule ID | Technique | Detection Method |
|---|---|---|
| CV-T1055-001 | T1055.012 Process Hollowing | svchost.exe outside expected parent lineage |
| CV-T1059-001 | T1059.001 PowerShell | PowerShell spawned by Office apps |
| CV-T1047-001 | T1047 WMI | CMD/PS spawned by wmiprvse.exe |
| CV-T1218-005 | T1218.005 Mshta | mshta.exe with http:// argument |
| CV-T1218-010 | T1218.010 Regsvr32 | regsvr32 with scrobj/URL argument |
| CV-T1036-005 | T1036.005 Masquerading | Known binary running from non-system path |
| CV-T1003-001 | T1003.001 LSASS Dump | lsass/mimikatz in command line |
| CV-T1059-003 | T1059.003 CMD Shell | CMD with encoded/piped script execution |

Rules are defined in `process_rules.json` — add new rules without code changes.

---

## Tamper-Evidence Guarantees

1. **SHA-256 Hash Chain** — each entry embeds `SHA256(canonical(entry) || prev_hash)`. Any edit breaks every subsequent hash.
2. **Merkle Checkpoints** — every 50 events, a Merkle root is computed over the batch and published as a signed checkpoint. Off-host shipping ensures local attackers cannot retroactively forge the tree.
3. **Ed25519 Signatures** — every checkpoint is signed with the agent's private key. Verify at any time with `GET /api/forensics/verify_chain`.
4. **Merkle Inclusion Proofs** — `GET /api/forensics/proof/{seq}` returns an O(log n) proof that a specific event was in the authenticated log, without revealing other entries (same primitive as Certificate Transparency, RFC 6962).

---

## Explicit Limitations (Report-Worthy)

- Anti-forensic detection is ~500ms polling latency, not kernel-level prevention (that requires eBPF/minifilter drivers).
- Clipboard monitor is native OS push on Windows only; macOS/Linux use a 100ms polling fallback.
- Network engine inspects connection metadata only — no deep packet inspection (requires raw sockets / driver).
- DGA detection uses reverse DNS on already-established connections; pre-connection DNS interception requires a local DNS resolver hook.
- The off-host store in the reference build is a local file — production tamper-evidence requires a genuinely separate host.
