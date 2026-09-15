# CryptoVeil v2.2

CryptoVeil is a local endpoint and browser evidence collector. It gives a
non-technical user a small dashboard, while preserving a verifiable
record of what the browser extension and host sensors observed.

The important boundary is explicit: this repository provides tamper-evident
local collection and export. Independent off-host storage must be configured
using a separately managed filesystem mount. This filesystem backend cannot
attest to host separation, so it reports `host_separation_verified: false`.
An HTTPS collector or object-storage API is not implemented by this backend.

## What is implemented

- Browser observations are paired to the local app with a one-use, eight-digit
  code. The extension origin is bound to the token and the token is stored only
  as a SHA-256 hash on disk.
- The extension sends hostnames and coarse risk metadata only. It does not send
  form values, passwords, query strings, full URLs, file paths, or clipboard
  text. Events remain in an acknowledged queue until the app returns a durable
  receipt.
- Every accepted event is written through a durable subscriber before the
  extension receives `received: true`. Retries are idempotent by `event_id`.
- The evidence ledger combines canonical JSON, a SHA-256 hash chain, signed
  Ed25519 Merkle checkpoints, and a signed head. Verification checks the local
  ledger, checkpoint metadata/signatures, the pinned public key, and the
  per-event archive for missing, added, reordered, malformed, or modified
  records.
- If verification fails, the result is `MODIFIED_OR_MISSING` and collection is
  paused. The existing files are preserved for investigation; the application
  does not silently rebuild a new baseline.
- Daily reports can be generated as signed JSON plus PDF, CSV, and ZIP bundles.
  Reports are versioned and the application refuses to overwrite saved files.
  Downloads verify the signed manifest and serve the same bytes they checked.
  The report records whether the source evidence verified when it was generated;
  a preserved report remains exportable if the live ledger is later damaged.
- The dashboard has four simple views: Overview, Activity, Evidence, and
  Reports. It shows plain-language next steps instead of a dense SOC wall.
- Host sensors are best-effort and expose their health state. A sensor failure
  is visible without making the forensic ledger pretend it collected data.
- Windows process-start notifications complement filesystem push events and
  sampled exit reconciliation; unavailable Windows notifications produce a
  visible sampling fallback. Linked findings connect LotL indicators, encryption
  bursts and recent browser AI observations for review.
- The dashboard receives live change notifications after storage. Browser
  profiles can optionally attach a browser-reported or manually entered email
  label; previously queued evidence keeps its original identity context.

See [architecture, project abstract and security boundaries](docs/ARCHITECTURE.md)
for the real-time pipeline, Shadow AI limitations and precise integrity claims.

## Quick start

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

Open <http://127.0.0.1:8765/dashboard/>. The API deliberately listens on
loopback only. The desktop wrapper can be launched with `python desktop_app.py`
or, on Windows, `start.bat` / `Install_CryptoVeil_App.bat`.

### Pair the extension

1. Load the `extension/` directory as an unpacked Chrome/Edge Manifest V3
   extension (`chrome://extensions`, enable Developer mode).
2. Open the CryptoVeil dashboard and choose **Connect browser**.
3. Enter the one-use code in the extension popup. Codes expire after five
   minutes and accept at most five failed attempts.

The popup shows whether the application is online, how many observations are
queued, the last durable receipt, and whether collection has been paused by an
integrity failure.

Pair each Chrome or Edge profile separately. Your choice of search engine does
not affect collection. In **Connected browser and account**, optionally choose
**Use browser profile email**, or enter a manual email label. The email is added
to future evidence and reports only after this choice. Manual labels are not
verified sign-in; no inbox access is requested. **Stop sharing account email**
removes the optional permissions; previously saved evidence retains its labels.

## Evidence and integrity files

The data directory is configurable with `CRYPTOVEIL_DATA_DIR` (default:
`data/`). The default layout is:

```text
data/
├── audit_log.jsonl                 # canonical hash-chain entries
├── checkpoints.jsonl               # signed Merkle checkpoints
├── integrity_v2.marker             # prevents silent reinitialization
├── ed25519_key.pem                 # local signing key; protect this file
├── ed25519_public_key.hex          # pinned verification key
├── paired_browsers.json            # hashed extension tokens and status
├── evidence_archive/
│   ├── events/                     # immutable per-event copies
│   ├── checkpoints/                # immutable checkpoint copies
│   ├── reports/                    # separately saved signed report manifests
│   └── head.json                   # signed head, counts and unsealed hashes
└── reports/YYYY-MM-DD/<snapshot>/   # versioned daily report bundles
```

For a recorded event, the ledger stores the event, its sequence number, the
previous entry hash, and the current entry hash. Every checkpoint stores the
Merkle leaves and root. Version-3 checkpoints sign a compact header whose root
commits to the leaves; version-2 checkpoints retain their original signatures.
A compact proof for
one sequence can be verified independently with the trusted public key:

```text
GET /api/forensics/proof/{seq}
POST /api/forensics/verify_proof
```

To demonstrate the detection path without touching the real data directory:

```text
POST /api/forensics/demo
```

The demonstration edits a copy in a temporary directory and shows that an
unchanged copy verifies while an altered or deleted record does not.

The saved baseline is preserved; verification recalculates the current Merkle
root every 30 seconds while the app is running, and whenever **Verify evidence
now** is selected. A hash does not change by itself when a file changes.
Verification compares canonical JSON content, so whitespace-only changes are
not content changes; duplicate JSON keys and changed fields are rejected.

## Daily reports

The scheduler keeps a report for the configured timezone (default
`Asia/Kolkata`) and back-fills missing days after restart. A report records:

- the reporting window and time basis;
- event counts and plain-language summaries;
- browser and endpoint alert counts;
- the evidence verification result at generation time;
- checkpoint/root and archive metadata;
- recommended next steps for each alert.

Available endpoints:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/reports` | List the latest signed snapshot for each day |
| `GET /api/reports/{date}` | Read one verified report |
| `POST /api/reports/generate?date=YYYY-MM-DD` | Generate a new immutable version |
| `GET /api/reports/{date}/verify` | Verify the report manifest and files |
| `GET /api/reports/{date}/download?format=pdf\|csv\|json\|zip` | Download a verified artifact |

PDF and CSV exports are intentionally conservative: text is escaped and CSV
cells that could be interpreted as spreadsheet formulas are prefixed safely.

## API and security boundaries

| Endpoint | Authentication |
| --- | --- |
| `GET /api/health` | Public loopback health check |
| `GET /api/session` | Starts the dashboard session and returns its CSRF token |
| `POST /api/pairing/code` | Dashboard session + CSRF |
| `POST /api/pairing/complete` | Paired extension origin + one-use code |
| `POST /api/browser/telemetry` | Paired extension bearer token + extension origin |
| `POST /api/browser/heartbeat` | Paired extension bearer token + extension origin |
| Other `/api/*` reads/writes | Dashboard session; writes also require CSRF |

Requests are JSON-only for mutations, limited to 64 KiB, protected by strict
security headers, and reject non-loopback hosts or cross-site requests. The
dashboard has no API documentation route enabled in production.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `CRYPTOVEIL_DATA_DIR` | `data` | Ledger, keys, pairing state, and reports |
| `CRYPTOVEIL_ARCHIVE_DIR` | `data/evidence_archive` | Archive root; accepts a filesystem path, including a separately managed network mount |
| `CRYPTOVEIL_RULES_PATH` | `process_rules.json` | MITRE process rules |
| `CRYPTOVEIL_REPORT_TIMEZONE` | `Asia/Kolkata` | Daily report timezone |
| `CRYPTOVEIL_REPORT_FORMATS` | `pdf,csv,json` | Formats generated at each report boundary |
| `CRYPTOVEIL_TRUSTED_PUBLIC_KEY` | Key pinned on first use | Optional independently recorded Ed25519 public key, in hex |
| `CRYPTOVEIL_WATCH_PATHS` | Existing Documents and Downloads folders | Paths separated by `;` on Windows or `:` on Linux/macOS |

Keep `ed25519_key.pem` private. If the key or pinned public key is lost, the
old evidence remains readable but cannot be treated as a newly trusted chain;
CryptoVeil intentionally fails closed instead of minting a replacement identity.

## Tests and quality checks

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
ruff check agent tests scripts desktop_app.py run.py setup_desktop_shortcuts.py
node --test tests/extension.test.mjs
git diff --check
```

The suite covers hash-chain restart/replay, archive deletion and modification,
checkpoint/signature attacks, malformed Merkle proofs, concurrent sequence
allocation, pairing/authentication/CSRF boundaries, idempotent extension
delivery, report tamper detection, and sensor regressions.

## Windows executable

`build_desktop_exe.bat` builds the desktop bundle with PyInstaller. Distribute
the complete `dist\CryptoVeil` directory and install Microsoft Edge WebView2
on the target machine.

GitHub Actions tests the project on Linux and Windows, then builds the Windows
application. A successful run provides the **CryptoVeil-Windows** artifact for
14 days. Extract the full download and open `CryptoVeil.exe`. The executable
is not code-signed. A build pass does not substitute for testing the native
window and extension on the target Windows device.

## Removed or replaced paths

The old websocket bridge and local `off_host_store` were replaced by
acknowledged HTTP delivery and the verified archive. Automatic browser-account
scanning and browser launching were removed; the extension is explicitly
paired instead. Live evidence-modification demo endpoints were replaced with
isolated sample-data demos. Duplicate launch scripts, empty runtime
placeholders, and container configurations that exposed the unauthenticated
agent were removed. The Windows launcher, desktop builder, host sensors,
extension, dashboard, tests, and daily reports remain.

## Known limits

- The archive is local unless `CRYPTOVEIL_ARCHIVE_DIR` is backed by an
  independently controlled host or storage service. This build does not claim
  to defeat an attacker who can rewrite every local copy or steal the signing
  key.
- Sensors observe user-space metadata. They are not kernel prevention drivers,
  deep packet inspection, or DNS interception.
- Browser risk scoring is a conservative local heuristic. It is a warning aid,
  not a verdict that a site or process is malicious.
- Daily reports are snapshots. They preserve the evidence state at generation
  time and should be regenerated after a legitimate, reviewed collection
  change.
