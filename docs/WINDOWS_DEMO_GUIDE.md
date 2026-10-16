# CryptoVeil: Windows setup and live demonstration

This guide is for a normal user and for a final-year project demonstration. It does **not** require editing project source files or starting a terminal.

## Install and start

1. Download the **CryptoVeil-Windows** artifact from a successful GitHub Actions run on this branch. Extract the **entire** CryptoVeil folder; do not run only the executable without its companion files.
2. Install the Microsoft Edge WebView2 runtime if the native window does not open. The app can use the system browser as a fallback when supported.
3. Open **CryptoVeil.exe** and wait for **Command Center**. Use **Simple** mode first.
4. Check the status of Browser Protection, Endpoint Monitoring, Ransomware Monitoring, Clipboard Monitoring, Shadow AI Monitoring, and Evidence Integrity. If a sensor says *Limited* or *Unavailable*, explain it rather than presenting it as active.
5. For troubleshooting, switch to **Analyst** mode → **Runtime Readiness**. Look for missing assets, data-directory permissions, or integrity problems. On Windows, the default runtime directory is `%LOCALAPPDATA%\CryptoVeil\data`. Your original evidence must not be deleted to resolve an integrity alert.

## Pair the extension

1. In Chrome or Edge, open `chrome://extensions` (or `edge://extensions`), switch on **Developer mode**, choose **Load unpacked**, and select the repository's **extension** folder.
2. In the desktop application, click **Connect browser** to generate the one-use eight-digit pairing code.
3. Enter that code in the CryptoVeil popup and choose **Connect securely**.
4. Confirm that **Desktop Authentication** shows **Authenticated** while the desktop app is online. The current website trust score and verdict should appear for supported HTTP/HTTPS pages.

Pair each browser profile separately. Never share pairing codes, authentication tokens, passwords or real personal form data in a demo.

## Six-minute demonstration

| Approx. time | Show | What to explain |
| --- | --- | --- |
| 0:00–0:45 | Command Center | Unified browser and endpoint protection with simple, live status |
| 0:45–1:30 | Browser extension popup | Current website trust, sensitive field **categories**, and Shadow AI observation |
| 1:30–2:30 | Simulation Lab → Real Sensor Tests | Launch a harmless process and create temporary high-entropy test files; success requires real stored sensor evidence |
| 2:30–3:15 | Threat Investigation | MITRE ATT&CK-aligned process alerts, process relationships, and linked evidence; an indicator is not proof of malware |
| 3:15–4:15 | Evidence → Verify all dates | SHA-256 chain, Merkle checkpoints, Ed25519 signatures and signed date-wise evidence; open Analyst details if requested |
| 4:15–5:15 | Download an evidence bundle | Export JSON Events, PDF Report, Hash & Metadata and ZIP; inspect signed `manifest.json` and `daily_seal.json` |
| 5:15–6:00 | Simulation Lab → Demo Simulations | Tamper evidence in **temporary sample data**; the real ledger is never edited |

## Authorize an evidence export

On the Evidence screen, choose **Authorized export** for a verified date.

1. For the first export, set an owner passphrase of at least **16 characters** and confirm it. Keep it safely; CryptoVeil does not have a silent reset option.
2. For subsequent exports or after restarting CryptoVeil, enter the passphrase to unlock exports for up to **five minutes**.
3. Select just one format in the dialog: **PDF**, **signed hashes and metadata**, **JSON events**, or **complete ZIP**.
4. Choose **Download authorized evidence**. CryptoVeil verifies the bundle and writes an export-receipt event (date, type, SHA-256 and byte count) before sending the file.
5. Use **Lock exports** when finished. The dashboard never stores the unlocked token in localStorage.

**Limit:** This is a local-owner export gate, not enterprise role-based access control or encryption of saved files. A permitted local user may still view security event summaries. Securely store exported files.

## Restart and offline queue test

1. After successfully pairing the extension, close CryptoVeil normally.
2. Visit a permitted test site while the app is offline. The extension should **queue** the observation instead of silently discarding it.
3. Start CryptoVeil again. Confirm the existing extension pairing and verify that a previously queued event appears in the Activity/Evidence views after its durable receipt.
4. Do not manually change live evidence to show tampering: use the isolated demo instead.

## Understanding the forensic output

New daily bundles contain an Ed25519-signed `daily_seal.json` with date, sequence range, event count, final chain hash, daily Merkle root, previous-day root and seal time; `daily_summary.json` gives a concise activity summary. The signed `manifest.json` authenticates each bundled file's SHA-256 checksum. Evidence verification is based on the available trusted baseline and recorded signatures.

The local archive is a reference copy, **not** automatically proof of physical off-host storage. Protect against complete host compromise by configuring independently managed storage and independently pinning the verification key.

## Troubleshooting

- **App will not open:** check the error dialog and `desktop_app.log`; check whether port 8765 is occupied and confirm that the extracted directory is complete.
- **Browser says app offline:** open CryptoVeil, check `http://127.0.0.1:8765/api/health` and ensure the extension pairing is for the same browser profile.
- **Sensor says unavailable:** use Analyst → Runtime Readiness and verify permissions and operating-system support. Do not substitute fake detections.
- **Evidence says modified/missing:** preserve the evidence, archive, key and logs. Do not delete the data directory or silently rebuild a baseline.
- **Daily evidence absent:** generate a daily report from the desktop Reports view before attempting a download.

## Claims and limitations

CryptoVeil collects user-space metadata. It is not a kernel driver, a commercial EDR, or a guarantee of malware prevention. It reports ransomware-like file activity, possible C2 beaconing, DGA heuristics, Shadow AI observations and ATT&CK-aligned behavioral indicators—not confirmed attribution, data exfiltration or successful attacks.
