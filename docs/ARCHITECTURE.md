# CryptoVeil: scope, architecture and security claims

CryptoVeil combines browser observations and endpoint telemetry in one local
application. Its asynchronous Pub/Sub broker persists each accepted event before
acknowledging delivery, evaluates process behaviour, correlates related indicators,
and notifies the dashboard. Its purpose is rapid detection and evidence review.
It does not claim to prevent every attack or remain trustworthy after an attacker
controls the application and all of its trust anchors.

## Project abstract

Modern computing environments expose organisations to threats that cross the
browser and operating system, including Living-off-the-Land execution, rapid
file encryption, and unapproved AI components that may access sensitive browser
content. CryptoVeil is a unified endpoint and browser monitoring framework built
around an asynchronous, event-driven architecture. Windows process-start
notifications and filesystem change events provide telemetry for live process
lineage, MITRE ATT&CK behaviour rules, and Shannon-entropy burst analysis.
A Manifest V3 extension observes navigation, known AI-service connections,
and changes to relevant DOM components without collecting form values.
Time-window correlation links related observations for analyst review while
distinguishing indicators from confirmed compromise. The application stores
evidence in a SHA-256 hash chain and uses RFC 6962 Merkle hashing with Ed25519
signed checkpoints. Compact inclusion proofs allow verification of an individual
record in O(log n) time against a trusted checkpoint. Signed daily reports
provide portable evidence summaries. Independently retained checkpoints and
protected verification keys are required to establish evidence integrity after
host compromise; a local copy alone cannot provide that guarantee.

## What each component actually establishes

| Component | Implementation | Boundary |
| --- | --- | --- |
| Browser identity | Optional primary-profile email through the browser identity API; manual email label when unavailable | Labels are reported metadata, not proof of mailbox ownership or server-verified sign-in |
| Browser compatibility | Chromium Manifest V3, including desktop Chrome and Edge; per-profile pairing | The search engine is irrelevant; Firefox/Safari builds are not included |
| Process telemetry | Windows WMI `Win32_ProcessStartTrace` on a separate COM thread; psutil enrichment and one-second reconciliation | Permissions/provider failures produce visible fallback sampling; command lines may be unavailable for short-lived or protected processes |
| File telemetry | Watchdog native filesystem events; samples up to 64 KiB per changed file | Eight distinct high-entropy files in 20 seconds is an indicator, not proof of ransomware; compressed files can have high entropy |
| LotL rules | Validated JSON condition DSL for process, parent, path and command patterns | Behaviour rules still require maintenance; this is not a signature-free or self-learning detector |
| Shadow AI | MutationObserver checks known AI iframe/script hosts and explicitly declared AI components; network observations supplement DOM evidence | Isolated extension worlds, closed shadow roots and unobservable reads limit coverage; a page can spoof its own attributes |
| Correlation | Two-minute window, bounded history, same-profile/document checks for AI + sensitive-field observations | Same-host timing does not prove a causal chain or identify the process that wrote a file; stale queued browser evidence is excluded |
| Live dashboard | Authenticated server-sent change notifications after persistence; bounded one-slot queues per viewer; reconnect and periodic refresh | Near-real-time monitoring, not a hard real-time deadline guarantee |
| Integrity | Canonical JSON hash chain, signed head, per-record archive, Merkle checkpoint signatures and key pinning | Signatures authenticate the recorded bytes, not the truth of an observation; full-host control can stop sensors or steal local keys |

## Account labels and consent

Each browser profile is paired separately and has its own token and client ID.
Choose **Connected browser and account → Use browser profile email** to grant
the optional `identity` and `identity.email` permissions. Chrome returns its
primary profile account when available. Edge can return Microsoft/Entra profile
information, subject to account and browser limitations. CryptoVeil never reads
mailboxes, page login fields, cookies, browser databases or other profiles to
discover an email. A manually entered email is labelled **manual, unverified**.

An observation stores the profile context present when it was queued. Changing
the label or signing out affects subsequent observations; it does not rewrite
existing evidence. Stop sharing email from the popup to remove the optional
permissions and stop adding email to future observations. Previously collected
email labels remain in the evidence and its existing report snapshots.

## Cryptographic format and verification cost

Merkle hashing uses SHA-256 with `0x00` before leaf data and `0x01` before child
hashes, splitting each tree at the largest power of two below its leaf count,
as specified by RFC 6962 section 2.1. CryptoVeil uses this tree algorithm; it is
not a complete Certificate Transparency protocol server.

New version-3 checkpoints sign a compact header containing the root, sequence
range, count, previous-checkpoint digest, time, key and format identifiers.
The archive also stores the leaf list, which full verification checks against
the signed root. Inclusion-proof responses contain the signed header and sibling
path, without all leaves. Proof verification takes O(log n) hashes, where n is
the number of records in that checkpoint. Older version-2 checkpoints remain
readable with their original signatures and larger proof payloads.

Generating a proof currently verifies the ledger and builds a checkpoint tree;
that operation is not O(log n). A full integrity audit is O(N) in the total
stored evidence, and performance depends on filesystem latency and load. The
broker waits for durable storage and applies backpressure rather than reporting
that unsaved evidence is safe. OS queries, hashing/persistence and report work
run off the application's event loop where applicable. No throughput, detection
rate or latency benchmark is claimed without measurement on the target device.

## Complete host compromise

An administrator/kernel-level attacker can stop this user-space application,
suppress future events, read its private signing key and replace local files.
No local hashing scheme can guarantee continued collection or prevent all of
those actions. Even an independent archive cannot establish that observations
created after compromise describe real activity.

The supported archive path can point to a separately administered filesystem
mount. Protect previously received evidence and signed checkpoints with retention
or server-side snapshots that the endpoint credential cannot rewrite or delete.
Retain the trusted public key and an authenticated checkpoint copy separately.
After an incident, verify exported evidence on a clean system against those
independent copies. The current backend cannot attest to host separation or
enforce a remote storage service's retention policy. No independent destination
has been provisioned by this code update.

The defensible claim is **tamper-evident forensic records verifiable against an
independently protected baseline**, not unconditional integrity under complete
host compromise or cryptographically irrefutable attribution.

## Validation and demonstration

The regression suite covers account consent boundaries and queued identity,
same-document correlation and stale-event exclusion, durable notifications,
PID reuse and missing lineage, compact and legacy Merkle proofs, evidence
tampering, pairing, reports and queue recovery. On Windows, it also subscribes
to WMI and launches a harmless short-lived Python process to check delivery.

For a target-device demonstration, pair a Chrome and an Edge profile separately,
optionally attach each account, and observe live records while changing search
engines. Review a known AI component and a sensitive field on a controlled test
page; this demonstrates an indicator, not actual theft. Use the app's isolated
integrity demo for edits/deletions. Do not destroy real evidence or run ransomware
to demonstrate the system. The installed native window, extension permissions,
off-host retention and load behaviour still require target-device validation.

## Primary references

- [Chrome identity API](https://developer.chrome.com/docs/extensions/reference/api/identity)
- [Microsoft Edge API support and account limitations](https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/api-support)
- [Chrome optional permissions](https://developer.chrome.com/docs/extensions/reference/api/permissions)
- [Content script isolation](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts)
- [Windows process-start events](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/krnlprov/win32-processstarttrace)
- [WMI event-source timeouts](https://learn.microsoft.com/en-us/windows/win32/wmisdk/swbemeventsource-nextevent)
- [RFC 6962, section 2.1](https://www.rfc-editor.org/rfc/rfc6962.html#section-2.1)
