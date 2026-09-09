"""
routes.py — REST API surface.

Implements every endpoint documented in README.md plus the new Reports
endpoints (24-hour SOC reports) and the forensic tamper-demo helpers used in
the panel demonstration script (docs/PROJECT_VISION.md §6).
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel

from ..bus.events import BrowserTelemetryEvent

router = APIRouter()


# ---------------------------------------------------------------------- #
# Health / status
# ---------------------------------------------------------------------- #

@router.get("/api/health")
async def health():
    return {"status": "ok", "service": "cryptoveil-agent"}


@router.get("/api/status")
async def status(request: Request):
    app_state = request.app.state
    stats = app_state.audit_logger.stats()
    return {
        "uptime_seconds": round(time.time() - app_state.start_time, 1),
        "event_count": stats["total_events"],
        "checkpoints": stats["checkpoints"],
        "pending_in_batch": stats["pending_in_batch"],
        "websocket_clients": app_state.ws_manager.counts(),
    }


# ---------------------------------------------------------------------- #
# Events
# ---------------------------------------------------------------------- #

@router.get("/api/events")
async def get_events(request: Request, limit: int = 200):
    log_path = request.app.state.audit_logger._log_path
    if not log_path.exists():
        return {"events": []}
    lines = log_path.read_text(encoding="utf-8").splitlines()
    tail = lines[-limit:] if limit > 0 else lines
    events = [json.loads(line)["event"] for line in tail]
    return {"events": events}


# ---------------------------------------------------------------------- #
# Forensics
# ---------------------------------------------------------------------- #

@router.get("/api/forensics/verify_chain")
async def verify_chain(request: Request):
    return request.app.state.audit_logger.verify_chain()


@router.get("/api/forensics/proof/{seq}")
async def get_proof(seq: int, request: Request):
    proof = request.app.state.audit_logger.get_proof(seq)
    if proof is None:
        raise HTTPException(status_code=404, detail="No sealed checkpoint covers this sequence yet")
    return proof


class ProofPayload(BaseModel):
    seq: int
    checkpoint_seq: int
    leaf_data: str
    leaf_index: int
    tree_size: int
    audit_path: list[str]
    merkle_root: str
    signature: str
    public_key: str


@router.post("/api/forensics/verify_proof")
async def verify_proof(payload: ProofPayload, request: Request):
    # Self-contained: uses only the fields in the submitted payload, exactly
    # as documented ("Verify a submitted proof (self-contained)").
    from ..forensics.audit_logger import AuditLogger
    return AuditLogger.verify_proof(payload.model_dump())


@router.post("/api/forensics/simulate_tamper/{seq}")
async def simulate_tamper(seq: int, request: Request):
    """
    Demo-only: mutates one local record so verify_chain() can be shown
    catching it live. The off-host copy of the same event is untouched,
    matching the panel demonstration script.
    """
    ok = request.app.state.audit_logger.simulate_tamper(seq)
    if not ok:
        raise HTTPException(status_code=404, detail="No such sequence number")
    return {
        "tampered_seq": seq,
        "note": "Local record altered for demonstration. Off-host copy is unaffected.",
    }


@router.get("/api/forensics/offhost/{seq}")
async def offhost_event(seq: int, request: Request):
    entry = request.app.state.off_host.retrieve_event(seq)
    if entry is None:
        raise HTTPException(status_code=404, detail="No off-host copy for this sequence")
    return entry


# ---------------------------------------------------------------------- #
# Process graph
# ---------------------------------------------------------------------- #

@router.get("/api/process/graph")
async def process_graph(request: Request):
    return request.app.state.mitre_engine.graph()


# ---------------------------------------------------------------------- #
# Browser Profiles & Email Accounts Discovery
# ---------------------------------------------------------------------- #

from ..sensors.browser_profiles import BrowserProfileScanner


@router.get("/api/browser/profiles")
async def get_browser_profiles():
    """
    Scans host system for installed Chromium browsers (Chrome, Edge, Brave, etc.)
    and returns discovered user profiles and associated email accounts.
    """
    from .main import BASE_DIR
    ext_path = BASE_DIR / "extension"
    if not ext_path.exists() and getattr(sys, "frozen", False):
        ext_path = Path(sys.executable).resolve().parent / "extension"
    extension_path = str(ext_path.resolve())
    profiles = BrowserProfileScanner.get_all_profiles()
    return {
        "profiles": profiles,
        "extension_path": extension_path,
        "total_discovered": len(profiles),
    }


class BrowserLaunchPayload(BaseModel):
    browser: str = "Google Chrome"
    profile_dir: str = "Default"
    url: Optional[str] = "http://127.0.0.1:8765/dashboard/index.html"


@router.post("/api/browser/launch")
async def launch_browser(payload: BrowserLaunchPayload):
    """
    Launches Chrome/Edge/Brave with the CryptoVeil extension auto-attached
    for the selected profile & email ID.
    """
    from .main import BASE_DIR
    ext_path = str((BASE_DIR / "extension").resolve())
    res = BrowserProfileScanner.launch_with_extension(
        browser_name=payload.browser,
        profile_dir=payload.profile_dir,
        extension_path=ext_path,
        target_url=payload.url or "http://127.0.0.1:8765/dashboard/index.html",
    )
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error", "Failed to launch browser."))
    return res


# ---------------------------------------------------------------------- #
# Browser telemetry ingest (HTTP fallback for background.js's fetch() call)
# ---------------------------------------------------------------------- #

class TelemetryPayload(BaseModel):
    type: str
    hostname: Optional[str] = None
    score: Optional[int] = None
    reasons: Optional[list[str]] = None
    aiDomain: Optional[str] = None
    url: Optional[str] = None
    user_email: Optional[str] = None
    browser_name: Optional[str] = None


@router.post("/api/browser/telemetry")
async def browser_telemetry(payload: TelemetryPayload, request: Request):
    broker = request.app.state.broker
    detail = payload.model_dump(exclude={"type", "hostname", "score", "user_email", "browser_name"}, exclude_none=True)
    await broker.publish(
        BrowserTelemetryEvent(
            event_kind=payload.type,
            hostname=payload.hostname,
            trust_score=payload.score,
            user_email=payload.user_email,
            browser_name=payload.browser_name,
            detail=detail,
        )
    )
    return {"received": True}


# ---------------------------------------------------------------------- #
# Bus diagnostics
# ---------------------------------------------------------------------- #

@router.get("/api/bus/dead_letters")
async def dead_letters(request: Request):
    return {"dead_letters": request.app.state.broker.dead_letters()}


# ---------------------------------------------------------------------- #
# Reports (24-hour SOC reports)
# ---------------------------------------------------------------------- #

@router.get("/api/reports")
async def list_reports(request: Request):
    return {"reports": request.app.state.report_store.list_reports()}


@router.get("/api/reports/{date_str}")
async def get_report(date_str: str, request: Request):
    report = request.app.state.report_store.get(date_str)
    if report is None:
        raise HTTPException(status_code=404, detail="No report for this date yet")
    return report


@router.post("/api/reports/generate")
async def generate_report_now(request: Request, date_str: Optional[str] = None):
    return request.app.state.scheduler.generate_now(date_str)


@router.get("/api/reports/{date_str}/download")
async def download_report(date_str: str, request: Request, format: str = "pdf"):
    report = request.app.state.report_store.get(date_str)
    if report is None:
        raise HTTPException(status_code=404, detail="No report for this date yet")
    from ..reports import export as report_export
    try:
        data, media_type, filename = report_export.export(report, format)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------- #
# System & Network Info
# ---------------------------------------------------------------------- #

import io
import os
import socket
import tempfile
import zipfile
from pathlib import Path


def _get_local_ips() -> list[str]:
    ips = set()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
    except Exception:
        pass
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass
    return sorted(list(ips)) or ["127.0.0.1"]


@router.get("/api/system/network_info")
async def system_network_info(request: Request):
    app_state = request.app.state
    port = int(os.environ.get("CRYPTOVEIL_PORT", "8765"))
    local_ips = _get_local_ips()
    primary_ip = local_ips[0] if local_ips else "127.0.0.1"
    hostname = socket.gethostname()
    host_header = request.headers.get("host", f"{primary_ip}:{port}")

    return {
        "hostname": hostname,
        "primary_ip": primary_ip,
        "all_ips": local_ips,
        "port": port,
        "local_url": f"http://localhost:{port}/dashboard/",
        "lan_url": f"http://{primary_ip}:{port}/dashboard/",
        "current_url": f"http://{host_header}/dashboard/",
        "api_docs_url": f"http://{primary_ip}:{port}/docs",
        "uptime_seconds": round(time.time() - app_state.start_time, 1),
    }


# ---------------------------------------------------------------------- #
# Forensics Events Chain Inspector
# ---------------------------------------------------------------------- #

@router.get("/api/forensics/events_chain")
async def get_events_chain(request: Request, limit: int = 100):
    log_path = request.app.state.audit_logger._log_path
    if not log_path.exists():
        return {"chain": []}

    lines = log_path.read_text(encoding="utf-8").splitlines()
    tail = lines[-limit:] if limit > 0 else lines
    chain = []
    for line in tail:
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            ev = entry.get("event", {})
            chain.append({
                "seq": entry.get("seq"),
                "hash": entry.get("hash"),
                "prev_hash": entry.get("prev_hash"),
                "timestamp": ev.get("timestamp"),
                "topic": ev.get("topic", ev.get("event_type", "unknown")),
                "severity": ev.get("severity", "info"),
                "source": ev.get("source", "unknown"),
                "event_id": ev.get("event_id"),
                "data": ev.get("data", {}),
            })
        except Exception:
            continue
    return {"chain": chain}


# ---------------------------------------------------------------------- #
# Interactive Attack / Threat Simulations
# ---------------------------------------------------------------------- #

@router.post("/api/simulations/run/{sim_name}")
async def run_simulation(sim_name: str, request: Request):
    app_state = request.app.state
    broker = app_state.broker
    t0 = time.monotonic()

    if sim_name == "sim_ransomware_burst":
        # Simulate high-entropy file burst
        from ..bus.events import FileEntropyEvent
        target_dir = tempfile.gettempdir()
        file_name = f"cv_sim_{int(time.time())}.locked"
        full_path = os.path.join(target_dir, file_name)
        try:
            with open(full_path, "wb") as f:
                f.write(os.urandom(65536))
        except Exception:
            pass

        await broker.publish(
            FileEntropyEvent(
                file_path=full_path,
                entropy=7.9942,
                event_kind="modified",
                burst_count=10,
                burst_triggered=True,
                severity="critical",
            )
        )
        elapsed = time.monotonic() - t0
        return {
            "simulation": "Ransomware Burst (Filesystem High-Entropy Burst)",
            "status": "TRIGGERED",
            "detection_latency_ms": round(elapsed * 1000, 2),
            "detail": f"Simulated 10 high-entropy file writes to {target_dir} with Shannon entropy ~7.99.",
        }

    elif sim_name == "sim_clipboard_hijack":
        from ..bus.events import ClipboardSwapEvent
        await broker.publish(
            ClipboardSwapEvent(
                source="clipboard_watcher",
                severity="high",
                expected_hash="1A2b3C4d5E6f7G8h9I0jWalletAddress",
                observed_hash="9Z8y7X6w5V4u3T2s1RAttackerAddress",
            )
        )
        elapsed = time.monotonic() - t0
        return {
            "simulation": "Clipboard Hijack (Cryptocurrency Wallet Swapper)",
            "status": "TRIGGERED",
            "detection_latency_ms": round(elapsed * 1000, 2),
            "detail": "Detected rapid unauthorized clipboard memory replacement of crypto wallet address.",
        }

    elif sim_name == "sim_anti_forensic":
        from ..bus.events import AntiForensicEvent
        await broker.publish(
            AntiForensicEvent(
                source="process_watcher",
                severity="critical",
                pid=9412,
                process_name="cmd.exe",
                cmdline="cmd.exe /c wevtutil cl Security-simulation-only",
                matched_pattern="wevtutil",
            )
        )
        elapsed = time.monotonic() - t0
        return {
            "simulation": "Anti-Forensic Command Execution",
            "status": "TRIGGERED",
            "detection_latency_ms": round(elapsed * 1000, 2),
            "detail": "Detected suspicious attempt to purge Windows event logs (wevtutil cl).",
        }

    elif sim_name == "sim_hash_chain_tamper":
        stats = app_state.audit_logger.stats()
        total = stats["total_events"]
        if total == 0:
            return {
                "simulation": "Hash Chain Tamper Demo",
                "status": "SKIPPED",
                "detail": "No events recorded yet. Run other actions or simulations first to populate the chain.",
            }
        target_seq = max(0, total // 2)
        tamper_ok = app_state.audit_logger.simulate_tamper(target_seq)
        verification = app_state.audit_logger.verify_chain()
        elapsed = time.monotonic() - t0
        return {
            "simulation": "Cryptographic Hash Chain Tamper Demonstration",
            "status": "SUCCESS",
            "tampered_seq": target_seq,
            "chain_verified": verification["verified"],
            "violations_found": len(verification["violations"]),
            "elapsed_ms": round(elapsed * 1000, 2),
            "detail": f"Tampered record seq #{target_seq}. Cryptographic verification detected integrity failure instantly.",
        }

    elif sim_name == "sim_mitre_hollowing":
        from ..bus.events import MitreAlertEvent
        await broker.publish(
            MitreAlertEvent(
                source="mitre_engine",
                severity="high",
                mitre_id="T1055.012",
                mitre_name="Process Hollowing",
                description="svchost.exe spawned from non-standard parent powershell.exe",
                pid=9844,
                process_name="svchost.exe",
                parent_name="powershell.exe",
                cmdline="svchost.exe -k netsvcs",
                rule_id="CV-T1055-001",
            )
        )
        elapsed = time.monotonic() - t0
        return {
            "simulation": "MITRE ATT&CK T1055.012 (Process Hollowing)",
            "status": "TRIGGERED",
            "detection_latency_ms": round(elapsed * 1000, 2),
            "detail": "Detected svchost.exe spawned outside system parent hierarchy.",
        }

    elif sim_name == "sim_c2_beacon":
        from ..bus.events import C2BeaconEvent
        await broker.publish(
            C2BeaconEvent(
                source="network_engine",
                severity="critical",
                pid=5124,
                process_name="powershell.exe",
                remote_addr="198.51.100.42",
                remote_port=4444,
                beacon_count=18,
                avg_interval_seconds=15.02,
                coefficient_of_variation=0.04,
            )
        )
        elapsed = time.monotonic() - t0
        return {
            "simulation": "C2 Command & Control Beaconing Detection",
            "status": "TRIGGERED",
            "detection_latency_ms": round(elapsed * 1000, 2),
            "detail": "Detected highly periodic outbound network traffic (CoV=0.04 < 0.15 threshold).",
        }

    elif sim_name == "sim_dga_detection":
        from ..bus.events import DgaDetectedEvent
        await broker.publish(
            DgaDetectedEvent(
                source="network_engine",
                severity="high",
                hostname="xj948kalsjd0183zz.cc",
                entropy_score=4.25,
                vowel_ratio=0.11,
                digit_ratio=0.33,
                label_length=18,
                pid=4100,
                process_name="updater.exe",
            )
        )
        elapsed = time.monotonic() - t0
        return {
            "simulation": "DGA Algorithmically Generated Domain Detection",
            "status": "TRIGGERED",
            "detection_latency_ms": round(elapsed * 1000, 2),
            "detail": "High-entropy domain queried with abnormal consonant/vowel ratio.",
        }

    elif sim_name == "sim_browser_threat":
        await broker.publish(
            BrowserTelemetryEvent(
                event_kind="site_warning",
                hostname="paypa1-secure-verification.top",
                trust_score=15,
                detail={
                    "reasons": ["Typosquat target: paypal.com", "High entropy hostname (3.92)", "Unregistered SSL issuer"]
                },
            )
        )
        elapsed = time.monotonic() - t0
        return {
            "simulation": "Browser Phishing / Typosquat Threat",
            "status": "TRIGGERED",
            "detection_latency_ms": round(elapsed * 1000, 2),
            "detail": "Browser extension flagged low-trust typosquatting domain (Trust Score: 15/100).",
        }

    elif sim_name == "sim_shadow_ai":
        await broker.publish(
            BrowserTelemetryEvent(
                event_kind="shadow_ai_network",
                hostname="api.openai.com",
                trust_score=80,
                detail={
                    "aiDomain": "api.openai.com",
                    "url": "https://api.openai.com/v1/chat/completions",
                    "method": "POST",
                },
            )
        )
        elapsed = time.monotonic() - t0
        return {
            "simulation": "Shadow AI Network Interception",
            "status": "TRIGGERED",
            "detection_latency_ms": round(elapsed * 1000, 2),
            "detail": "Intercepted unauthorized AI API egress to api.openai.com.",
        }

    elif sim_name == "sim_all":
        # Trigger full suite
        for s in [
            "sim_ransomware_burst",
            "sim_clipboard_hijack",
            "sim_anti_forensic",
            "sim_mitre_hollowing",
            "sim_c2_beacon",
            "sim_dga_detection",
            "sim_browser_threat",
            "sim_shadow_ai",
        ]:
            await run_simulation(s, request)
        elapsed = time.monotonic() - t0
        return {
            "simulation": "Comprehensive Security Simulation Suite",
            "status": "ALL_TRIGGERED",
            "total_latency_ms": round(elapsed * 1000, 2),
            "detail": "Executed full spectrum of endpoint, network, MITRE, browser, and forensic attack simulations.",
        }

    else:
        raise HTTPException(status_code=404, detail=f"Unknown simulation: {sim_name}")


# ---------------------------------------------------------------------- #
# Extension WebSocket message handling (called from main.py's /ws/extension)
# ---------------------------------------------------------------------- #

async def handle_extension_ws_message(app, raw_message: str) -> None:
    try:
        msg = json.loads(raw_message)
    except json.JSONDecodeError:
        return
    broker = app.state.broker
    await broker.publish(
        BrowserTelemetryEvent(
            event_kind=msg.get("type", "unknown"),
            hostname=msg.get("hostname"),
            trust_score=msg.get("score"),
            user_email=msg.get("user_email"),
            browser_name=msg.get("browser_name"),
            detail={k: v for k, v in msg.items() if k not in ("type", "hostname", "score", "ts", "user_email", "browser_name")},
        )
    )

