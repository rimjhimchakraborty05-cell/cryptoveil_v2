"""
attack_simulation.py — Detection latency harness (evaluation chapter).

Drives four controlled, harmless trigger conditions against a *running*
CryptoVeil agent and measures how long each takes to appear as a detected
event. Nothing here performs a real attack: the "ransomware burst" writes
random bytes to temp files inside the configured watch path, the "anti-
forensic" simulation spawns a subprocess whose command line merely echoes a
matching phrase (it does not clear any logs), and the clipboard test copies
harmless strings.

Usage (agent must already be running — `python run.py`):
    python tests/attack_simulation.py sim_all
    python tests/attack_simulation.py sim_ransomware_burst
    python tests/attack_simulation.py sim_clipboard_hijack
    python tests/attack_simulation.py sim_anti_forensic
    python tests/attack_simulation.py sim_hash_chain_tamper
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time

import requests

AGENT_URL = os.environ.get("CRYPTOVEIL_AGENT_URL", "http://127.0.0.1:8765")
POLL_INTERVAL = 0.25
POLL_TIMEOUT = 15.0


def _recent_events(limit: int = 300) -> list[dict]:
    resp = requests.get(f"{AGENT_URL}/api/events", params={"limit": limit}, timeout=5)
    resp.raise_for_status()
    return resp.json()["events"]

def _wait_for_event(predicate, timeout: float = POLL_TIMEOUT) -> tuple[bool, float]:
    """Poll /api/events until an event matching `predicate` appears."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        for ev in _recent_events():
            if predicate(ev):
                return True, time.monotonic() - start
        time.sleep(POLL_INTERVAL)
    return False, timeout


def sim_ransomware_burst() -> None:
    print("\n[Ransomware Burst] Writing high-entropy files to trigger the entropy sensor...")
    watch_dirs = os.environ.get("CRYPTOVEIL_WATCH_PATHS", "").split(os.pathsep)
    target_dir = next((d for d in watch_dirs if d and os.path.isdir(d)), tempfile.gettempdir())

    t0 = time.monotonic()
    for i in range(10):
        with open(os.path.join(target_dir, f"cv_sim_{int(t0)}_{i}.bin"), "wb") as f:
            f.write(os.urandom(65536))

    ok, elapsed = _wait_for_event(
        lambda ev: ev.get("topic") == "sensor.filesystem.entropy" and ev.get("burst_triggered")
    )
    _report("Ransomware burst detection", ok, elapsed)


def sim_clipboard_hijack() -> None:
    print("\n[Clipboard Hijack] Simulating a rapid clipboard swap...")
    try:
        import pyperclip
    except ImportError:
        print("  SKIPPED — pyperclip not available in this environment")
        return

    pyperclip.copy("1A2b3C4d5E6f7G8h9I0jWalletAddress")
    time.sleep(0.3)
    pyperclip.copy("9Z8y7X6w5V4u3T2s1RAttackerAddress")

    ok, elapsed = _wait_for_event(lambda ev: ev.get("topic") == "sensor.clipboard.swap")
    _report("Clipboard hijack detection", ok, elapsed)


def sim_anti_forensic() -> None:
    print("\n[Anti-Forensic] Spawning a benign process whose cmdline matches a detection pattern...")
    # This launches the OS shell with an ECHO command containing a matching
    # phrase — it prints text to a pipe and exits. It does not clear any
    # actual log.
    if sys.platform == "win32":
        cmd = ["cmd.exe", "/c", "echo", "wevtutil", "cl", "Security-simulation-only"]
    else:
        cmd = ["/bin/sh", "-c", "echo wevtutil cl Security-simulation-only"]

    t0 = time.monotonic()
    subprocess.run(cmd, capture_output=True)

    ok, elapsed = _wait_for_event(
        lambda ev: ev.get("topic") == "engine.antiforensic.detected"
        and "simulation-only" in ev.get("cmdline", "")
    )
    _report("Anti-forensic command detection", ok, elapsed)


def sim_hash_chain_tamper() -> None:
    print("\n[Hash Chain Tamper] Verifying chain, tampering one record, re-verifying...")

    resp = requests.get(f"{AGENT_URL}/api/forensics/verify_chain", timeout=5)
    before = resp.json()
    print(f"  Before: verified={before['verified']} total_events={before['total_events']}")

    if before["total_events"] == 0:
        print("  SKIPPED — no events recorded yet")
        return

    target_seq = before["total_events"] // 2
    t0 = time.monotonic()
    tamper_resp = requests.post(f"{AGENT_URL}/api/forensics/simulate_tamper/{target_seq}", timeout=5)
    tamper_resp.raise_for_status()

    after = requests.get(f"{AGENT_URL}/api/forensics/verify_chain", timeout=5).json()
    elapsed = time.monotonic() - t0

    detected = not after["verified"] and any(v["seq"] == target_seq for v in after["violations"])
    print(f"  After:  verified={after['verified']} violations={len(after['violations'])}")
    _report("Hash chain tamper detection", detected, elapsed)

    if detected:
        offhost = requests.get(f"{AGENT_URL}/api/forensics/offhost/{target_seq}", timeout=5)
        if offhost.status_code == 200:
            print(f"  Off-host copy of seq={target_seq}: AVAILABLE ✓ (local copy was tampered)")
        else:
            print(f"  Off-host copy of seq={target_seq}: not yet checkpointed (no batch sealed containing it)")


def _report(label: str, ok: bool, elapsed: float) -> None:
    status = "DETECTED" if ok else "NOT DETECTED (timeout)"
    print(f"  {label}: {status} in {elapsed:.3f}s")


SIMULATIONS = {
    "sim_ransomware_burst": sim_ransomware_burst,
    "sim_clipboard_hijack": sim_clipboard_hijack,
    "sim_anti_forensic": sim_anti_forensic,
    "sim_hash_chain_tamper": sim_hash_chain_tamper,
}


def sim_all() -> None:
    for fn in SIMULATIONS.values():
        fn()


def main() -> None:
    parser = argparse.ArgumentParser(description="CryptoVeil detection latency harness")
    parser.add_argument(
        "simulation",
        choices=["sim_all", *SIMULATIONS.keys()],
        help="Which simulation to run",
    )
    args = parser.parse_args()

    try:
        requests.get(f"{AGENT_URL}/api/health", timeout=3).raise_for_status()
    except requests.RequestException:
        print(f"ERROR: could not reach agent at {AGENT_URL}. Start it first with `python run.py`.")
        sys.exit(1)

    if args.simulation == "sim_all":
        sim_all()
    else:
        SIMULATIONS[args.simulation]()


if __name__ == "__main__":
    main()
