"""
run.py — CryptoVeil v2 Startup Entry Point.

By default, launches CryptoVeil as a Native Desktop Application GUI window.
Use `--server` or `--headless` to run as a background/console server only.
"""
import sys
import os
import argparse

# ── Force UTF-8 on Windows console ───────────────────────────────────────
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")


def main():
    parser = argparse.ArgumentParser(description="CryptoVeil v2 — Security Operations Suite")
    parser.add_argument(
        "--server", "--headless",
        action="store_true",
        help="Run in headless server mode (no desktop window GUI)",
    )
    parser.add_argument(
        "--desktop",
        action="store_true",
        default=True,
        help="Run as native Desktop Application window (default)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("CRYPTOVEIL_PORT", "8765")),
        help="Port to bind (default: 8765)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=os.environ.get("CRYPTOVEIL_HOST", "0.0.0.0"),
        help="Host binding address (default: 0.0.0.0)",
    )

    args, unknown = parser.parse_known_args()
    os.environ["CRYPTOVEIL_PORT"] = str(args.port)
    os.environ["CRYPTOVEIL_HOST"] = args.host

    # Check if explicit headless/server mode was requested
    if args.server:
        import uvicorn
        print(f"""
  ╔══════════════════════════════════════════════════════════════╗
  ║       CryptoVeil v2 — Headless Security Server Mode          ║
  ║  Binding Interface : {args.host}:{args.port}                        ║
  ╚══════════════════════════════════════════════════════════════╝
        """)
        uvicorn.run(
            "agent.server.main:app",
            host=args.host,
            port=args.port,
            reload=False,
            log_level="info",
        )
    else:
        # Launch Desktop Application Window
        from desktop_app import main as desktop_main
        desktop_main()


if __name__ == "__main__":
    main()

