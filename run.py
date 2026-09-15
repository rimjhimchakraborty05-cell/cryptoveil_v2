"""Launch the desktop app or its loopback HTTP service."""

import argparse
import multiprocessing
import os


def main():
    parser = argparse.ArgumentParser(description="CryptoVeil security and evidence application")
    parser.add_argument(
        "--server",
        "--headless",
        action="store_true",
        help="Run the local service without a native window",
    )
    parser.add_argument("--port", type=int, default=int(os.environ.get("CRYPTOVEIL_PORT", "8765")))
    parser.add_argument(
        "--host",
        choices=["127.0.0.1", "localhost"],
        default="127.0.0.1",
        help="Local loopback only",
    )
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")
    os.environ["CRYPTOVEIL_PORT"] = str(args.port)
    if args.server:
        import uvicorn

        print(f"CryptoVeil: http://127.0.0.1:{args.port}/dashboard/")
        uvicorn.run(
            "agent.server.main:app",
            host=args.host,
            port=args.port,
            loop="asyncio",
            log_level="info",
        )
    else:
        from desktop_app import main as desktop_main

        desktop_main()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
