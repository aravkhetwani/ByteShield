#!/usr/bin/env python3
"""One-command launcher for ByteShield.

    python start.py            # creates .venv, installs deps, builds the dashboard, starts everything

The gateway (API + dashboard) listens on http://127.0.0.1:8080 and spawns the three demo MCP servers.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import venv
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
DASHBOARD = ROOT / "dashboard"


def venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def inside_venv() -> bool:
    return Path(sys.prefix).resolve() == VENV.resolve()


def ensure_venv() -> None:
    if not venv_python().exists():
        print(">> creating virtualenv in .venv")
        venv.create(VENV, with_pip=True)


def ensure_dependencies() -> None:
    req = ROOT / "requirements.txt"
    digest = hashlib.sha256(req.read_bytes()).hexdigest()
    marker = VENV / ".byteshield-deps"
    if marker.exists() and marker.read_text().strip() == digest:
        return
    print(">> installing Python dependencies (first run only)")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "-r", str(req)])
    marker.write_text(digest)


def ensure_dashboard(force: bool) -> None:
    if (DASHBOARD / "dist" / "index.html").exists() and not force:
        return
    npm = shutil.which("npm")
    if npm is None:
        print("!! npm not found - starting without the dashboard UI (the API at /docs still works).\n"
              "   Install Node.js 18+ and re-run, or build manually: cd dashboard && npm install && npm run build")
        return
    print(">> building the React dashboard (first run only)")
    subprocess.check_call([npm, "install", "--no-audit", "--no-fund"], cwd=DASHBOARD)
    subprocess.check_call([npm, "run", "build"], cwd=DASHBOARD)


def main() -> int:
    parser = argparse.ArgumentParser(description="Start ByteShield (gateway + dashboard + demo MCP servers)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--open", action="store_true", help="open the dashboard in your browser")
    parser.add_argument("--rebuild-dashboard", action="store_true")
    parser.add_argument("--mode", choices=["enforce", "monitor"], help="override policy mode")
    args = parser.parse_args()

    if not inside_venv():
        ensure_venv()
        return subprocess.call([str(venv_python()), str(Path(__file__).resolve()), *sys.argv[1:]])

    ensure_dependencies()
    ensure_dashboard(args.rebuild_dashboard)
    if args.mode:
        os.environ["BYTESHIELD_MODE"] = args.mode

    sys.path.insert(0, str(ROOT))
    import logging

    import uvicorn

    from byteshield.app import create_app

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    url = f"http://{args.host}:{args.port}"
    print(f"\n  ByteShield dashboard : {url}\n  Agent API (REST)     : {url}/v1/tools , POST {url}/v1/call\n"
          f"  Agent API (JSON-RPC) : POST {url}/mcp\n  Attack demos         : python -m demo.run_attacks   (in a 2nd terminal)\n")
    if args.open:
        webbrowser.open(url)
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
