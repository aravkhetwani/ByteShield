"""Run the automated attack demos against a live ByteShield gateway.

    python -m demo.run_attacks                      # all scenarios
    python -m demo.run_attacks tool_poisoning rug_pull
    python -m demo.run_attacks --url http://127.0.0.1:8080 --reset
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import httpx

from byteshield.config import ROOT
from demo.scenarios import SCENARIOS, format_report, run_scenario


def main() -> int:
    parser = argparse.ArgumentParser(description="ByteShield automated attack demos")
    parser.add_argument("scenarios", nargs="*", help=f"any of: {', '.join(SCENARIOS)} (default: all)")
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--data-dir", default=os.environ.get("BYTESHIELD_DATA", str(ROOT / "data")),
                        help="the gateway's data directory (the rug-pull demo flips a flag file in it)")
    parser.add_argument("--reset", action="store_true", help="wipe audit log / fingerprints first for a clean run")
    args = parser.parse_args()

    names = args.scenarios or list(SCENARIOS)
    unknown = [n for n in names if n not in SCENARIOS]
    if unknown:
        parser.error(f"unknown scenario(s): {', '.join(unknown)}")

    headers = {"x-admin-token": os.environ["BYTESHIELD_ADMIN_TOKEN"]} if os.environ.get("BYTESHIELD_ADMIN_TOKEN") else {}
    with httpx.Client(base_url=args.url, timeout=60, headers=headers) as client:
        try:
            client.get("/api/health").raise_for_status()
        except httpx.HTTPError as exc:
            print(f"Cannot reach the gateway at {args.url}: {exc}\nStart it first:  python start.py", file=sys.stderr)
            return 2
        if args.reset:
            client.post("/api/demo/reset", params={"wipe": "true"}).raise_for_status()
        failures = 0
        for name in names:
            result = run_scenario(name, client, Path(args.data_dir))
            print(format_report(result))
            failures += 0 if result["passed"] else 1
    print(f"\n{len(names) - failures}/{len(names)} scenarios passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
