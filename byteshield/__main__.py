"""`python -m byteshield` - run the gateway (and dashboard, if built)."""
from __future__ import annotations

import argparse
import logging

import uvicorn

from .app import create_app


def main() -> None:
    parser = argparse.ArgumentParser(prog="byteshield", description="ByteShield MCP security gateway")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
