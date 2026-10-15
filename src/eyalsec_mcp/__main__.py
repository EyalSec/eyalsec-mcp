"""Command line entry point: `eyalsec-mcp` runs the server on stdio."""

from __future__ import annotations

import argparse
import asyncio
import sys

from . import __version__
from .client import API_KEY_ENV, URL_ENV, APIError, ConfigError, EyalSecClient


async def _check() -> int:
    """Call the API once with the configured key and say what it found.
    Everything goes to stderr: on stdio, stdout belongs to the MCP protocol."""
    try:
        api = EyalSecClient()
    except ConfigError as exc:
        print(f"eyalsec-mcp: {exc}", file=sys.stderr)
        return 2
    try:
        profile = await api.get("/api/account/")
        key = await api.get("/api/account/apikey")
        machines = await api.get("/api/get_all_machines/")
    except (APIError, ConfigError) as exc:
        print(f"eyalsec-mcp: {exc}", file=sys.stderr)
        return 1
    finally:
        await api.aclose()
    print(
        f"eyalsec-mcp {__version__}: connected to {api.base_url} as {profile.get('username', '?')}; "
        f"key scope {key.get('scope', '?')}; {len(machines.get('machines') or [])} machine(s).",
        file=sys.stderr,
    )
    if key.get("scope") == "full":
        print(
            "eyalsec-mcp: this server only reads, so a read-only key is enough. "
            "Consider generating one on Settings > API access.",
            file=sys.stderr,
        )
    return 0


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="eyalsec-mcp",
        description="MCP server (stdio) for reading your EyalSec account: events, machines, runs and rules.",
        epilog=f"Configuration: {API_KEY_ENV} (required, an API key from Settings > API access; "
        f"a read-only key is enough) and {URL_ENV} (optional, default https://eyalsec.com).",
    )
    parser.add_argument("--version", action="version", version=f"eyalsec-mcp {__version__}")
    parser.add_argument(
        "--check",
        action="store_true",
        help="call the API once with the configured key, report the result and exit",
    )
    args = parser.parse_args(argv)
    if args.check:
        sys.exit(asyncio.run(_check()))

    from .server import create_server

    try:
        server = create_server()
    except ConfigError as exc:
        print(f"eyalsec-mcp: {exc}", file=sys.stderr)
        sys.exit(2)
    server.run("stdio")


if __name__ == "__main__":
    main()
