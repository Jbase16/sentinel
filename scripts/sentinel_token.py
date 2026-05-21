#!/usr/bin/env python3
"""
sentinel-token — manage platform API credentials for SentinelForge intel.

Stores HackerOne / Bugcrowd API credentials in the OS keychain
(macOS Keychain) or an encrypted-permissions file fallback, via
``core.intel.token_store``.

Commands:

    sentinel-token add <platform> --handle <handle>
        Store a credential. The token is read from a hidden prompt
        (getpass) — never passed on the command line, never in shell
        history, never visible in `ps`.

    sentinel-token list
        List which platforms have a stored credential (names only —
        never handles or tokens).

    sentinel-token show <platform>
        Show the stored HANDLE for a platform (never the token).

    sentinel-token remove <platform>
        Delete a stored credential.

Examples:

    sentinel-token add hackerone --handle your-handle
    # Enter API token: (hidden)

    sentinel-token list
    sentinel-token show hackerone
    sentinel-token remove hackerone

Exit codes:
    0  success
    1  error (invalid platform, storage failure, etc.)
    2  usage error
"""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

# Path setup so this works from repo root or as an installed script.
_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from core.intel import token_store
from core.intel.token_store import TokenStoreError

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

_SUPPORTED = ("hackerone", "bugcrowd")


def cmd_add(args: argparse.Namespace) -> int:
    platform = args.platform
    handle = args.handle.strip()
    if not handle:
        print("❌ --handle must not be empty", file=sys.stderr)
        return EXIT_USAGE

    # Read the token from a hidden prompt — NEVER from argv.
    try:
        token = getpass.getpass(f"Enter {platform} API token (input hidden): ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.", file=sys.stderr)
        return EXIT_USAGE
    if not token:
        print("❌ token must not be empty", file=sys.stderr)
        return EXIT_USAGE

    try:
        token_store.put(platform, handle, token)
    except TokenStoreError as e:
        print(f"❌ could not store credential: {e}", file=sys.stderr)
        return EXIT_ERROR

    backend = token_store.backend_name()
    print(f"✓ Stored {platform} credential for handle '{handle}' (backend: {backend}).")
    print(f"  Auth shape will be probed on first use. Test with:")
    print(f"    sentinel-ingest --program {platform}:<program-handle>")
    return EXIT_OK


def cmd_list(args: argparse.Namespace) -> int:
    try:
        stored = token_store.list_stored()
    except TokenStoreError as e:
        print(f"❌ could not read credential store: {e}", file=sys.stderr)
        return EXIT_ERROR
    if not stored:
        print("No stored credentials. Add one with: sentinel-token add hackerone --handle <handle>")
        return EXIT_OK
    print(f"Stored credentials (backend: {token_store.backend_name()}):")
    for platform in stored:
        print(f"  • {platform}")
    return EXIT_OK


def cmd_show(args: argparse.Namespace) -> int:
    platform = args.platform
    try:
        cred = token_store.get(platform)
    except TokenStoreError as e:
        print(f"❌ could not read credential: {e}", file=sys.stderr)
        return EXIT_ERROR
    if cred is None:
        print(f"No stored credential for {platform}.", file=sys.stderr)
        return EXIT_ERROR
    # Handle only — NEVER print the token.
    print(f"{platform}: handle='{cred.handle}' token=<stored, hidden>")
    return EXIT_OK


def cmd_remove(args: argparse.Namespace) -> int:
    platform = args.platform
    try:
        removed = token_store.remove(platform)
    except TokenStoreError as e:
        print(f"❌ could not remove credential: {e}", file=sys.stderr)
        return EXIT_ERROR
    if removed:
        print(f"✓ Removed {platform} credential.")
    else:
        print(f"No stored credential for {platform} (nothing to remove).")
    return EXIT_OK


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel-token",
        description="Manage platform API credentials for SentinelForge intel.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="Store a credential (token via hidden prompt).")
    p_add.add_argument("platform", choices=_SUPPORTED)
    p_add.add_argument("--handle", required=True,
                       help="Your platform username / handle (the Basic-Auth username).")
    p_add.set_defaults(func=cmd_add)

    p_list = sub.add_parser("list", help="List platforms with a stored credential.")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", help="Show the stored handle for a platform (never the token).")
    p_show.add_argument("platform", choices=_SUPPORTED)
    p_show.set_defaults(func=cmd_show)

    p_remove = sub.add_parser("remove", help="Delete a stored credential.")
    p_remove.add_argument("platform", choices=_SUPPORTED)
    p_remove.set_defaults(func=cmd_remove)

    return p


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
