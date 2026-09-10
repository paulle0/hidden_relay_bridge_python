#!/usr/bin/env python3
"""Talk to a hidden relay from the command line.

Examples
--------
Read the last 5 kind 1 notes through the bridge:

    python tools/hidden_relay_client.py \
        --relay wss://relay.napttr.eu \
        --bridge npub1thebridge... \
        --nsec nsec1yourclientkey... \
        req '{"kinds":[1],"limit":5}'

Send raw relay messages (anything NIP-01 allows):

    python tools/hidden_relay_client.py ... raw '[["REQ","s1",{"limit":1}]]'

Discover a bridge's rendez-vous relays from its kind 10112 event:

    python tools/hidden_relay_client.py --relay wss://... --bridge npub1... \
        --nsec nsec1... discover
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from hidden_relay_bridge.client import HiddenRelayClient  # noqa: E402
from hidden_relay_bridge.nostr.nip19 import decode_nrv  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Reference client for a hidden relay")
    parser.add_argument("--relay", help="rendez-vous relay URL (ws:// or wss://)")
    parser.add_argument("--bridge", help="hidden relay npub, nrv or hex pubkey")
    parser.add_argument("--nrv", help="nrv address; supplies both --bridge and --relay")
    parser.add_argument(
        "--nsec",
        help="client secret key (nsec or hex); a throwaway key is generated if omitted",
    )
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--no-auth", action="store_true", help="do not answer NIP-42 AUTH")
    parser.add_argument("-v", "--verbose", action="store_true")

    sub = parser.add_subparsers(dest="command", required=True)
    req = sub.add_parser("req", help="run a REQ and print the events")
    req.add_argument("filter", nargs="+", help="one or more JSON filters")
    req.add_argument("--sub-id", default="sub1")

    publish = sub.add_parser("publish", help="publish an already signed event")
    publish.add_argument("event", help="the event as JSON")

    raw = sub.add_parser("raw", help="send a JSON array of relay messages and print replies")
    raw.add_argument("messages", help="JSON array of relay messages")
    raw.add_argument("--listen", type=float, default=5.0, help="seconds to keep listening")

    sub.add_parser("discover", help="read the bridge's kind 10112 rendez-vous list")
    return parser


async def run(args: argparse.Namespace) -> int:
    bridge, relay = args.bridge, args.relay
    if args.nrv:
        pubkey, relays = decode_nrv(args.nrv)
        bridge = bridge or pubkey
        relay = relay or (relays[0] if relays else None)
    if not bridge or not relay:
        print("need --bridge and --relay (or --nrv)", file=sys.stderr)
        return 2

    secret = args.nsec or secrets.token_bytes(32).hex()
    if not args.nsec:
        print("using a throwaway client key; whitelist it on the bridge", file=sys.stderr)

    client = HiddenRelayClient(secret, bridge, relay, auth=not args.no_auth)
    print(f"client pubkey: {client.pubkey}", file=sys.stderr)
    if not await client.connect(args.timeout):
        print(f"could not connect to {relay}", file=sys.stderr)
        await client.close()
        return 1

    try:
        if args.command == "req":
            filters = [json.loads(f) for f in args.filter]
            events = await client.request(filters, args.sub_id, timeout=args.timeout)
            print(json.dumps(events, indent=2))
            print(f"{len(events)} event(s)", file=sys.stderr)
        elif args.command == "publish":
            result = await client.publish(json.loads(args.event), timeout=args.timeout)
            print(json.dumps(result) if result else "no OK received before the timeout")
        elif args.command == "raw":
            await client.send(json.loads(args.messages))
            async for message in client.messages(timeout=args.listen):
                print(json.dumps(message))
        elif args.command == "discover":
            relays = await client.discover(timeout=args.timeout)
            print(json.dumps(relays, indent=2) if relays else "no kind 10112 event found")
    finally:
        await client.close()
    return 0


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
