"""Command line interface.

    hidden-relay-bridge run     --config config.toml
    hidden-relay-bridge keygen
    hidden-relay-bridge show    --config config.toml
    hidden-relay-bridge check   --config config.toml
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from .bridge import Bridge
from .config import Config, ConfigError, load_config
from .logging_setup import running_under_systemd, setup_logging
from .nostr.crypto import available_backends, get_backend
from .nostr.keys import Identity
from .nostr.nip19 import encode_nrv, parse_pubkey

log = logging.getLogger("hidden_relay_bridge")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hidden-relay-bridge",
        description="Bridge a local nostr relay onto public rendez-vous relays "
        "using the hidden relay NIP (kinds 10112, 10113, 27901).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_config_arg(target: argparse.ArgumentParser) -> None:
        target.add_argument(
            "-c",
            "--config",
            type=Path,
            default=None,
            help="path to the TOML config file (default: ./config.toml, "
            "then /etc/hidden-relay-bridge/config.toml)",
        )

    run = sub.add_parser("run", help="run the bridge in the foreground")
    add_config_arg(run)
    run.add_argument("--log-level", default=None, help="override [logging].level")
    run.add_argument("--log-file", default=None, help="override [logging].file")

    keygen = sub.add_parser("keygen", help="generate a new bridge identity")
    keygen.add_argument("--json", action="store_true", help="print JSON instead of text")
    keygen.add_argument(
        "--relay",
        action="append",
        default=[],
        help="rendez-vous relay to embed in the nrv address (repeatable)",
    )

    show = sub.add_parser("show", help="print the identity and announcement events")
    add_config_arg(show)
    show.add_argument("--json", action="store_true", help="print JSON instead of text")

    check = sub.add_parser("check", help="validate the config and test connectivity")
    add_config_arg(check)
    check.add_argument(
        "--timeout", type=float, default=15.0, help="connectivity timeout in seconds"
    )

    address = sub.add_parser("address", help="build an nrv address from a pubkey")
    address.add_argument("pubkey", help="npub, nrv or hex public key")
    address.add_argument("--relay", action="append", default=[], help="repeatable relay URL")

    return parser


def _load(path: Optional[Path]) -> Config:
    try:
        return load_config(path)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def cmd_keygen(args: argparse.Namespace) -> int:
    identity = Identity.generate(get_backend("auto"))
    data = {
        "nsec": identity.nsec,
        "npub": identity.npub,
        "secret_key_hex": identity.secret_hex,
        "public_key_hex": identity.public_hex,
        "nrv": identity.nrv(args.relay),
    }
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print("New hidden relay identity")
        print("-------------------------")
        print(f"nsec (keep secret) : {data['nsec']}")
        print(f"npub               : {data['npub']}")
        print(f"secret key (hex)   : {data['secret_key_hex']}")
        print(f"public key (hex)   : {data['public_key_hex']}")
        print(f"nrv address        : {data['nrv']}")
        print()
        print("Put the nsec in [bridge].secret_key, or in a file referenced by")
        print("[bridge].secret_key_file with permissions 0600.")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    config = _load(args.config)
    bridge = Bridge(config)
    rendezvous_event = bridge.rendezvous.build_rendezvous_event()
    information_event = bridge.rendezvous.build_information_event()
    data = {
        "npub": bridge.npub,
        "public_key_hex": bridge.identity.public_hex,
        "nrv": bridge.nrv,
        "crypto_backend": bridge.backend.name,
        "local_relay": config.local_relay.url,
        "rendezvous_relays": config.rendezvous.relays,
        "allowed_pubkeys": config.allowed_pubkeys_hex,
        "kind_10112": rendezvous_event.to_dict(),
        "kind_10113": information_event.to_dict(),
    }
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(f"npub              : {data['npub']}")
        print(f"public key (hex)  : {data['public_key_hex']}")
        print(f"nrv address       : {data['nrv']}")
        print(f"crypto backend    : {data['crypto_backend']}")
        print(f"local relay       : {data['local_relay']}")
        print(f"rendez-vous relays: {', '.join(data['rendezvous_relays'])}")
        print(f"whitelisted keys  : {len(data['allowed_pubkeys'])}")
        print()
        print("kind 10112 (rendez-vous list):")
        print(json.dumps(data["kind_10112"], indent=2))
        print()
        print("kind 10113 (relay information):")
        print(json.dumps(data["kind_10113"], indent=2))
    return 0


def cmd_address(args: argparse.Namespace) -> int:
    print(encode_nrv(parse_pubkey(args.pubkey), args.relay))
    return 0


async def _check(config: Config, timeout: float) -> int:
    from .nostr.relay import RelayConnection

    problems = 0
    print(f"config            : {config.source_path}")
    print(f"crypto backends   : {', '.join(available_backends())}")
    bridge = Bridge(config)
    print(f"identity          : {bridge.npub}")
    print(f"nrv address       : {bridge.nrv}")

    async def _noop(_message) -> None:
        return None

    for label, url, auth in [
        ("local relay", config.local_relay.url, config.local_relay.auth),
        *[("rendez-vous", url, config.rendezvous.auth) for url in config.rendezvous.relays],
    ]:
        connection = RelayConnection(
            url,
            on_message=_noop,
            identity=bridge.identity,
            auth_enabled=auth,
            label=url,
            connect_timeout=timeout,
        )
        connection.start()
        ok = await connection.wait_connected(timeout)
        await connection.stop()
        print(f"{label:<18}: {'reachable' if ok else 'UNREACHABLE'}  {url}")
        problems += 0 if ok else 1

    if config.local_relay.fetch_nip11:
        from .nip11 import fetch_document

        document = await fetch_document(config.nip11_http_url, timeout)
        name = document.get("name") if document else None
        print(f"local NIP-11      : {name or 'not available'}")

    print()
    print("all good" if problems == 0 else f"{problems} relay(s) unreachable")
    return 0 if problems == 0 else 1


def cmd_check(args: argparse.Namespace) -> int:
    config = _load(args.config)
    setup_logging("WARNING")
    return asyncio.run(_check(config, args.timeout))


async def _run(config: Config) -> int:
    bridge = Bridge(config)
    loop = asyncio.get_running_loop()

    def _request_stop(signame: str) -> None:
        log.info("received %s", signame)
        bridge.request_stop()

    for signame in ("SIGINT", "SIGTERM"):
        try:
            loop.add_signal_handler(
                getattr(signal, signame), _request_stop, signame
            )
        except (NotImplementedError, AttributeError):  # pragma: no cover - non-POSIX
            pass

    try:
        await bridge.run_forever()
    finally:
        await bridge.stop()
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    config = _load(args.config)
    setup_logging(
        args.log_level or config.logging.level,
        args.log_file if args.log_file is not None else config.logging.file,
        systemd=running_under_systemd(),
    )
    log.info("hidden-relay-bridge %s starting", __version__)
    try:
        return asyncio.run(_run(config))
    except KeyboardInterrupt:  # pragma: no cover - handled via signals normally
        return 0


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "run": cmd_run,
        "keygen": cmd_keygen,
        "show": cmd_show,
        "check": cmd_check,
        "address": cmd_address,
    }
    return handlers[args.command](args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
