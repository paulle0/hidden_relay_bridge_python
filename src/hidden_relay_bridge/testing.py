"""A minimal in-memory nostr relay.

Enough of NIP-01 (and optionally NIP-42) to exercise the bridge end to end:
the test suite stands one up as the "local relay" and another as the
"rendez-vous relay".  It is also handy for trying the bridge out before
pointing it at real infrastructure:

    python -m hidden_relay_bridge.testing --port 7777
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import websockets
from websockets.asyncio.server import Server, ServerConnection, serve

from .nostr.crypto import get_backend
from .nostr.event import Event

log = logging.getLogger(__name__)

EPHEMERAL_RANGE = range(20000, 30000)
REPLACEABLE_RANGE = range(10000, 20000)


def matches_filter(event: Event, filt: Dict[str, Any]) -> bool:
    """NIP-01 filter matching: ids, authors, kinds, #-tags, since, until."""
    if "ids" in filt and event.id not in filt["ids"]:
        return False
    if "authors" in filt and event.pubkey not in filt["authors"]:
        return False
    if "kinds" in filt and event.kind not in filt["kinds"]:
        return False
    if "since" in filt and event.created_at < filt["since"]:
        return False
    if "until" in filt and event.created_at > filt["until"]:
        return False
    for key, wanted in filt.items():
        if not key.startswith("#") or len(key) != 2:
            continue
        values = event.tag_values(key[1])
        if not any(value in wanted for value in values):
            return False
    return True


class MiniRelay:
    """An in-memory relay you can start and stop from a test."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        require_auth: bool = False,
        max_events: int = 10000,
        name: str = "mini-relay",
    ) -> None:
        self.host = host
        self.port = port
        self.require_auth = require_auth
        self.max_events = max_events
        self.name = name
        self._events: List[Event] = []
        self._subscriptions: Dict[ServerConnection, Dict[str, List[Dict[str, Any]]]] = {}
        self._authenticated: Set[ServerConnection] = set()
        self._challenges: Dict[ServerConnection, str] = {}
        self._server: Optional[Server] = None
        self._backend = get_backend("builtin")
        self.received_subscription_ids: List[Tuple[str, str]] = []

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> "MiniRelay":
        self._server = await serve(self._handle, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]
        log.info("%s listening on %s", self.name, self.url)
        return self

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def __aenter__(self) -> "MiniRelay":
        return await self.start()

    async def __aexit__(self, *_exc: Any) -> None:
        await self.stop()

    @property
    def url(self) -> str:
        return f"ws://{self.host}:{self.port}"

    # -- store -------------------------------------------------------------

    @property
    def events(self) -> List[Event]:
        return list(self._events)

    def seed(self, events: Sequence[Event]) -> None:
        for event in events:
            self._store(event)

    def _store(self, event: Event) -> None:
        if event.kind in EPHEMERAL_RANGE:
            return
        if event.kind in REPLACEABLE_RANGE or event.kind in (0, 3):
            self._events = [
                existing
                for existing in self._events
                if not (existing.kind == event.kind and existing.pubkey == event.pubkey)
            ]
        self._events.append(event)
        if len(self._events) > self.max_events:
            del self._events[: len(self._events) - self.max_events]

    # -- protocol ----------------------------------------------------------

    async def _handle(self, ws: ServerConnection) -> None:
        self._subscriptions[ws] = {}
        if self.require_auth:
            challenge = secrets.token_hex(16)
            self._challenges[ws] = challenge
            await self._send(ws, ["AUTH", challenge])
        try:
            async for raw in ws:
                try:
                    message = json.loads(raw)
                except json.JSONDecodeError:
                    await self._send(ws, ["NOTICE", "invalid JSON"])
                    continue
                if not isinstance(message, list) or not message:
                    await self._send(ws, ["NOTICE", "invalid message"])
                    continue
                await self._dispatch(ws, message)
        except websockets.ConnectionClosed:
            pass
        finally:
            self._subscriptions.pop(ws, None)
            self._authenticated.discard(ws)
            self._challenges.pop(ws, None)

    async def _dispatch(self, ws: ServerConnection, message: List[Any]) -> None:
        verb = message[0]
        if verb == "AUTH":
            await self._on_auth(ws, message)
        elif verb == "EVENT":
            await self._on_event(ws, message)
        elif verb == "REQ":
            await self._on_req(ws, message)
        elif verb == "CLOSE":
            self._subscriptions.get(ws, {}).pop(message[1] if len(message) > 1 else "", None)
        elif verb == "COUNT":
            await self._on_count(ws, message)
        else:
            await self._send(ws, ["NOTICE", f"unsupported verb {verb}"])

    def _needs_auth(self, ws: ServerConnection) -> bool:
        return self.require_auth and ws not in self._authenticated

    async def _on_auth(self, ws: ServerConnection, message: List[Any]) -> None:
        if len(message) < 2 or not isinstance(message[1], dict):
            return
        try:
            event = Event.from_dict(message[1])
        except ValueError:
            return
        challenge = self._challenges.get(ws)
        if (
            event.kind == 22242
            and event.first_tag("challenge") == challenge
            and event.verify(self._backend)
        ):
            self._authenticated.add(ws)
            await self._send(ws, ["OK", event.id, True, ""])
        else:
            await self._send(ws, ["OK", event.id, False, "restricted: bad auth"])

    async def _on_event(self, ws: ServerConnection, message: List[Any]) -> None:
        if len(message) < 2 or not isinstance(message[1], dict):
            await self._send(ws, ["NOTICE", "EVENT needs an event object"])
            return
        try:
            event = Event.from_dict(message[1])
        except ValueError as exc:
            await self._send(ws, ["OK", "", False, f"invalid: {exc}"])
            return
        if self._needs_auth(ws):
            await self._send(ws, ["OK", event.id, False, "auth-required: authenticate first"])
            return
        if not event.verify(self._backend):
            await self._send(ws, ["OK", event.id, False, "invalid: bad id or signature"])
            return
        self._store(event)
        await self._send(ws, ["OK", event.id, True, ""])
        await self._fan_out(event)

    async def _fan_out(self, event: Event) -> None:
        for peer, subscriptions in list(self._subscriptions.items()):
            for sub_id, filters in list(subscriptions.items()):
                if any(matches_filter(event, f) for f in filters):
                    await self._send(peer, ["EVENT", sub_id, event.to_dict()])

    async def _on_req(self, ws: ServerConnection, message: List[Any]) -> None:
        if len(message) < 2 or not isinstance(message[1], str):
            await self._send(ws, ["NOTICE", "REQ needs a subscription id"])
            return
        sub_id = message[1]
        filters = [f for f in message[2:] if isinstance(f, dict)] or [{}]
        self.received_subscription_ids.append((sub_id, str(filters)))
        if self._needs_auth(ws):
            await self._send(ws, ["CLOSED", sub_id, "auth-required: authenticate first"])
            return
        self._subscriptions.setdefault(ws, {})[sub_id] = filters
        for event in self._events:
            if any(matches_filter(event, f) for f in filters):
                await self._send(ws, ["EVENT", sub_id, event.to_dict()])
        await self._send(ws, ["EOSE", sub_id])

    async def _on_count(self, ws: ServerConnection, message: List[Any]) -> None:
        if len(message) < 2 or not isinstance(message[1], str):
            return
        filters = [f for f in message[2:] if isinstance(f, dict)] or [{}]
        count = sum(1 for e in self._events if any(matches_filter(e, f) for f in filters))
        await self._send(ws, ["COUNT", message[1], {"count": count}])

    async def _send(self, ws: ServerConnection, message: List[Any]) -> None:
        try:
            await ws.send(json.dumps(message, separators=(",", ":"), ensure_ascii=False))
        except websockets.ConnectionClosed:
            pass


async def _main() -> None:  # pragma: no cover - manual tool
    import argparse

    parser = argparse.ArgumentParser(description="Run a throwaway in-memory nostr relay")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7777)
    parser.add_argument("--require-auth", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    relay = MiniRelay(args.host, args.port, require_auth=args.require_auth)
    await relay.start()
    print(f"mini relay on {relay.url} (ctrl-c to stop)")
    try:
        await asyncio.Future()
    except asyncio.CancelledError:
        pass
    finally:
        await relay.stop()


if __name__ == "__main__":  # pragma: no cover
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
