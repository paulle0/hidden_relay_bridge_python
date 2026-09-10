"""A reference client for talking to a hidden relay.

Useful on its own for testing a deployment, and used by the end-to-end tests.
It speaks the client half of the NIP: wrap relay messages in encrypted kind
27901 events, publish them to a rendez-vous relay, and unwrap the replies.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, AsyncIterator, Dict, List, Optional, Sequence

from .nostr.crypto import CryptoBackend, get_backend
from .nostr.event import Event, build_event
from .nostr.keys import Identity
from .nostr.nip19 import decode_nrv, parse_pubkey
from .nostr.relay import RelayConnection
from .protocol import (
    ENCRYPTION_NIP44_V2,
    KIND_COMMUNICATION,
    KIND_RENDEZVOUS_LIST,
    communication_tags,
    parse_payload,
    split_pubkey_and_encryption,
)

log = logging.getLogger(__name__)

_INBOX_SUBSCRIPTION = "hrc-inbox"


class HiddenRelayClient:
    """Talks to one hidden relay over one rendez-vous relay."""

    def __init__(
        self,
        secret_key: str,
        bridge_pubkey: str,
        relay_url: str,
        *,
        backend: Optional[CryptoBackend] = None,
        auth: bool = True,
        max_messages_per_event: int = 256,
    ) -> None:
        self._backend = backend or get_backend("auto")
        self.identity = Identity.from_secret(secret_key, self._backend)
        self.bridge_pubkey = parse_pubkey(bridge_pubkey)
        self.relay_url = relay_url
        self._max_messages_per_event = max_messages_per_event
        self.inbox: asyncio.Queue[List[Any]] = asyncio.Queue()
        self._connection = RelayConnection(
            relay_url,
            on_message=self._on_relay_message,
            on_connected=self._on_connected,
            identity=self.identity,
            auth_enabled=auth,
            label=f"client[{relay_url}]",
        )

    @classmethod
    def from_nrv(
        cls, secret_key: str, nrv: str, relay_url: Optional[str] = None, **kwargs
    ) -> "HiddenRelayClient":
        """Build a client from an `nrv1...` address, which carries the relays."""
        pubkey, relays = decode_nrv(nrv)
        url = relay_url or (relays[0] if relays else None)
        if url is None:
            raise ValueError("nrv address carries no relay and none was given")
        return cls(secret_key, pubkey, url, **kwargs)

    @property
    def pubkey(self) -> str:
        return self.identity.public_hex

    # -- lifecycle ---------------------------------------------------------

    async def connect(self, timeout: float = 15.0) -> bool:
        self._connection.start()
        return await self._connection.wait_connected(timeout)

    async def close(self) -> None:
        await self._connection.stop()

    async def __aenter__(self) -> "HiddenRelayClient":
        await self.connect()
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.close()

    # -- transport ---------------------------------------------------------

    async def _on_connected(self) -> None:
        await self._connection.send(
            [
                "REQ",
                _INBOX_SUBSCRIPTION,
                {
                    "kinds": [KIND_COMMUNICATION],
                    "authors": [self.bridge_pubkey],
                    "#p": [self.pubkey],
                    "since": int(time.time()) - 60,
                },
            ]
        )

    async def _on_relay_message(self, message: List[Any]) -> None:
        if message[0] != "EVENT" or len(message) < 3 or not isinstance(message[2], dict):
            if message[0] == "OK" and len(message) >= 3 and not message[2]:
                log.warning("rendez-vous relay rejected our event: %s", message[3:])
            return
        try:
            event = Event.from_dict(message[2])
        except ValueError:
            return
        if event.kind != KIND_COMMUNICATION or event.pubkey != self.bridge_pubkey:
            return
        recipients, _encryption = split_pubkey_and_encryption(event.tags)
        if self.pubkey not in recipients:
            return
        if not event.verify(self._backend):
            log.warning("dropping bridge event %s: bad signature", event.id[:12])
            return
        try:
            plaintext = self.identity.decrypt_from(event.pubkey, event.content)
            for relay_message in parse_payload(plaintext, self._max_messages_per_event):
                await self.inbox.put(relay_message)
        except Exception as exc:  # noqa: BLE001
            log.warning("could not read bridge event %s: %s", event.id[:12], exc)

    async def send(self, messages: Sequence[Sequence[Any]]) -> Event:
        """Wrap relay messages in one kind 27901 event and publish it."""
        plaintext = json.dumps(list(messages), separators=(",", ":"), ensure_ascii=False)
        event = build_event(
            self.identity,
            KIND_COMMUNICATION,
            content=self.identity.encrypt_to(self.bridge_pubkey, plaintext),
            tags=communication_tags(self.bridge_pubkey, ENCRYPTION_NIP44_V2),
        )
        await self._connection.send(["EVENT", event.to_dict()])
        return event

    # -- convenience -------------------------------------------------------

    async def messages(self, timeout: Optional[float] = None) -> AsyncIterator[List[Any]]:
        """Yield relay messages as they arrive, stopping after `timeout` idle."""
        while True:
            try:
                if timeout is None:
                    yield await self.inbox.get()
                else:
                    yield await asyncio.wait_for(self.inbox.get(), timeout)
            except asyncio.TimeoutError:
                return

    async def request(
        self,
        filters: Sequence[Dict[str, Any]],
        subscription_id: str = "sub1",
        timeout: float = 20.0,
        close_after_eose: bool = True,
    ) -> List[Dict[str, Any]]:
        """Run a REQ and collect events until EOSE (or the timeout)."""
        await self.send([["REQ", subscription_id, *filters]])
        events: List[Dict[str, Any]] = []
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                log.warning("REQ '%s' timed out after %.1fs", subscription_id, timeout)
                break
            try:
                message = await asyncio.wait_for(self.inbox.get(), remaining)
            except asyncio.TimeoutError:
                break
            if len(message) < 2 or message[1] != subscription_id:
                continue
            if message[0] == "EVENT" and len(message) >= 3:
                events.append(message[2])
            elif message[0] == "EOSE":
                break
            elif message[0] == "CLOSED":
                log.warning("subscription '%s' closed: %s", subscription_id, message[2:])
                return events
        if close_after_eose:
            await self.send([["CLOSE", subscription_id]])
        return events

    async def publish(
        self, event: Dict[str, Any], timeout: float = 20.0
    ) -> Optional[List[Any]]:
        """Publish an event through the hidden relay and wait for its OK."""
        await self.send([["EVENT", event]])
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return None
            try:
                message = await asyncio.wait_for(self.inbox.get(), remaining)
            except asyncio.TimeoutError:
                return None
            if message[0] == "OK" and len(message) >= 2 and message[1] == event.get("id"):
                return message

    async def discover(self, timeout: float = 10.0) -> Optional[List[str]]:
        """Read the bridge's kind 10112 event to learn its rendez-vous relays."""
        await self._connection.send(
            [
                "REQ",
                "hrc-discover",
                {"kinds": [KIND_RENDEZVOUS_LIST], "authors": [self.bridge_pubkey], "limit": 1},
            ]
        )
        # Discovery reads the rendez-vous relay directly, not through the bridge,
        # so it cannot use the encrypted inbox queue.
        found: List[str] = []
        queue: asyncio.Queue = asyncio.Queue()

        original = self._connection._on_message  # noqa: SLF001

        async def sniff(message: List[Any]) -> None:
            if (
                message[0] == "EVENT"
                and len(message) >= 3
                and isinstance(message[2], dict)
                and message[2].get("kind") == KIND_RENDEZVOUS_LIST
            ):
                await queue.put(message[2])
            await original(message)

        self._connection._on_message = sniff  # noqa: SLF001
        try:
            raw = await asyncio.wait_for(queue.get(), timeout)
            found = [tag[1] for tag in raw.get("tags", []) if len(tag) >= 2 and tag[0] == "r"]
        except asyncio.TimeoutError:
            return None
        finally:
            self._connection._on_message = original  # noqa: SLF001
            await self._connection.send(["CLOSE", "hrc-discover"])
        return found
