"""The public side of the bridge: listening on and publishing to rendez-vous relays."""

from __future__ import annotations

import asyncio
import collections
import json
import logging
import time
from typing import Any, Awaitable, Callable, Deque, List, Optional, Sequence, Set

from .config import Config
from .nip11 import build_document, fetch_document
from .nostr.event import Event, build_event
from .nostr.keys import Identity
from .nostr.relay import RelayConnection, RelayPool
from .protocol import (
    ENCRYPTION_NIP44_V2,
    KIND_COMMUNICATION,
    KIND_RELAY_INFORMATION,
    KIND_RENDEZVOUS_LIST,
    SUPPORTED_ENCRYPTION,
    ProtocolError,
    communication_tags,
    parse_payload,
    split_pubkey_and_encryption,
)
from .ratelimit import PerKeyRateLimiter

log = logging.getLogger(__name__)

RequestHandler = Callable[[str, List[List[Any]]], Awaitable[None]]

SUBSCRIPTION_ID = "hrb-inbox"
_SEEN_EVENT_CAPACITY = 8192


class SeenEvents:
    """Bounded FIFO set, so a redelivered event is only handled once."""

    def __init__(self, capacity: int = _SEEN_EVENT_CAPACITY) -> None:
        self.capacity = capacity
        self._order: Deque[str] = collections.deque()
        self._ids: Set[str] = set()

    def add(self, event_id: str) -> bool:
        """True if the id is new."""
        if event_id in self._ids:
            return False
        self._ids.add(event_id)
        self._order.append(event_id)
        if len(self._order) > self.capacity:
            self._ids.discard(self._order.popleft())
        return True


class RendezvousHub:
    """Owns the rendez-vous relay connections and the NIP framing on them."""

    def __init__(
        self,
        config: Config,
        identity: Identity,
        on_request: RequestHandler,
    ) -> None:
        self.config = config
        self.identity = identity
        self._on_request = on_request
        self._backend = identity.backend
        self._seen = SeenEvents()
        self._limiter = PerKeyRateLimiter(config.limits.inbound_events_per_minute)
        self._announcer: Optional[asyncio.Task] = None
        self._nip11_document: Optional[dict] = None
        self.events_received = 0
        self.events_accepted = 0
        self.events_published = 0

        self._pool = RelayPool(
            [
                RelayConnection(
                    url,
                    on_message=self._on_relay_message,
                    on_connected=self._make_on_connected(url),
                    identity=identity,
                    auth_enabled=config.rendezvous.auth,
                    label=f"rendezvous[{url}]",
                )
                for url in config.rendezvous.relays
            ]
        )

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        if self.config.rendezvous.publish_announcements and self.config.nip11.enabled:
            await self._load_nip11_document()
        self._pool.start()
        if self.config.rendezvous.publish_announcements:
            self._announcer = asyncio.create_task(self._announce_loop(), name="announcer")

    async def stop(self) -> None:
        if self._announcer is not None:
            self._announcer.cancel()
            try:
                await self._announcer
            except asyncio.CancelledError:
                pass
            self._announcer = None
        await self._pool.stop()

    async def wait_connected(self, timeout: float = 15.0) -> bool:
        return await self._pool.wait_any_connected(timeout)

    # -- inbound -----------------------------------------------------------

    def _make_on_connected(self, url: str) -> Callable[[], Awaitable[None]]:
        async def on_connected() -> None:
            await self._subscribe(url)
            if self.config.rendezvous.publish_announcements:
                await self._publish_announcements()

        return on_connected

    def _inbox_filter(self) -> dict:
        since = int(time.time()) - self.config.rendezvous.subscribe_since_slack_seconds
        filters: dict = {
            "kinds": [KIND_COMMUNICATION],
            "#p": [self.identity.public_hex],
            "since": since,
        }
        # Letting the relay do the whitelist filtering saves bandwidth on the Pi.
        if not self.config.access.allow_all and self.config.allowed_pubkeys_hex:
            filters["authors"] = list(self.config.allowed_pubkeys_hex)
        return filters

    async def _subscribe(self, url: str) -> None:
        for connection in self._pool.connections:
            if connection.url == url:
                await connection.send(["REQ", SUBSCRIPTION_ID, self._inbox_filter()])
                log.info("%s: subscribed to kind %d inbox", connection.label, KIND_COMMUNICATION)

    async def _on_relay_message(self, message: List[Any]) -> None:
        verb = message[0]
        if verb == "EVENT" and len(message) >= 3 and isinstance(message[2], dict):
            await self._on_inbound_event(message[2])
        elif verb == "OK" and len(message) >= 3 and not message[2]:
            reason = message[3] if len(message) > 3 else ""
            log.warning("rendez-vous relay rejected event %s: %s", str(message[1])[:12], reason)
        elif verb == "NOTICE":
            log.info("rendez-vous notice: %s", message[1] if len(message) > 1 else "")
        elif verb == "CLOSED":
            log.warning("rendez-vous closed subscription: %s", message[1:])

    async def _on_inbound_event(self, raw: dict) -> None:
        self.events_received += 1
        try:
            event = Event.from_dict(raw)
        except ValueError as exc:
            log.warning("dropping malformed event: %s", exc)
            return
        reason = self._reject_reason(event)
        if reason is not None:
            log.info("dropping event %s from %s: %s", event.id[:12], event.pubkey[:8], reason)
            return
        if not self._seen.add(event.id):
            log.debug("event %s already handled", event.id[:12])
            return

        try:
            plaintext = self.identity.decrypt_from(event.pubkey, event.content)
        except Exception as exc:  # noqa: BLE001 - decryption failure is the peer's problem
            log.warning("could not decrypt event %s from %s: %s", event.id[:12], event.pubkey[:8], exc)
            return
        try:
            messages = parse_payload(plaintext, self.config.limits.max_messages_per_event)
        except ProtocolError as exc:
            log.warning("bad payload from %s: %s", event.pubkey[:8], exc)
            return

        self.events_accepted += 1
        log.debug("accepted %d message(s) from %s", len(messages), event.pubkey[:8])
        await self._on_request(event.pubkey, messages)

    def _reject_reason(self, event: Event) -> Optional[str]:
        if event.kind != KIND_COMMUNICATION:
            return f"unexpected kind {event.kind}"
        if event.pubkey == self.identity.public_hex:
            return "authored by the bridge itself"
        access = self.config.access
        if not access.allow_all and event.pubkey not in self.config.allowed_pubkeys_hex:
            return "pubkey is not whitelisted"

        now = int(time.time())
        rendezvous = self.config.rendezvous
        if rendezvous.max_event_age_seconds > 0 and event.created_at < now - rendezvous.max_event_age_seconds:
            return f"created_at is {now - event.created_at}s old"
        if rendezvous.max_event_future_seconds > 0 and event.created_at > now + rendezvous.max_event_future_seconds:
            return f"created_at is {event.created_at - now}s in the future"

        recipients, encryption = split_pubkey_and_encryption(event.tags)
        if self.identity.public_hex not in recipients:
            return "no p tag addressing this bridge"
        if encryption and encryption not in SUPPORTED_ENCRYPTION:
            return f"unsupported encryption '{encryption}'"

        if not event.verify(self._backend):
            return "invalid id or signature"
        if not self._limiter.allow(event.pubkey):
            return "rate limit exceeded"
        return None

    # -- outbound ----------------------------------------------------------

    async def send_to_client(self, client_pubkey: str, batches: Sequence[Sequence[List[Any]]]) -> None:
        """Wrap batches of relay messages in kind 27901 events and publish them."""
        for batch in batches:
            plaintext = json.dumps(list(batch), separators=(",", ":"), ensure_ascii=False)
            try:
                content = self.identity.encrypt_to(client_pubkey, plaintext)
            except Exception:  # noqa: BLE001
                log.exception("could not encrypt a response for %s", client_pubkey[:8])
                continue
            event = build_event(
                self.identity,
                KIND_COMMUNICATION,
                content=content,
                tags=communication_tags(client_pubkey, ENCRYPTION_NIP44_V2),
            )
            self.events_published += 1
            log.debug(
                "publishing %d message(s) to %s (%d bytes plaintext)",
                len(batch),
                client_pubkey[:8],
                len(plaintext),
            )
            await self._pool.broadcast(["EVENT", event.to_dict()])

    # -- announcements -----------------------------------------------------

    async def _load_nip11_document(self) -> None:
        fetched = None
        if self.config.local_relay.fetch_nip11:
            fetched = await fetch_document(self.config.nip11_http_url)
        self._nip11_document = build_document(
            fetched, self.config.nip11.overrides, self.identity.public_hex
        )

    def build_rendezvous_event(self) -> Event:
        """Kind 10112: where this hidden relay can be reached."""
        tags = [["r", url] for url in self.config.rendezvous.relays]
        return build_event(self.identity, KIND_RENDEZVOUS_LIST, content="", tags=tags)

    def build_information_event(self) -> Event:
        """Kind 10113: the NIP-11 document of this hidden relay."""
        document = self._nip11_document or build_document(
            None, self.config.nip11.overrides, self.identity.public_hex
        )
        return build_event(
            self.identity,
            KIND_RELAY_INFORMATION,
            content=json.dumps(document, separators=(",", ":"), ensure_ascii=False),
            tags=[["encryption", ENCRYPTION_NIP44_V2]],
        )

    async def _publish_announcements(self) -> None:
        for event in (self.build_rendezvous_event(), self.build_information_event()):
            log.info("publishing kind %d announcement %s", event.kind, event.id[:12])
            await self._pool.broadcast(["EVENT", event.to_dict()])

    async def _announce_loop(self) -> None:
        interval = self.config.rendezvous.announce_interval_seconds
        while True:
            await asyncio.sleep(max(60, interval))
            if interval <= 0:
                continue
            await self._publish_announcements()
            self._limiter.forget_full()

    def stats(self) -> dict:
        return {
            "relays": [
                {"url": c.url, "connected": c.is_connected, "connects": c.connect_count}
                for c in self._pool.connections
            ],
            "events_received": self.events_received,
            "events_accepted": self.events_accepted,
            "events_published": self.events_published,
        }
