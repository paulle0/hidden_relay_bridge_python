"""Per-client sessions against the local relay.

Every whitelisted client pubkey gets its own session: its own websocket to the
local relay, its own subscription table and its own outbound batcher.  Keeping
clients apart means one client's reconnect, subscription flood or slow drain
cannot disturb another's, and it makes the subscription bookkeeping obvious.

Subscription ids are still rewritten to be unique per pubkey (see
`subscriptions.py`), so the local relay sees globally distinct ids and its logs
stay readable no matter how many clients call their subscription "sub1".
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence

from .config import Config
from .framing import batch_messages, is_oversized
from .nostr.keys import Identity
from .nostr.relay import RelayConnection
from .subscriptions import ClientSubscriptions, TooManySubscriptions

log = logging.getLogger(__name__)

# Client -> relay verbs that carry a subscription id in position 1.
_SUBSCRIBING_VERBS = ("REQ", "COUNT")
# Relay -> client verbs that carry a subscription id in position 1.
_SUB_ADDRESSED_VERBS = ("EVENT", "EOSE", "CLOSED", "COUNT")

DeliverCallback = Callable[[str, List[List[Any]]], Awaitable[None]]


class ClientSession:
    """One whitelisted client and its connection to the local relay."""

    def __init__(
        self,
        pubkey: str,
        config: Config,
        identity: Identity,
        deliver: DeliverCallback,
    ) -> None:
        self.pubkey = pubkey
        self.config = config
        self.identity = identity
        self._deliver = deliver
        self.subscriptions = ClientSubscriptions(
            pubkey=pubkey,
            max_subscriptions=config.limits.max_subscriptions_per_client,
        )
        self.created_at = time.time()
        self.last_activity = self.created_at
        self.messages_in = 0
        self.messages_out = 0

        # Serialises forwarding against the connect-time subscription rebuild,
        # so the two can never both issue the same REQ.
        self._forward_lock = asyncio.Lock()
        self._outbound: asyncio.Queue[List[Any]] = asyncio.Queue(maxsize=4096)
        self._flusher: Optional[asyncio.Task] = None
        self._connection = RelayConnection(
            config.local_relay.url,
            on_message=self._on_local_message,
            on_connected=self._on_local_connected,
            identity=identity,
            auth_enabled=config.local_relay.auth,
            label=f"local[{pubkey[:8]}]",
            connect_timeout=config.local_relay.connect_timeout_seconds,
            max_message_bytes=config.local_relay.max_message_bytes,
        )

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        self._connection.start()
        if self._flusher is None:
            self._flusher = asyncio.create_task(
                self._flush_loop(), name=f"flush:{self.pubkey[:8]}"
            )

    async def close(self) -> None:
        if self._flusher is not None:
            self._flusher.cancel()
            try:
                await self._flusher
            except asyncio.CancelledError:
                pass
            self._flusher = None
        await self._connection.stop()
        self.subscriptions.clear()

    @property
    def idle_seconds(self) -> float:
        return time.time() - self.last_activity

    @property
    def is_connected(self) -> bool:
        return self._connection.is_connected

    # -- client -> local relay --------------------------------------------

    async def handle_client_messages(self, messages: Sequence[Sequence[Any]]) -> None:
        """Forward a decrypted batch of client messages to the local relay."""
        self.last_activity = time.time()
        for message in messages:
            if not isinstance(message, list) or not message or not isinstance(message[0], str):
                log.warning("%s: dropping malformed client message", self._log_prefix)
                continue
            self.messages_in += 1
            try:
                await self._forward_to_local(message)
            except Exception:  # noqa: BLE001 - never let one message kill the batch
                log.exception("%s: failed to forward %s", self._log_prefix, message[0])

    async def _forward_to_local(self, message: List[Any]) -> None:
        async with self._forward_lock:
            await self._forward_to_local_locked(message)

    async def _forward_to_local_locked(self, message: List[Any]) -> None:
        verb = message[0]

        if verb in _SUBSCRIBING_VERBS:
            if len(message) < 2 or not isinstance(message[1], str) or not message[1]:
                await self._notice("subscription id must be a non-empty string")
                return
            client_sub_id = message[1]
            filters = list(message[2:])
            try:
                upstream_id = self.subscriptions.open(client_sub_id, filters, verb)
            except TooManySubscriptions as exc:
                log.info("%s: %s", self._log_prefix, exc)
                await self._enqueue(["CLOSED", client_sub_id, f"rate-limited: {exc}"])
                return
            except ValueError as exc:
                await self._enqueue(["CLOSED", client_sub_id, f"error: {exc}"])
                return
            log.debug(
                "%s: %s '%s' -> '%s'", self._log_prefix, verb, client_sub_id, upstream_id
            )
            await self._connection.send([verb, upstream_id, *filters])
            return

        if verb == "CLOSE":
            if len(message) < 2 or not isinstance(message[1], str):
                return
            upstream_id = self.subscriptions.close(message[1])
            if upstream_id is None:
                log.debug("%s: CLOSE for unknown '%s'", self._log_prefix, message[1])
                return
            await self._connection.send(["CLOSE", upstream_id])
            return

        # EVENT, AUTH and anything a future NIP adds travel through untouched.
        if verb not in ("EVENT", "AUTH"):
            log.debug("%s: forwarding unrecognised verb %s verbatim", self._log_prefix, verb)
        await self._connection.send(list(message))

    # -- local relay -> client --------------------------------------------

    async def _on_local_message(self, message: List[Any]) -> None:
        self.last_activity = time.time()
        verb = message[0]

        if verb in _SUB_ADDRESSED_VERBS and len(message) >= 2 and isinstance(message[1], str):
            client_sub_id = self.subscriptions.to_client_id(message[1])
            if client_sub_id is None:
                # Usually a late message for a subscription the client closed.
                log.debug("%s: dropping %s for unknown '%s'", self._log_prefix, verb, message[1])
                return
            message = [verb, client_sub_id, *message[2:]]
            if verb in ("CLOSED", "COUNT"):
                self.subscriptions.close(client_sub_id)

        await self._enqueue(message)

    async def _on_local_connected(self) -> None:
        """Rebuild the local relay's view of this client's subscriptions.

        Queued REQ/CLOSE messages are dropped first: the subscription table
        already reflects them, so replaying from it alone means a connect can
        neither duplicate a subscription (the bug of sending both) nor lose one
        that was queued while the relay was down.
        """
        async with self._forward_lock:
            self._connection.drop_pending(
                lambda message: bool(message) and message[0] in ("REQ", "COUNT", "CLOSE")
            )
            replays = list(self.subscriptions.replay())
            if not replays:
                return
            log.info("%s: (re)issuing %d subscription(s)", self._log_prefix, len(replays))
            for verb, upstream_id, filters in replays:
                await self._connection.send([verb, upstream_id, *filters])

    # -- outbound batching -------------------------------------------------

    async def _enqueue(self, message: List[Any]) -> None:
        try:
            self._outbound.put_nowait(message)
        except asyncio.QueueFull:
            log.warning("%s: outbound queue full, dropping a message", self._log_prefix)

    async def _notice(self, text: str) -> None:
        await self._enqueue(["NOTICE", f"hidden-relay-bridge: {text}"])

    async def _flush_loop(self) -> None:
        limits = self.config.limits
        delay = limits.flush_delay_ms / 1000.0
        while True:
            first = await self._outbound.get()
            pending = [first]
            if delay > 0:
                deadline = asyncio.get_running_loop().time() + delay
                while len(pending) < limits.max_messages_per_event:
                    remaining = deadline - asyncio.get_running_loop().time()
                    if remaining <= 0:
                        break
                    try:
                        pending.append(
                            await asyncio.wait_for(self._outbound.get(), remaining)
                        )
                    except asyncio.TimeoutError:
                        break
            else:
                while len(pending) < limits.max_messages_per_event:
                    try:
                        pending.append(self._outbound.get_nowait())
                    except asyncio.QueueEmpty:
                        break

            for message in pending:
                if is_oversized(message, limits.max_payload_bytes):
                    log.warning(
                        "%s: %s message is larger than max_payload_bytes; sending it "
                        "anyway, the rendez-vous relay may reject it",
                        self._log_prefix,
                        message[0],
                    )
            batches = batch_messages(
                pending, limits.max_payload_bytes, limits.max_messages_per_event
            )
            self.messages_out += len(pending)
            try:
                await self._deliver(self.pubkey, batches)
            except Exception:  # noqa: BLE001
                log.exception("%s: delivery failed", self._log_prefix)

    @property
    def _log_prefix(self) -> str:
        return f"session[{self.pubkey[:8]}]"

    def stats(self) -> Dict[str, Any]:
        return {
            "pubkey": self.pubkey,
            "connected": self.is_connected,
            "subscriptions": len(self.subscriptions),
            "messages_in": self.messages_in,
            "messages_out": self.messages_out,
            "idle_seconds": round(self.idle_seconds, 1),
        }


class SessionManager:
    """Creates, reuses and reaps `ClientSession` objects."""

    def __init__(self, config: Config, identity: Identity, deliver: DeliverCallback) -> None:
        self.config = config
        self.identity = identity
        self._deliver = deliver
        self._sessions: Dict[str, ClientSession] = {}
        self._reaper: Optional[asyncio.Task] = None

    def start(self) -> None:
        if self._reaper is None:
            self._reaper = asyncio.create_task(self._reap_loop(), name="session-reaper")

    async def stop(self) -> None:
        if self._reaper is not None:
            self._reaper.cancel()
            try:
                await self._reaper
            except asyncio.CancelledError:
                pass
            self._reaper = None
        await asyncio.gather(
            *(session.close() for session in self._sessions.values()), return_exceptions=True
        )
        self._sessions.clear()

    async def get(self, pubkey: str) -> ClientSession:
        session = self._sessions.get(pubkey)
        if session is not None:
            return session
        if len(self._sessions) >= self.config.limits.max_sessions:
            await self._evict_idlest()
        session = ClientSession(pubkey, self.config, self.identity, self._deliver)
        self._sessions[pubkey] = session
        session.start()
        log.info(
            "session[%s]: opened (%d/%d active)",
            pubkey[:8],
            len(self._sessions),
            self.config.limits.max_sessions,
        )
        return session

    async def _evict_idlest(self) -> None:
        victim = max(self._sessions.values(), key=lambda s: s.idle_seconds, default=None)
        if victim is None:
            return
        log.info(
            "session[%s]: evicting to stay under max_sessions (idle %.0fs)",
            victim.pubkey[:8],
            victim.idle_seconds,
        )
        await self._close(victim.pubkey)

    async def _close(self, pubkey: str) -> None:
        session = self._sessions.pop(pubkey, None)
        if session is not None:
            await session.close()

    async def _reap_loop(self) -> None:
        timeout = self.config.limits.session_idle_timeout_seconds
        while True:
            await asyncio.sleep(max(5.0, timeout / 4))
            if timeout <= 0:
                continue
            stale = [
                pubkey
                for pubkey, session in self._sessions.items()
                if session.idle_seconds > timeout and len(session.subscriptions) == 0
            ]
            for pubkey in stale:
                log.info("session[%s]: closing idle session", pubkey[:8])
                await self._close(pubkey)

    def stats(self) -> List[Dict[str, Any]]:
        return [session.stats() for session in self._sessions.values()]

    def __len__(self) -> int:
        return len(self._sessions)
