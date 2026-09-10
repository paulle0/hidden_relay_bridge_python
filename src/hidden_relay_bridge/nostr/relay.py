"""A resilient websocket client for a single nostr relay.

Handles reconnection with exponential backoff, an outbound queue that survives
short outages, and the NIP-42 `AUTH` handshake.  Message parsing beyond "it is
a JSON array" is left to the caller so the bridge can pass relay messages
through untouched.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from typing import Any, Awaitable, Callable, List, Optional

import websockets
from websockets.asyncio.client import ClientConnection

from .event import build_event
from .keys import Identity

log = logging.getLogger(__name__)

MessageHandler = Callable[[List[Any]], Awaitable[None]]
ConnectedHandler = Callable[[], Awaitable[None]]

KIND_CLIENT_AUTH = 22242


class RelayConnection:
    """Keeps one websocket to `url` alive and pumps messages both ways."""

    def __init__(
        self,
        url: str,
        *,
        on_message: MessageHandler,
        on_connected: Optional[ConnectedHandler] = None,
        identity: Optional[Identity] = None,
        auth_enabled: bool = False,
        label: Optional[str] = None,
        send_queue_size: int = 512,
        connect_timeout: float = 10.0,
        ping_interval: float = 30.0,
        max_message_bytes: int = 2 * 1024 * 1024,
        initial_backoff: float = 1.0,
        max_backoff: float = 60.0,
    ) -> None:
        self.url = url
        self.label = label or url
        self._on_message = on_message
        self._on_connected = on_connected
        self._identity = identity
        self._auth_enabled = auth_enabled
        self._connect_timeout = connect_timeout
        self._ping_interval = ping_interval
        self._max_message_bytes = max_message_bytes
        self._initial_backoff = initial_backoff
        self._max_backoff = max_backoff

        self._queue: asyncio.Queue[List[Any]] = asyncio.Queue(maxsize=send_queue_size)
        self._ws: Optional[ClientConnection] = None
        self._connected = asyncio.Event()
        self._stopping = False
        self._task: Optional[asyncio.Task] = None
        self._authenticated = False
        self.connect_count = 0
        self.dropped_messages = 0

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name=f"relay:{self.label}")

    async def stop(self) -> None:
        self._stopping = True
        if self._ws is not None:
            await self._ws.close()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    @property
    def is_connected(self) -> bool:
        return self._connected.is_set()

    async def wait_connected(self, timeout: Optional[float] = None) -> bool:
        try:
            await asyncio.wait_for(self._connected.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            return False

    # -- sending -----------------------------------------------------------

    async def send(self, message: List[Any]) -> None:
        """Queue a relay message.  Oldest queued message is dropped when full."""
        try:
            self._queue.put_nowait(message)
        except asyncio.QueueFull:
            try:
                self._queue.get_nowait()
                self.dropped_messages += 1
                log.warning("%s: send queue full, dropped the oldest message", self.label)
            except asyncio.QueueEmpty:  # pragma: no cover - racing drain
                pass
            await self._queue.put(message)

    def drop_pending(self, predicate: Callable[[List[Any]], bool]) -> int:
        """Remove queued messages matching `predicate`, returning how many went.

        Used on (re)connect to discard stale subscription traffic before the
        owner replays its subscriptions from its own table.
        """
        kept: List[List[Any]] = []
        dropped = 0
        while True:
            try:
                message = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            if predicate(message):
                dropped += 1
            else:
                kept.append(message)
        for message in kept:
            self._queue.put_nowait(message)
        return dropped

    async def send_now(self, message: List[Any]) -> bool:
        """Write directly to the socket, bypassing the queue.  False if down."""
        ws = self._ws
        if ws is None:
            return False
        try:
            await ws.send(json.dumps(message, separators=(",", ":"), ensure_ascii=False))
            return True
        except Exception as exc:  # noqa: BLE001 - connection races are expected
            log.debug("%s: direct send failed: %s", self.label, exc)
            return False

    # -- internals ---------------------------------------------------------

    async def _run(self) -> None:
        backoff = self._initial_backoff
        while not self._stopping:
            try:
                async with websockets.connect(
                    self.url,
                    open_timeout=self._connect_timeout,
                    ping_interval=self._ping_interval,
                    max_size=self._max_message_bytes,
                ) as ws:
                    self._ws = ws
                    self._authenticated = False
                    self.connect_count += 1
                    self._connected.set()
                    backoff = self._initial_backoff
                    log.info("%s: connected", self.label)
                    if self._on_connected is not None:
                        await self._on_connected()
                    writer = asyncio.create_task(self._writer(ws), name=f"writer:{self.label}")
                    try:
                        await self._reader(ws)
                    finally:
                        writer.cancel()
                        try:
                            await writer
                        except asyncio.CancelledError:
                            pass
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - any failure means retry
                log.warning("%s: connection error: %s", self.label, exc)
            finally:
                self._ws = None
                self._connected.clear()

            if self._stopping:
                break
            delay = min(backoff, self._max_backoff) * (0.5 + random.random())
            log.info("%s: reconnecting in %.1fs", self.label, delay)
            await asyncio.sleep(delay)
            backoff = min(backoff * 2, self._max_backoff)

    async def _writer(self, ws: ClientConnection) -> None:
        while True:
            message = await self._queue.get()
            try:
                await ws.send(json.dumps(message, separators=(",", ":"), ensure_ascii=False))
            except asyncio.CancelledError:
                # Put it back so the next connection picks it up.
                self._queue.put_nowait(message)
                raise
            except Exception as exc:  # noqa: BLE001
                log.warning("%s: send failed, requeueing: %s", self.label, exc)
                try:
                    self._queue.put_nowait(message)
                except asyncio.QueueFull:
                    self.dropped_messages += 1
                return

    async def _reader(self, ws: ClientConnection) -> None:
        async for raw in ws:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                log.warning("%s: ignoring non-JSON frame", self.label)
                continue
            if not isinstance(message, list) or not message:
                log.warning("%s: ignoring malformed relay message", self.label)
                continue
            if message[0] == "AUTH" and self._auth_enabled:
                await self._handle_auth(message)
                continue
            try:
                await self._on_message(message)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - one bad message must not kill the loop
                log.exception("%s: message handler failed", self.label)

    async def _handle_auth(self, message: List[Any]) -> None:
        if self._identity is None or len(message) < 2 or not isinstance(message[1], str):
            return
        challenge = message[1]
        event = build_event(
            self._identity,
            KIND_CLIENT_AUTH,
            content="",
            tags=[["relay", self.url], ["challenge", challenge]],
        )
        log.info("%s: answering NIP-42 AUTH challenge", self.label)
        if await self.send_now(["AUTH", event.to_dict()]):
            self._authenticated = True


class RelayPool:
    """A set of relays that all receive the same publishes."""

    def __init__(self, connections: List[RelayConnection]) -> None:
        self.connections = connections

    def start(self) -> None:
        for connection in self.connections:
            connection.start()

    async def stop(self) -> None:
        await asyncio.gather(*(c.stop() for c in self.connections), return_exceptions=True)

    async def broadcast(self, message: List[Any]) -> None:
        for connection in self.connections:
            await connection.send(message)

    async def wait_any_connected(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(c.is_connected for c in self.connections):
                return True
            await asyncio.sleep(0.1)
        return any(c.is_connected for c in self.connections)
