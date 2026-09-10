"""The bridge itself: rendez-vous relays on one side, the local relay on the other."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, List, Optional, Sequence

from .config import Config
from .nostr.crypto import get_backend
from .nostr.keys import Identity
from .rendezvous import RendezvousHub
from .session import SessionManager

log = logging.getLogger(__name__)


class Bridge:
    """Wire the public rendez-vous side to per-client local relay sessions."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.backend = get_backend(config.crypto.backend)
        self.identity = Identity.from_secret(config.secret_key_hex, self.backend)
        self.sessions = SessionManager(config, self.identity, self._deliver_to_client)
        self.rendezvous = RendezvousHub(config, self.identity, self._handle_client_request)
        self._stopped = asyncio.Event()
        self._stats_task: Optional[asyncio.Task] = None

    @property
    def npub(self) -> str:
        return self.identity.npub

    @property
    def nrv(self) -> str:
        return self.identity.nrv(self.config.rendezvous.relays)

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        log.info("bridge identity: %s", self.npub)
        log.info("bridge address:  %s", self.nrv)
        log.info("crypto backend:  %s", self.backend.name)
        log.info("local relay:     %s", self.config.local_relay.url)
        log.info("rendez-vous:     %s", ", ".join(self.config.rendezvous.relays))
        if self.config.access.allow_all:
            log.warning("access: allow_all is enabled, every pubkey may use this bridge")
        else:
            log.info("access: %d whitelisted pubkey(s)", len(self.config.allowed_pubkeys_hex))
        self.sessions.start()
        await self.rendezvous.start()
        self._stats_task = asyncio.create_task(self._stats_loop(), name="stats")

    async def stop(self) -> None:
        log.info("shutting down")
        if self._stats_task is not None:
            self._stats_task.cancel()
            try:
                await self._stats_task
            except asyncio.CancelledError:
                pass
            self._stats_task = None
        await self.rendezvous.stop()
        await self.sessions.stop()
        self._stopped.set()

    async def run_forever(self) -> None:
        """Start up and block until `request_stop` is called (or a signal arrives)."""
        await self.start()
        await self._stopped.wait()

    def request_stop(self) -> None:
        self._stopped.set()

    # -- the two directions ------------------------------------------------

    async def _handle_client_request(self, client_pubkey: str, messages: List[List[Any]]) -> None:
        """Client -> local relay."""
        session = await self.sessions.get(client_pubkey)
        await session.handle_client_messages(messages)

    async def _deliver_to_client(
        self, client_pubkey: str, batches: Sequence[Sequence[List[Any]]]
    ) -> None:
        """Local relay -> client."""
        await self.rendezvous.send_to_client(client_pubkey, batches)

    # -- observability -----------------------------------------------------

    async def _stats_loop(self, interval: float = 300.0) -> None:
        while True:
            await asyncio.sleep(interval)
            stats = self.rendezvous.stats()
            log.info(
                "stats: sessions=%d received=%d accepted=%d published=%d relays=%s",
                len(self.sessions),
                stats["events_received"],
                stats["events_accepted"],
                stats["events_published"],
                ", ".join(
                    f"{r['url']}={'up' if r['connected'] else 'down'}" for r in stats["relays"]
                ),
            )
