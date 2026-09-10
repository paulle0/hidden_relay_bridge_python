"""Per-pubkey subscription id namespacing.

The NIP lets several clients reach the local relay through one bridge, and
nothing stops two of them from picking the same subscription id ("sub1" is a
popular choice).  Subscription ids therefore have to be unique per client
pubkey rather than per websocket connection, so the bridge rewrites every id on
the way to the local relay and restores the client's own id on the way back.

Layout of a rewritten id (NIP-01 caps subscription ids at 64 characters):

    <first 16 hex chars of the client pubkey>.r.<client id>     (short ids)
    <first 16 hex chars of the client pubkey>.h.<sha256[:32]>   (long ids)

The `.r.` / `.h.` marker keeps the two forms from ever colliding.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

MAX_SUBSCRIPTION_ID_LEN = 64
PUBKEY_PREFIX_LEN = 16
_RAW_MARKER = ".r."
_HASH_MARKER = ".h."
_MAX_RAW_CLIENT_ID_LEN = MAX_SUBSCRIPTION_ID_LEN - PUBKEY_PREFIX_LEN - len(_RAW_MARKER)


class TooManySubscriptions(RuntimeError):
    """Raised when a client exceeds its subscription budget."""


def make_upstream_id(pubkey_hex: str, client_sub_id: str) -> str:
    """Deterministic, globally unique id for `(pubkey, client subscription)`."""
    if not client_sub_id:
        raise ValueError("subscription id must not be empty")
    prefix = pubkey_hex[:PUBKEY_PREFIX_LEN]
    if len(client_sub_id) <= _MAX_RAW_CLIENT_ID_LEN:
        return f"{prefix}{_RAW_MARKER}{client_sub_id}"
    digest = hashlib.sha256(client_sub_id.encode("utf-8")).hexdigest()[:32]
    return f"{prefix}{_HASH_MARKER}{digest}"


@dataclass
class ClientSubscriptions:
    """The open subscriptions of one client pubkey."""

    pubkey: str
    max_subscriptions: int
    _to_upstream: Dict[str, str] = field(default_factory=dict)
    _to_client: Dict[str, str] = field(default_factory=dict)
    _filters: Dict[str, list] = field(default_factory=dict)
    _verbs: Dict[str, str] = field(default_factory=dict)

    def open(
        self, client_sub_id: str, filters: Optional[list] = None, verb: str = "REQ"
    ) -> str:
        """Register (or re-register) a subscription and return the upstream id."""
        upstream = make_upstream_id(self.pubkey, client_sub_id)
        if client_sub_id not in self._to_upstream:
            if len(self._to_upstream) >= self.max_subscriptions:
                raise TooManySubscriptions(
                    f"subscription limit of {self.max_subscriptions} reached"
                )
            existing = self._to_client.get(upstream)
            if existing is not None and existing != client_sub_id:
                # Only reachable if two different long ids hash the same.
                raise ValueError(f"upstream id collision for '{client_sub_id}'")
        self._to_upstream[client_sub_id] = upstream
        self._to_client[upstream] = client_sub_id
        self._filters[client_sub_id] = list(filters or [])
        self._verbs[client_sub_id] = verb
        return upstream

    def close(self, client_sub_id: str) -> Optional[str]:
        """Forget a subscription and return the upstream id it had, if any."""
        upstream = self._to_upstream.pop(client_sub_id, None)
        if upstream is not None:
            self._to_client.pop(upstream, None)
            self._filters.pop(client_sub_id, None)
            self._verbs.pop(client_sub_id, None)
        return upstream

    def to_client_id(self, upstream_id: str) -> Optional[str]:
        return self._to_client.get(upstream_id)

    def to_upstream_id(self, client_sub_id: str) -> Optional[str]:
        return self._to_upstream.get(client_sub_id)

    def owns(self, upstream_id: str) -> bool:
        return upstream_id in self._to_client

    def open_ids(self) -> List[str]:
        return list(self._to_upstream)

    def replay(self) -> Iterable[Tuple[str, str, list]]:
        """`(verb, upstream id, filters)` for every open subscription.

        This table is the single source of truth: on every connect to the local
        relay the session discards queued REQ/CLOSE traffic and re-issues these,
        so a reconnect can neither duplicate nor lose a subscription.
        """
        for client_sub_id, upstream in self._to_upstream.items():
            yield (
                self._verbs.get(client_sub_id, "REQ"),
                upstream,
                self._filters.get(client_sub_id, []),
            )

    def clear(self) -> None:
        self._to_upstream.clear()
        self._to_client.clear()
        self._filters.clear()
        self._verbs.clear()

    def __len__(self) -> int:
        return len(self._to_upstream)
