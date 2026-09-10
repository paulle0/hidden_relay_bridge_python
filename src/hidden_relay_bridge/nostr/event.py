"""NIP-01 event construction, hashing and verification."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .crypto import CryptoBackend
from .keys import Identity

Tags = List[List[str]]


def serialize_for_id(
    pubkey: str, created_at: int, kind: int, tags: Sequence[Sequence[str]], content: str
) -> bytes:
    """The NIP-01 serialization whose sha256 is the event id."""
    payload = [0, pubkey, created_at, kind, [list(tag) for tag in tags], content]
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_id(
    pubkey: str, created_at: int, kind: int, tags: Sequence[Sequence[str]], content: str
) -> str:
    return hashlib.sha256(serialize_for_id(pubkey, created_at, kind, tags, content)).hexdigest()


@dataclass
class Event:
    id: str
    pubkey: str
    created_at: int
    kind: int
    tags: Tags = field(default_factory=list)
    content: str = ""
    sig: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "pubkey": self.pubkey,
            "created_at": self.created_at,
            "kind": self.kind,
            "tags": self.tags,
            "content": self.content,
            "sig": self.sig,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Event":
        try:
            event = cls(
                id=str(data["id"]),
                pubkey=str(data["pubkey"]),
                created_at=int(data["created_at"]),
                kind=int(data["kind"]),
                tags=[[str(item) for item in tag] for tag in data.get("tags", [])],
                content=str(data.get("content", "")),
                sig=str(data.get("sig", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"malformed event: {exc}") from exc
        return event

    def computed_id(self) -> str:
        return compute_id(self.pubkey, self.created_at, self.kind, self.tags, self.content)

    def verify(self, backend: CryptoBackend) -> bool:
        """Check both the id and the signature."""
        if len(self.id) != 64 or len(self.pubkey) != 64 or len(self.sig) != 128:
            return False
        if self.computed_id() != self.id:
            return False
        return backend.verify(self.pubkey, bytes.fromhex(self.id), self.sig)

    def first_tag(self, name: str) -> Optional[str]:
        for tag in self.tags:
            if len(tag) >= 2 and tag[0] == name:
                return tag[1]
        return None

    def tag_values(self, name: str) -> List[str]:
        return [tag[1] for tag in self.tags if len(tag) >= 2 and tag[0] == name]


def build_event(
    identity: Identity,
    kind: int,
    content: str = "",
    tags: Optional[Sequence[Sequence[str]]] = None,
    created_at: Optional[int] = None,
) -> Event:
    """Create a signed event authored by `identity`."""
    tag_list: Tags = [list(tag) for tag in (tags or [])]
    created_at = int(time.time()) if created_at is None else created_at
    event_id = compute_id(identity.public_hex, created_at, kind, tag_list, content)
    return Event(
        id=event_id,
        pubkey=identity.public_hex,
        created_at=created_at,
        kind=kind,
        tags=tag_list,
        content=content,
        sig=identity.sign(bytes.fromhex(event_id)),
    )
