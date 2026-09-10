"""Constants and helpers for the hidden relay NIP itself."""

from __future__ import annotations

import json
from typing import Any, List, Sequence, Tuple

KIND_RENDEZVOUS_LIST = 10112
KIND_RELAY_INFORMATION = 10113
KIND_COMMUNICATION = 27901

ENCRYPTION_NIP44_V2 = "nip44_v2"
SUPPORTED_ENCRYPTION = (ENCRYPTION_NIP44_V2,)

TAG_ENCRYPTION = "encryption"
TAG_PUBKEY = "p"
TAG_RELAY = "r"


class ProtocolError(ValueError):
    """Raised when a peer sends something the NIP does not allow."""


def communication_tags(recipient_pubkey_hex: str, encryption: str = ENCRYPTION_NIP44_V2) -> List[List[str]]:
    return [[TAG_PUBKEY, recipient_pubkey_hex], [TAG_ENCRYPTION, encryption]]


def parse_payload(plaintext: str, max_messages: int) -> List[List[Any]]:
    """Validate the decrypted content of a kind 27901 event.

    The NIP defines it as an array of ordinary nostr protocol messages.
    """
    try:
        parsed = json.loads(plaintext)
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"content is not valid JSON: {exc}") from exc
    if not isinstance(parsed, list):
        raise ProtocolError("content must be a JSON array of relay messages")
    if len(parsed) > max_messages:
        raise ProtocolError(
            f"content carries {len(parsed)} messages, the limit is {max_messages}"
        )
    messages: List[List[Any]] = []
    for item in parsed:
        if not isinstance(item, list) or not item or not isinstance(item[0], str):
            raise ProtocolError("each message must be an array starting with a verb")
        messages.append(item)
    return messages


def split_pubkey_and_encryption(tags: Sequence[Sequence[str]]) -> Tuple[List[str], str]:
    """Return `(p tag values, encryption tag value)` from an event's tags."""
    recipients: List[str] = []
    encryption = ""
    for tag in tags:
        if len(tag) < 2:
            continue
        if tag[0] == TAG_PUBKEY:
            recipients.append(tag[1])
        elif tag[0] == TAG_ENCRYPTION and not encryption:
            encryption = tag[1]
    return recipients, encryption
