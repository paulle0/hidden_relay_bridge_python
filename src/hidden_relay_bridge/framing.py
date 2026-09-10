"""Packing relay messages into kind 27901 payloads.

The NIP carries an array of ordinary nostr protocol messages inside the
encrypted content of one event, and asks for the content to stay small enough
that ordinary relays accept it.  `batch_messages` does the packing; sizes are
measured on the *plaintext* JSON, so remember that NIP-44 output is roughly
4/3 of it plus a small constant.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, List, Sequence

RelayMessage = Sequence[Any]

# NIP-44 v2 cannot carry more than 65535 bytes of plaintext.
MAX_PLAINTEXT_BYTES = 65535


def encode_payload(messages: Sequence[RelayMessage]) -> str:
    return json.dumps(list(messages), separators=(",", ":"), ensure_ascii=False)


def message_size(message: RelayMessage) -> int:
    return len(encode_payload([message])) - 2  # drop the enclosing brackets


def estimate_encrypted_size(plaintext_bytes: int) -> int:
    """Size of the base64 NIP-44 payload for a plaintext of that size."""
    from .nostr.nip44_builtin import calc_padded_len

    padded = 2 + calc_padded_len(plaintext_bytes)
    overhead = 1 + 32 + 32  # version byte, nonce, MAC
    return ((padded + overhead + 2) // 3) * 4


def batch_messages(
    messages: Iterable[RelayMessage],
    max_payload_bytes: int,
    max_messages: int,
) -> List[List[RelayMessage]]:
    """Greedily group messages into payloads under the size and count limits.

    A single message larger than `max_payload_bytes` is not silently dropped;
    it gets a batch of its own so the caller can decide what to do about it.
    """
    limit = min(max_payload_bytes, MAX_PLAINTEXT_BYTES)
    batches: List[List[RelayMessage]] = []
    current: List[RelayMessage] = []
    current_size = 2  # the "[" and "]"

    for message in messages:
        size = message_size(message)
        separator = 1 if current else 0
        too_big = current_size + separator + size > limit
        too_many = len(current) >= max_messages
        if current and (too_big or too_many):
            batches.append(current)
            current = []
            current_size = 2
            separator = 0
        current.append(message)
        current_size += separator + size

    if current:
        batches.append(current)
    return batches


def is_oversized(message: RelayMessage, max_payload_bytes: int) -> bool:
    """True when a message cannot fit in a payload even on its own."""
    return message_size(message) + 2 > min(max_payload_bytes, MAX_PLAINTEXT_BYTES)
