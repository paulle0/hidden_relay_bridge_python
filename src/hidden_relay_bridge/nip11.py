"""The NIP-11 relay information document announced in the kind 10113 event."""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.request
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

DEFAULT_DOCUMENT: Dict[str, Any] = {
    "name": "hidden relay",
    "description": "A hidden relay reachable over kind 27901 rendez-vous events.",
    "software": "https://github.com/paulle0/hidden_relay_bridge_python",
    "supported_nips": [1, 11, 19, 42, 44],
}


def _fetch_sync(url: str, timeout: float) -> Optional[Dict[str, Any]]:
    request = urllib.request.Request(url, headers={"Accept": "application/nostr+json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        payload = response.read().decode("utf-8")
    document = json.loads(payload)
    if not isinstance(document, dict):
        raise ValueError("NIP-11 document is not a JSON object")
    return document


async def fetch_document(url: str, timeout: float = 10.0) -> Optional[Dict[str, Any]]:
    """Fetch the local relay's NIP-11 document, or None if it is unavailable."""
    try:
        return await asyncio.to_thread(_fetch_sync, url, timeout)
    except Exception as exc:  # noqa: BLE001 - a missing document is not fatal
        log.warning("could not fetch NIP-11 document from %s: %s", url, exc)
        return None


def build_document(
    fetched: Optional[Dict[str, Any]],
    overrides: Dict[str, Any],
    pubkey_hex: str,
) -> Dict[str, Any]:
    """Merge defaults, whatever the local relay reported, and config overrides."""
    document: Dict[str, Any] = dict(DEFAULT_DOCUMENT)
    if fetched:
        document.update(fetched)
    document.update(overrides)
    # The announcement describes the hidden relay, so the identity is its own.
    document.setdefault("pubkey", pubkey_hex)
    supported = set(document.get("supported_nips") or [])
    supported.update(DEFAULT_DOCUMENT["supported_nips"])
    document["supported_nips"] = sorted(supported)
    return document
