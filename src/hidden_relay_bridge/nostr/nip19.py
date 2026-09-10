"""NIP-19 bech32 entities plus the `nrv` entity defined by the hidden relay NIP.

`nrv1...` follows the NIP-19 TLV rules used by `nprofile`:

* TLV 0 -- the 32 byte public key of the hidden relay
* TLV 1 -- a rendez-vous relay URL, repeatable
"""

from __future__ import annotations

from typing import Dict, List, Sequence, Tuple

from .bech32 import Bech32Error, decode_bytes, encode_bytes

HRP_NPUB = "npub"
HRP_NSEC = "nsec"
HRP_NPROFILE = "nprofile"
HRP_NRV = "nrv"

TLV_SPECIAL = 0
TLV_RELAY = 1


def _tlv_encode(entries: Sequence[Tuple[int, bytes]]) -> bytes:
    out = bytearray()
    for tlv_type, value in entries:
        if len(value) > 255:
            raise ValueError(f"TLV value of type {tlv_type} exceeds 255 bytes")
        out.append(tlv_type)
        out.append(len(value))
        out.extend(value)
    return bytes(out)


def _tlv_decode(payload: bytes) -> Dict[int, List[bytes]]:
    entries: Dict[int, List[bytes]] = {}
    index = 0
    while index < len(payload):
        if index + 2 > len(payload):
            raise Bech32Error("truncated TLV header")
        tlv_type = payload[index]
        length = payload[index + 1]
        index += 2
        if index + length > len(payload):
            raise Bech32Error("truncated TLV value")
        entries.setdefault(tlv_type, []).append(payload[index : index + length])
        index += length
    return entries


def _require_hex32(value: str, label: str) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{label} is not valid hex") from exc
    if len(raw) != 32:
        raise ValueError(f"{label} must be 32 bytes, got {len(raw)}")
    return raw


def encode_npub(pubkey_hex: str) -> str:
    return encode_bytes(HRP_NPUB, _require_hex32(pubkey_hex, "public key"))


def encode_nsec(secret_hex: str) -> str:
    return encode_bytes(HRP_NSEC, _require_hex32(secret_hex, "secret key"))


def decode_npub(npub: str) -> str:
    hrp, raw = decode_bytes(npub)
    if hrp != HRP_NPUB:
        raise Bech32Error(f"expected an npub, got '{hrp}'")
    if len(raw) != 32:
        raise Bech32Error("npub payload must be 32 bytes")
    return raw.hex()


def decode_nsec(nsec: str) -> str:
    hrp, raw = decode_bytes(nsec)
    if hrp != HRP_NSEC:
        raise Bech32Error(f"expected an nsec, got '{hrp}'")
    if len(raw) != 32:
        raise Bech32Error("nsec payload must be 32 bytes")
    return raw.hex()


def encode_nrv(pubkey_hex: str, relays: Sequence[str] = ()) -> str:
    """Build the `nrv1...` address of a hidden relay."""
    entries: List[Tuple[int, bytes]] = [
        (TLV_SPECIAL, _require_hex32(pubkey_hex, "public key"))
    ]
    for relay in relays:
        entries.append((TLV_RELAY, relay.encode("ascii")))
    return encode_bytes(HRP_NRV, _tlv_encode(entries))


def decode_nrv(nrv: str) -> Tuple[str, List[str]]:
    """Return `(pubkey_hex, rendez-vous relays)` of an `nrv1...` address."""
    hrp, raw = decode_bytes(nrv)
    if hrp != HRP_NRV:
        raise Bech32Error(f"expected an nrv address, got '{hrp}'")
    entries = _tlv_decode(raw)
    special = entries.get(TLV_SPECIAL, [])
    if len(special) != 1 or len(special[0]) != 32:
        raise Bech32Error("nrv address must carry exactly one 32 byte TLV 0")
    relays = [value.decode("ascii") for value in entries.get(TLV_RELAY, [])]
    return special[0].hex(), relays


def parse_pubkey(value: str) -> str:
    """Accept an npub, an nrv address or raw hex and return 64 char hex."""
    value = value.strip()
    if value.startswith(HRP_NPUB + "1"):
        return decode_npub(value)
    if value.startswith(HRP_NRV + "1"):
        return decode_nrv(value)[0]
    return _require_hex32(value.lower(), "public key").hex()


def parse_secret_key(value: str) -> str:
    """Accept an nsec or raw hex and return 64 char hex."""
    value = value.strip()
    if value.startswith(HRP_NSEC + "1"):
        return decode_nsec(value)
    return _require_hex32(value.lower(), "secret key").hex()
