"""Bech32 / bech32m codec.

Vendored from the BIP-173 / BIP-350 reference implementation by Pieter Wuille
(MIT licensed) and trimmed to the parts this project needs.  NIP-19 uses plain
bech32 (not bech32m), but the constant is kept configurable so the module stays
faithful to the reference.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence, Tuple

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3

# NIP-19 strings (nprofile, nevent, nrv, ...) are far longer than the 90
# character limit BIP-173 imposes on segwit addresses, so the limit is opt-in.
NO_LIMIT = 0


class Bech32Error(ValueError):
    """Raised when a bech32 string cannot be decoded."""


def _polymod(values: Iterable[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> List[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _verify_checksum(hrp: str, data: Sequence[int], const: int) -> bool:
    return _polymod(_hrp_expand(hrp) + list(data)) == const


def _create_checksum(hrp: str, data: Sequence[int], const: int) -> List[int]:
    values = _hrp_expand(hrp) + list(data)
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp: str, data: Sequence[int], const: int = BECH32_CONST) -> str:
    """Encode 5-bit `data` under human readable prefix `hrp`."""
    combined = list(data) + _create_checksum(hrp, data, const)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])


def bech32_decode(
    bech: str, const: int = BECH32_CONST, limit: int = NO_LIMIT
) -> Tuple[str, List[int]]:
    """Decode a bech32 string into `(hrp, 5-bit data)`.

    Raises `Bech32Error` instead of returning `(None, None)` so callers do not
    have to remember to check.
    """
    if limit and len(bech) > limit:
        raise Bech32Error(f"string too long: {len(bech)} > {limit}")
    if any(ord(x) < 33 or ord(x) > 126 for x in bech):
        raise Bech32Error("string contains characters outside the printable range")
    if bech.lower() != bech and bech.upper() != bech:
        raise Bech32Error("mixed case string")
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech):
        raise Bech32Error("missing or misplaced separator")
    hrp = bech[:pos]
    if any(x not in CHARSET for x in bech[pos + 1 :]):
        raise Bech32Error("data part contains characters outside the bech32 charset")
    data = [CHARSET.find(x) for x in bech[pos + 1 :]]
    if not _verify_checksum(hrp, data, const):
        raise Bech32Error("bad checksum")
    return hrp, data[:-6]


def convertbits(
    data: Iterable[int], frombits: int, tobits: int, pad: bool = True
) -> Optional[List[int]]:
    """General power-of-2 base conversion (BIP-173 reference helper)."""
    acc = 0
    bits = 0
    ret: List[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def encode_bytes(hrp: str, payload: bytes) -> str:
    """Encode raw bytes as a bech32 string under `hrp`."""
    converted = convertbits(payload, 8, 5)
    if converted is None:
        raise Bech32Error("could not convert payload to 5-bit groups")
    return bech32_encode(hrp, converted)


def decode_bytes(bech: str) -> Tuple[str, bytes]:
    """Decode a bech32 string into `(hrp, raw bytes)`."""
    hrp, data = bech32_decode(bech)
    converted = convertbits(data, 5, 8, False)
    if converted is None:
        raise Bech32Error("invalid padding in data part")
    return hrp, bytes(converted)
