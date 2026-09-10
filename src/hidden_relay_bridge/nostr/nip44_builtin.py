"""Pure Python NIP-44 v2 (ChaCha20 + HMAC-SHA256) implementation.

Kept dependency-light on purpose: it only needs `coincurve` for the ECDH step
and `cryptography` for ChaCha20.  The module is exercised against the official
NIP-44 test vectors in `tests/test_nip44.py`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from coincurve import PrivateKey, PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

VERSION = 2
MIN_PLAINTEXT_SIZE = 1
MAX_PLAINTEXT_SIZE = 65535
_MIN_CIPHERTEXT_SIZE = 99
_MAX_CIPHERTEXT_SIZE = 65603


class Nip44Error(ValueError):
    """Raised for malformed payloads, bad MACs and out-of-range plaintexts."""


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def secret_to_public_hex(secret_hex: str) -> str:
    """x-only public key for a 32 byte secret key."""
    key = PrivateKey(bytes.fromhex(secret_hex))
    return key.public_key.format(compressed=True)[1:].hex()


def ecdh_shared_x(secret_hex: str, peer_pubkey_hex: str) -> bytes:
    """x-coordinate of `secret * peer_pubkey`, as NIP-44 specifies."""
    # NIP-44 keys are x-only; lifting with the even-y prefix is what the
    # BIP-340 key format implies.
    peer = PublicKey(b"\x02" + bytes.fromhex(peer_pubkey_hex))
    shared = peer.multiply(bytes.fromhex(secret_hex))
    return shared.format(compressed=True)[1:]


def get_conversation_key(secret_hex: str, peer_pubkey_hex: str) -> bytes:
    """Long lived symmetric key shared by the two parties."""
    return _hkdf_extract(salt=b"nip44-v2", ikm=ecdh_shared_x(secret_hex, peer_pubkey_hex))


def get_message_keys(conversation_key: bytes, nonce: bytes) -> tuple[bytes, bytes, bytes]:
    if len(conversation_key) != 32:
        raise Nip44Error("conversation key must be 32 bytes")
    if len(nonce) != 32:
        raise Nip44Error("nonce must be 32 bytes")
    keys = _hkdf_expand(conversation_key, nonce, 76)
    return keys[0:32], keys[32:44], keys[44:76]


def calc_padded_len(unpadded_len: int) -> int:
    if unpadded_len < 1:
        raise Nip44Error("plaintext must not be empty")
    if unpadded_len <= 32:
        return 32
    next_power = 1 << (unpadded_len - 1).bit_length()
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * (((unpadded_len - 1) // chunk) + 1)


def pad(plaintext: str) -> bytes:
    unpadded = plaintext.encode("utf-8")
    length = len(unpadded)
    if length < MIN_PLAINTEXT_SIZE or length > MAX_PLAINTEXT_SIZE:
        raise Nip44Error(f"plaintext of {length} bytes is out of range")
    return length.to_bytes(2, "big") + unpadded + bytes(calc_padded_len(length) - length)


def unpad(padded: bytes) -> str:
    if len(padded) < 2:
        raise Nip44Error("padded plaintext is truncated")
    length = int.from_bytes(padded[:2], "big")
    unpadded = padded[2 : 2 + length]
    if (
        length < MIN_PLAINTEXT_SIZE
        or len(unpadded) != length
        or len(padded) != 2 + calc_padded_len(length)
    ):
        raise Nip44Error("invalid padding")
    return unpadded.decode("utf-8")


def _chacha20(key: bytes, nonce: bytes, data: bytes) -> bytes:
    # `cryptography` wants a 16 byte value: 4 byte little endian block counter
    # followed by the 12 byte nonce.
    cipher = Cipher(algorithms.ChaCha20(key, (0).to_bytes(4, "little") + nonce), mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _hmac_aad(key: bytes, message: bytes, aad: bytes) -> bytes:
    if len(aad) != 32:
        raise Nip44Error("AAD must be the 32 byte nonce")
    return hmac.new(key, aad + message, hashlib.sha256).digest()


def encrypt_with_conversation_key(
    plaintext: str, conversation_key: bytes, nonce: bytes | None = None
) -> str:
    nonce = secrets.token_bytes(32) if nonce is None else nonce
    chacha_key, chacha_nonce, hmac_key = get_message_keys(conversation_key, nonce)
    ciphertext = _chacha20(chacha_key, chacha_nonce, pad(plaintext))
    mac = _hmac_aad(hmac_key, ciphertext, nonce)
    return base64.b64encode(bytes([VERSION]) + nonce + ciphertext + mac).decode("ascii")


def decrypt_with_conversation_key(payload: str, conversation_key: bytes) -> str:
    if not payload:
        raise Nip44Error("empty payload")
    if payload[0] == "#":
        raise Nip44Error("unknown encryption version")
    if len(payload) < 132 or len(payload) > 87472:
        raise Nip44Error(f"invalid payload length: {len(payload)}")
    try:
        raw = base64.b64decode(payload, validate=True)
    except Exception as exc:  # noqa: BLE001 - base64 raises several types
        raise Nip44Error("payload is not valid base64") from exc
    if len(raw) < _MIN_CIPHERTEXT_SIZE or len(raw) > _MAX_CIPHERTEXT_SIZE:
        raise Nip44Error(f"invalid payload size: {len(raw)}")
    if raw[0] != VERSION:
        raise Nip44Error(f"unknown encryption version {raw[0]}")
    nonce, ciphertext, mac = raw[1:33], raw[33:-32], raw[-32:]
    chacha_key, chacha_nonce, hmac_key = get_message_keys(conversation_key, nonce)
    if not hmac.compare_digest(_hmac_aad(hmac_key, ciphertext, nonce), mac):
        raise Nip44Error("invalid MAC")
    return unpad(_chacha20(chacha_key, chacha_nonce, ciphertext))


def encrypt(secret_hex: str, peer_pubkey_hex: str, plaintext: str) -> str:
    return encrypt_with_conversation_key(
        plaintext, get_conversation_key(secret_hex, peer_pubkey_hex)
    )


def decrypt(secret_hex: str, peer_pubkey_hex: str, payload: str) -> str:
    return decrypt_with_conversation_key(
        payload, get_conversation_key(secret_hex, peer_pubkey_hex)
    )
