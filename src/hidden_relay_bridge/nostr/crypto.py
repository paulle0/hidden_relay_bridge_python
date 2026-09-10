"""Pluggable crypto backends.

Two implementations of the same small interface:

* ``builtin``    -- `coincurve` + `cryptography`, with the NIP-44 v2 code in
                    `nip44_builtin.py`.  Light and easy to install on a Pi.
* ``nostr-sdk``  -- delegates to the rust-nostr bindings when they are
                    installed.

Both are checked against the official NIP-44 vectors in the test suite, so the
choice is purely about which dependency you would rather ship.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from typing import List

from . import nip44_builtin

BACKEND_BUILTIN = "builtin"
BACKEND_NOSTR_SDK = "nostr-sdk"
BACKEND_AUTO = "auto"
KNOWN_BACKENDS = (BACKEND_AUTO, BACKEND_BUILTIN, BACKEND_NOSTR_SDK)


class CryptoBackend(ABC):
    """Everything the bridge needs from a signing/encryption library."""

    name: str

    @abstractmethod
    def public_key_hex(self, secret_hex: str) -> str:
        """x-only public key for a secret key, both 64 char hex."""

    @abstractmethod
    def sign(self, secret_hex: str, digest: bytes) -> str:
        """BIP-340 signature over a 32 byte digest, as 128 char hex."""

    @abstractmethod
    def verify(self, pubkey_hex: str, digest: bytes, signature_hex: str) -> bool:
        """Check a BIP-340 signature; never raises for malformed input."""

    @abstractmethod
    def nip44_encrypt(self, secret_hex: str, peer_pubkey_hex: str, plaintext: str) -> str:
        ...

    @abstractmethod
    def nip44_decrypt(self, secret_hex: str, peer_pubkey_hex: str, payload: str) -> str:
        ...


class BuiltinBackend(CryptoBackend):
    name = BACKEND_BUILTIN

    def __init__(self) -> None:
        from coincurve import PrivateKey, PublicKeyXOnly  # noqa: F401  (import check)

        self._PrivateKey = PrivateKey
        self._PublicKeyXOnly = PublicKeyXOnly

    def public_key_hex(self, secret_hex: str) -> str:
        return nip44_builtin.secret_to_public_hex(secret_hex)

    def sign(self, secret_hex: str, digest: bytes) -> str:
        if len(digest) != 32:
            raise ValueError("digest must be 32 bytes")
        return self._PrivateKey(bytes.fromhex(secret_hex)).sign_schnorr(digest).hex()

    def verify(self, pubkey_hex: str, digest: bytes, signature_hex: str) -> bool:
        try:
            pubkey = self._PublicKeyXOnly(bytes.fromhex(pubkey_hex))
            return pubkey.verify(bytes.fromhex(signature_hex), digest)
        except Exception:  # noqa: BLE001 - malformed input is just "invalid"
            return False

    def nip44_encrypt(self, secret_hex: str, peer_pubkey_hex: str, plaintext: str) -> str:
        return nip44_builtin.encrypt(secret_hex, peer_pubkey_hex, plaintext)

    def nip44_decrypt(self, secret_hex: str, peer_pubkey_hex: str, payload: str) -> str:
        return nip44_builtin.decrypt(secret_hex, peer_pubkey_hex, payload)


class NostrSdkBackend(CryptoBackend):
    name = BACKEND_NOSTR_SDK

    def __init__(self) -> None:
        import nostr_sdk

        self._sdk = nostr_sdk

    def _keys(self, secret_hex: str):
        return self._sdk.Keys(self._sdk.SecretKey.parse(secret_hex))

    def public_key_hex(self, secret_hex: str) -> str:
        return self._keys(secret_hex).public_key().to_hex()

    def sign(self, secret_hex: str, digest: bytes) -> str:
        if len(digest) != 32:
            raise ValueError("digest must be 32 bytes")
        return self._keys(secret_hex).sign_schnorr(digest)

    def verify(self, pubkey_hex: str, digest: bytes, signature_hex: str) -> bool:
        # The bindings verify whole events rather than bare digests, so fall
        # back to coincurve for this one operation.
        return _fallback_verify(pubkey_hex, digest, signature_hex)

    def nip44_encrypt(self, secret_hex: str, peer_pubkey_hex: str, plaintext: str) -> str:
        return self._sdk.nip44_encrypt(
            self._sdk.SecretKey.parse(secret_hex),
            self._sdk.PublicKey.parse(peer_pubkey_hex),
            plaintext,
            self._sdk.Nip44Version.V2,
        )

    def nip44_decrypt(self, secret_hex: str, peer_pubkey_hex: str, payload: str) -> str:
        return self._sdk.nip44_decrypt(
            self._sdk.SecretKey.parse(secret_hex),
            self._sdk.PublicKey.parse(peer_pubkey_hex),
            payload,
        )


def _fallback_verify(pubkey_hex: str, digest: bytes, signature_hex: str) -> bool:
    try:
        from coincurve import PublicKeyXOnly

        return PublicKeyXOnly(bytes.fromhex(pubkey_hex)).verify(
            bytes.fromhex(signature_hex), digest
        )
    except Exception:  # noqa: BLE001
        return False


def available_backends() -> List[str]:
    found = []
    for name in (BACKEND_BUILTIN, BACKEND_NOSTR_SDK):
        try:
            get_backend(name)
        except Exception:  # noqa: BLE001
            continue
        found.append(name)
    return found


def get_backend(name: str = BACKEND_AUTO) -> CryptoBackend:
    """Instantiate a backend by name.

    ``auto`` prefers `nostr-sdk` when it imports and falls back to the builtin
    implementation otherwise.
    """
    if name == BACKEND_AUTO:
        try:
            return NostrSdkBackend()
        except Exception:  # noqa: BLE001 - optional dependency
            return BuiltinBackend()
    if name == BACKEND_BUILTIN:
        return BuiltinBackend()
    if name == BACKEND_NOSTR_SDK:
        return NostrSdkBackend()
    raise ValueError(f"unknown crypto backend '{name}', expected one of {KNOWN_BACKENDS}")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
