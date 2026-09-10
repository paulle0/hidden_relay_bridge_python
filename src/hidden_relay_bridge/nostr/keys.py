"""The bridge identity: a secret key plus its derived representations."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Sequence

from .crypto import CryptoBackend
from .nip19 import encode_npub, encode_nrv, encode_nsec, parse_secret_key


@dataclass(frozen=True)
class Identity:
    secret_hex: str
    public_hex: str
    _backend: CryptoBackend

    @classmethod
    def from_secret(cls, secret: str, backend: CryptoBackend) -> "Identity":
        secret_hex = parse_secret_key(secret)
        return cls(secret_hex, backend.public_key_hex(secret_hex), backend)

    @classmethod
    def generate(cls, backend: CryptoBackend) -> "Identity":
        return cls.from_secret(secrets.token_bytes(32).hex(), backend)

    @property
    def backend(self) -> CryptoBackend:
        return self._backend

    @property
    def npub(self) -> str:
        return encode_npub(self.public_hex)

    @property
    def nsec(self) -> str:
        return encode_nsec(self.secret_hex)

    def nrv(self, relays: Sequence[str] = ()) -> str:
        return encode_nrv(self.public_hex, relays)

    def sign(self, digest: bytes) -> str:
        return self._backend.sign(self.secret_hex, digest)

    def encrypt_to(self, peer_pubkey_hex: str, plaintext: str) -> str:
        return self._backend.nip44_encrypt(self.secret_hex, peer_pubkey_hex, plaintext)

    def decrypt_from(self, peer_pubkey_hex: str, payload: str) -> str:
        return self._backend.nip44_decrypt(self.secret_hex, peer_pubkey_hex, payload)

    def __repr__(self) -> str:  # keep the secret out of logs and tracebacks
        return f"Identity(npub={self.npub})"
