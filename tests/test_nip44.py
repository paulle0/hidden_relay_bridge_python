"""The official NIP-44 v2 vectors, run against every available backend."""

import hashlib
import json
from pathlib import Path

import pytest

from hidden_relay_bridge.nostr import nip44_builtin as nip44

VECTORS = json.loads((Path(__file__).parent / "vectors" / "nip44.vectors.json").read_text())
V2 = VECTORS["v2"]


@pytest.mark.parametrize("case", V2["valid"]["get_conversation_key"])
def test_conversation_key(case):
    key = nip44.get_conversation_key(case["sec1"], case["pub2"])
    assert key.hex() == case["conversation_key"]


@pytest.mark.parametrize("case", V2["valid"]["encrypt_decrypt"])
def test_encrypt_decrypt(case):
    key = nip44.get_conversation_key(case["sec1"], nip44.secret_to_public_hex(case["sec2"]))
    assert key.hex() == case["conversation_key"]
    payload = nip44.encrypt_with_conversation_key(
        case["plaintext"], key, bytes.fromhex(case["nonce"])
    )
    assert payload == case["payload"]
    assert nip44.decrypt_with_conversation_key(case["payload"], key) == case["plaintext"]


@pytest.mark.parametrize("case", V2["valid"]["calc_padded_len"])
def test_calc_padded_len(case):
    assert nip44.calc_padded_len(case[0]) == case[1]


@pytest.mark.parametrize("case", V2["valid"].get("encrypt_decrypt_long_msg", []))
def test_long_messages(case):
    plaintext = case["pattern"] * case["repeat"]
    assert hashlib.sha256(plaintext.encode()).hexdigest() == case["plaintext_sha256"]
    payload = nip44.encrypt_with_conversation_key(
        plaintext, bytes.fromhex(case["conversation_key"]), bytes.fromhex(case["nonce"])
    )
    assert hashlib.sha256(payload.encode()).hexdigest() == case["payload_sha256"]


@pytest.mark.parametrize("length", V2["invalid"]["encrypt_msg_lengths"])
def test_invalid_plaintext_lengths(length):
    with pytest.raises(nip44.Nip44Error):
        nip44.encrypt_with_conversation_key("a" * length, bytes(32), bytes(32))


@pytest.mark.parametrize("case", V2["invalid"]["decrypt"])
def test_invalid_payloads_are_rejected(case):
    with pytest.raises(nip44.Nip44Error):
        nip44.decrypt_with_conversation_key(
            case["payload"], bytes.fromhex(case["conversation_key"])
        )


@pytest.mark.parametrize("case", V2["invalid"]["get_conversation_key"])
def test_invalid_conversation_keys(case):
    with pytest.raises(Exception):
        nip44.get_conversation_key(case["sec1"], case["pub2"])


@pytest.mark.parametrize("case", V2["valid"]["encrypt_decrypt"][:8])
def test_backends_agree_with_the_vectors(any_backend, case):
    """Every backend must decrypt the official payloads and round-trip its own."""
    sec1, sec2 = case["sec1"], case["sec2"]
    pub1 = nip44.secret_to_public_hex(sec1)
    pub2 = nip44.secret_to_public_hex(sec2)
    assert any_backend.public_key_hex(sec1) == pub1

    assert any_backend.nip44_decrypt(sec2, pub1, case["payload"]) == case["plaintext"]
    payload = any_backend.nip44_encrypt(sec1, pub2, case["plaintext"])
    assert any_backend.nip44_decrypt(sec2, pub1, payload) == case["plaintext"]
    # And cross-backend, so the choice is never observable on the wire.
    assert nip44.decrypt(sec2, pub1, payload) == case["plaintext"]
