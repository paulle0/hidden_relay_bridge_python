import pytest

from hidden_relay_bridge.nostr.bech32 import Bech32Error
from hidden_relay_bridge.nostr.nip19 import (
    decode_npub,
    decode_nrv,
    decode_nsec,
    encode_npub,
    encode_nrv,
    encode_nsec,
    parse_pubkey,
    parse_secret_key,
)

# From NIP-19's own examples.
HEX_PUB = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
NPUB = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"
HEX_SEC = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa"
NSEC = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"


def test_npub_round_trip():
    assert encode_npub(HEX_PUB) == NPUB
    assert decode_npub(NPUB) == HEX_PUB


def test_nsec_round_trip():
    assert encode_nsec(HEX_SEC) == NSEC
    assert decode_nsec(NSEC) == HEX_SEC


def test_nrv_carries_pubkey_and_relays():
    relays = ["wss://relay.napttr.eu", "wss://relay.example.com/"]
    address = encode_nrv(HEX_PUB, relays)
    assert address.startswith("nrv1")
    pubkey, decoded_relays = decode_nrv(address)
    assert pubkey == HEX_PUB
    assert decoded_relays == relays


def test_nrv_without_relays():
    pubkey, relays = decode_nrv(encode_nrv(HEX_PUB))
    assert (pubkey, relays) == (HEX_PUB, [])


def test_parse_pubkey_accepts_every_form():
    assert parse_pubkey(HEX_PUB) == HEX_PUB
    assert parse_pubkey(NPUB) == HEX_PUB
    assert parse_pubkey(encode_nrv(HEX_PUB, ["wss://r.example"])) == HEX_PUB


def test_parse_secret_key_accepts_hex_and_nsec():
    assert parse_secret_key(NSEC) == HEX_SEC
    assert parse_secret_key(HEX_SEC.upper()) == HEX_SEC


def test_checksum_is_enforced():
    with pytest.raises(Bech32Error):
        decode_npub(NPUB[:-1] + ("q" if NPUB[-1] != "q" else "p"))


def test_wrong_prefix_is_rejected():
    with pytest.raises(Bech32Error):
        decode_nrv(NPUB)
    with pytest.raises(Bech32Error):
        decode_npub(encode_nrv(HEX_PUB))
