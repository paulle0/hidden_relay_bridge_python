import json

import pytest

from hidden_relay_bridge.nostr.event import Event, build_event, compute_id, serialize_for_id
from hidden_relay_bridge.nostr.keys import Identity

# Generated with the rust-nostr bindings from a fixed key, so the id and the
# signature pin this implementation against an independent one. The content is
# deliberately non-ASCII: NIP-01 hashes UTF-8, not escaped ASCII.
KNOWN = {
    "id": "808320ded5c20394c9c0bb6a355897c548d76693718b344703282ba8cafcbeb4",
    "pubkey": "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e",
    "created_at": 1673347337,
    "kind": 1,
    "tags": [
        ["e", "3da979448d9ba263864c4d6f14984c423a3838364ec255f03c7904b1ae77f206"],
        ["p", "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"],
    ],
    "content": (
        "Walled gardens became prisons, and nostr is the first step towards "
        "tearing down the prison walls. \U0001f30d gr\u00fc\u00dfe"
    ),
    "sig": (
        "e9929337c22c544d5fac83a6b363db9e059364bdb9d7bb961fae43c4a0c2fc81"
        "c88b00ad2281667ea3752407251d1a466b81fabc522c2ca4e20b0fe34c44cdbc"
    ),
}
KNOWN_SECRET = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa"


def test_serialization_matches_nip01():
    serialized = serialize_for_id(
        KNOWN["pubkey"], KNOWN["created_at"], KNOWN["kind"], KNOWN["tags"], KNOWN["content"]
    )
    assert json.loads(serialized) == [
        0,
        KNOWN["pubkey"],
        KNOWN["created_at"],
        KNOWN["kind"],
        KNOWN["tags"],
        KNOWN["content"],
    ]
    assert serialized.startswith(b'[0,"')
    assert b'", "' not in serialized  # compact separators, no whitespace
    assert "\U0001f30d".encode("utf-8") in serialized  # UTF-8, not \u escapes


def test_known_event_id_and_signature(any_backend):
    event = Event.from_dict(KNOWN)
    assert event.computed_id() == KNOWN["id"]
    assert event.verify(any_backend) is True


def test_signing_the_known_event_reproduces_it(any_backend):
    identity = Identity.from_secret(KNOWN_SECRET, any_backend)
    assert identity.public_hex == KNOWN["pubkey"]
    rebuilt = build_event(
        identity,
        KNOWN["kind"],
        content=KNOWN["content"],
        tags=KNOWN["tags"],
        created_at=KNOWN["created_at"],
    )
    assert rebuilt.id == KNOWN["id"]
    assert rebuilt.verify(any_backend) is True


@pytest.mark.parametrize("field", ["content", "created_at", "kind", "sig"])
def test_tampering_breaks_verification(any_backend, field):
    mutated = {"content": "!", "created_at": 1, "kind": 2, "sig": "00" * 64}[field]
    tampered = dict(KNOWN)
    tampered[field] = (
        KNOWN[field] + mutated if field == "content" else mutated
    )
    assert Event.from_dict(tampered).verify(any_backend) is False


def test_build_event_round_trip(any_backend):
    identity = Identity.generate(any_backend)
    event = build_event(identity, 27901, content="hello", tags=[["p", identity.public_hex]])
    assert event.kind == 27901
    assert event.pubkey == identity.public_hex
    assert event.first_tag("p") == identity.public_hex
    assert event.verify(any_backend) is True
    assert Event.from_dict(event.to_dict()) == event


def test_non_ascii_content_hashes_consistently(backend):
    identity = Identity.generate(backend)
    event = build_event(identity, 1, content="grüße 🌍")
    assert event.verify(backend) is True
    assert compute_id(
        event.pubkey, event.created_at, event.kind, event.tags, event.content
    ) == event.id


def test_malformed_events_are_rejected():
    with pytest.raises(ValueError):
        Event.from_dict({"id": "x"})


def test_identity_repr_hides_the_secret(backend):
    identity = Identity.generate(backend)
    assert identity.secret_hex not in repr(identity)
