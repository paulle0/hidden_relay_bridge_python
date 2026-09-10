import pytest

from hidden_relay_bridge.protocol import (
    KIND_COMMUNICATION,
    ProtocolError,
    communication_tags,
    parse_payload,
    split_pubkey_and_encryption,
)


def test_communication_tags_follow_the_nip():
    tags = communication_tags("ab" * 32)
    assert tags == [["p", "ab" * 32], ["encryption", "nip44_v2"]]
    assert KIND_COMMUNICATION == 27901


def test_parse_payload_accepts_an_array_of_messages():
    messages = parse_payload('[["REQ","s1",{"kinds":[1]}],["CLOSE","s0"]]', 10)
    assert messages[0][0] == "REQ"
    assert messages[1] == ["CLOSE", "s0"]


@pytest.mark.parametrize(
    "payload",
    ['{"not":"an array"}', "[[]]", '["REQ"]', "[123]", "not json", '[{"a":1}]'],
)
def test_parse_payload_rejects_malformed_content(payload):
    with pytest.raises(ProtocolError):
        parse_payload(payload, 10)


def test_parse_payload_enforces_the_message_cap():
    with pytest.raises(ProtocolError, match="limit"):
        parse_payload('[["EOSE","a"],["EOSE","b"],["EOSE","c"]]', 2)


def test_split_pubkey_and_encryption():
    tags = [["p", "aa"], ["encryption", "nip44_v2"], ["p", "bb"], ["r", "wss://x"]]
    recipients, encryption = split_pubkey_and_encryption(tags)
    assert recipients == ["aa", "bb"]
    assert encryption == "nip44_v2"


def test_missing_tags_are_tolerated():
    assert split_pubkey_and_encryption([["p"], []]) == ([], "")
