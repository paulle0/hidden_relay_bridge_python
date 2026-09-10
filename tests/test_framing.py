import json

from hidden_relay_bridge.framing import (
    batch_messages,
    encode_payload,
    estimate_encrypted_size,
    is_oversized,
    message_size,
)


def _event_message(sub_id, size):
    return ["EVENT", sub_id, {"content": "x" * size}]


def test_single_small_batch():
    messages = [["EOSE", "sub1"], ["NOTICE", "hi"]]
    batches = batch_messages(messages, 10000, 64)
    assert batches == [messages]


def test_batches_respect_the_byte_limit():
    messages = [_event_message("sub1", 400) for _ in range(10)]
    batches = batch_messages(messages, 1000, 64)
    assert len(batches) > 1
    for batch in batches:
        assert len(encode_payload(batch)) <= 1000
    assert [m for b in batches for m in b] == messages


def test_batches_respect_the_message_count_limit():
    messages = [["EOSE", f"sub{i}"] for i in range(10)]
    batches = batch_messages(messages, 100000, 3)
    assert [len(b) for b in batches] == [3, 3, 3, 1]


def test_oversized_message_gets_its_own_batch_and_is_not_dropped():
    messages = [["EOSE", "small"], _event_message("sub1", 5000), ["EOSE", "other"]]
    batches = batch_messages(messages, 1024, 64)
    flattened = [m for b in batches for m in b]
    assert flattened == messages
    assert [_event_message("sub1", 5000)] in batches


def test_is_oversized_matches_the_batcher():
    big = _event_message("sub1", 5000)
    assert is_oversized(big, 1024) is True
    assert is_oversized(["EOSE", "s"], 1024) is False


def test_message_size_matches_the_encoded_payload():
    message = ["EVENT", "sub1", {"content": "hello"}]
    assert message_size(message) == len(json.dumps(message, separators=(",", ":")))


def test_encrypted_size_estimate_is_close():
    from hidden_relay_bridge.nostr import nip44_builtin as nip44

    plaintext = "x" * 4000
    actual = len(
        nip44.encrypt_with_conversation_key(plaintext, bytes(32), bytes(32))
    )
    estimate = estimate_encrypted_size(len(plaintext))
    assert abs(estimate - actual) <= 64


def test_empty_input_produces_no_batches():
    assert batch_messages([], 1000, 10) == []
