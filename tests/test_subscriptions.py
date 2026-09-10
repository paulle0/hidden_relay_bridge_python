import pytest

from hidden_relay_bridge.subscriptions import (
    MAX_SUBSCRIPTION_ID_LEN,
    ClientSubscriptions,
    TooManySubscriptions,
    make_upstream_id,
)

ALICE = "a" * 64
BOB = "b" * 64


def test_same_client_id_from_two_pubkeys_maps_to_distinct_upstream_ids():
    """The whole point: 'sub1' from two clients must not collide upstream."""
    assert make_upstream_id(ALICE, "sub1") != make_upstream_id(BOB, "sub1")


def test_upstream_ids_stay_within_the_nip01_limit():
    for client_id in ("s", "sub1", "x" * 45, "y" * 64):
        assert len(make_upstream_id(ALICE, client_id)) <= MAX_SUBSCRIPTION_ID_LEN


def test_long_client_ids_are_hashed_but_still_per_pubkey():
    long_id = "z" * 64
    alice = make_upstream_id(ALICE, long_id)
    bob = make_upstream_id(BOB, long_id)
    assert alice != bob
    assert ".h." in alice
    assert ".r." in make_upstream_id(ALICE, "short")


def test_hashed_and_raw_forms_cannot_collide():
    """A client cannot forge the hashed form of another of its subscriptions."""
    hashed = make_upstream_id(ALICE, "z" * 64)
    forged = make_upstream_id(ALICE, hashed[len(ALICE[:16]) :])
    assert forged != hashed


def test_open_close_round_trip():
    subs = ClientSubscriptions(ALICE, max_subscriptions=5)
    upstream = subs.open("sub1", [{"kinds": [1]}])
    assert subs.to_client_id(upstream) == "sub1"
    assert subs.to_upstream_id("sub1") == upstream
    assert subs.close("sub1") == upstream
    assert subs.to_client_id(upstream) is None
    assert subs.close("sub1") is None


def test_reopening_the_same_id_does_not_consume_budget():
    subs = ClientSubscriptions(ALICE, max_subscriptions=1)
    first = subs.open("sub1", [{"kinds": [1]}])
    second = subs.open("sub1", [{"kinds": [7]}])
    assert first == second
    assert len(subs) == 1
    assert list(subs.replay()) == [("REQ", first, [{"kinds": [7]}])]


def test_subscription_budget_is_enforced():
    subs = ClientSubscriptions(ALICE, max_subscriptions=2)
    subs.open("a")
    subs.open("b")
    with pytest.raises(TooManySubscriptions):
        subs.open("c")
    subs.close("a")
    assert subs.open("c")


def test_replay_reports_every_open_subscription_with_its_verb():
    subs = ClientSubscriptions(ALICE, max_subscriptions=5)
    subs.open("a", [{"kinds": [1]}])
    subs.open("b", [{"kinds": [2]}, {"kinds": [3]}], verb="COUNT")
    replayed = {upstream: (verb, filters) for verb, upstream, filters in subs.replay()}
    assert len(replayed) == 2
    assert replayed[subs.to_upstream_id("a")] == ("REQ", [{"kinds": [1]}])
    assert replayed[subs.to_upstream_id("b")] == (
        "COUNT",
        [{"kinds": [2]}, {"kinds": [3]}],
    )


def test_empty_subscription_id_is_rejected():
    with pytest.raises(ValueError):
        make_upstream_id(ALICE, "")
