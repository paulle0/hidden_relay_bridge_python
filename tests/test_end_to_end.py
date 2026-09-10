"""Full-path tests: client -> rendez-vous relay -> bridge -> local relay -> back.

Both relays are real websocket servers (`MiniRelay`), and the bridge under test
is the same object the daemon runs, so these cover the framing, the encryption,
the whitelist, the subscription rewriting and the reconnect handling together.
"""

from __future__ import annotations

import asyncio
import secrets

import pytest

from hidden_relay_bridge.bridge import Bridge
from hidden_relay_bridge.client import HiddenRelayClient
from hidden_relay_bridge.config import (
    AccessSection,
    BridgeSection,
    Config,
    CryptoSection,
    LimitsSection,
    LocalRelaySection,
    Nip11Section,
    RendezvousSection,
)
from hidden_relay_bridge.nostr.crypto import get_backend
from hidden_relay_bridge.nostr.event import build_event
from hidden_relay_bridge.nostr.keys import Identity
from hidden_relay_bridge.protocol import KIND_RELAY_INFORMATION, KIND_RENDEZVOUS_LIST
from hidden_relay_bridge.testing import MiniRelay

pytestmark = pytest.mark.asyncio

BACKEND = get_backend("builtin")
CONNECT_TIMEOUT = 10.0
REPLY_TIMEOUT = 10.0


def make_config(local_url, rendezvous_url, secret_hex, allowed, **limit_overrides) -> Config:
    limits = LimitsSection(
        max_payload_bytes=4096,
        flush_delay_ms=10,
        max_sessions=4,
        max_subscriptions_per_client=3,
        session_idle_timeout_seconds=0,
        max_messages_per_event=16,
        inbound_events_per_minute=0,
    )
    for key, value in limit_overrides.items():
        setattr(limits, key, value)
    config = Config(
        bridge=BridgeSection(secret_key=secret_hex),
        local_relay=LocalRelaySection(url=local_url, fetch_nip11=False),
        rendezvous=RendezvousSection(
            relays=[rendezvous_url],
            auth=True,
            publish_announcements=True,
            announce_interval_seconds=3600,
        ),
        access=AccessSection(allowed_pubkeys=list(allowed)),
        limits=limits,
        crypto=CryptoSection(backend="builtin"),
        nip11=Nip11Section(enabled=False, overrides={"name": "test hidden relay"}),
    )
    config.secret_key_hex = secret_hex
    config.allowed_pubkeys_hex = list(allowed)
    return config


class Harness:
    def __init__(self, local, rendezvous, bridge):
        self.local = local
        self.rendezvous = rendezvous
        self.bridge = bridge

    def client(self, secret_hex=None) -> HiddenRelayClient:
        return HiddenRelayClient(
            secret_hex or secrets.token_bytes(32).hex(),
            self.bridge.identity.public_hex,
            self.rendezvous.url,
            backend=BACKEND,
        )


async def _make_harness(allowed_secrets, seed_kinds=(1,), **limit_overrides):
    local = await MiniRelay(name="local").start()
    rendezvous = await MiniRelay(name="rendezvous").start()
    allowed = [BACKEND.public_key_hex(s) for s in allowed_secrets]
    bridge_secret = secrets.token_bytes(32).hex()
    config = make_config(
        local.url, rendezvous.url, bridge_secret, allowed, **limit_overrides
    )
    author = Identity.generate(BACKEND)
    for kind in seed_kinds:
        local.seed([build_event(author, kind, content=f"note of kind {kind}")])
    bridge = Bridge(config)
    await bridge.start()
    assert await bridge.rendezvous.wait_connected(CONNECT_TIMEOUT)
    return Harness(local, rendezvous, bridge)


@pytest.fixture
async def harness():
    created = await _make_harness([])
    yield created
    await created.bridge.stop()
    await created.local.stop()
    await created.rendezvous.stop()


async def _connected_client(harness, secret_hex=None):
    client = harness.client(secret_hex)
    harness.bridge.config.allowed_pubkeys_hex.append(client.pubkey)
    assert await client.connect(CONNECT_TIMEOUT)
    return client


async def test_req_reaches_the_local_relay_and_events_come_back(harness):
    client = await _connected_client(harness)
    try:
        events = await client.request([{"kinds": [1]}], "sub1", timeout=REPLY_TIMEOUT)
        assert len(events) == 1
        assert events[0]["content"] == "note of kind 1"
    finally:
        await client.close()


async def test_publishing_through_the_bridge_stores_on_the_local_relay(harness):
    client = await _connected_client(harness)
    try:
        author = Identity.generate(BACKEND)
        note = build_event(author, 1, content="published through the bridge").to_dict()
        ok = await client.publish(note, timeout=REPLY_TIMEOUT)
        assert ok is not None and ok[2] is True
        assert any(e.content == "published through the bridge" for e in harness.local.events)
    finally:
        await client.close()


async def test_two_clients_may_share_a_subscription_id(harness):
    """The requirement that subscription ids be unique per pubkey, exercised."""
    alice = await _connected_client(harness)
    bob = await _connected_client(harness)
    try:
        alice_events, bob_events = await asyncio.gather(
            alice.request([{"kinds": [1]}], "sub1", timeout=REPLY_TIMEOUT),
            bob.request([{"kinds": [1]}], "sub1", timeout=REPLY_TIMEOUT),
        )
        assert len(alice_events) == 1
        assert len(bob_events) == 1

        upstream_ids = [
            sub_id
            for sub_id, _filters in harness.local.received_subscription_ids
            if sub_id.endswith("sub1")
        ]
        assert len(upstream_ids) == 2
        assert len(set(upstream_ids)) == 2, "ids must differ per pubkey"
        assert upstream_ids[0].startswith(alice.pubkey[:16]) or upstream_ids[
            0
        ].startswith(bob.pubkey[:16])
    finally:
        await alice.close()
        await bob.close()


async def test_live_subscription_delivers_new_events(harness):
    client = await _connected_client(harness)
    try:
        await client.send([["REQ", "live", {"kinds": [7]}]])
        # Drain the EOSE for the initial (empty) result set.
        deadline = asyncio.get_running_loop().time() + REPLY_TIMEOUT
        while asyncio.get_running_loop().time() < deadline:
            message = await asyncio.wait_for(client.inbox.get(), REPLY_TIMEOUT)
            if message[0] == "EOSE" and message[1] == "live":
                break

        author = Identity.generate(BACKEND)
        harness.local.seed([])  # no-op, keeps the intent explicit
        publisher = await _connected_client(harness)
        try:
            await publisher.publish(
                build_event(author, 7, content="a reaction").to_dict(), timeout=REPLY_TIMEOUT
            )
            message = await asyncio.wait_for(client.inbox.get(), REPLY_TIMEOUT)
            assert message[0] == "EVENT"
            assert message[1] == "live"
            assert message[2]["content"] == "a reaction"
        finally:
            await publisher.close()
    finally:
        await client.close()


async def test_close_stops_delivery(harness):
    client = await _connected_client(harness)
    try:
        await client.request([{"kinds": [1]}], "sub1", timeout=REPLY_TIMEOUT)
        session = await harness.bridge.sessions.get(client.pubkey)
        await asyncio.sleep(0.2)
        assert len(session.subscriptions) == 0, "CLOSE should have cleared it"
    finally:
        await client.close()


async def test_events_from_unknown_pubkeys_are_ignored(harness):
    stranger = harness.client()  # deliberately not whitelisted
    assert await stranger.connect(CONNECT_TIMEOUT)
    try:
        await stranger.send([["REQ", "sub1", {"kinds": [1]}]])
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(stranger.inbox.get(), 2.0)
        assert harness.bridge.rendezvous.events_accepted == 0
    finally:
        await stranger.close()


async def test_a_forged_signature_is_rejected(harness):
    client = await _connected_client(harness)
    try:
        event = build_event(
            client.identity, 27901, content="x", tags=[["p", harness.bridge.identity.public_hex]]
        ).to_dict()
        event["sig"] = "00" * 64
        await client._connection.send(["EVENT", event])  # noqa: SLF001
        await asyncio.sleep(0.5)
        assert harness.bridge.rendezvous.events_accepted == 0
    finally:
        await client.close()


async def test_large_result_sets_are_split_across_events(harness):
    client = await _connected_client(harness)
    try:
        author = Identity.generate(BACKEND)
        harness.local.seed(
            [build_event(author, 30, content="y" * 1000) for _ in range(12)]
        )
        before = harness.bridge.rendezvous.events_published
        events = await client.request([{"kinds": [30]}], "big", timeout=REPLY_TIMEOUT)
        assert len(events) == 12
        published = harness.bridge.rendezvous.events_published - before
        assert published > 1, "a 12 KB result set must not fit in one 4 KB payload"
    finally:
        await client.close()


async def test_subscription_budget_reports_closed_to_the_client(harness):
    client = await _connected_client(harness)
    try:
        for index in range(3):
            await client.send([["REQ", f"s{index}", {"kinds": [9999]}]])
        await asyncio.sleep(0.5)
        await client.send([["REQ", "over-budget", {"kinds": [9999]}]])
        deadline = asyncio.get_running_loop().time() + REPLY_TIMEOUT
        while asyncio.get_running_loop().time() < deadline:
            message = await asyncio.wait_for(client.inbox.get(), REPLY_TIMEOUT)
            if message[0] == "CLOSED" and message[1] == "over-budget":
                assert "limit" in message[2]
                return
        pytest.fail("expected a CLOSED for the over-budget subscription")
    finally:
        await client.close()


async def test_announcement_events_are_published(harness):
    await asyncio.sleep(0.5)
    kinds = {event.kind for event in harness.rendezvous.events}
    assert KIND_RENDEZVOUS_LIST in kinds
    assert KIND_RELAY_INFORMATION in kinds
    announcement = next(
        e for e in harness.rendezvous.events if e.kind == KIND_RENDEZVOUS_LIST
    )
    assert announcement.tag_values("r") == [harness.rendezvous.url]
    assert announcement.verify(BACKEND)


async def test_discovery_reads_the_rendezvous_list(harness):
    client = await _connected_client(harness)
    try:
        relays = await client.discover(timeout=REPLY_TIMEOUT)
        assert relays == [harness.rendezvous.url]
    finally:
        await client.close()


async def test_subscriptions_are_replayed_after_a_local_relay_restart(harness):
    client = await _connected_client(harness)
    try:
        await client.send([["REQ", "durable", {"kinds": [7]}]])
        await asyncio.sleep(0.5)
        session = await harness.bridge.sessions.get(client.pubkey)
        assert len(session.subscriptions) == 1

        port = harness.local.port
        await harness.local.stop()
        await asyncio.sleep(0.5)
        harness.local = await MiniRelay(port=port, name="local-restarted").start()

        # Reconnect backoff is randomised; give it room.
        for _ in range(60):
            await asyncio.sleep(0.5)
            if any(
                sub_id.endswith("durable")
                for sub_id, _ in harness.local.received_subscription_ids
            ):
                break
        else:
            pytest.fail("subscription was not replayed after the relay came back")

        author = Identity.generate(BACKEND)
        harness.local.seed([build_event(author, 7, content="after restart")])
        publisher = await _connected_client(harness)
        try:
            await publisher.publish(
                build_event(author, 7, content="live after restart").to_dict(),
                timeout=REPLY_TIMEOUT,
            )
            deadline = asyncio.get_running_loop().time() + REPLY_TIMEOUT
            while asyncio.get_running_loop().time() < deadline:
                message = await asyncio.wait_for(client.inbox.get(), REPLY_TIMEOUT)
                if message[0] == "EVENT" and message[1] == "durable":
                    assert message[2]["content"] == "live after restart"
                    return
            pytest.fail("no event delivered on the replayed subscription")
        finally:
            await publisher.close()
    finally:
        await client.close()


async def test_nip42_auth_is_answered_on_both_sides():
    """A rendez-vous relay that demands AUTH still works end to end."""
    local = await MiniRelay(name="local", require_auth=True).start()
    rendezvous = await MiniRelay(name="rendezvous", require_auth=True).start()
    client_secret = secrets.token_bytes(32).hex()
    bridge_secret = secrets.token_bytes(32).hex()
    config = make_config(
        local.url,
        rendezvous.url,
        bridge_secret,
        [BACKEND.public_key_hex(client_secret)],
    )
    config.local_relay.auth = True
    author = Identity.generate(BACKEND)
    local.seed([build_event(author, 1, content="behind auth")])
    bridge = Bridge(config)
    await bridge.start()
    client = HiddenRelayClient(
        client_secret, bridge.identity.public_hex, rendezvous.url, backend=BACKEND
    )
    try:
        assert await client.connect(CONNECT_TIMEOUT)
        events = await client.request([{"kinds": [1]}], "sub1", timeout=REPLY_TIMEOUT)
        assert [e["content"] for e in events] == ["behind auth"]
    finally:
        await client.close()
        await bridge.stop()
        await local.stop()
        await rendezvous.stop()
