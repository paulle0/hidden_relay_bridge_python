# hidden_relay_bridge_python

A Python bridge that makes a nostr relay on your LAN reachable from the open
internet, without opening a port, by relaying the protocol over encrypted
events on a public relay.

It implements the ["Virtual/Hidden Relay" NIP](https://github.com/paulle0/hidden_relay_nip):
kinds **10112** (rendez-vous list), **10113** (relay information) and **27901**
(the encrypted communication event), plus the `nrv1...` bech32 address format.

```
                 public internet                    your LAN
                 ───────────────                    ────────
   client  ──► wss://relay.napttr.eu ──►  bridge  ──►  ws://192.168.11.26:7000
          kind 27901, NIP-44 encrypted     (Pi)         plain NIP-01
   client  ◄── wss://relay.napttr.eu ◄──          ◄──
```

The bridge holds a nostr identity of its own. Clients address it by npub or by
its `nrv1...` address, wrap ordinary NIP-01 messages (`REQ`, `EVENT`, `CLOSE`,
`COUNT`, `AUTH`) in the encrypted content of a kind 27901 event, and get the
relay's answers back the same way. Only whitelisted pubkeys are served.

## Contents

- [Quick start](#quick-start)
- [Running it on a Pi](#running-it-on-a-pi)
- [How it works](#how-it-works)
- [Subscription ids are unique per pubkey](#subscription-ids-are-unique-per-pubkey)
- [Configuration](#configuration)
- [The client tool](#the-client-tool)
- [Security notes](#security-notes)
- [Development](#development)

## Quick start

Requires Python 3.11 or newer.

```bash
git clone https://github.com/paulle0/hidden_relay_bridge_python
cd hidden_relay_bridge_python
python3 -m venv venv && ./venv/bin/pip install -e .

# 1. Create the identity of your hidden relay
./venv/bin/hidden-relay-bridge keygen --relay wss://relay.napttr.eu

# 2. Fill in the config
cp config.example.toml config.toml
$EDITOR config.toml      # secret_key, local_relay.url, rendezvous.relays, access.allowed_pubkeys

# 3. Check that both relays answer, then run it
./venv/bin/hidden-relay-bridge check
./venv/bin/hidden-relay-bridge run
```

`keygen` prints the `nrv1...` address. That single string carries both the
bridge pubkey and its rendez-vous relays, so it is the only thing a client
needs.

### Try it without touching your real relay

The package ships a throwaway in-memory relay, so you can see the whole path
work on one machine:

```bash
# two terminals
python -m hidden_relay_bridge.testing --port 7801     # stands in for the LAN relay
python -m hidden_relay_bridge.testing --port 7802     # stands in for the public relay
```

Point `local_relay.url` at `ws://127.0.0.1:7801` and `rendezvous.relays` at
`ws://127.0.0.1:7802`, whitelist a client npub, start the bridge, and query it
with the client tool below.

## Running it on a Pi

`deploy/install.sh` sets the bridge up as a systemd service. Run it from a
checkout on the Pi:

```bash
sudo ./deploy/install.sh
sudo -u hiddenrelay /opt/hidden-relay-bridge/venv/bin/hidden-relay-bridge \
    keygen --relay wss://relay.napttr.eu
sudo $EDITOR /etc/hidden-relay-bridge/config.toml
sudo systemctl start hidden-relay-bridge
journalctl -u hidden-relay-bridge -f
```

The installer creates a `hiddenrelay` system user, installs into
`/opt/hidden-relay-bridge`, puts the config in `/etc/hidden-relay-bridge`, and
enables the unit at boot. Re-running it upgrades the code and leaves the config
alone. The unit restarts on failure and the bridge reconnects to both relays on
its own with exponential backoff, so a flaky uplink or a relay restart needs no
attention.

For a secret key that never sits in the config file, use
`[bridge].secret_key_file` (mode `0600`) or the
`HIDDEN_RELAY_BRIDGE_SECRET_KEY` environment variable.

## How it works

**Announcing.** On startup the bridge publishes two replaceable events to every
rendez-vous relay: kind **10112** listing its rendez-vous relays as `r` tags,
and kind **10113** carrying a NIP-11 document. The NIP-11 document is fetched
from your local relay (`local_relay.fetch_nip11`) and merged with the `[nip11]`
overrides, so the hidden relay advertises what the real relay actually
supports. Both are republished every `announce_interval_seconds`.

**Listening.** The bridge subscribes on each rendez-vous relay for kind 27901
events tagged `["p", <bridge pubkey>]`. When a whitelist is configured it is
also sent as the `authors` filter, so the relay does the filtering and the Pi
never sees the traffic.

**Accepting.** An inbound event has to clear every one of these before anything
is decrypted or forwarded: right kind, `p` tag addressing this bridge,
whitelisted author, `created_at` inside the replay window, a supported
`encryption` tag, a valid id and signature, an unseen event id, and the
per-pubkey rate limit.

**Forwarding.** The content is decrypted with NIP-44 v2 and parsed as an array
of NIP-01 messages. Each client pubkey gets its own session with its own
websocket to the local relay, so one client's reconnect, subscription flood or
slow drain cannot disturb another's.

**Answering.** Messages coming back from the local relay are collected for a
few milliseconds (`flush_delay_ms`), packed into batches under
`max_payload_bytes`, encrypted to the client and published as kind 27901 events.
Batching matters: an `EVENT` plus its `EOSE` usually travel in one event rather
than two.

**Reconnecting.** If the local relay goes away, the session's subscription
table is the single source of truth. On every connect the bridge discards any
queued subscription traffic and re-issues the table, so a reconnect can neither
duplicate a subscription nor lose one. NIP-42 `AUTH` challenges from either
side are answered with the bridge identity, or passed through to the client if
you would rather it authenticate end to end (`local_relay.auth = false`).

## Subscription ids are unique per pubkey

Several clients reach one local relay through one bridge, and nothing stops two
of them from calling their subscription `sub1`. Subscription ids therefore have
to be unique per client pubkey, not per websocket connection, so the bridge
rewrites every id on the way in and restores the client's own id on the way
out:

```
client A: REQ "sub1"   ──►   local relay sees REQ "3b5919bbd054b7a7.r.sub1"
client B: REQ "sub1"   ──►   local relay sees REQ "b7d0777499b93d97.r.sub1"
```

The prefix is the first 16 hex characters of the client pubkey. NIP-01 caps
subscription ids at 64 characters, so ids that would not fit are hashed
instead:

```
<pubkey[:16]>.r.<client id>            ids up to 45 characters
<pubkey[:16]>.h.<sha256(id)[:32]>      anything longer
```

The `.r.` / `.h.` marker means the two forms can never collide, so a client
cannot craft an id that lands on another of its subscriptions. Responses are
mapped back before they reach the client, which never sees the rewritten form.
Your relay's logs stay readable, and `CLOSED`/`EOSE`/`COUNT` still address the
right subscription.

## Configuration

Everything lives in one TOML file; see `config.example.toml` for the annotated
version. The settings that matter most:

| Key | Meaning |
| --- | --- |
| `bridge.secret_key` | The hidden relay's identity, as `nsec` or hex. Also `secret_key_file` or `$HIDDEN_RELAY_BRIDGE_SECRET_KEY`. |
| `local_relay.url` | The relay on your LAN, e.g. `ws://192.168.11.26:7000`. |
| `rendezvous.relays` | Public relays clients drop requests on, e.g. `wss://relay.napttr.eu`. Several are allowed. |
| `access.allowed_pubkeys` | Who may use the bridge, as npub or hex. `allow_all = true` serves everyone. |
| `limits.max_payload_bytes` | Plaintext size of one 27901 payload. The encrypted content ends up roughly 4/3 of it, so leave headroom under your relay's event size limit. Hard ceiling 65535. |
| `limits.flush_delay_ms` | How long to wait for more messages before sending a batch. `0` disables batching. |
| `limits.max_sessions` | Concurrent client sessions. The idlest is evicted when the limit is reached. |
| `crypto.backend` | `auto`, `builtin` or `nostr-sdk`. See below. |

Changing the whitelist means restarting the bridge: it is also used as the
relay-side `authors` filter.

### Crypto backends

Signing and NIP-44 can come from either of two implementations, and the choice
is not observable on the wire. Both are tested against the official NIP-44 v2
vectors, and cross-tested against each other.

- `builtin` uses `coincurve` and `cryptography`. Lightest to install, which is
  what you usually want on a Pi.
- `nostr-sdk` uses the [rust-nostr](https://github.com/rust-nostr/nostr)
  bindings. Install with `pip install -e '.[sdk]'`.
- `auto` (the default) prefers `nostr-sdk` when it imports, else `builtin`.

## The client tool

`tools/hidden_relay_client.py` speaks the client half of the NIP, which is
handy for checking a deployment:

```bash
# Read notes through the bridge. --nrv supplies both the pubkey and the relay.
python tools/hidden_relay_client.py \
    --nrv nrv1qqs8axvxsk4... --nsec nsec1yourclientkey... \
    req '{"kinds":[1],"limit":5}'

# Publish a signed event through the bridge
python tools/hidden_relay_client.py --nrv nrv1... --nsec nsec1... publish '<event json>'

# Send arbitrary relay messages and watch what comes back
python tools/hidden_relay_client.py --nrv nrv1... --nsec nsec1... \
    raw '[["REQ","s1",{"limit":1}],["COUNT","c1",{"kinds":[1]}]]'

# Read a bridge's kind 10112 event to learn its rendez-vous relays
python tools/hidden_relay_client.py --relay wss://relay.napttr.eu \
    --bridge npub1thebridge... --nsec nsec1... discover
```

Global options go before the subcommand. The same thing is available as a
library:

```python
from hidden_relay_bridge.client import HiddenRelayClient

async with HiddenRelayClient(my_nsec, bridge_npub, "wss://relay.napttr.eu") as client:
    events = await client.request([{"kinds": [1], "limit": 20}])
```

## Security notes

- **The rendez-vous relay sees metadata, not content.** Payloads are NIP-44 v2
  encrypted between the client and the bridge. The relay still learns that two
  pubkeys are talking, how often, and roughly how much.
- **The whitelist is the access control.** `allow_all = true` lets anyone who
  knows the bridge pubkey read and write your local relay. Use it only while
  testing.
- **Replays are bounded** by `created_at` windows and an event id cache, not by
  a nonce handshake. Keep the clocks roughly right on both ends.
- **Kind 27901 is ephemeral.** Relays are not supposed to store it, but do not
  rely on that: assume the ciphertext could be retained.
- **The bridge is the local relay's only client.** Everything a whitelisted
  pubkey sends is executed against your relay under the bridge's connection, so
  whitelist deliberately.

## Development

```bash
./venv/bin/pip install -e '.[dev,sdk]'
./venv/bin/python -m pytest
```

The suite covers the official NIP-44 v2 vectors on every installed backend,
NIP-19 (including the `nrv` TLV), event ids and signatures against a fixture
generated with rust-nostr, the subscription rewriting, the batching, config
validation, and a set of end-to-end tests that run the real bridge between two
live websocket relays and cover publishing, live subscriptions, the whitelist,
forged signatures, payload splitting, NIP-42 auth on both sides, and recovery
after the local relay restarts.

### Layout

```
src/hidden_relay_bridge/
├── cli.py            run / keygen / show / check / address
├── config.py         TOML loading and validation
├── bridge.py         wires the two sides together
├── rendezvous.py     public side: 27901 in and out, 10112/10113 announcements
├── session.py        one session per client pubkey, local relay connection
├── subscriptions.py  per-pubkey subscription id rewriting
├── framing.py        packing relay messages into 27901 payloads
├── protocol.py       kinds, tags, payload validation
├── client.py         reference client
├── testing.py        throwaway in-memory relay
└── nostr/            events, keys, NIP-19, NIP-44, websocket relay client
```

## License

MIT, see `LICENSE`.
