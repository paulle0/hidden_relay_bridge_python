"""A bridge that exposes a local nostr relay as a hidden relay.

Implements the "Virtual/Hidden Relay" NIP: clients send ordinary nostr relay
messages inside encrypted kind 27901 events on a public rendez-vous relay, and
this bridge replays them against a relay that is only reachable on the local
network.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
