"""Configuration loading and validation.

The config is a TOML file; every section has defaults so a minimal file only
needs the secret key, the local relay and the rendez-vous relays.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse

from .nostr.crypto import KNOWN_BACKENDS
from .nostr.nip19 import parse_pubkey, parse_secret_key

DEFAULT_CONFIG_PATHS = (
    Path("config.toml"),
    Path("/etc/hidden-relay-bridge/config.toml"),
)

ENV_SECRET_KEY = "HIDDEN_RELAY_BRIDGE_SECRET_KEY"


class ConfigError(ValueError):
    """Raised with a human readable reason when a config file is unusable."""


@dataclass
class BridgeSection:
    secret_key: str = ""
    secret_key_file: str = ""
    name: str = "hidden-relay-bridge"


@dataclass
class LocalRelaySection:
    url: str = "ws://127.0.0.1:7000"
    connect_timeout_seconds: float = 10.0
    auth: bool = False
    fetch_nip11: bool = True
    nip11_url: str = ""
    max_message_bytes: int = 2 * 1024 * 1024


@dataclass
class RendezvousSection:
    relays: List[str] = field(default_factory=list)
    auth: bool = True
    publish_announcements: bool = True
    announce_interval_seconds: int = 3600
    # `since` slack when subscribing, to tolerate clock skew between peers.
    subscribe_since_slack_seconds: int = 60
    max_event_age_seconds: int = 120
    max_event_future_seconds: int = 120


@dataclass
class AccessSection:
    allowed_pubkeys: List[str] = field(default_factory=list)
    allow_all: bool = False


@dataclass
class LimitsSection:
    max_payload_bytes: int = 32768
    flush_delay_ms: int = 40
    max_sessions: int = 32
    max_subscriptions_per_client: int = 20
    session_idle_timeout_seconds: int = 600
    max_messages_per_event: int = 64
    inbound_events_per_minute: int = 600


@dataclass
class CryptoSection:
    backend: str = "auto"
    encryption: str = "nip44_v2"


@dataclass
class LoggingSection:
    level: str = "INFO"
    file: str = ""


@dataclass
class Nip11Section:
    """Overrides merged over whatever the local relay reports."""

    enabled: bool = True
    overrides: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Config:
    bridge: BridgeSection = field(default_factory=BridgeSection)
    local_relay: LocalRelaySection = field(default_factory=LocalRelaySection)
    rendezvous: RendezvousSection = field(default_factory=RendezvousSection)
    access: AccessSection = field(default_factory=AccessSection)
    limits: LimitsSection = field(default_factory=LimitsSection)
    crypto: CryptoSection = field(default_factory=CryptoSection)
    logging: LoggingSection = field(default_factory=LoggingSection)
    nip11: Nip11Section = field(default_factory=Nip11Section)
    source_path: Optional[Path] = None

    # Normalised at load time.
    secret_key_hex: str = ""
    allowed_pubkeys_hex: List[str] = field(default_factory=list)

    @property
    def nip11_http_url(self) -> str:
        if self.local_relay.nip11_url:
            return self.local_relay.nip11_url
        return websocket_url_to_http(self.local_relay.url)


def websocket_url_to_http(url: str) -> str:
    parsed = urlparse(url)
    scheme = {"ws": "http", "wss": "https"}.get(parsed.scheme, parsed.scheme)
    return urlunparse(parsed._replace(scheme=scheme))


def _section(raw: Dict[str, Any], name: str) -> Dict[str, Any]:
    value = raw.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"section [{name}] must be a table")
    return value


def _build(cls, data: Dict[str, Any], section_name: str):
    known = {f for f in cls.__dataclass_fields__}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(
            f"unknown key(s) in [{section_name}]: {', '.join(sorted(unknown))}"
        )
    return cls(**data)


def _validate_relay_url(url: str, label: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("ws", "wss") or not parsed.netloc:
        raise ConfigError(f"{label} must be a ws:// or wss:// URL, got '{url}'")
    return url


def load_config(path: Optional[Path] = None) -> Config:
    """Read, validate and normalise a config file."""
    if path is None:
        for candidate in DEFAULT_CONFIG_PATHS:
            if candidate.exists():
                path = candidate
                break
        else:
            raise ConfigError(
                "no config file found, looked for: "
                + ", ".join(str(p) for p in DEFAULT_CONFIG_PATHS)
            )
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc

    unknown_sections = set(raw) - set(Config.__dataclass_fields__)
    if unknown_sections:
        raise ConfigError(f"unknown section(s): {', '.join(sorted(unknown_sections))}")

    nip11_raw = _section(raw, "nip11")
    config = Config(
        bridge=_build(BridgeSection, _section(raw, "bridge"), "bridge"),
        local_relay=_build(LocalRelaySection, _section(raw, "local_relay"), "local_relay"),
        rendezvous=_build(RendezvousSection, _section(raw, "rendezvous"), "rendezvous"),
        access=_build(AccessSection, _section(raw, "access"), "access"),
        limits=_build(LimitsSection, _section(raw, "limits"), "limits"),
        crypto=_build(CryptoSection, _section(raw, "crypto"), "crypto"),
        logging=_build(LoggingSection, _section(raw, "logging"), "logging"),
        nip11=Nip11Section(
            enabled=bool(nip11_raw.get("enabled", True)),
            overrides={k: v for k, v in nip11_raw.items() if k != "enabled"},
        ),
        source_path=path,
    )
    _finalise(config)
    return config


def _finalise(config: Config) -> None:
    config.secret_key_hex = _resolve_secret_key(config)

    _validate_relay_url(config.local_relay.url, "[local_relay].url")
    if not config.rendezvous.relays:
        raise ConfigError("[rendezvous].relays must list at least one relay")
    for url in config.rendezvous.relays:
        _validate_relay_url(url, "[rendezvous].relays entry")

    if config.crypto.backend not in KNOWN_BACKENDS:
        raise ConfigError(
            f"[crypto].backend must be one of {', '.join(KNOWN_BACKENDS)}"
        )
    if config.crypto.encryption != "nip44_v2":
        raise ConfigError("[crypto].encryption currently only supports 'nip44_v2'")

    hex_keys = []
    for entry in config.access.allowed_pubkeys:
        try:
            hex_keys.append(parse_pubkey(entry))
        except Exception as exc:  # noqa: BLE001
            raise ConfigError(f"[access].allowed_pubkeys entry '{entry}': {exc}") from exc
    config.allowed_pubkeys_hex = hex_keys
    if not hex_keys and not config.access.allow_all:
        raise ConfigError(
            "[access] has no allowed_pubkeys; add pubkeys or set allow_all = true"
        )

    limits = config.limits
    if limits.max_payload_bytes < 1024:
        raise ConfigError("[limits].max_payload_bytes must be at least 1024")
    if limits.flush_delay_ms < 0:
        raise ConfigError("[limits].flush_delay_ms must not be negative")
    for name in (
        "max_sessions",
        "max_subscriptions_per_client",
        "max_messages_per_event",
    ):
        if getattr(limits, name) < 1:
            raise ConfigError(f"[limits].{name} must be at least 1")


def _resolve_secret_key(config: Config) -> str:
    sources = 0
    value = ""
    env_value = os.environ.get(ENV_SECRET_KEY, "").strip()
    if env_value:
        sources += 1
        value = env_value
    if config.bridge.secret_key:
        sources += 1
        value = config.bridge.secret_key
    if config.bridge.secret_key_file:
        sources += 1
        key_path = Path(config.bridge.secret_key_file).expanduser()
        if not key_path.exists():
            raise ConfigError(f"[bridge].secret_key_file not found: {key_path}")
        value = key_path.read_text(encoding="utf-8").strip()
    if sources == 0:
        raise ConfigError(
            "no secret key: set [bridge].secret_key, [bridge].secret_key_file "
            f"or the {ENV_SECRET_KEY} environment variable"
        )
    # Precedence when several are set: file, then inline, then environment.
    try:
        return parse_secret_key(value)
    except Exception as exc:  # noqa: BLE001
        raise ConfigError(f"invalid bridge secret key: {exc}") from exc
