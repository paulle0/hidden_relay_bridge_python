import textwrap

import pytest

from hidden_relay_bridge.config import ConfigError, load_config, websocket_url_to_http

MINIMAL = """
[bridge]
secret_key = "{secret}"

[local_relay]
url = "ws://192.168.11.26:7000"

[rendezvous]
relays = ["wss://relay.napttr.eu"]

[access]
allowed_pubkeys = ["npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"]
"""

NSEC = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"
HEX_SEC = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa"
HEX_PUB = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"


def write(tmp_path, text, name="config.toml"):
    path = tmp_path / name
    path.write_text(textwrap.dedent(text), encoding="utf-8")
    return path


def test_minimal_config_loads(tmp_path):
    config = load_config(write(tmp_path, MINIMAL.format(secret=NSEC)))
    assert config.secret_key_hex == HEX_SEC
    assert config.allowed_pubkeys_hex == [HEX_PUB]
    assert config.local_relay.url == "ws://192.168.11.26:7000"
    assert config.limits.max_payload_bytes == 32768  # default


def test_shipped_example_config_is_valid(tmp_path):
    from pathlib import Path

    example = Path(__file__).resolve().parent.parent / "config.example.toml"
    text = example.read_text(encoding="utf-8").replace(
        "nsec1replace_me_with_the_output_of_keygen", NSEC
    )
    # The example ships with an empty whitelist on purpose.
    text = text.replace("allow_all = false", "allow_all = true")
    config = load_config(write(tmp_path, text, "example.toml"))
    assert config.rendezvous.relays == ["wss://relay.napttr.eu"]
    assert config.nip11.overrides["name"] == "hidden home relay"


def test_secret_key_file_is_read(tmp_path):
    key_file = tmp_path / "bridge.nsec"
    key_file.write_text(NSEC + "\n", encoding="utf-8")
    text = MINIMAL.format(secret=NSEC).replace(
        f'secret_key = "{NSEC}"', f'secret_key_file = "{key_file}"'
    )
    assert load_config(write(tmp_path, text)).secret_key_hex == HEX_SEC


def test_secret_key_from_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("HIDDEN_RELAY_BRIDGE_SECRET_KEY", HEX_SEC)
    text = MINIMAL.format(secret=NSEC).replace(f'secret_key = "{NSEC}"\n', "")
    assert load_config(write(tmp_path, text)).secret_key_hex == HEX_SEC


def test_missing_secret_key_is_an_error(tmp_path, monkeypatch):
    monkeypatch.delenv("HIDDEN_RELAY_BRIDGE_SECRET_KEY", raising=False)
    text = MINIMAL.format(secret=NSEC).replace(f'secret_key = "{NSEC}"\n', "")
    with pytest.raises(ConfigError, match="no secret key"):
        load_config(write(tmp_path, text))


def test_empty_whitelist_without_allow_all_is_an_error(tmp_path):
    text = MINIMAL.format(secret=NSEC).replace(
        '["npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"]', "[]"
    )
    with pytest.raises(ConfigError, match="allow_all"):
        load_config(write(tmp_path, text))


def test_http_url_is_derived_for_nip11(tmp_path):
    config = load_config(write(tmp_path, MINIMAL.format(secret=NSEC)))
    assert config.nip11_http_url == "http://192.168.11.26:7000"
    assert websocket_url_to_http("wss://relay.example.com/x") == "https://relay.example.com/x"


def test_non_websocket_local_url_is_rejected(tmp_path):
    text = MINIMAL.format(secret=NSEC).replace(
        'url = "ws://192.168.11.26:7000"', 'url = "http://192.168.11.26:7000"'
    )
    with pytest.raises(ConfigError, match="ws://"):
        load_config(write(tmp_path, text))


def test_empty_rendezvous_list_is_rejected(tmp_path):
    text = MINIMAL.format(secret=NSEC).replace(
        'relays = ["wss://relay.napttr.eu"]', "relays = []"
    )
    with pytest.raises(ConfigError, match="at least one relay"):
        load_config(write(tmp_path, text))


def test_non_websocket_rendezvous_url_is_rejected(tmp_path):
    text = MINIMAL.format(secret=NSEC).replace(
        'relays = ["wss://relay.napttr.eu"]', 'relays = ["https://relay.napttr.eu"]'
    )
    with pytest.raises(ConfigError, match="ws://"):
        load_config(write(tmp_path, text))


def test_unknown_keys_are_reported(tmp_path):
    text = MINIMAL.format(secret=NSEC) + "\n[bridge]\n"
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, text))

    text = MINIMAL.format(secret=NSEC).replace("[access]", "[access]\ntypo = 1")
    with pytest.raises(ConfigError, match="unknown key"):
        load_config(write(tmp_path, text))


def test_unknown_crypto_backend_is_rejected(tmp_path):
    text = MINIMAL.format(secret=NSEC) + '\n[crypto]\nbackend = "wat"\n'
    with pytest.raises(ConfigError, match="backend"):
        load_config(write(tmp_path, text))


def test_bad_pubkey_in_whitelist_is_reported(tmp_path):
    text = MINIMAL.format(secret=NSEC).replace(
        "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6", "not-a-key"
    )
    with pytest.raises(ConfigError, match="allowed_pubkeys"):
        load_config(write(tmp_path, text))
