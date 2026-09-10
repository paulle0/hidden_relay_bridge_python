import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from hidden_relay_bridge.nostr.crypto import available_backends, get_backend  # noqa: E402


@pytest.fixture(scope="session")
def backend():
    return get_backend("builtin")


@pytest.fixture(params=available_backends())
def any_backend(request):
    return get_backend(request.param)
