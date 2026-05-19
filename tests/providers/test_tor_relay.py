import pytest
from proxy_vault.providers.tor_relay import TorRelayProvider


def test_tor_name():
    p = TorRelayProvider()
    assert p.name == "tor"


def test_tor_max_hops():
    p = TorRelayProvider()
    assert p.max_hops == 3


@pytest.mark.asyncio
async def test_tor_fetch_returns_entry():
    p = TorRelayProvider()
    proxies = await p.fetch_proxies()
    assert len(proxies) == 1
    assert proxies[0].host == "127.0.0.1"
    assert proxies[0].port == 9050


@pytest.mark.asyncio
async def test_tor_availability_check():
    p = TorRelayProvider()
    result = await p.is_available()
    assert isinstance(result, bool)
