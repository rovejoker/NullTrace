import pytest
from proxy_vault.providers.base import BaseProvider
from proxy_vault.models import ProxyEntry, ProxyType, ProxyStatus


class MockProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "mock"

    async def fetch_proxies(self) -> list[ProxyEntry]:
        return [
            ProxyEntry(host="1.2.3.4", port=8080, types=[ProxyType.HTTP], status=ProxyStatus.ACTIVE)
        ]


@pytest.mark.asyncio
async def test_provider_name():
    p = MockProvider()
    assert p.name == "mock"


@pytest.mark.asyncio
async def test_fetch_proxies():
    p = MockProvider()
    proxies = await p.fetch_proxies()
    assert len(proxies) == 1
    assert proxies[0].host == "1.2.3.4"


@pytest.mark.asyncio
async def test_get_proxy_returns_first():
    p = MockProvider()
    proxy = await p.get_proxy()
    assert proxy is not None
    assert proxy.host == "1.2.3.4"


@pytest.mark.asyncio
async def test_get_proxy_empty():
    class EmptyProvider(BaseProvider):
        @property
        def name(self) -> str:
            return "empty"
        async def fetch_proxies(self) -> list[ProxyEntry]:
            return []

    p = EmptyProvider()
    proxy = await p.get_proxy()
    assert proxy is None


@pytest.mark.asyncio
async def test_default_max_hops():
    p = MockProvider()
    assert p.max_hops == 1


@pytest.mark.asyncio
async def test_validate_unreachable():
    p = MockProvider()
    bad = ProxyEntry(host="10.255.255.1", port=9999, types=[ProxyType.HTTP])
    result = await p.validate(bad)
    assert result is False
