import pytest
from proxy_vault.providers.collectors.http_collectors import (
    ProxyScrapeCollector,
    FreeProxyListCollector,
)


def test_proxyscrape_name():
    c = ProxyScrapeCollector()
    assert c.name == "proxyscrape"


def test_proxyscrape_has_interval():
    c = ProxyScrapeCollector()
    assert c.interval > 0


def test_free_proxy_list_name():
    c = FreeProxyListCollector()
    assert c.name == "free-proxy-list"


@pytest.mark.asyncio
async def test_proxyscrape_collect_returns_list():
    c = ProxyScrapeCollector()
    proxies = await c.collect()
    assert isinstance(proxies, list)
    for p in proxies:
        assert p.host
        assert p.port > 0


@pytest.mark.asyncio
async def test_free_proxy_list_collect_returns_list():
    c = FreeProxyListCollector()
    proxies = await c.collect()
    assert isinstance(proxies, list)
