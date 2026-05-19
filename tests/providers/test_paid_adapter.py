import pytest
from proxy_vault.providers.paid_adapter import PaidAdapterProvider


def test_paid_not_configured_by_default():
    p = PaidAdapterProvider()
    assert not p.is_configured


def test_paid_max_hops():
    p = PaidAdapterProvider()
    assert p.max_hops == 2


@pytest.mark.asyncio
async def test_paid_fetch_empty_when_not_configured():
    p = PaidAdapterProvider()
    proxies = await p.fetch_proxies()
    assert proxies == []
