import pytest
from proxy_vault.models import ProxyEntry, ProxyType, ProxyStatus, AnonymityLevel


@pytest.fixture
def sample_proxy():
    return ProxyEntry(
        host="1.2.3.4",
        port=8080,
        types=[ProxyType.HTTP],
        anonymity=AnonymityLevel.ELITE,
        status=ProxyStatus.ACTIVE,
        score=70,
        latency_ms=200,
    )


@pytest.fixture
def sample_proxies():
    return [
        ProxyEntry(host=f"10.0.0.{i}", port=8080 + i, types=[ProxyType.HTTP])
        for i in range(1, 6)
    ]
