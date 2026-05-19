import pytest
import asyncio
from proxy_vault.core.proxy_manager import ProxyManager


@pytest.fixture
def manager():
    return ProxyManager()


def test_initial_state(manager):
    state = manager.state
    assert state.running is False
    assert state.provider == "free"
    assert state.mode == "pool"


@pytest.mark.asyncio
async def test_start_stop(manager):
    await manager.start(provider="custom", proxy_url="socks5://1.2.3.4:1080", mode="single")
    assert manager.state.running is True
    assert manager.state.provider == "custom"
    assert manager.state.mode == "single"
    await manager.stop()
    assert manager.state.running is False


@pytest.mark.asyncio
async def test_start_with_chain(manager):
    await manager.start(provider="free", chain="free,tor")
    assert manager.state.running is True
    # Don't wait for collectors, just stop
    await manager.stop()


@pytest.mark.asyncio
async def test_restart(manager):
    await manager.start(provider="free")
    await manager.stop()
    await manager.start(provider="tor")
    assert manager.state.provider == "tor"
    await manager.stop()


@pytest.mark.asyncio
async def test_get_available_proxies_empty(manager):
    proxies = manager.get_available_proxies()
    assert proxies == []


@pytest.mark.asyncio
async def test_switch_mode(manager):
    await manager.start(provider="free", mode="pool")
    manager.switch_mode("single")
    assert manager.state.mode == "single"
    await manager.stop()


def test_switch_mode_when_stopped(manager):
    manager.switch_mode("pool")
    assert manager.state.mode == "pool"


@pytest.mark.asyncio
async def test_get_stats_while_running(manager):
    await manager.start(provider="free")
    await asyncio.sleep(0.1)
    stats = manager.get_stats()
    assert "total" in stats
    assert "running" in stats
    assert stats["running"] is True
    await manager.stop()
