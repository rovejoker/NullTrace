import asyncio
import pytest
from proxy_vault.core.health_monitor import HealthMonitor
from proxy_vault.providers.free_pool import FreeProxyPool
from proxy_vault.models import ProxyEntry, ProxyType, ProxyStatus


@pytest.mark.asyncio
async def test_health_monitor_checks_proxies():
    pool = FreeProxyPool()
    p = ProxyEntry(host="127.0.0.1", port=9999, types=[ProxyType.HTTP], status=ProxyStatus.ACTIVE)
    pool.add(p)
    monitor = HealthMonitor(pool, check_interval=0.1)
    # Run check directly to avoid timing issues
    await monitor._check_all()
    assert p.consecutive_fails > 0


@pytest.mark.asyncio
async def test_health_monitor_handles_empty_pool():
    pool = FreeProxyPool()
    monitor = HealthMonitor(pool, check_interval=0.1)
    await monitor._check_all()
    # Should not raise any exception


@pytest.mark.asyncio
async def test_is_running():
    pool = FreeProxyPool()
    monitor = HealthMonitor(pool)
    assert not monitor.is_running
    task = asyncio.create_task(monitor.start())
    await asyncio.sleep(0.1)
    assert monitor.is_running
    monitor.stop()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
