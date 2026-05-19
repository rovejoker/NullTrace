import asyncio
from proxy_vault.providers.free_pool import FreeProxyPool
from proxy_vault.models import ProxyEntry
from proxy_vault.config import config


class HealthMonitor:
    def __init__(self, pool: FreeProxyPool, check_interval: float | None = None):
        self._pool = pool
        self._interval = check_interval or config.get("free_pool.health_check_interval", 60)
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    async def start(self) -> None:
        self._running = True
        while self._running:
            await self._check_all()
            await asyncio.sleep(self._interval)

    async def _check_all(self) -> None:
        proxies = list(self._pool._proxies.values())
        if not proxies:
            return
        semaphore = asyncio.Semaphore(50)
        async def check_one(p: ProxyEntry):
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(p.host, p.port),
                        timeout=5,
                    )
                    writer.close()
                    await writer.wait_closed()
                    self._pool.mark_success(p.key, latency=0)
                except Exception:
                    self._pool.mark_failure(p.key)
        await asyncio.gather(*[check_one(p) for p in proxies])

    async def check_single(self, proxy: ProxyEntry) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(proxy.host, proxy.port),
                timeout=5,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    def stop(self) -> None:
        self._running = False
